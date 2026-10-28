//! 管理成员查询共享有界执行者；连接可复用，成员事实必须逐次读取。

use crate::config::model::NacosDiscoveryCfg;
use nasa::discovery::nacos::{NacosDiscoveryClient, NacosProps};
use nasa::discovery::Instance;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

const QUEUE_CAPACITY: usize = 16;
const CLIENT_CAPACITY: usize = 4;
pub(in crate::admin) const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(in crate::admin) struct Runtime {
    worker: parking_lot::Mutex<Option<Worker>>,
}

struct Worker {
    sender: mpsc::Sender<Request>,
    stop: Option<oneshot::Sender<()>>,
}

struct Request {
    props: NacosProps,
    service: String,
    deadline: Instant,
    reply: oneshot::Sender<anyhow::Result<Vec<Instance>>>,
}

#[derive(Default)]
struct Clients {
    entries: VecDeque<(NacosProps, NacosDiscoveryClient)>,
}

impl Runtime {
    /// 业务作用：在共享预算内查询冻结发现域的实时全部成员，避免请求数决定线程数。
    ///
    /// 参数说明：
    /// - `nacos`：已由调用方冻结的注册中心配置。
    /// - `service`：该配置声明的本网关自注册服务。
    /// - `timeout`：包含排队时间的完整期限，至多五秒。
    ///
    /// 返回：当前全部实例；关闭、饱和、取消、期限或依赖故障返回低敏错误，不回退为空成功。
    pub(in crate::admin) async fn discover(
        &self,
        nacos: &NacosDiscoveryCfg,
        service: String,
        timeout: Duration,
    ) -> anyhow::Result<Vec<Instance>> {
        // 管理查询不能绕过自注册开关，也不能用外部输入扩大到任意服务域。
        anyhow::ensure!(
            crate::upstream::discovery::self_register_service_name(nacos).as_deref()
                == Some(service.as_str()),
            "cluster discovery is disabled or service is outside the configured domain"
        );
        let deadline = Instant::now() + timeout.min(REQUEST_TIMEOUT);
        anyhow::ensure!(
            Instant::now() < deadline,
            "cluster discovery deadline exceeded"
        );
        let (reply, receiver) = oneshot::channel();
        let request = Request {
            props: crate::upstream::discovery::nacos_props(nacos),
            service,
            deadline,
            reply,
        };
        self.sender()?
            .try_send(request)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => anyhow::anyhow!("cluster discovery is busy"),
                mpsc::error::TrySendError::Closed(_) => {
                    anyhow::anyhow!("cluster discovery worker is unavailable")
                }
            })?;
        tokio::time::timeout_at(deadline, receiver)
            .await
            .map_err(|_| anyhow::anyhow!("cluster discovery deadline exceeded"))?
            .map_err(|_| anyhow::anyhow!("cluster discovery worker is unavailable"))?
    }

    /// 业务作用：首次实际查询才创建唯一执行者，多监听和并发请求共享同一有界队列。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：共享发送端；线程创建失败可重试，已退出执行者保持失败而不自动重启。
    fn sender(&self) -> anyhow::Result<mpsc::Sender<Request>> {
        let mut owner = self.worker.lock();
        if let Some(worker) = owner.as_ref() {
            return Ok(worker.sender.clone());
        }
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let (stop, stopped) = oneshot::channel();
        std::thread::Builder::new()
            .name("admin-member-discovery".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(run(receiver, stopped));
                runtime.shutdown_timeout(Duration::from_secs(1));
            })
            .map_err(|_| anyhow::anyhow!("cluster discovery worker is unavailable"))?;
        *owner = Some(Worker {
            sender: sender.clone(),
            stop: Some(stop),
        });
        Ok(sender)
    }
}

impl Drop for Worker {
    /// 业务作用：管理状态释放时取消执行者，不让排队或在途查询延长管理进程资源生命周期。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：发送停止通知；不在异步连接线程中阻塞等待线程退出。
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// 业务作用：串行执行实时查询并维持客户端所属运行时，调用取消与停止均优先于新工作。
///
/// 参数说明：
/// - `requests`：最多十六个排队请求。
/// - `stopped`：管理状态释放时触发的唯一停止信号。
///
/// 返回：停止或发送端全部关闭后释放本地客户端与队列；不把未完成查询报告成功。
async fn run(mut requests: mpsc::Receiver<Request>, mut stopped: oneshot::Receiver<()>) {
    let mut clients = Clients::default();
    loop {
        let request = tokio::select! {
            biased;
            _ = &mut stopped => return,
            request = requests.recv() => request,
        };
        let Some(mut request) = request else {
            return;
        };
        // 过期或调用方已离开的排队项不再连接外部依赖，避免取消后继续放大故障流量。
        if request.reply.is_closed() || Instant::now() >= request.deadline {
            let _ = request
                .reply
                .send(Err(anyhow::anyhow!("cluster discovery deadline exceeded")));
            continue;
        }
        let result = tokio::select! {
            biased;
            _ = &mut stopped => return,
            _ = request.reply.closed() => continue,
            result = tokio::time::timeout_at(
                request.deadline,
                clients.discover(request.props, &request.service),
            ) => result.unwrap_or_else(|_| Err(anyhow::anyhow!("cluster discovery deadline exceeded"))),
        };
        let _ = request.reply.send(result);
    }
}

impl Clients {
    /// 业务作用：按连接身份复用命名客户端，逐次查询全部实例，不缓存过去的成员事实。
    ///
    /// 参数说明：
    /// - `props`：已规范化的连接参数，包含当前查询自己的凭据。
    /// - `service`：本次冻结的自注册服务名。
    ///
    /// 返回：成功移动实例列表；依赖错误仅保留固定原因，连接成功后故障仍复用SDK重连机制。
    async fn discover(
        &mut self,
        props: NacosProps,
        service: &str,
    ) -> anyhow::Result<Vec<Instance>> {
        if let Some(index) = self
            .entries
            .iter()
            .position(|(existing, _)| same_connection(existing, &props))
        {
            let entry = self.entries.remove(index).expect("located client entry");
            self.entries.push_front(entry);
        } else {
            // 先收回缓存预算再创建新身份，不能临时持有第五个客户端或跨凭据复用连接。
            if self.entries.len() == CLIENT_CAPACITY {
                self.entries.pop_back();
            }
            let client = NacosDiscoveryClient::connect(&props)
                .await
                .map_err(|_| anyhow::anyhow!("cluster discovery connection is unavailable"))?;
            self.entries.push_front((props, client));
        }
        self.entries
            .front()
            .expect("connected client entry")
            .1
            .discover_all(service)
            .await
            .map_err(|_| anyhow::anyhow!("cluster discovery query is unavailable"))
    }
}

/// 业务作用：完整比较连接域和认证身份，禁止只按地址缓存而混用命名空间或已轮换凭据。
///
/// 参数说明：
/// - `left`：已缓存客户端的规范化参数。
/// - `right`：当前请求的规范化参数。
///
/// 返回：所有NASA连接字段一致才允许复用；服务名和业务轮询频率不影响连接身份。
fn same_connection(left: &NacosProps, right: &NacosProps) -> bool {
    left.server_addr == right.server_addr
        && left.namespace == right.namespace
        && left.group == right.group
        && left.app_name == right.app_name
        && left.discovery_ip == right.discovery_ip
        && left.username == right.username
        && left.password == right.password
}
