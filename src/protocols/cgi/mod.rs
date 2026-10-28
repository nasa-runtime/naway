//! 有界 CGI 会话；只有完整请求与响应均结束的 FastCGI 连接能够回池。

pub(crate) mod metrics;
mod params;
mod semantic;
mod wire;

use crate::proxy::forward::{PhysicalConnectionBudget, PhysicalConnectionSlot};
use crate::{config::cgi::CgiCfg, BoxBody, BoxError};
use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response};
use hyper::body::{Body, Frame};
use parking_lot::Mutex;
use std::{
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, Semaphore},
    task::JoinHandle,
};

pub(crate) struct Plan {
    pub config: CgiCfg,
    inflight: Arc<Semaphore>,
    idle: Mutex<Vec<Idle>>,
}

struct Idle {
    key: Arc<str>,
    at: Instant,
    connection: TcpStream,
    slot: PhysicalConnectionSlot,
}

/// 输入元数据拒绝与后端故障分离，不允许恶意大头影响服务被动健康。
#[derive(Debug)]
pub(crate) struct InputRejected;
impl std::fmt::Display for InputRejected {
    /// 业务作用：输出固定低敏输入拒绝原因。
    ///
    /// 参数说明：
    /// - `f`：诊断输出目标。
    ///
    /// 返回：写入不含原始头或参数的固定描述。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CGI request parameters rejected")
    }
}
impl std::error::Error for InputRejected {}

/// 业务作用：在进入上游治理前拒绝无法无缓冲映射的输入长度。
///
/// 参数说明：
/// - `parts`：请求 head。
/// - `body`：尚未读取的实体流。
///
/// 返回：声明或精确 size hint 的长度；未知或歧义时拒绝，不读取 body。
pub(crate) fn request_length(parts: &http::request::Parts, body: &BoxBody) -> Result<u64> {
    params::length(parts, body)
}

#[derive(Clone)]
pub(crate) struct Input {
    pub plan: Arc<Plan>,
    pub uri: http::Uri,
    pub client_ip: IpAddr,
    pub https: bool,
    pub version: http::Version,
}

impl Plan {
    /// 业务作用：在完整候选阶段建立固定脚本计划及有界连接状态。
    ///
    /// 参数说明：
    /// - `config`：路由的受信脚本与资源声明。
    ///
    /// 返回：校验通过时返回独立计划；不进行网络连接或脚本执行。
    pub fn build(config: &CgiCfg) -> Result<Arc<Self>> {
        config.validate()?;
        Ok(Arc::new(Self {
            config: config.clone(),
            inflight: Arc::new(Semaphore::new(config.max_inflight)),
            idle: Mutex::new(Vec::new()),
        }))
    }

    /// 业务作用：输出不含文件路径或请求参数的管理语义。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：协议、预算、复用语义和完整声明的摘要。
    pub fn semantic(&self) -> serde_json::Value {
        serde_json::json!({
            "protocol": self.config.protocol.name(),
            "multiplexing": false,
            "keep_conn": self.config.keep_conn,
            "max_inflight": self.config.max_inflight,
            "max_param_bytes": self.config.max_param_bytes,
            "max_header_bytes": self.config.max_header_bytes,
            "fingerprint": nasa::crypto::sha256(&serde_json::to_string(&self.config).expect("serializable CGI config"))
        })
    }

    /// 业务作用：优先取回同一实例身份的干净连接，关闭超龄或已被对端关闭的连接。
    ///
    /// 参数说明：
    /// - `key`：实例及协议的完整身份。
    ///
    /// 返回：已复验的单请求连接；不存在时由调用者在共享预算内拨号。
    fn take(&self, key: &str) -> Option<Idle> {
        let mut idle = self.idle.lock();
        idle.retain(|item| item.at.elapsed() < Duration::from_millis(self.config.idle_timeout_ms));
        while let Some(index) = idle.iter().position(|item| item.key.as_ref() == key) {
            let item = idle.swap_remove(index);
            let mut byte = [0u8; 1];
            // 多余字节意味着上一请求并未干净结束，绝不让下一身份接收这段残留。
            if matches!(item.connection.try_read(&mut byte), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            {
                return Some(item);
            }
        }
        None
    }
}

/// 业务作用：把固定脚本请求交给全双工记录会话并保持下游取消可传播。
///
/// 参数说明：
/// - `request`：已完成安全策略的请求头与实体流。
/// - `input`：固定脚本计划及可信连接元数据。
/// - `endpoint`：已选实例的受信地址。
/// - `key`：实例与协议隔离身份。
/// - `budget`：跨快照物理连接门。
/// - `connect_ms`：拨号阶段的毫秒上限。
///
/// 返回：合法响应头和有界流式 body；容量、拨号或协议错误不发布成功响应。
pub(crate) async fn send(
    request: Request<BoxBody>,
    input: Input,
    endpoint: Arc<str>,
    key: Arc<str>,
    budget: Arc<PhysicalConnectionBudget>,
    connect_ms: u64,
) -> Result<Response<CgiBody>, BoxError> {
    let permit = input
        .plan
        .inflight
        .clone()
        .try_acquire_owned()
        .map_err(|_| crate::proxy::forward::ConnectionLimitReached)?;
    let (parts, body) = request.into_parts();
    let (variables, length) = params::build(&parts, &body, &input).map_err(|_| InputRejected)?;
    let plan = input.plan.clone();
    let idle = plan.take(&key);
    let (connection, slot) = if let Some(idle) = idle {
        (idle.connection, idle.slot)
    } else {
        let slot = budget.try_acquire()?;
        let uri: http::Uri = endpoint.parse()?;
        if uri.scheme_str() != Some("http") {
            return Err("CGI endpoint cannot use TLS implicitly".into());
        }
        let host = uri
            .host()
            .ok_or("CGI endpoint has no host")?
            .trim_matches(['[', ']']);
        let port = uri.port_u16().ok_or("CGI endpoint has no explicit port")?;
        let timeout = Duration::from_millis(if connect_ms == 0 {
            10_000
        } else {
            connect_ms
        });
        let connection = tokio::time::timeout(timeout, TcpStream::connect((host, port))).await??;
        connection.set_nodelay(true)?;
        (connection, slot)
    };
    let (head_tx, head_rx) = oneshot::channel();
    let (body_tx, body_rx) = mpsc::channel(2);
    let task = tokio::spawn(async move {
        let _permit = permit;
        let (read, write) = connection.into_split();
        let mut head_tx = Some(head_tx);
        let result = tokio::try_join!(
            wire::write_request(write, body, &variables, length, &plan.config),
            wire::read_response(
                read,
                &plan.config,
                parts.method == http::Method::HEAD,
                &mut head_tx,
                &body_tx
            ),
        );
        match result {
            Ok((write, (read, last))) => {
                // 最后一块必须等待请求长度和响应终止记录全部通过；否则短输入可能被包装为完整成功。
                if let Some(last) = last {
                    if body_tx.send(Ok(Frame::data(last))).await.is_err() {
                        return;
                    }
                }
                if plan.config.keep_conn {
                    if let Ok(connection) = read.reunite(write) {
                        let mut idle = plan.idle.lock();
                        if idle.len() < plan.config.max_inflight {
                            idle.push(Idle {
                                key,
                                at: Instant::now(),
                                connection,
                                slot,
                            });
                        }
                    }
                }
            }
            Err(error) => {
                super::cgi::wire::record_failure(plan.config.protocol);
                tracing::warn!(protocol = plan.config.protocol.name(), reason = %error, "CGI session terminated");
                if let Some(tx) = head_tx.take() {
                    let _ = tx.send(Err(error));
                } else {
                    let _ = body_tx.send(Err(error)).await;
                }
            }
        }
    });
    let task = TaskGuard(task);
    let head = head_rx
        .await
        .map_err(|_| "CGI session ended without response headers")??;
    Ok(Response::from_parts(
        head,
        CgiBody {
            receiver: body_rx,
            _task: task,
            done: false,
        },
    ))
}

struct TaskGuard(JoinHandle<()>);
impl Drop for TaskGuard {
    /// 业务作用：使下游取消、超时及未消费的响应立即终止两方向 I/O。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：释放会话任务，未完成连接不会回池。
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct CgiBody {
    receiver: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
    _task: TaskGuard,
    done: bool,
}
impl Body for CgiBody {
    type Data = Bytes;
    type Error = BoxError;
    /// 业务作用：按下游消费速率取回有界记录数据，传播协议失败。
    ///
    /// 参数说明：
    /// - `cx`：异步调度上下文。
    ///
    /// 返回：单个流式帧、等待或已经验证的结束；不依据 Content-Length 提前宣告收尾。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                self.done = true;
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }
    /// 业务作用：只在会话明确结束后允许调用者回收响应期名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整结束或失败终止时为 true。
    fn is_end_stream(&self) -> bool {
        self.done
    }
}
