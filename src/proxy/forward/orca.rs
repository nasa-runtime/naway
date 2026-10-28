//! 原生 ORCA 服务端流；后台观察与业务请求共用实例、TLS 和 HTTP/2 客户端。

use super::*;
use crate::upstream::load::{metrics, subscription, targets::Target, wire, InstanceLoad};
use std::collections::HashMap;
use std::sync::Weak;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

type Key = (Arc<str>, Arc<str>, u64);

struct TaskPermit {
    _state: Option<crate::control::ownership::state::Lease>,
}

impl Drop for TaskPermit {
    /// 业务作用：订阅任务真正释放时归还观测数量，取消或异常退出不留下虚假活跃连接。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：递减一次活动订阅数，工作区状态名额随字段释放。
    fn drop(&mut self) {
        metrics::SUBSCRIPTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

impl super::super::GatewayProxy {
    /// 业务作用：按唯一快照与新鲜发现目录管理带外订阅，删除、换代和停机都撤销旧任务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：由应用生命周期持有的任务句柄；取消管理器会同步撤销所有子订阅。
    pub fn spawn_upstream_orca(self: &Arc<Self>) -> JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut jobs = JoinSet::new();
            let mut active: HashMap<Key, AbortHandle> = HashMap::new();
            let mut version = 0;
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                while jobs.try_join_next().is_some() {}
                active.retain(|_, task| !task.is_finished());
                let Some(proxy) = weak.upgrade() else {
                    return;
                };
                let snapshot = proxy.snap.load_full();
                if snapshot.version != version {
                    // 先停止旧代 I/O 再授予新订阅，不能借 reload 短暂突破订阅和状态预算。
                    jobs.shutdown().await;
                    active.clear();
                    version = snapshot.version;
                }
                let targets = match snapshot.upstreams.orca_targets() {
                    Ok(targets) => targets,
                    Err(_) => {
                        // 全目录超限或传输不可信时停止反馈，不能只选任意前几个实例制造调度偏置。
                        metrics::CAPACITY.fetch_add(1, Ordering::Relaxed);
                        jobs.shutdown().await;
                        active.clear();
                        continue;
                    }
                };
                active.retain(|key, task| {
                    let keep = targets.iter().any(|target| target.key() == *key);
                    if !keep {
                        task.abort();
                    }
                    keep
                });
                for target in targets {
                    let key = target.key();
                    if active.contains_key(&key) || jobs.len() >= subscription::MAX_SUBSCRIPTIONS {
                        continue;
                    }
                    let permit = match task_permit(&proxy, &snapshot, &target) {
                        Some(permit) => permit,
                        None => {
                            metrics::CAPACITY.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    let Some(entry) = proxy
                        .upstream_health
                        .load_entry(&target.instance, snapshot.version)
                    else {
                        metrics::CAPACITY.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    // 从引用该服务的 listener 取得真实池策略；未引用服务仍可在零业务 QPS 时获得反馈。
                    let limits = snapshot
                        .proxies
                        .iter()
                        .find(|listener| {
                            listener
                                .router
                                .upstream_service_refs()
                                .iter()
                                .any(|(service, _)| service.as_str() == target.service.as_ref())
                        })
                        .map(|listener| listener.limits.clone())
                        .unwrap_or_default();
                    let pool = HttpPoolPolicy::from_limits(&limits);
                    let handle =
                        jobs.spawn(run(weak.clone(), target, entry, pool, version, permit));
                    active.insert(key, handle);
                }
            }
        })
    }
}

/// 业务作用：按受信服务归属取得跨代工作区状态名额，后台订阅不能绕过租户预算。
///
/// 参数说明：
/// - `proxy`：共享运行态。
/// - `snapshot`：当前已发布配置。
/// - `target`：由该配置的实例目录生成的订阅目标。
///
/// 返回：身份和容量允许时授予任务名额；缺失归属或资源不足时拒绝。
fn task_permit(
    proxy: &super::super::GatewayProxy,
    snapshot: &GatewaySnapshot,
    target: &Target,
) -> Option<TaskPermit> {
    if !snapshot.ownership.enabled() {
        // 未启用多租户的本地配置属于平台；仍受全进程订阅上限约束，不要求不存在的对象目录。
        metrics::SUBSCRIPTIONS.fetch_add(1, Ordering::Relaxed);
        return Some(TaskPermit {
            _state: None,
        });
    }
    let owner = snapshot
        .ownership
        .object_owner(&format!("service:{}", target.service))?;
    let budget = proxy
        .workspace_state
        .budget(&snapshot.ownership, owner)
        .ok()?;
    let state = budget
        .as_ref()
        .map(|budget| budget.acquire())
        .transpose()
        .ok()?;
    metrics::SUBSCRIPTIONS.fetch_add(1, Ordering::Relaxed);
    Some(TaskPermit {
        _state: state,
    })
}

/// 业务作用：只在原配置与实例仍获授权时接受报告，旧流不得把同地址新实例当作原实例。
///
/// 参数说明：
/// - `weak`：不延长整个网关生命周期的共享句柄。
/// - `target`：订阅冻结的实例和策略。
/// - `version`：授予订阅时的配置版本。
///
/// 返回：快照、实例和 TLS 权威全部仍有效时为 true。
fn current(weak: &Weak<super::super::GatewayProxy>, target: &Target, version: u64) -> bool {
    let Some(proxy) = weak.upgrade() else {
        return false;
    };
    let snapshot = proxy.snap.load();
    snapshot.version == version && snapshot.upstreams.orca_target_current(target)
}

/// 业务作用：为单个实例维护有界重连循环，通信失败只让反馈自然过期，不改变健康事实。
///
/// 参数说明：
/// - `weak`：共享客户端和当前目录的弱引用。
/// - `target`：冻结的服务、实例与订阅配置。
/// - `entry`：调度者已有的反馈对象。
/// - `pool`：真实业务 HTTP/2 池参数。
/// - `version`：当前订阅获权的配置版本。
/// - `_permit`：随任务真实结束归还的工作区状态名额。
///
/// 返回：撤权时结束；可恢复传输错误指数退避，最长等待一分钟且不会写健康状态。
async fn run(
    weak: Weak<super::super::GatewayProxy>,
    target: Target,
    entry: Arc<InstanceLoad>,
    pool: HttpPoolPolicy,
    version: u64,
    _permit: TaskPermit,
) {
    let cfg = target
        .policy
        .out_of_band
        .as_ref()
        .expect("validated ORCA subscription");
    let request = wire::request(cfg.report_interval_ms);
    let mut backoff = cfg.reconnect_backoff_ms;
    while current(&weak, &target, version) {
        let received = stream(&weak, &target, &entry, pool, version, request.clone()).await;
        if !current(&weak, &target, version) {
            metrics::STALE.fetch_add(1, Ordering::Relaxed);
            return;
        }
        metrics::RETRIES.fetch_add(1, Ordering::Relaxed);
        if received {
            backoff = cfg.reconnect_backoff_ms;
        }
        // 失败循环有绝对上限退避和节点内扰动；不能在故障期向同一后端无间隔重拨。
        let jitter = crate::upstream::load::monotonic_ms() % (backoff / 4 + 1);
        tokio::time::sleep(Duration::from_millis((backoff + jitter).min(60_000))).await;
        backoff = backoff.saturating_mul(2).min(60_000);
    }
}

/// 业务作用：用已校验实例的同一 TLS/连接预算打开标准 ORCA gRPC 服务端流。
///
/// 参数说明：
/// - `proxy`：已存在的上游客户端目录。
/// - `target`：固定 authority、协议与 TLS 身份。
/// - `pool`：真实业务池策略。
/// - `payload`：预编码的报告间隔请求。
///
/// 返回：只接受 HTTP/2 200 和未压缩 gRPC；其它响应不产生反馈，也不跟随重定向。
async fn open(
    proxy: &super::super::GatewayProxy,
    target: &Target,
    pool: HttpPoolPolicy,
    payload: Bytes,
) -> Result<Response<UpstreamResponseBody>, BoxError> {
    let instance = &target.instance;
    let cfg = target
        .policy
        .out_of_band
        .as_ref()
        .expect("validated ORCA subscription");
    let reservation = UpstreamReservation {
        base: instance.uri.clone(),
        health_key: instance.health_key.clone(),
        protocol: instance.protocol,
        connect_timeout_ms: instance.connect_timeout_ms,
        tls_profile: instance.tls_profile.clone(),
        pool_policy: pool,
        feedback: None,
        outlier: None,
        counter: None,
        pending_counter: None,
        release_on_drop: false,
    };
    if instance
        .tls_profile
        .as_ref()
        .is_some_and(|profile| !profile.allows_new_requests())
    {
        return Err("ORCA identity is no longer authorized".into());
    }
    let uri = upstream_uri(&instance.uri, wire::METHOD, "")?;
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .version(http::Version::HTTP_2)
        .header(CONTENT_TYPE, "application/grpc")
        .header(TE, "trailers")
        .header("grpc-accept-encoding", "identity")
        .body(full_body(payload))?;
    let send = async {
        if instance.protocol == UpstreamProtocol::H2c {
            proxy
                .h2c_client_for(&reservation, Some(0))
                .request(request)
                .await
        } else {
            proxy
                .http_client_for(&reservation, true, Some(0))
                .request(request)
                .await
        }
    };
    let response =
        tokio::time::timeout(Duration::from_millis(cfg.connect_timeout_ms), send).await??;
    if response.status() != StatusCode::OK
        || response.version() != http::Version::HTTP_2
        || !has_native_grpc_content_type(response.headers())
        || response
            .headers()
            .get("grpc-encoding")
            .is_some_and(|value| value != "identity")
        || response.headers().contains_key("grpc-status")
    {
        return Err("invalid ORCA gRPC response".into());
    }
    Ok(response)
}

/// 业务作用：逐帧读取并复验带外报告，完整帧借用解析，分片和高频发送受独立硬门限制。
///
/// 参数说明：
/// - `weak`：当前目录权威与共享传输的弱引用。
/// - `target`：被授予的订阅目标。
/// - `entry`：该实例的共享负载状态。
/// - `pool`：共享 HTTP/2 连接策略。
/// - `version`：冻结的配置版本。
/// - `payload`：可跨重连共享的请求帧。
///
/// 返回：是否收到过有效报告，用于重置重连退避；任何失败均丢弃流而不影响健康事实。
async fn stream(
    weak: &Weak<super::super::GatewayProxy>,
    target: &Target,
    entry: &InstanceLoad,
    pool: HttpPoolPolicy,
    version: u64,
    payload: Bytes,
) -> bool {
    let Some(proxy) = weak.upgrade() else {
        return false;
    };
    let Ok(response) = open(&proxy, target, pool, payload).await else {
        return false;
    };
    drop(proxy);
    let cfg = target
        .policy
        .out_of_band
        .as_ref()
        .expect("validated ORCA subscription");
    let mut body = response.into_body();
    let mut decoder = wire::Decoder::new(cfg.max_report_bytes);
    let mut deadline = TokioInstant::now() + Duration::from_millis(cfg.idle_timeout_ms);
    let mut window = TokioInstant::now();
    let mut reports = 0usize;
    let mut received = false;
    loop {
        if TokioInstant::now() >= deadline || !current(weak, target, version) {
            return received;
        }
        let Ok(Some(Ok(frame))) = tokio::time::timeout_at(deadline, body.frame()).await else {
            return received;
        };
        let Ok(data) = frame.into_data() else {
            return received;
        };
        let mut input = data.as_ref();
        while !input.is_empty() {
            let value = match decoder.next(&mut input) {
                Ok(Some(value)) => value,
                Ok(None) => break,
                Err(()) => {
                    metrics::INVALID.fetch_add(1, Ordering::Relaxed);
                    return received;
                }
            };
            let now = TokioInstant::now();
            if now.duration_since(window) >= Duration::from_millis(cfg.report_interval_ms) {
                window = now;
                reports = 0;
            }
            reports += 1;
            // 允许有限网络合并，但拒绝持续超过声明频率的报告，避免反馈流耗尽 worker。
            if reports > 4 || !current(weak, target, version) {
                metrics::INVALID.fetch_add(1, Ordering::Relaxed);
                return received;
            }
            entry.record_utilization(value, target.policy.smoothing_bp);
            metrics::ACCEPTED.fetch_add(1, Ordering::Relaxed);
            received = true;
            deadline = now + Duration::from_millis(cfg.idle_timeout_ms);
            tokio::task::yield_now().await;
        }
        // 空 DATA 或逐字节分片不能通过持续 ready 的 poll 饿死其它任务或延长完整报告期限。
        tokio::task::yield_now().await;
    }
}
