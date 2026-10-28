//! 按需运行的共享实时采样器，只保留当前结果和一个累计基线。

mod buckets;
mod circuit;
mod cluster;
mod http_stream;
pub(super) mod model;
mod process;
mod publication;
mod response_codec;
pub(in crate::admin) mod routes;

use publication::Publication;
mod source;

use super::{AdminState, BoxBody};
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http::{Response, StatusCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tokio_util::task::AbortOnDropHandle;

const IDLE_MS: u64 = 12_000;
const RESPONSE_LIMIT: usize = 1024 * 1024;

pub(super) struct Runtime {
    origin: Instant,
    boot_id: String,
    last_interest: AtomicU64,
    remote_until: AtomicU64,
    wake: Arc<Notify>,
    latest: ArcSwapOption<Publication>,
    task: OnceLock<AbortOnDropHandle<()>>,
    cluster: cluster::Runtime,
    route_readers: tokio::sync::Semaphore,
}

impl Runtime {
    /// 业务作用：向同进程的管理读面提供唯一启动身份，避免把同一节点的多个入口重复计数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与采样器生命周期一致的只读启动标识。
    pub(super) fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// 业务作用：建立唯一进程采样身份与空结果，不在构建阶段打开外部资源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未开始采样的管理运行态，只有已授权观察请求才产生兴趣。
    pub(super) fn new() -> Self {
        Self {
            origin: Instant::now(),
            boot_id: format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            last_interest: AtomicU64::new(0),
            remote_until: AtomicU64::new(0),
            wake: Arc::new(Notify::new()),
            latest: ArcSwapOption::empty(),
            task: OnceLock::new(),
            cluster: cluster::Runtime::new(),
            route_readers: tokio::sync::Semaphore::new(4),
        }
    }

    /// 业务作用：以进程单调时钟记录采样及观察期限，墙钟调整不能延长观察权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：启动以来的有界毫秒数。
    fn elapsed_ms(&self) -> u64 {
        self.origin.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    /// 业务作用：保持当前采样兴趣，多个浏览器只唤醒同一个协调器。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：更新有限观察期限，不创建独立任务或等待队列。
    fn touch(&self) {
        self.last_interest
            .store(self.elapsed_ms().saturating_add(1), Ordering::Release);
        if self.latest.load().is_none() {
            self.wake.notify_one();
        }
    }

    /// 业务作用：把管理目标的有限兴趣并集交给唯一采样器，不续期本地HTTP观察权。
    ///
    /// 参数说明：
    /// - `until`：所有当前授权目标的最晚截止时刻，空值立即撤销远端兴趣。
    ///
    /// 返回：只保存绝对单调期限并唤醒采样，无单目标任务或历史队列。
    #[cfg(feature = "admin-grpc")]
    pub(in crate::admin) fn remote_interest(&self, until: Option<Instant>) {
        let remaining = until.map_or(Duration::ZERO, |at| {
            at.saturating_duration_since(Instant::now())
        });
        let deadline = if remaining.is_zero() {
            0
        } else {
            self.elapsed_ms()
                .saturating_add(remaining.as_millis().min(12_000) as u64)
        };
        self.remote_until.store(deadline, Ordering::Release);
        self.wake.notify_one();
    }

    /// 业务作用：向已授权上报轮次借出当前结构化样本，配置身份和年龄失效时不传旧数据。
    ///
    /// 参数说明：
    /// - `snapshot`：本轮事实和目标采用的冻结配置。
    ///
    /// 返回：共享样本与原采集时刻；不会编码HTTP响应或延长兴趣。
    #[cfg(feature = "admin-grpc")]
    pub(in crate::admin) fn upload_sample(
        &self,
        snapshot: &crate::config::GatewaySnapshot,
    ) -> Option<(Arc<model::Sample>, Instant)> {
        self.latest
            .load_full()
            .filter(|value| {
                snapshot.admin_monitor.enabled
                    && value.at.elapsed() <= snapshot.admin_monitor.period * 3
                    && value.sample.state.config_version == snapshot.version
                    && value.sample.state.config_fingerprint
                        == snapshot
                            .config_fingerprint
                            .map(|value| format!("{value:016x}"))
            })
            .map(|value| (value.sample.clone(), value.at))
    }
}

/// 业务作用：把唯一采样任务绑定到进程管理状态，监听器热换代不能另建基线或重复采样。
///
/// 参数说明：
/// - `state`：各代监听器共用的管理状态，仅在一次采样期间升级弱引用。
///
/// 返回：首次调用启动任务，之后复用；管理状态销毁时自动终止，不延长进程寿命。
pub(super) fn start(state: &Arc<AdminState>) {
    state.monitor.task.get_or_init(|| {
        AbortOnDropHandle::new(tokio::spawn(run(
            Arc::downgrade(state),
            state.monitor.wake.clone(),
        )))
    });
    cluster::start(state);
}

/// 业务作用：按固定周期建立当前快照，无观察者时停止采集并释放基线。
///
/// 参数说明：
/// - `owner`：监听器拥有的弱状态引用。
/// - `wake`：共享唤醒器，不反向持有管理状态。
///
/// 返回：管理状态释放时结束；无任何监控文件、数据库或历史队列副作用。
async fn run(owner: Weak<AdminState>, wake: Arc<Notify>) {
    let mut next = tokio::time::Instant::now();
    let mut previous: Option<Arc<model::Sample>> = None;
    let mut sequence = 0u64;
    loop {
        let scheduled = tokio::select! {
            _ = tokio::time::sleep_until(next) => true,
            _ = wake.notified() => false,
        };
        let Some(state) = owner.upgrade() else {
            return;
        };
        let runtime = &state.monitor;
        let plan = state.snap.load().admin_monitor.clone();
        if scheduled {
            next = tokio::time::Instant::now() + plan.period.min(Duration::from_secs(1));
        }
        let interest = runtime.last_interest.load(Ordering::Acquire);
        let now = runtime.elapsed_ms();
        let local = interest != 0
            && now.saturating_sub(interest) <= IDLE_MS.max(plan.period.as_millis() as u64 * 3);
        let remote = now < runtime.remote_until.load(Ordering::Acquire);
        if !plan.enabled || (!local && !remote) {
            // 无观察者不保留过去区间；恢复时必须先建立新基线，不能把空档摊薄成低速率。
            previous = None;
            runtime.latest.store(None);
            continue;
        }
        // 周期由定时器负责；若用采样完成时刻再次比较期限，细小处理耗时会错误跳过整轮。
        // 浏览器唤醒只负责首样本，不能提高已经运行中的采样频率。
        if !scheduled
            && previous
                .as_ref()
                .is_some_and(|sample| sample.sampling_period_ms == plan.period.as_millis() as u64)
        {
            continue;
        }
        // 期限从采样开始计，不从编码完成时刻再续期，避免处理耗时累计造成漏采。
        next = tokio::time::Instant::now() + plan.period;
        sequence = sequence.saturating_add(1);
        let at = Instant::now();
        let mut current = source::sample(&state, runtime, sequence);
        if !model::validate(&mut current) {
            previous = None;
            runtime.latest.store(None);
            continue;
        }
        let current = Arc::new(current);
        // 先发布通过校验的结构化事实；HTTP编码延迟到对应读面首次访问，纯上传不生成JSON。
        runtime.latest.store(Some(Arc::new(Publication::new(
            current.clone(),
            previous.take(),
            at,
        ))));
        previous = Some(current);
    }
}

/// 业务作用：从已计算的固定指标组装首屏摘要，分母仅用同区间已完成响应。
///
/// 参数说明：
/// - `points`：本轮差值与瞬时状态。
///
/// 返回：速率、错误比例、资源及管理监听摘要；没有有效样本时保留null。
fn summary(points: &[model::Point<'_>]) -> serde_json::Value {
    let find = |name| {
        points
            .iter()
            .find(|point| point.name == name && point.labels.is_empty())
    };
    let rate = |name| find(name).and_then(|point| point.per_second);
    let gauge = |name| find(name).and_then(|point| point.current);
    let response_rate = [
        "gw_responses_2xx_total",
        "gw_responses_3xx_total",
        "gw_responses_4xx_total",
        "gw_responses_5xx_total",
    ]
    .into_iter()
    .try_fold(0.0, |sum, name| Some(sum + rate(name)?));
    let ratio = |name| {
        rate(name)
            .zip(response_rate)
            .filter(|(_, count)| *count > 0.0)
            .map(|(count, total)| count / total)
    };
    serde_json::json!({
        "requests_per_second": rate("gw_requests_total"),
        "responses_5xx_per_second": rate("gw_responses_5xx_total"),
        "server_error_ratio": ratio("gw_responses_5xx_total"),
        "client_error_ratio": ratio("gw_responses_4xx_total"),
        "connections": gauge("gw_active_connections"),
        "stream_connections": gauge("gw_stream_active_connections"),
        "stream_in_bytes_per_second": rate("gw_stream_bytes_downstream_to_upstream_total"),
        "stream_out_bytes_per_second": rate("gw_stream_bytes_upstream_to_downstream_total"),
        "cpu_percent_one_core": rate("gw_process_cpu_nanoseconds_total").map(|value| value / 10_000_000.0),
        "resident_bytes": gauge("gw_process_resident_bytes"),
        "rate_rejections_per_second": rate("gw_rate_limited_total"),
        "circuit_rejections_per_second": rate("gw_circuit_rejected_total"),
        "http_stream": http_stream::view(points),
        "circuit": circuit::view(points),
        "rate_buckets": buckets::view(points),
        "response_codec": response_codec::view(points),
        "management": {
            "receiver_enabled": gauge("gw_management_receiver_enabled").map(|value| value == 1.0),
            "receiver_observed": gauge("gw_management_receiver_observed").map(|value| value == 1.0),
            "receiver_state": points.iter()
                .find(|point| point.name == "gw_management_receiver_state" && point.current == Some(1.0))
                .and_then(|point| point.labels.get("state")),
            "connections": gauge("gw_management_active_connections"),
            "consecutive_accept_failures": gauge("gw_management_consecutive_accept_failures"),
            "accept_stall_milliseconds": gauge("gw_management_accept_stall_milliseconds"),
        },
    })
}

/// 业务作用：在硬响应预算内编码一次共享快照，后续HTTP请求只克隆Bytes引用。
///
/// 参数说明：
/// - `value`：固定目录生成的有限读模型。
///
/// 返回：不超过1MiB的JSON；编码或容量失败为None。
fn encode(value: &impl serde::Serialize) -> Option<Bytes> {
    let mut buffer = LimitedBuffer(Vec::with_capacity(8192));
    serde_json::to_writer(&mut buffer, value).ok()?;
    Some(Bytes::from(buffer.0))
}

struct LimitedBuffer(Vec<u8>);

impl std::io::Write for LimitedBuffer {
    /// 业务作用：在JSON编码期间拒绝超预算输出，避免先构造巨大响应再截断。
    ///
    /// 参数说明：
    /// - `bytes`：编码器当前输出片段。
    ///
    /// 返回：完整接收长度；超预算不写入并返回错误。
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > RESPONSE_LIMIT.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("monitor response capacity exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// 业务作用：完成内存编码器的刷新协议，不产生外部写入。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：内存缓冲无需额外刷新，始终成功。
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 业务作用：向已通过认证与Cluster/Read门的请求返回共享当前结果。
///
/// 参数说明：
/// - `state`：共享采样和当前配置权威。
/// - `raw`：内部节点抓取累计事实，浏览器读取区间结果。
///
/// 返回：当前JSON或202采样中；不接受历史范围，不触发逐请求采样。
pub(super) fn read(state: &AdminState, raw: bool) -> Response<BoxBody> {
    let plan = state.snap.load().admin_monitor.clone();
    if !plan.enabled {
        return pending("disabled", plan.period);
    }
    state.monitor.touch();
    let Some(publication) = state.monitor.latest.load_full().filter(|value| {
        value.at.elapsed() <= plan.period * 3 && {
            let snapshot = state.snap.load();
            value.sample.state.config_version == snapshot.version
                && value.sample.state.config_fingerprint
                    == snapshot
                        .config_fingerprint
                        .map(|value| format!("{value:016x}"))
        }
    }) else {
        return pending("sampling", plan.period);
    };
    let Some(body) = publication.body(raw) else {
        return pending("capacity", plan.period);
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header(
            "x-naway-sample-age-ms",
            publication.at.elapsed().as_millis().to_string(),
        )
        .body(crate::full_body(body))
        .expect("fixed monitor response headers")
}

/// 业务作用：明确报告关闭或尚无有效样本，不把缺失区间编码为零流量。
///
/// 参数说明：
/// - `availability`：固定采样状态。
/// - `period`：当前配置的服务端周期。
///
/// 返回：禁止缓存的202状态，不携带旧数值。
fn pending(availability: &'static str, period: Duration) -> Response<BoxBody> {
    let mut response = super::json(
        StatusCode::ACCEPTED,
        serde_json::json!({
            "availability": availability, "sampling_period_ms": period.as_millis()
        }),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}

/// 业务作用：向已授权集群观察者提供同一共享协调结果，不按页面数启动外连。
///
/// 参数说明：
/// - `state`：当前管理权威与集群采样运行态。
///
/// 返回：集群当前快照或明确未就绪状态。
pub(super) fn read_cluster(state: &AdminState) -> Response<BoxBody> {
    cluster::read(state)
}

/// 业务作用：向会话能力与集群读面提供一致的监控接入判定，推送不扩大HTTP抓取权。
///
/// 参数说明：
/// - `snapshot`：当前完整配置。
///
/// 返回：至少一种明确授权的实时指标来源可用时为true。
pub(super) fn cluster_enabled(snapshot: &crate::config::GatewaySnapshot) -> bool {
    cluster::enabled(snapshot)
}

/// 业务作用：为页面标注当前采样时间，计算速率仍使用独立单调时钟。
///
/// 参数说明: 无。
///
/// 返回：有界Unix毫秒，系统时间早于epoch时为零。
fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
