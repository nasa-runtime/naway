//! 非阻塞 access log。
//!
//! 热路径只做 bounded `try_send`;队列满则丢弃并计数。格式渲染、条件判断和采样都在后台
//! 日志任务中执行,避免慢 sink 或模板处理反压数据面。

use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use http::{Method, Uri};
use tokio::sync::mpsc;

use crate::config::model::AccessLogCfg;
use crate::config::GatewaySnapshot;
use crate::observability::metrics::Metrics;

/// 数据面到后台日志 worker 的非阻塞发送句柄。
#[derive(Clone)]
pub struct AccessLogger {
    active: Arc<ArcSwap<AccessLoggerInner>>,
    metrics: Arc<Metrics>,
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
}

struct AccessLoggerInner {
    tx: mpsc::Sender<AccessRecord>,
    metrics: Arc<Metrics>,
    accepting: AtomicBool,
    shutdown_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    done_rx: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    shutdown_timeout: Duration,
}

impl AccessLogger {
    /// 业务作用：启动 access log 后台任务。
    ///
    /// 参数说明：
    /// - `metrics`: 日志丢弃计数等低基数指标。
    /// - `snap`: 当前网关快照;后台任务逐条读取最新 `access_log` 配置,支持热更格式/条件/采样。
    /// - `queue_size`: bounded 队列容量。队列容量是 channel 属性,启动期生效。
    pub fn spawn(
        metrics: Arc<Metrics>,
        snap: Arc<ArcSwap<GatewaySnapshot>>,
        queue_size: usize,
    ) -> Result<Self> {
        let runtime = snap.load().access_log.clone();
        Self::spawn_with_runtime(metrics, snap, queue_size, &runtime)
    }

    /// 业务作用：为尚未发布的候选快照准备独立 access-log dispatcher 与 sink worker。
    ///
    /// 参数说明：
    /// - `metrics`：承载丢弃计数
    /// - `snap`：在提交后提供当前格式
    /// - `queue_size`：是硬队列上限
    /// - `runtime`：提供候选 sink 拓扑。
    ///
    /// 返回：所有 sink 客户端与有界 worker 已就绪时返回未接收业务记录的候选代；
    /// 任一初始化失败则返回错误，在线代不受影响。
    pub fn spawn_with_runtime(
        metrics: Arc<Metrics>,
        snap: Arc<ArcSwap<GatewaySnapshot>>,
        queue_size: usize,
        runtime: &AccessLogRuntime,
    ) -> Result<Self> {
        // 候选必须在发布前建好全部 sink，避免快照已上线却丢失审计出口。
        let sink_specs = runtime.sink_specs.clone();
        let spawned = crate::observability::log_sink::spawn_sink_workers(
            sink_specs.as_ref(),
            metrics.clone(),
        )?;
        let shutdown_timeout = sink_specs
            .iter()
            .map(|spec| spec.timeout.saturating_add(Duration::from_secs(1)))
            .max()
            .unwrap_or(Duration::from_secs(3));
        let (tx, mut rx) = mpsc::channel::<AccessRecord>(queue_size.max(1));
        let worker_metrics = metrics.clone();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let worker_snapshot = snap.clone();
        tokio::spawn(async move {
            let process = |record: AccessRecord| {
                let snap = worker_snapshot.load_full();
                let runtime = &snap.access_log;
                if !runtime.should_log(&record) {
                    return;
                }
                let event = match encode_record(runtime, record) {
                    Ok(event) => Arc::new(event),
                    Err(error) => {
                        worker_metrics.inc_log_sink_dropped("dispatcher", 1, "encode");
                        tracing::warn!(error = %error, "access log JSON encoding failed");
                        return;
                    }
                };
                for sink in &spawned.senders {
                    sink.try_send(event.clone());
                }
            };
            loop {
                tokio::select! {
                    record = rx.recv() => match record {
                        Some(record) => process(record),
                        None => break,
                    },
                    _ = &mut shutdown_rx => {
                        // 停止 accept/完成数据面 drain 后才触发；排空已经进入 dispatcher 的记录。
                        while let Ok(record) = rx.try_recv() {
                            process(record);
                        }
                        break;
                    }
                }
            }
            drop(spawned.senders);
            for worker in spawned.workers {
                if let Err(error) = worker.await {
                    tracing::warn!(%error, "access log sink worker join failed");
                }
            }
            let _ = done_tx.send(());
        });
        Ok(Self {
            active: Arc::new(ArcSwap::from_pointee(AccessLoggerInner {
                tx,
                metrics: metrics.clone(),
                accepting: AtomicBool::new(true),
                shutdown_tx: Mutex::new(Some(shutdown_tx)),
                done_rx: Mutex::new(Some(done_rx)),
                shutdown_timeout,
            })),
            metrics,
            snapshot: snap,
        })
    }

    /// 业务作用：复用当前 logger 的指标与快照句柄，完整准备候选 sink 代。
    ///
    /// 参数说明：
    /// - `runtime`：是候选快照编译得到的格式、队列与 sink 计划。
    ///
    /// 返回：全部 sink worker 已就绪时返回候选 logger；失败时在线代不变。
    pub fn prepare_replacement(&self, runtime: &AccessLogRuntime) -> Result<Self> {
        Self::spawn_with_runtime(
            self.metrics.clone(),
            self.snapshot.clone(),
            runtime.queue_size,
            runtime,
        )
    }

    /// 业务作用：尝试写入一条 access log 记录。
    ///
    /// 参数说明：
    /// - `record`: 已在请求管线收集好的低基数字段。
    pub fn log(&self, record: AccessRecord) {
        let active = self.active.load_full();
        if !active.accepting.load(Ordering::Acquire) {
            return;
        }
        if active.tx.try_send(record).is_err() {
            active.metrics.inc_access_log_dropped();
        }
    }

    /// 业务作用：在快照发布后原子切换 access-log 写入代，并异步排空旧 sink。
    ///
    /// 参数说明：
    /// - `candidate`：是已成功准备但尚未接收数据面记录的候选代。
    ///
    /// 返回：无返回值；新记录立即只进入候选代，旧队列在自身 deadline 内排空。
    pub fn replace(&self, candidate: &Self) {
        let next = candidate.active.load_full();
        let old = self.active.swap(next);
        old.accepting.store(false, Ordering::Release);
        tokio::spawn(async move {
            if let Err(error) = shutdown_generation(old).await {
                tracing::warn!(%error, "old access log generation drain failed");
            }
        });
    }

    /// 业务作用：停止接收新记录，排空 dispatcher 与所有 sink queue，并执行 backend flush/shutdown。
    pub async fn shutdown(&self) -> Result<()> {
        shutdown_generation(self.active.load_full()).await
    }
}

/// 业务作用：停收并有界排空单个 access-log 代，不影响已切换的新代。
///
/// 参数说明：
/// - `generation`：持有该代唯一队列、sink worker 和完成回执。
///
/// 返回：全部排空并确认退出时成功；超时或 worker 异常时返回错误。
async fn shutdown_generation(generation: Arc<AccessLoggerInner>) -> Result<()> {
    generation.accepting.store(false, Ordering::Release);
    if let Some(tx) = generation
        .shutdown_tx
        .lock()
        .expect("access log shutdown mutex poisoned")
        .take()
    {
        let _ = tx.send(());
    }
    let done = generation
        .done_rx
        .lock()
        .expect("access log done mutex poisoned")
        .take();
    let Some(done) = done else {
        return Ok(());
    };
    tokio::time::timeout(generation.shutdown_timeout, done)
        .await
        .context("access log sink shutdown timed out")?
        .context("access log dispatcher exited before shutdown acknowledgement")
}

/// access log 的运行期配置。
#[derive(Clone)]
pub struct AccessLogRuntime {
    /// 是否启用 access log。
    enabled: bool,
    /// 启动期 bounded 队列容量。
    pub queue_size: usize,
    /// 自定义日志格式;未配置时保持原有 structured fields。
    format: Option<AccessLogFormat>,
    /// 条件日志表达式。
    condition: Option<AccessLogCondition>,
    /// 稳定采样率,范围 0.0..=1.0。
    sample: f64,
    /// 启动期已校验/解密的 sink 计划。reload 只允许完全相同，避免留下两套 worker。
    pub(crate) sink_specs: Arc<[crate::observability::log_sink::LogSinkSpec]>,
}

impl AccessLogRuntime {
    /// 业务作用：从 yml 配置构建运行期 access log 配置。
    ///
    /// 参数说明：
    /// - `cfg`: 顶层 `access_log` 配置。
    /// - `config_dir`：日志文件与凭据相对路径的解析根。
    pub fn build(cfg: &AccessLogCfg, config_dir: &Path) -> Result<Self> {
        if !cfg.sample.is_finite() || !(0.0..=1.0).contains(&cfg.sample) {
            bail!("access_log.sample must be within 0.0..=1.0");
        }
        let format = cfg
            .format
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(AccessLogFormat::parse)
            .transpose()
            .context("build access_log.format")?;
        let condition = cfg
            .condition
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(AccessLogCondition::parse)
            .transpose()
            .context("build access_log.if")?;
        let sink_specs = crate::observability::log_sink::build_sink_specs(
            cfg.sinks.as_slice(),
            config_dir,
            cfg.queue_size.max(1),
        )
        .context("build access_log.sinks")?;
        Ok(Self {
            enabled: cfg.enabled,
            queue_size: cfg.queue_size,
            format,
            condition,
            sample: cfg.sample,
            sink_specs,
        })
    }

    /// 业务作用：返回当前快照是否启用 access log。
    ///
    /// 数据面在构造 [`AccessRecord`] 前先检查该位：关闭态不能仍把每个请求送入 dispatcher，
    /// 否则不仅产生 route/upstream/trace-id 字符串分配，还会让无消费者价值的记录争用 bounded
    /// queue。该位属于不可变快照，读取不需要原子操作或锁。
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    /// 业务作用：判断当前记录是否需要输出。
    ///
    /// 参数说明：
    /// - `record`: 待输出 access record。
    fn should_log(&self, record: &AccessRecord) -> bool {
        self.enabled
            && self
                .condition
                .as_ref()
                .map(|condition| condition.matches(record))
                .unwrap_or(true)
            && sampled(record.request_id.as_str(), self.sample)
    }

    /// 业务作用：Sink client/channel 属 bootstrap 资源；该比较只用于拒绝无法原地重建的热更。
    pub(crate) fn same_sink_topology(&self, other: &Self) -> bool {
        self.queue_size == other.queue_size && self.sink_specs == other.sink_specs
    }
}

/// 单条 access log 记录。
pub struct AccessRecord {
    /// 请求/连接唯一 id。
    pub request_id: String,
    /// HTTP trace-id；与 OTel server span 共享 Arc，L4 未接 trace 时为 `None`。
    pub trace_id: Option<Arc<str>>,
    /// HTTP method 或 L4 stream 伪 method；HTTP 分支 clone `Method` 而不复制字符串。
    pub method: AccessMethod,
    /// HTTP URI 或 L4 stream id；HTTP 分支 clone `Uri` 的共享存储，不复制 path 字节。
    pub path: AccessPath,
    /// 公开入口 route id；多层路由保持根观测归属，叶子身份保存在完整执行链。
    pub route_id: Option<Arc<str>>,
    /// 已访问的稳定根到当前层链；只共享构建期字符串，不记录主体、claim 或条件值。
    pub route_chain: Option<Arc<[Arc<str>]>>,
    /// 最终上游标识；与选择器/响应 trace 共享底层字符串。
    pub upstream: Option<Arc<str>>,
    /// 实际发起的上游尝试次数。
    pub upstream_attempts: usize,
    /// 下游响应状态码。
    pub status: u16,
    /// 请求或 stream 连接持续时间。
    pub elapsed: Duration,
    /// 已按可信代理规则求得的审计对端。
    pub peer: String,
    /// L4 下游到上游字节数；HTTP 未统计时为 `None`。
    pub bytes_downstream_to_upstream: Option<u64>,
    /// L4 上游到下游字节数；HTTP 未统计时为 `None`。
    pub bytes_upstream_to_downstream: Option<u64>,
}

/// access log method 的少拷贝表示。
pub enum AccessMethod {
    /// HTTP method；标准 method clone 不复制 method 文本。
    Http(Method),
    /// L4 stream 连接的固定标识。
    Stream,
}

impl AccessMethod {
    /// 业务作用：返回仅在记录渲染期借用的文本。
    fn as_str(&self) -> &str {
        match self {
            Self::Http(method) => method.as_str(),
            Self::Stream => "STREAM",
        }
    }
}

/// access log path 的少拷贝表示。
pub enum AccessPath {
    /// 原始 HTTP URI；clone 复用 `Uri` 内部共享字节。
    Http(Uri),
    /// L4 stream listener/route id。
    Stream(Arc<str>),
}

impl AccessPath {
    /// 业务作用：返回 HTTP path（不含 query）或 stream id。
    fn as_str(&self) -> &str {
        match self {
            Self::Http(uri) => uri.path(),
            Self::Stream(id) => id,
        }
    }
}

/// 已编译的自定义 access log 格式。
#[derive(Clone)]
struct AccessLogFormat {
    parts: Arc<[LogFormatPart]>,
}

/// 日志格式片段。
#[derive(Clone)]
enum LogFormatPart {
    /// 静态字面量。
    Literal(Arc<str>),
    /// access log 字段变量。
    Var(AccessLogVar),
}

/// access log 条件表达式。
#[derive(Clone)]
struct AccessLogCondition {
    left: AccessLogVar,
    op: ConditionOp,
    right: ConditionValue,
}

/// 条件操作符。
#[derive(Clone, Copy)]
enum ConditionOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

/// 条件右值。
#[derive(Clone)]
enum ConditionValue {
    Number(u64),
    Text(Arc<str>),
}

/// access log 可引用字段。
#[derive(Clone, Copy)]
enum AccessLogVar {
    RequestId,
    TraceId,
    Method,
    Path,
    Route,
    RouteChain,
    Upstream,
    UpstreamAttempts,
    Status,
    ElapsedMs,
    Peer,
    BytesDownstreamToUpstream,
    BytesUpstreamToDownstream,
}

impl AccessLogFormat {
    /// 业务作用：编译 `access_log.format`。
    ///
    /// 参数说明：
    /// - `raw`: 格式字符串,支持 `$status` 与 `${status}` 两种变量写法。
    fn parse(raw: &str) -> Result<Self> {
        let mut parts = Vec::new();
        let mut pos = 0;
        while let Some(offset) = raw[pos..].find('$') {
            let dollar = pos + offset;
            if dollar > pos {
                push_literal(&mut parts, &raw[pos..dollar]);
            }
            let rest = &raw[dollar + 1..];
            if let Some(after_open) = rest.strip_prefix('{') {
                let Some(end) = after_open.find('}') else {
                    bail!("access_log.format has unclosed `${{`");
                };
                let name = &after_open[..end];
                parts.push(LogFormatPart::Var(parse_log_var(name)?));
                pos = dollar + 1 + 1 + end + 1;
                continue;
            }
            let name_len = rest
                .char_indices()
                .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '.')
                .map(|(idx, ch)| idx + ch.len_utf8())
                .last()
                .unwrap_or(0);
            if name_len == 0 {
                push_literal(&mut parts, "$");
                pos = dollar + 1;
                continue;
            }
            let name = &rest[..name_len];
            parts.push(LogFormatPart::Var(parse_log_var(name)?));
            pos = dollar + 1 + name_len;
        }
        if pos < raw.len() {
            push_literal(&mut parts, &raw[pos..]);
        }
        Ok(Self {
            parts: parts.into(),
        })
    }

    /// 业务作用：渲染 access log 字符串。
    ///
    /// 参数说明：
    /// - `record`: 当前 access log 记录。
    fn render(&self, record: &AccessRecord) -> String {
        let mut out = String::new();
        for part in self.parts.iter() {
            match part {
                LogFormatPart::Literal(value) => out.push_str(value),
                LogFormatPart::Var(var) => out.push_str(var.value(record).as_ref()),
            }
        }
        out
    }
}

impl AccessLogCondition {
    /// 业务作用：编译 `access_log.if` 条件表达式。
    ///
    /// 参数说明：
    /// - `raw`: 条件表达式,如 `$status >= 500` 或 `${method} = GET`。
    fn parse(raw: &str) -> Result<Self> {
        let (left, op, right) = split_condition(raw)?;
        let left = parse_log_var(strip_var_sigil(left.trim()))?;
        let right = parse_condition_value(right.trim(), left, op)?;
        Ok(Self {
            left,
            op,
            right,
        })
    }

    /// 业务作用：判断记录是否满足条件。
    ///
    /// 参数说明：
    /// - `record`: 当前 access log 记录。
    fn matches(&self, record: &AccessRecord) -> bool {
        match &self.right {
            ConditionValue::Number(right) => {
                let Some(left) = self.left.numeric_value(record) else {
                    return false;
                };
                match self.op {
                    ConditionOp::Eq => left == *right,
                    ConditionOp::Ne => left != *right,
                    ConditionOp::Gt => left > *right,
                    ConditionOp::Ge => left >= *right,
                    ConditionOp::Lt => left < *right,
                    ConditionOp::Le => left <= *right,
                }
            }
            ConditionValue::Text(right) => {
                let left = self.left.value(record);
                match self.op {
                    ConditionOp::Eq => left.as_ref() == right.as_ref(),
                    ConditionOp::Ne => left.as_ref() != right.as_ref(),
                    ConditionOp::Gt | ConditionOp::Ge | ConditionOp::Lt | ConditionOp::Le => false,
                }
            }
        }
    }
}

impl AccessLogVar {
    /// 业务作用：在后台日志渲染时解析字段，根路由和完整层级链使用独立变量。
    ///
    /// 参数说明：
    /// - `record`：是数据面已冻结的低敏访问事实。
    ///
    /// 返回：借用已有文本或格式化有限数值、层级链，不读取请求凭据。
    fn value(self, record: &AccessRecord) -> Cow<'_, str> {
        match self {
            Self::RequestId => Cow::Borrowed(record.request_id.as_str()),
            Self::TraceId => Cow::Borrowed(record.trace_id.as_deref().unwrap_or("-")),
            Self::Method => Cow::Borrowed(record.method.as_str()),
            Self::Path => Cow::Borrowed(record.path.as_str()),
            Self::Route => Cow::Borrowed(record.route_id.as_deref().unwrap_or("-")),
            Self::RouteChain => Cow::Owned(
                record
                    .route_chain
                    .as_deref()
                    .map(|chain| {
                        chain
                            .iter()
                            .map(AsRef::as_ref)
                            .collect::<Vec<&str>>()
                            .join(">")
                    })
                    .unwrap_or_else(|| "-".to_owned()),
            ),
            Self::Upstream => Cow::Borrowed(record.upstream.as_deref().unwrap_or("-")),
            Self::UpstreamAttempts => Cow::Owned(record.upstream_attempts.to_string()),
            Self::Status => Cow::Owned(record.status.to_string()),
            Self::ElapsedMs => Cow::Owned(record.elapsed.as_millis().to_string()),
            Self::Peer => Cow::Borrowed(record.peer.as_str()),
            Self::BytesDownstreamToUpstream => {
                Cow::Owned(record.bytes_downstream_to_upstream.unwrap_or(0).to_string())
            }
            Self::BytesUpstreamToDownstream => {
                Cow::Owned(record.bytes_upstream_to_downstream.unwrap_or(0).to_string())
            }
        }
    }

    /// 业务作用：取数值形式字段值。
    ///
    /// 参数说明：
    /// - `record`: 当前 access log 记录。
    fn numeric_value(self, record: &AccessRecord) -> Option<u64> {
        match self {
            Self::UpstreamAttempts => Some(record.upstream_attempts as u64),
            Self::Status => Some(record.status as u64),
            Self::ElapsedMs => Some(record.elapsed.as_millis().min(u128::from(u64::MAX)) as u64),
            Self::BytesDownstreamToUpstream => record.bytes_downstream_to_upstream.or(Some(0)),
            Self::BytesUpstreamToDownstream => record.bytes_upstream_to_downstream.or(Some(0)),
            _ => None,
        }
    }

    /// 业务作用：该变量是否支持数值比较。
    fn is_numeric(self) -> bool {
        matches!(
            self,
            Self::UpstreamAttempts
                | Self::Status
                | Self::ElapsedMs
                | Self::BytesDownstreamToUpstream
                | Self::BytesUpstreamToDownstream
        )
    }
}

/// 业务作用：把一条已完成请求的访问事实写入 Naway access tracing target，供本地日志层消费。
///
/// 参数说明：
/// - `record`：是当前 access log 记录
/// - `line`：是当前快照已渲染的可选自定义行。
///
/// 返回：无；日志层是否保留记录由当前 subscriber 与过滤配置决定。
pub(crate) fn log_record(record: &AccessRecord, line: Option<&str>) {
    tracing::info!(
        target: "naway::access",
        request_id = %record.request_id,
        trace_id = %record.trace_id.as_deref().unwrap_or("-"),
        method = record.method.as_str(),
        path = record.path.as_str(),
        route = %record.route_id.as_deref().unwrap_or("-"),
        route_chain = ?record.route_chain.as_deref().unwrap_or(&[]),
        upstream = %record.upstream.as_deref().unwrap_or("-"),
        upstream_attempts = record.upstream_attempts,
        status = record.status,
        elapsed_ms = record.elapsed.as_millis(),
        peer = %record.peer,
        bytes_downstream_to_upstream = record.bytes_downstream_to_upstream.unwrap_or(0),
        bytes_upstream_to_downstream = record.bytes_upstream_to_downstream.unwrap_or(0),
        access = %line.unwrap_or(""),
        "access"
    );
}

/// 业务作用：为所有远端 sink 序列化同一份访问事实和稳定层级链，不重复复制业务正文或身份。
///
/// 参数说明：
/// - `runtime`：提供当前输出格式
/// - `record`：从数据面移交后台日志 worker。
///
/// 返回：可共享的 JSON 与原始记录；序列化失败返回错误，不生成部分事件。
fn encode_record(
    runtime: &AccessLogRuntime,
    record: AccessRecord,
) -> Result<crate::observability::log_sink::LogEnvelope> {
    #[derive(serde::Serialize)]
    struct WireRecord<'a> {
        timestamp_unix_nanos: u128,
        request_id: &'a str,
        trace_id: Option<&'a str>,
        method: &'a str,
        path: &'a str,
        route_id: Option<&'a str>,
        route_chain: Option<Vec<&'a str>>,
        upstream: Option<&'a str>,
        upstream_attempts: usize,
        status: u16,
        elapsed_ms: u128,
        peer: &'a str,
        bytes_downstream_to_upstream: Option<u64>,
        bytes_upstream_to_downstream: Option<u64>,
        formatted: Option<&'a str>,
    }

    let formatted = runtime.format.as_ref().map(|format| format.render(&record));
    let unix_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let json = serde_json::to_vec(&WireRecord {
        timestamp_unix_nanos: unix_nanos,
        request_id: record.request_id.as_str(),
        trace_id: record.trace_id.as_deref(),
        method: record.method.as_str(),
        path: record.path.as_str(),
        route_id: record.route_id.as_deref(),
        route_chain: record
            .route_chain
            .as_deref()
            .map(|chain| chain.iter().map(AsRef::as_ref).collect()),
        upstream: record.upstream.as_deref(),
        upstream_attempts: record.upstream_attempts,
        status: record.status,
        elapsed_ms: record.elapsed.as_millis(),
        peer: record.peer.as_str(),
        bytes_downstream_to_upstream: record.bytes_downstream_to_upstream,
        bytes_upstream_to_downstream: record.bytes_upstream_to_downstream,
        formatted: formatted.as_deref(),
    })
    .context("serialize access log record")?;
    Ok(crate::observability::log_sink::LogEnvelope {
        record: Arc::new(record),
        json: bytes::Bytes::from(json),
        unix_nanos,
        formatted: formatted.map(Arc::from),
    })
}

/// 业务作用：追加字面量片段。
///
/// 参数说明：
/// - `parts`: 正在构建的格式片段列表。
/// - `value`: 要追加的字面量。
fn push_literal(parts: &mut Vec<LogFormatPart>, value: &str) {
    if !value.is_empty() {
        parts.push(LogFormatPart::Literal(Arc::from(value)));
    }
}

/// 业务作用：限定日志模板只能读取已声明的访问事实，不能借任意变量暴露请求内容。
///
/// 参数说明：
/// - `name`：是去掉变量标记后的字段名。
///
/// 返回：已知字段的强类型标识；未知字段拒绝候选配置。
fn parse_log_var(name: &str) -> Result<AccessLogVar> {
    match name.trim() {
        "request_id" => Ok(AccessLogVar::RequestId),
        "trace_id" => Ok(AccessLogVar::TraceId),
        "method" | "request_method" => Ok(AccessLogVar::Method),
        "path" | "uri" | "request_uri" => Ok(AccessLogVar::Path),
        "route" | "route_id" => Ok(AccessLogVar::Route),
        "route_chain" => Ok(AccessLogVar::RouteChain),
        "upstream" | "upstream_addr" => Ok(AccessLogVar::Upstream),
        "upstream_attempts" => Ok(AccessLogVar::UpstreamAttempts),
        "status" => Ok(AccessLogVar::Status),
        "elapsed_ms" | "request_time_ms" => Ok(AccessLogVar::ElapsedMs),
        "peer" | "remote_addr" => Ok(AccessLogVar::Peer),
        "bytes_downstream_to_upstream" => Ok(AccessLogVar::BytesDownstreamToUpstream),
        "bytes_upstream_to_downstream" | "body_bytes_sent" => {
            Ok(AccessLogVar::BytesUpstreamToDownstream)
        }
        other => bail!("unsupported access_log variable `{other}`"),
    }
}

/// 业务作用：拆分条件表达式。
///
/// 参数说明：
/// - `raw`: 原始条件表达式。
fn split_condition(raw: &str) -> Result<(&str, ConditionOp, &str)> {
    for (token, op) in [
        (">=", ConditionOp::Ge),
        ("<=", ConditionOp::Le),
        ("==", ConditionOp::Eq),
        ("!=", ConditionOp::Ne),
        ("=", ConditionOp::Eq),
        (">", ConditionOp::Gt),
        ("<", ConditionOp::Lt),
    ] {
        if let Some((left, right)) = raw.split_once(token) {
            if left.trim().is_empty() || right.trim().is_empty() {
                bail!("access_log.if has empty side around `{token}`");
            }
            return Ok((left, op, right));
        }
    }
    bail!("access_log.if must contain one of = != == >= <= > <");
}

/// 业务作用：去掉变量表达式的 `$` 或 `${}` 包裹。
///
/// 参数说明：
/// - `raw`: 条件左值。
fn strip_var_sigil(raw: &str) -> &str {
    raw.strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
        .or_else(|| raw.strip_prefix('$'))
        .unwrap_or(raw)
}

/// 业务作用：解析条件右值。
///
/// 参数说明：
/// - `raw`: 条件右值。
/// - `left`: 左值变量。
/// - `op`: 条件操作符。
fn parse_condition_value(raw: &str, left: AccessLogVar, op: ConditionOp) -> Result<ConditionValue> {
    let raw = raw.trim().trim_matches('"').trim_matches('\'').to_string();
    match op {
        ConditionOp::Gt | ConditionOp::Ge | ConditionOp::Lt | ConditionOp::Le => {
            if !left.is_numeric() {
                bail!("access_log.if range compare requires numeric variable");
            }
            Ok(ConditionValue::Number(raw.parse::<u64>().with_context(
                || format!("access_log.if right side `{raw}` is not a number"),
            )?))
        }
        ConditionOp::Eq | ConditionOp::Ne => {
            if left.is_numeric() {
                if let Ok(value) = raw.parse::<u64>() {
                    return Ok(ConditionValue::Number(value));
                }
            }
            Ok(ConditionValue::Text(Arc::from(raw)))
        }
    }
}

/// 业务作用：按 request id 做稳定采样。
///
/// 参数说明：
/// - `request_id`: 网关生成的请求 ID。
/// - `sample`: 采样率,范围 0.0..=1.0。
fn sampled(request_id: &str, sample: f64) -> bool {
    if sample >= 1.0 {
        return true;
    }
    if sample <= 0.0 {
        return false;
    }
    let mut hasher = DefaultHasher::new();
    request_id.hash(&mut hasher);
    let bucket = hasher.finish() as f64 / u64::MAX as f64;
    bucket < sample
}
