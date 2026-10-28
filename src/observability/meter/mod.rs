//! 外部持久计量：先确认准入事件，再执行业务；结束事实以固定事件身份重投，未知结果不虚构成功。

pub(crate) mod traffic;

use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use http::HeaderValue;
use naoutbox_core::OutboxEvent;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeterCfg {
    pub endpoint: String,
    pub authorization: String,
    #[serde(default)]
    pub ca_certificate: String,
    pub max_pending: usize,
    pub timeout_ms: u64,
    pub retry_ms: u64,
}

/// 无网络副作用的冻结传输计划，进程启动后端点、信任与容量变更需要重启。
#[derive(Clone)]
pub struct MeterPlan {
    pub signature: String,
    settings: Option<Arc<Settings>>,
}

struct Settings {
    client: reqwest::Client,
    events: reqwest::Url,
    query: reqwest::Url,
    authorization: HeaderValue,
    max_pending: usize,
    retry: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    pub team: String,
    pub product: String,
    pub version: String,
    pub operation: String,
    pub application: String,
    pub consumer: String,
    pub plan: String,
    pub config_generation: u64,
}

#[derive(Serialize)]
struct Envelope {
    event_id: String,
    aggregate_type: String,
    aggregate_id: String,
    event_type: String,
    tenant: String,
    payload: Value,
}

struct Record {
    id: String,
    digest: String,
    body: bytes::Bytes,
}
struct Pending {
    record: Record,
    _permit: OwnedSemaphorePermit,
}

pub struct Meter {
    accepting: AtomicBool,
    settings: Option<Arc<Settings>>,
    pending: Option<mpsc::Sender<Pending>>,
    capacity: Arc<Semaphore>,
    reads: Semaphore,
    pub admitted: AtomicU64,
    pub rejected: AtomicU64,
    pub retry_count: Arc<AtomicU64>,
}

#[derive(Clone, Default)]
pub(crate) struct MeterFacts(Arc<Facts>);

#[derive(Default)]
struct Facts {
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    extensions: parking_lot::Mutex<ExtendedUsage>,
}

#[derive(Default, Serialize)]
struct ExtendedUsage {
    graphql_cost: Option<u64>,
    ai_input_tokens: Option<u64>,
    ai_output_tokens: Option<u64>,
    ai_cost_microusd: Option<u64>,
}

pub(crate) struct RequestMeter {
    attribution: Attribution,
    request: String,
    facts: MeterFacts,
    started: Instant,
    status: u16,
    outcome: &'static str,
    pending: mpsc::Sender<Pending>,
    permit: Option<OwnedSemaphorePermit>,
}

impl MeterPlan {
    /// 业务作用：校验固定 HTTPS meter、信任与容量，在配置候选阶段只构造客户端而不外呼或开 worker。
    ///
    /// 参数说明：
    /// - `cfg`：是可选计量声明
    /// - `directory`：用于 SecretSource 解析。
    ///
    /// 返回：关闭态空计划或完整冻结计划；URL、凭据和预算不合规时拒绝候选。
    pub fn build(cfg: Option<&MeterCfg>, directory: &Path) -> Result<Self> {
        let Some(cfg) = cfg else {
            return Ok(Self {
                signature: "disabled".to_owned(),
                settings: None,
            });
        };
        ensure!(
            (1..=4096).contains(&cfg.max_pending)
                && (100..=10000).contains(&cfg.timeout_ms)
                && (100..=30000).contains(&cfg.retry_ms),
            "invalid meter resource budget"
        );
        let base = reqwest::Url::parse(&cfg.endpoint)?;
        ensure!(
            cfg.endpoint.len() <= 2048
                && base.scheme() == "https"
                && base.username().is_empty()
                && base.password().is_none()
                && base.host_str().is_some()
                && base.query().is_none()
                && base.fragment().is_none()
                && base.path().ends_with('/'),
            "meter endpoint must be a fixed HTTPS base URL without credentials/query/fragment"
        );
        let secret = crate::security::secret::resolve_text(
            &cfg.authorization,
            directory,
            "meter authorization",
        )?;
        ensure!(
            !secret.is_empty() && secret.len() <= 4096,
            "meter requires bounded authorization"
        );
        let mut authorization = HeaderValue::from_str(&secret)?;
        authorization.set_sensitive(true);
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(cfg.timeout_ms));
        let certificate = if cfg.ca_certificate.is_empty() {
            String::new()
        } else {
            let certificate =
                crate::security::secret::resolve_text(&cfg.ca_certificate, directory, "meter CA")?;
            builder =
                builder.add_root_certificate(crate::tls::trust::http_ca(certificate.as_bytes())?);
            certificate
        };
        let signature = nasa::crypto::sha256(&json!([cfg, secret, certificate]).to_string());
        Ok(Self {
            signature,
            settings: Some(Arc::new(Settings {
                client: builder.build()?,
                events: base.join("events")?,
                query: base.join("query")?,
                authorization,
                max_pending: cfg.max_pending,
                retry: Duration::from_millis(cfg.retry_ms),
            })),
        })
    }

    /// 业务作用：报告本快照是否要求外部计量，不把 worker 存活情况当成配置授权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：声明合法计量后为 true。
    pub fn enabled(&self) -> bool {
        self.settings.is_some()
    }
}

impl Meter {
    /// 业务作用：输出固定维度传输健康事实，应用、consumer 和凭据不进入 Prometheus 标签。
    ///
    /// 参数说明：
    /// - `output`：为当前 metrics 响应缓冲。
    ///
    /// 返回：仅启用计量时追加准入、拒绝、重投和占用指标；这些不是持久账本。
    pub(crate) fn render_metrics(&self, output: &mut String) {
        self.render_named_metrics(output, "meter");
    }

    /// 业务作用：按产品或流量计量域输出独立的低基数容量与交付指标。
    ///
    /// 参数说明：
    /// - `output`：指标输出缓冲。
    /// - `domain`：代码内固定的指标域，不接受配置或请求标签。
    ///
    /// 返回：启用域的准入、重投和容量事实；关闭态不输出。
    fn render_named_metrics(&self, output: &mut String, domain: &'static str) {
        use std::fmt::Write as _;
        let Some(settings) = &self.settings else {
            return;
        };
        for (name, value) in [
            ("admitted", self.admitted.load(Ordering::Relaxed)),
            ("rejected", self.rejected.load(Ordering::Relaxed)),
            ("retry", self.retry_count.load(Ordering::Relaxed)),
        ] {
            let _ = writeln!(
                output,
                "# TYPE gw_{domain}_{name}_total counter\ngw_{domain}_{name}_total {value}"
            );
        }
        let pending = settings
            .max_pending
            .saturating_sub(self.capacity.available_permits());
        let _ = writeln!(
            output,
            "# TYPE gw_{domain}_pending gauge\ngw_{domain}_pending {pending}"
        );
    }

    /// 业务作用：启动唯一有界结束事实 worker，关闭态不建立队列或后台任务。
    ///
    /// 参数说明：
    /// - `plan`：是启动时已验证的不可变传输计划。
    ///
    /// 返回：共享计量 owner；本方法必须在 Tokio 运行时内调用，不发出网络请求。
    pub fn start(plan: &MeterPlan) -> Arc<Self> {
        let retries = Arc::new(AtomicU64::new(0));
        let pending = plan.settings.as_ref().map(|settings| {
            let (sender, mut receiver) = mpsc::channel::<Pending>(settings.max_pending);
            let settings = settings.clone();
            let retries = retries.clone();
            tokio::spawn(async move {
                while let Some(pending) = receiver.recv().await {
                    // 只有固定 event id 和摘要的 Committed/Duplicate 收据才能释放容量；断连与坏收据不能当作已交付。
                    while settings.deliver(&pending.record).await.is_err() {
                        retries.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(settings.retry).await;
                    }
                }
            });
            sender
        });
        Arc::new(Self {
            accepting: AtomicBool::new(true),
            settings: plan.settings.clone(),
            pending,
            capacity: Arc::new(Semaphore::new(
                plan.settings.as_ref().map_or(0, |s| s.max_pending),
            )),
            reads: Semaphore::new(8),
            admitted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            retry_count: retries,
        })
    }

    /// 业务作用：在业务副作用前取得结束事实容量并持久确认开始事件，sink 不可用时关闭该计量入口。
    ///
    /// 参数说明：
    /// - `attribution`：全部来自已验证身份、应用订阅与同代产品绑定
    /// - `facts`：持有有界流式计数。
    ///
    /// 返回：确认后返回随响应生命周期移动的唯一计量凭据；容量、网络或收据错误不会执行上游业务。
    pub(crate) async fn admit(
        &self,
        attribution: Attribution,
        facts: MeterFacts,
    ) -> Result<RequestMeter> {
        ensure!(self.accepting.load(Ordering::Acquire), "meter is draining");
        let settings = self.settings.as_ref().context("meter is disabled")?;
        let permit = self.capacity.clone().try_acquire_owned().map_err(|_| {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            anyhow::anyhow!("meter capacity exhausted")
        })?;
        let request = OutboxEvent::new(
            "GatewayUsage",
            &attribution.application,
            "request_started",
            Vec::new(),
        )
        .event_id;
        let record = record(
            &request,
            "request_started",
            &attribution,
            json!({
                "attribution":attribution,
                "timestamp_ms":now_ms()
            }),
        );
        let guard = RequestMeter {
            attribution,
            request,
            facts,
            started: Instant::now(),
            status: 0,
            outcome: "not_dispatched",
            pending: self.pending.as_ref().expect("enabled meter queue").clone(),
            permit: Some(permit),
        };
        if settings.deliver(&record).await.is_err() {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("meter admission was not durably acknowledged");
        }
        self.admitted.fetch_add(1, Ordering::Relaxed);
        Ok(guard)
    }

    /// 业务作用：停机时关闭新计量准入，已确认的响应仍由原 worker 提交结束事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：后续准入失败闭合，不撤销在途请求的事实所有权。
    pub fn stop_admissions(&self) {
        self.accepting.store(false, Ordering::Release);
    }

    /// 业务作用：在有界停机窗口等待在途和待确认事实，依赖故障不无限延长进程生命周期。
    ///
    /// 参数说明：
    /// - `timeout`：为本次 flush 总时间预算。
    ///
    /// 返回：全部容量释放为 true；超时为 false，此时远端开始事件仍标记 incomplete。
    pub async fn flush(&self, timeout: Duration) -> bool {
        let Some(settings) = &self.settings else {
            return true;
        };
        let deadline = tokio::time::Instant::now() + timeout;
        while self.capacity.available_permits() < settings.max_pending {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        true
    }

    /// 业务作用：从外部事实源读取被当前门户授权的应用用量，输入不接受客户端 tenant 或任意检索条件。
    ///
    /// 参数说明：
    /// - `applications`：为服务端已筛选应用
    /// - `export`：选择汇总或有界事件导出
    /// - `cursor`：为有界不透明分页游标。
    ///
    /// 返回：筛选后的 JSON；容量、依赖、大小或跨应用结果拒绝，不暴露外部响应正文错误。
    pub(crate) async fn query(
        &self,
        applications: &[String],
        export: bool,
        cursor: Option<&str>,
    ) -> Result<Value> {
        let settings = self.settings.as_ref().context("meter is disabled")?;
        ensure!(
            applications.len() <= 1024
                && cursor.is_none_or(|v| v.len() <= 1024
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))),
            "meter query budget exceeded"
        );
        // 空授权集直接返回，不能依赖外部 sink 对空数组采用过滤语义。
        if applications.is_empty() {
            return Ok(json!({
                "rows":[],
                "next_cursor":null
            }));
        }
        let _permit = self
            .reads
            .try_acquire()
            .context("meter read capacity exhausted")?;
        let response = settings
            .client
            .post(settings.query.clone())
            .header(http::header::AUTHORIZATION, settings.authorization.clone())
            .json(&json!({
                "applications":applications,
                "kind":if export {
                    "events"
                }else{
                    "summary"
                },
                "cursor":cursor,
                "limit":512
            }))
            .send()
            .await?;
        ensure!(response.status().is_success(), "meter query rejected");
        let body = bounded_json(response, 2 * 1024 * 1024).await?;
        let rows = body
            .get("rows")
            .and_then(Value::as_array)
            .context("invalid meter rows")?;
        ensure!(rows.len() <= 512, "meter row limit exceeded");
        let mut output = Vec::new();
        for row in rows {
            let app = row
                .get("application")
                .and_then(Value::as_str)
                .context("missing meter application")?;
            ensure!(
                applications.iter().any(|id| id == app),
                "meter returned unauthorized application"
            );
            let mut item = serde_json::Map::new();
            item.insert("application".to_owned(), json!(app));
            for key in [
                "requests",
                "errors",
                "latency_us",
                "request_bytes",
                "response_bytes",
                "graphql_cost",
                "ai_input_tokens",
                "ai_output_tokens",
                "ai_cost_microusd",
                "incomplete",
            ] {
                if let Some(value) = row.get(key) {
                    ensure!(
                        value.is_u64() || value.is_null(),
                        "invalid meter numeric fact"
                    );
                    item.insert(key.to_owned(), value.clone());
                }
            }
            if export {
                for key in [
                    "event_id",
                    "product",
                    "version",
                    "operation",
                    "consumer",
                    "plan",
                    "outcome",
                ] {
                    if let Some(value) = row.get(key) {
                        let text = value.as_str().context("invalid meter event field")?;
                        ensure!(
                            text.len() <= 256 && !text.chars().any(char::is_control),
                            "invalid meter event field"
                        );
                        item.insert(key.to_owned(), value.clone());
                    }
                }
            }
            output.push(Value::Object(item));
        }
        let cursor = body.get("next_cursor").and_then(Value::as_str);
        ensure!(
            cursor.is_none_or(|v| v.len() <= 1024
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))),
            "invalid meter cursor"
        );
        Ok(json!({
            "rows":output,
            "next_cursor":cursor
        }))
    }
}

impl Settings {
    /// 业务作用：投递不变用量事件并验证持久去重收据，HTTP 成功码本身不视为提交证据。
    ///
    /// 参数说明：
    /// - `record`：的 event id、摘要与字节在所有重投中保持不变。
    ///
    /// 返回：仅匹配身份/摘要的 committed 或 duplicate 收据成功，其它结果均保留未确认状态。
    async fn deliver(&self, record: &Record) -> Result<()> {
        let response = self
            .client
            .post(self.events.clone())
            .header(http::header::AUTHORIZATION, self.authorization.clone())
            .header("idempotency-key", &record.id)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(record.body.clone())
            .send()
            .await?;
        ensure!(response.status().is_success(), "meter event rejected");
        let receipt = bounded_json(response, 4096).await?;
        ensure!(
            receipt["event_id"].as_str() == Some(&record.id)
                && receipt["sha256"].as_str() == Some(&record.digest)
                && matches!(receipt["outcome"].as_str(), Some("committed" | "duplicate")),
            "meter receipt is not a matching durable acknowledgement"
        );
        Ok(())
    }
}

impl MeterFacts {
    /// 业务作用：在认证后为真实请求正文附加计数，不聚合、不信任客户端长度声明。
    ///
    /// 参数说明：
    /// - `body`：是当前未消费正文。
    ///
    /// 返回：保持 backpressure 的流式正文，只累计成功观察的数据帧。
    pub(crate) fn request_body(&self, body: crate::BoxBody) -> crate::BoxBody {
        use http_body_util::BodyExt as _;
        MeteredBody {
            inner: body,
            facts: self.clone(),
            request: true,
            completion: None,
        }
        .boxed()
    }
    /// 业务作用：只累计已观测的正文帧字节，不从 Content-Length 估算实际交付。
    ///
    /// 参数说明：
    /// - `request`：选择方向
    /// - `bytes`：为当前帧长度。
    ///
    /// 返回：饱和增加对应计数，不分配或执行 I/O。
    pub(crate) fn bytes(&self, request: bool, bytes: usize) {
        let counter = if request {
            &self.0.request_bytes
        } else {
            &self.0.response_bytes
        };
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(bytes as u64))
        });
    }
    /// 业务作用：保存已通过 GraphQL 解析的成本事实，不使用客户端自报值。
    ///
    /// 参数说明：
    /// - `cost`：是已验证操作的计算成本。
    ///
    /// 返回：记录成本；未执行解析时保持未知。
    pub(crate) fn graphql(&self, cost: u64) {
        self.0.extensions.lock().graphql_cost = Some(cost);
    }
    /// 业务作用：保存 provider 返回并经协议解析的 token/费用，不把估算额度冒充实际用量。
    ///
    /// 参数说明：
    /// - `input`：受控 provider 确认的输入 token 数。
    /// - `output`：受控 provider 确认的输出 token 数。
    /// - `cost`：受控 provider 确认的可选费用。
    ///
    /// 返回：更新已知事实，缺少费用时明确为未知。
    pub(crate) fn ai(&self, input: u64, output: u64, cost: Option<u64>) {
        let mut facts = self.0.extensions.lock();
        facts.ai_input_tokens = Some(input);
        facts.ai_output_tokens = Some(output);
        facts.ai_cost_microusd = cost;
    }

    /// 业务作用：以本请求冻结模型单价计算已知 token 费用，不用估算 token 填补缺失 usage。
    ///
    /// 参数说明：
    /// - `input`：provider 确认的输入 token 数。
    /// - `output`：provider 确认的输出 token 数。
    /// - `input_price`：每百万输入 token 的微美元单价。
    /// - `output_price`：每百万输出 token 的微美元单价。
    ///
    /// 返回：有配置单价时保存向下取整的饱和费用；两个单价均为零视为价格未知。
    pub(crate) fn ai_priced(&self, input: u64, output: u64, input_price: u64, output_price: u64) {
        let cost = (input_price != 0 || output_price != 0).then(|| {
            let total = u128::from(input)
                .saturating_mul(u128::from(input_price))
                .saturating_add(u128::from(output).saturating_mul(u128::from(output_price)));
            (total / 1_000_000).min(u128::from(u64::MAX)) as u64
        });
        self.ai(input, output, cost);
    }
}

impl RequestMeter {
    /// 业务作用：将结束事实所有权移交最终响应正文，避免仅收到 response head 就记为完成。
    ///
    /// 参数说明：
    /// - `status`：是最终 HTTP 状态
    /// - `body`：是压缩、变换完成后的交付正文。
    ///
    /// 返回：保持流式语义的计量正文；取消、EOF 和错误各产生一次结束事实。
    pub(crate) fn response_body(mut self, status: u16, body: crate::BoxBody) -> crate::BoxBody {
        use http_body_util::BodyExt as _;
        use hyper::body::Body as _;
        self.response(status);
        if body.is_end_stream() {
            self.finish(true);
        }
        MeteredBody {
            facts: self.facts.clone(),
            inner: body,
            request: false,
            completion: Some(self),
        }
        .boxed()
    }
    /// 业务作用：记录最终响应 head，流式结束或取消仍由持有者完成，不以收到 head 冒充交付完成。
    ///
    /// 参数说明：
    /// - `status`：是最终发送的 HTTP 状态。
    ///
    /// 返回：更新状态，结束事实仍未入队。
    pub(crate) fn response(&mut self, status: u16) {
        self.status = status;
        self.outcome = "cancelled";
    }
    /// 业务作用：标记正文的实际结束方式，为正常 EOF、协议错误和取消提供不同事实。
    ///
    /// 参数说明：
    /// - `complete`：表示观察到正常 EOF，否则为正文错误。
    ///
    /// 返回：更新终态；Drop 负责唯一入队。
    pub(crate) fn finish(&mut self, complete: bool) {
        self.outcome = if complete {
            "completed"
        } else {
            "failed"
        };
    }
}

struct MeteredBody {
    inner: crate::BoxBody,
    facts: MeterFacts,
    request: bool,
    completion: Option<RequestMeter>,
}

impl hyper::body::Body for MeteredBody {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;

    /// 业务作用：逐帧记录实际观测字节，并在 EOF/错误处完成唯一结束事实。
    ///
    /// 参数说明：
    /// - `cx`：是下游施加 backpressure 的任务上下文。
    ///
    /// 返回：透传原帧及错误，不复制正文、不提前读取后续帧。
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        let this = self.get_mut();
        let frame = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        match &frame {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    this.facts.bytes(this.request, bytes.len());
                }
                if this.inner.is_end_stream() {
                    if let Some(mut completion) = this.completion.take() {
                        completion.finish(true);
                    }
                }
            }
            std::task::Poll::Ready(None) => {
                if let Some(mut completion) = this.completion.take() {
                    completion.finish(true);
                }
            }
            std::task::Poll::Ready(Some(Err(_))) => {
                if let Some(mut completion) = this.completion.take() {
                    completion.finish(false);
                }
            }
            _ => {}
        }
        frame
    }
    /// 业务作用：保留原正文的结束提示，不让计量包装改变空正文协议行为。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原正文的结束状态。
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    /// 业务作用：透传长度提示供 HTTP framing 使用，不将提示当作已交付字节。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原正文长度提示。
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for RequestMeter {
    /// 业务作用：用预留容量提交唯一结束事实，取消分支也不会把已持久准入静默视为业务成功。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：将不可变事件与容量租约移交 worker；进程崩溃时远端仅保留开始事件并显示 incomplete。
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let extensions = self.facts.0.extensions.lock();
        let payload = json!({
            "attribution":self.attribution,
            "request_id":self.request,
            "timestamp_ms":now_ms(),
            "status":self.status,
            "outcome":self.outcome,
            "latency_us":self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            "request_bytes":self.facts.0.request_bytes.load(Ordering::Relaxed),
            "response_bytes":self.facts.0.response_bytes.load(Ordering::Relaxed),
            "extended":*extensions
        });
        let record = record(
            &self.request,
            "request_finished",
            &self.attribution,
            payload,
        );
        // 每个在途/排队/投递中的事实都占一个共同 semaphore 名额，因此队列不会因结束风暴溢出。
        if self
            .pending
            .try_send(Pending {
                record,
                _permit: permit,
            })
            .is_err()
        {
            tracing::error!("meter worker unavailable; durable admission remains incomplete");
        }
    }
}

/// 业务作用：将低敏用量载荷映射为 NASA Outbox 事件，并固定重投身份及摘要。
///
/// 参数说明：
/// - `request`：唯一的请求关联标识。
/// - `phase`：固定计量生命周期阶段。
/// - `attribution`：从已验证合同冻结的归属。
/// - `payload`：不含正文与凭据的计量事实。
///
/// 返回：不可变且有界的 JSON 事件，身份在每个阶段唯一。
fn record(request: &str, phase: &str, attribution: &Attribution, payload: Value) -> Record {
    event_record("GatewayUsage", request, phase, &attribution.team, payload)
}

/// 业务作用：让不同计量域共用 NASA 事件身份与摘要合同，避免把流量归属伪装成产品订阅。
///
/// 参数说明：
/// - `aggregate`：代码内固定的业务事件域。
/// - `request`：本次随机关联身份。
/// - `phase`：固定生命周期阶段。
/// - `tenant`：已验证的计量归属。
/// - `payload`：有界且不包含实体或凭据的事实。
///
/// 返回：单次编码的不可变事件，重投复用相同字节、身份和摘要。
fn event_record(
    aggregate: &'static str,
    request: &str,
    phase: &str,
    tenant: &str,
    payload: Value,
) -> Record {
    let mut event = OutboxEvent::new(aggregate, request, phase, Vec::new());
    event.event_id = format!("{request}:{phase}");
    event.tenant = tenant.to_owned();
    let envelope = Envelope {
        event_id: event.event_id.clone(),
        aggregate_type: event.aggregate_type,
        aggregate_id: event.aggregate_id,
        event_type: event.event_type,
        tenant: event.tenant,
        payload,
    };
    let body = serde_json::to_string(&envelope).expect("bounded usage event serialization");
    Record {
        id: event.event_id,
        digest: nasa::crypto::sha256_cased(&body, false),
        body: body.into(),
    }
}

/// 业务作用：为远端收据和分析响应执行流式字节硬门，拒绝整包无界分配。
///
/// 参数说明：
/// - `response`：是固定 sink 响应
/// - `limit`：是当前协议阶段的硬上限。
///
/// 返回：有限 JSON；媒体类型、长度、网络或语法不匹配返回错误。
async fn bounded_json(response: reqwest::Response, limit: usize) -> Result<Value> {
    use futures::StreamExt as _;
    ensure!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(';').next() == Some("application/json")),
        "meter response must be JSON"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|bytes| bytes <= limit as u64),
        "meter response exceeds limit"
    );
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= limit,
            "meter response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// 业务作用：生成计量事实的观测时间，不承担跨节点排序或业务权威。
///
/// 参数说明: 无。
///
/// 返回：Unix 毫秒；系统时钟异常时使用零值以避免取消路径 panic。
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
