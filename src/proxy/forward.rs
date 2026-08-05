//! 上游流式转发:StripPrefix + hop-by-hop 头处理 + body 流式直通(不全量 buffer,少拷贝)。

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http::header::{
    HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE,
    EXPECT, HOST, TE, TRANSFER_ENCODING, UPGRADE,
};
use http::request::Parts;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode};
use hyper_rustls::{FixedServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, Sleep};
use tokio_rustls::rustls::pki_types::ServerName;
use tower_service::Service;

use crate::config::GatewaySnapshot;
use crate::config::ProxyRuntime;
use crate::conn_registry::{CloseNotified, ConnGuard, ConnectionRegistry, LongProto};
use crate::dubbo::{DubboError, DubboResult};
use crate::external_plugin::{ExternalPlugin, ExternalPluginPayload};
use crate::metrics::DubboMetric;
use crate::opa::{OpaInputPayload, OpaPolicy};
use crate::routing::{strip_n_segments, ExtAuthzPolicy, MirrorPolicy, RequestHeaderSet, Route};
use crate::tls::UpstreamTlsProfile;
use crate::upstream::{NextUpstreamPolicy, PassiveHealthPolicy, UpstreamProtocol};
use crate::{full_body, BoxBody, BoxError};

type RawUpstreamHttpClient = Client<BudgetedConnector<HttpsConnector<HttpConnector>>, BoxBody>;

const H2_SHARD_COLD: u8 = 0;
const H2_SHARD_CONNECTING: u8 = 1;
const H2_SHARD_READY: u8 = 2;
const PROXY_AUTHENTICATE: HeaderName = HeaderName::from_static("proxy-authenticate");
const PROXY_AUTHORIZATION: HeaderName = HeaderName::from_static("proxy-authorization");
const X_CLIENT_CERT_VERIFIED: HeaderName = HeaderName::from_static("x-client-cert-verified");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_ORIGINAL_REQUEST_ID: HeaderName = HeaderName::from_static("x-original-request-id");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
/// direct h2c activity 的终止哨兵；idle worker 只有从 0 CAS 到该值后才能关闭 transport。
const H2C_ACTIVITY_CLOSING: u64 = u64::MAX;
/// WS idle 计时精度。默认 idle 上限为分钟级；10ms 把提前/延后判定误差限制在一个 tick，
/// 同时让所有隧道共享一次单调时钟读取，而不是在每次 socket read/write 时读取时钟。
const WS_ACTIVITY_CLOCK_TICK: Duration = Duration::from_millis(10);

/// 启动 WebSocket 活动时间的共享粗粒度单调时钟。
///
/// worker 只持有 `Weak`：GatewayProxy 及仍在线隧道释放最后一个时钟 owner 后，后台任务在
/// 下个 tick 自动退出。`MissedTickBehavior::Skip` 防止 runtime 短暂停顿后补跑大量无意义 tick。
/// 时间值仅作同一进程内 idle 差值，不读取墙钟，也不参与协议数据。
pub(super) fn start_ws_activity_clock() -> Arc<AtomicU64> {
    let clock = Arc::new(AtomicU64::new(0));
    let worker_clock = Arc::downgrade(&clock);
    tokio::spawn(async move {
        let started = TokioInstant::now();
        let mut ticker = tokio::time::interval(WS_ACTIVITY_CLOCK_TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(clock) = worker_clock.upgrade() else {
                return;
            };
            let elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            clock.store(elapsed_ms, Ordering::Relaxed);
        }
    });
    clock
}

/// 一个 H2 client shard 的首次冷启动/已观察错误后恢复单飞门。
///
/// Hyper legacy pool 能在握手完成后复用同一条 H2 transport，但首批请求同时看到空池时会并发
/// 调用 connector。单飞门只串行第一个 response head；稳态为一次 Acquire load，不引入 mutex，
/// 也不缓存、复制或 collect 请求/响应 body。等待者挂在 `Notify` 上，由现有 TTFB timeout 统一
/// 限时，因此这里没有第二个无界请求队列。
struct H2ColdStartGate {
    state: AtomicU8,
    changed: Notify,
}

impl H2ColdStartGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(H2_SHARD_COLD),
            changed: Notify::new(),
        })
    }

    /// 请求错误通常表示池中 transport 已不可用；仅由一个观察者把 shard 退回 cold，下一次
    /// 请求重新执行单飞。已越过 ready 检查的少量并发请求仍可能同时失败，但不会重复建连接。
    fn mark_cold_after_error(&self) {
        if self
            .state
            .compare_exchange(
                H2_SHARD_READY,
                H2_SHARD_COLD,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.changed.notify_waiters();
        }
    }
}

/// 正在执行首次连接或错误后恢复的 RAII owner。TTFB timeout 或下游取消会 drop 请求 future；此 guard 必须
/// 把状态退回 cold 并唤醒等待者，否则一次取消就会让整个 shard 永久停在 connecting。
struct H2ColdStartLeader<'a> {
    gate: &'a H2ColdStartGate,
    completed: bool,
}

impl H2ColdStartLeader<'_> {
    fn finish(mut self, ready: bool) {
        self.gate.state.store(
            if ready { H2_SHARD_READY } else { H2_SHARD_COLD },
            Ordering::Release,
        );
        self.completed = true;
        self.gate.changed.notify_waiters();
    }
}

impl Drop for H2ColdStartLeader<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.gate.state.store(H2_SHARD_COLD, Ordering::Release);
            self.gate.changed.notify_waiters();
        }
    }
}

/// 普通 HTTP/HTTPS client wrapper。H1 的 gate 为 None，完全沿用 Hyper 池；显式 H2 shard
/// 共享一个 gate，避免同一 shard 冷启动时重复建立物理连接。
#[derive(Clone)]
pub(crate) struct UpstreamHttpClient {
    inner: RawUpstreamHttpClient,
    h2_gate: Option<Arc<H2ColdStartGate>>,
}

impl UpstreamHttpClient {
    async fn request(
        &self,
        request: Request<BoxBody>,
    ) -> Result<Response<UpstreamResponseBody>, BoxError> {
        let Some(gate) = &self.h2_gate else {
            return self
                .inner
                .request(request)
                .await
                .map(|response| response.map(UpstreamResponseBody::Pooled))
                .map_err(|error| Box::new(error) as BoxError);
        };
        let mut request = Some(request);
        loop {
            // 先注册通知再读状态，封住 connecting -> ready 恰好发生在二者之间的丢唤醒竞态。
            let changed = gate.changed.notified();
            match gate.state.load(Ordering::Acquire) {
                H2_SHARD_READY => {
                    let result = self
                        .inner
                        .request(request.take().expect("H2 request consumed once"))
                        .await;
                    if result.is_err() {
                        gate.mark_cold_after_error();
                    }
                    return result
                        .map(|response| response.map(UpstreamResponseBody::Pooled))
                        .map_err(|error| Box::new(error) as BoxError);
                }
                H2_SHARD_COLD => {
                    if gate
                        .state
                        .compare_exchange(
                            H2_SHARD_COLD,
                            H2_SHARD_CONNECTING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        let leader = H2ColdStartLeader {
                            gate,
                            completed: false,
                        };
                        let result = self
                            .inner
                            .request(request.take().expect("H2 request consumed once"))
                            .await;
                        leader.finish(result.is_ok());
                        return result
                            .map(|response| response.map(UpstreamResponseBody::Pooled))
                            .map_err(|error| Box::new(error) as BoxError);
                    }
                }
                H2_SHARD_CONNECTING => changed.await,
                _ => unreachable!("invalid H2 shard state"),
            }
        }
    }
}

/// 单条 direct h2c transport 的活跃 stream/idle 状态。
///
/// 请求只在 response body 存活期持有一个 RAII guard；payload/trailer 继续由 Hyper `Incoming`
/// 原样移动。idle worker 只观察两个原子和 `Notify`，不扫描请求表，也不建立周期轮询任务。
struct H2cConnectionActivity {
    active_streams: AtomicU64,
    idle_since_ms: AtomicU64,
    changed: Notify,
}

impl H2cConnectionActivity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            active_streams: AtomicU64::new(0),
            idle_since_ms: AtomicU64::new(pool_clock_millis()),
            changed: Notify::new(),
        })
    }

    #[inline]
    fn try_begin(&self) -> bool {
        // 与 idle worker 的 0 -> CLOSING CAS 竞争：请求先成功则计数非零、回收方继续等待；
        // 回收方先成功则本请求不得把已决定关闭的 transport“复活”，而是让外层重连。
        self.active_streams
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active != H2C_ACTIVITY_CLOSING)
                    .then(|| active.checked_add(1))
                    .flatten()
                    .filter(|next| *next != H2C_ACTIVITY_CLOSING)
            })
            .is_ok()
    }

    /// 结束一个已经由 [`Self::try_begin`] 登记的 stream。独立方法也让竞态测试能直接驱动
    /// 状态机，不必伪造 Hyper `SendRequest`；生产调用始终由 RAII guard 的 Drop 触发。
    fn finish_stream(&self) {
        let previous = self.active_streams.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0 && previous != H2C_ACTIVITY_CLOSING);
        if previous == 1 {
            self.idle_since_ms
                .store(pool_clock_millis(), Ordering::Release);
            self.changed.notify_one();
        }
    }
}

/// direct h2c stream 的 RAII 活跃计数；TTFB future 取消、body 错误和正常 EOF 共用此释放路径。
///
/// guard 直接接管本次 ArcSwap `load_full` 得到的 connection Arc，而不是另 clone 一次内部
/// activity Arc。响应 body 本来就必须让该 generation 存活到 EOF；移动现有 Arc 可让每个 RPC
/// 少一对共享引用计数 RMW，同时仍不复制任何 HEADERS/DATA/trailer。
struct H2cActiveStreamGuard {
    connection: Option<Arc<DirectH2cConnection>>,
}

impl H2cActiveStreamGuard {
    #[inline]
    fn finish(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        connection.activity.finish_stream();
    }
}

impl Drop for H2cActiveStreamGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

/// direct h2c response body；唯一附加状态是活跃 stream guard，不复制或 collect frame。
struct DirectH2cBody {
    inner: Incoming,
    active: H2cActiveStreamGuard,
}

impl Body for DirectH2cBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => {
                self.active.finish();
                Poll::Ready(Some(Err(Box::new(error) as BoxError)))
            }
            Poll::Ready(None) => {
                self.active.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 普通 Hyper pool 与 direct h2c 共用的静态响应 body 枚举；避免为了统一两个分支先 box
/// `Incoming`，最外层 `CountedBody` 仍只做一次必要类型擦除。
enum UpstreamResponseBody {
    Pooled(Incoming),
    DirectH2c(DirectH2cBody),
}

impl Body for UpstreamResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut *self {
            Self::Pooled(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|frame| frame.map(|frame| frame.map_err(|error| Box::new(error) as BoxError))),
            Self::DirectH2c(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Pooled(body) => body.is_end_stream(),
            Self::DirectH2c(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Pooled(body) => body.size_hint(),
            Self::DirectH2c(body) => body.size_hint(),
        }
    }
}

type DirectH2cSender = hyper::client::conn::http2::SendRequest<BoxBody>;

struct DirectH2cConnection {
    sender: DirectH2cSender,
    activity: Arc<H2cConnectionActivity>,
}

struct DirectH2cState {
    current: ArcSwapOption<DirectH2cConnection>,
    connector: BudgetedConnector<HttpConnector>,
    policy: HttpPoolPolicy,
}

impl DirectH2cState {
    async fn connect(&self, uri: http::Uri) -> Result<(), BoxError> {
        let mut connector = self.connector.clone();
        std::future::poll_fn(|cx| connector.poll_ready(cx)).await?;
        let io = connector.call(uri).await?;
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder
            .initial_stream_window_size(Some(self.policy.h2_initial_stream_window_bytes))
            .initial_connection_window_size(Some(self.policy.h2_initial_connection_window_bytes));
        let (sender, connection) = builder
            .handshake::<_, BoxBody>(io)
            .await
            .map_err(|error| Box::new(error) as BoxError)?;
        let activity = H2cConnectionActivity::new();
        self.current.store(Some(Arc::new(DirectH2cConnection {
            sender,
            activity: activity.clone(),
        })));
        let idle_timeout_ms = self.policy.idle_timeout_ms;
        tokio::spawn(async move {
            tokio::pin!(connection);
            if idle_timeout_ms == 0 {
                let _ = connection.await;
                return;
            }
            tokio::select! {
                _ = &mut connection => {}
                _ = wait_for_h2c_idle(activity, idle_timeout_ms) => {}
            }
        });
        Ok(())
    }
}

/// 等待 direct h2c transport 连续空闲到配置上限；新 stream 与最后一个 body 结束都会唤醒并
/// 重新核验，timer 与新请求同时就绪时也不会错误关闭活跃 transport。
async fn wait_for_h2c_idle(activity: Arc<H2cConnectionActivity>, idle_timeout_ms: u64) {
    loop {
        let changed = activity.changed.notified();
        let active = activity.active_streams.load(Ordering::Acquire);
        if active == H2C_ACTIVITY_CLOSING {
            return;
        }
        if active != 0 {
            changed.await;
            continue;
        }
        let idle_since_ms = activity.idle_since_ms.load(Ordering::Acquire);
        let elapsed_ms = pool_clock_millis().saturating_sub(idle_since_ms);
        if elapsed_ms >= idle_timeout_ms {
            // 单次 CAS 把“确认空闲”和“决定关闭”变成同一个原子动作。旧实现先 load 0 再
            // return，请求可能恰好在两者之间 begin，导致正在发送的新 stream 被误关。
            if activity
                .active_streams
                .compare_exchange(0, H2C_ACTIVITY_CLOSING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(idle_timeout_ms - elapsed_ms)) => {}
            _ = changed => {}
        }
    }
}

/// h2c prior-knowledge direct sender；每个实例就是一个可多路复用的物理连接 shard。
///
/// 绕过 legacy pool 的 authority lookup/dispatch，但仍保留 cold-start singleflight、物理 socket
/// RAII cap、generation 换版、idle 回收、TTFB cancellation、GOAWAY/断连恢复和原帧流式 body。
#[derive(Clone)]
pub(crate) struct UpstreamH2cClient {
    state: Arc<DirectH2cState>,
    h2_gate: Arc<H2ColdStartGate>,
}

impl UpstreamH2cClient {
    async fn request(
        &self,
        request: Request<BoxBody>,
    ) -> Result<Response<UpstreamResponseBody>, BoxError> {
        let mut request = Some(request);
        loop {
            let changed = self.h2_gate.changed.notified();
            match self.h2_gate.state.load(Ordering::Acquire) {
                H2_SHARD_READY => {
                    let Some(connection) = self.state.current.load_full() else {
                        self.h2_gate.mark_cold_after_error();
                        continue;
                    };
                    if connection.sender.is_closed() {
                        self.h2_gate.mark_cold_after_error();
                        continue;
                    }
                    if !connection.activity.try_begin() {
                        // idle worker 已原子决定关闭本 transport；不能向它再投递 stream。
                        self.h2_gate.mark_cold_after_error();
                        continue;
                    }
                    let mut sender = connection.sender.clone();
                    // 移动而非 clone `connection`：guard/body 接管 ArcSwap load_full 已支付的引用，
                    // 错误/取消则由本作用域 Drop，成功则随 DirectH2cBody 一直活到 EOF。
                    let active = H2cActiveStreamGuard {
                        connection: Some(connection),
                    };
                    let result = sender
                        .send_request(request.take().expect("h2c request consumed once"))
                        .await;
                    return match result {
                        Ok(response) => Ok(response.map(|inner| {
                            UpstreamResponseBody::DirectH2c(DirectH2cBody { inner, active })
                        })),
                        Err(error) => {
                            self.h2_gate.mark_cold_after_error();
                            Err(Box::new(error) as BoxError)
                        }
                    };
                }
                H2_SHARD_COLD => {
                    if self
                        .h2_gate
                        .state
                        .compare_exchange(
                            H2_SHARD_COLD,
                            H2_SHARD_CONNECTING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        let leader = H2ColdStartLeader {
                            gate: &self.h2_gate,
                            completed: false,
                        };
                        let uri = request
                            .as_ref()
                            .expect("h2c request exists before send")
                            .uri()
                            .clone();
                        let result = self.state.connect(uri).await;
                        leader.finish(result.is_ok());
                        result?;
                    }
                }
                H2_SHARD_CONNECTING => changed.await,
                _ => unreachable!("invalid h2c shard state"),
            }
        }
    }
}

/// 一个结构化上游身份跨 client generation 共享的物理 socket 预算。
///
/// Hyper 的 `pool_max_idle_per_host` 只限制 idle cache，不能限制正在使用的连接。本计数器在 connector
/// 真正 dial 前 CAS 占位，并由 transport Drop 归还；reload 调小上限时，现存连接自然退出前不再允许新拨号。
pub(crate) struct PhysicalConnectionBudget {
    /// 当前仍存活的物理 transport 数。
    active: AtomicU64,
    /// 当前配置上限；0 表示不限制但仍记账，便于热调小后收敛。
    limit: AtomicU64,
}

impl PhysicalConnectionBudget {
    /// 创建一个物理连接预算。
    ///
    /// # 参数
    /// - `limit`: 物理 socket 上限；0 表示不限制。
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicU64::new(0),
            limit: AtomicU64::new(limit.min(u64::MAX as usize) as u64),
        })
    }

    /// 更新热配置上限；不会粗暴关闭已有连接，新拨号会按新值判定。
    ///
    /// # 参数
    /// - `limit`: 新物理 socket 上限；0 表示不限制。
    fn set_limit(&self, limit: usize) {
        self.limit
            .store(limit.min(u64::MAX as usize) as u64, Ordering::Release);
    }

    /// 非阻塞占用一个 dial 名额。满载必须快速失败，不能在 connector 内形成隐藏等待队列。
    fn try_acquire(self: &Arc<Self>) -> Result<PhysicalConnectionSlot, ConnectionLimitReached> {
        let acquired = self
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |active| {
                let limit = self.limit.load(Ordering::Acquire);
                (limit == 0 || active < limit).then_some(active.saturating_add(1))
            })
            .is_ok();
        acquired
            .then(|| PhysicalConnectionSlot {
                budget: self.clone(),
            })
            .ok_or(ConnectionLimitReached)
    }
}

/// 物理 socket 已到上限。该错误保留在 Hyper error source chain 中，调用方映射为快速 503。
#[derive(Debug)]
struct ConnectionLimitReached;

impl fmt::Display for ConnectionLimitReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("upstream physical connection limit reached")
    }
}

impl std::error::Error for ConnectionLimitReached {}

/// 一个已占用的物理 transport 名额。
struct PhysicalConnectionSlot {
    /// 跨 generation 共享的预算；Drop 是唯一归还路径。
    budget: Arc<PhysicalConnectionBudget>,
}

impl Drop for PhysicalConnectionSlot {
    fn drop(&mut self) {
        self.budget.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 为任意 Hyper connector 增加严格物理 socket 上限。
///
/// 普通 HTTP/HTTPS 与 h2c 必须走同一 wrapper；只包 h2c 会让 TLS/ALPN 主路径绕过资源预算。
#[derive(Clone)]
pub(crate) struct BudgetedConnector<C> {
    /// 实际 HttpConnector 或 HttpsConnector。
    inner: C,
    /// 结构化上游身份的跨 generation 总预算。
    budget: Arc<PhysicalConnectionBudget>,
}

impl<C> BudgetedConnector<C> {
    /// 包装 connector；调用方保证 budget 与完整 health_key/protocol 绑定。
    fn new(inner: C, budget: Arc<PhysicalConnectionBudget>) -> Self {
        Self { inner, budget }
    }
}

impl<C> Service<http::Uri> for BudgetedConnector<C>
where
    C: Service<http::Uri> + Send,
    C::Response: Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Send + 'static,
{
    type Response = BudgetedIo<C::Response>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::poll_ready(&mut self.inner, cx).map_err(Into::into)
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        // WHY:必须先占位再创建 inner future；旧实现先 `inner.call()`，即使 permit 未到手也已经开始拨号。
        let slot = match self.budget.try_acquire() {
            Ok(slot) => slot,
            Err(error) => return Box::pin(async move { Err(Box::new(error) as BoxError) }),
        };
        let fut = Service::call(&mut self.inner, uri);
        Box::pin(async move {
            let io = fut.await.map_err(Into::into)?;
            Ok(BudgetedIo {
                inner: io,
                _slot: slot,
            })
        })
    }
}

pub(crate) struct BudgetedIo<I> {
    inner: I,
    _slot: PhysicalConnectionSlot,
}
impl<I: HyperRead + Unpin> HyperRead for BudgetedIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<I: HyperWrite + Unpin> HyperWrite for BudgetedIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl<I: Connection> Connection for BudgetedIo<I> {
    fn connected(&self) -> Connected {
        // 保留 HttpsConnector 的 negotiated_h2/proxy 元数据；重建 `Connected::new()` 会破坏 ALPN h2 选择。
        self.inner.connected()
    }
}

/// 按上游 protocol 配置(review L1)决定给上游请求打什么 HTTP 版本 hint。
/// hyper-util legacy client 据请求版本 + 连接器 ALPN 选择 h1/h2。
fn upstream_request_version(protocol: UpstreamProtocol, parts: &Parts) -> http::Version {
    match protocol {
        UpstreamProtocol::H1 => http::Version::HTTP_11,
        // h2(TLS 经 ALPN)/ h2c(明文 prior-knowledge)都用 HTTP_2 版本 hint。
        UpstreamProtocol::H2 | UpstreamProtocol::H2c => http::Version::HTTP_2,
        // auto:gRPC(content-type=application/grpc*)默认 h2,其余 h1。
        UpstreamProtocol::Auto => {
            if is_grpc_request(parts) {
                http::Version::HTTP_2
            } else {
                http::Version::HTTP_11
            }
        }
    }
}

/// 是否 gRPC 请求(content-type 以 `application/grpc` 开头)。
fn is_grpc_request(parts: &Parts) -> bool {
    has_native_grpc_content_type(&parts.headers)
}

/// 精确识别 native gRPC media type，排除需要不同 framing 的 grpc-web。
fn has_native_grpc_content_type(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|media_type| {
            media_type == "application/grpc"
                || media_type
                    .strip_prefix("application/grpc")
                    .is_some_and(|suffix| suffix.starts_with('+'))
        })
}

pub(super) struct ForwardRequest<'a> {
    pub snap: &'a GatewaySnapshot,
    pub proxy: &'a ProxyRuntime,
    pub route: &'a Route,
    pub parts: Parts,
    pub body: ForwardBody,
    /// V6 LLM provider 的显式模型上游；None 使用 route 常规 URI/template。
    pub upstream_override: Option<&'a str>,
    /// V6 provider API path；设置时不继承下游 query，防客户端参数越过统一契约。
    pub path_override: Option<&'a str>,
    /// 真实客户端 IP(review L6:PROXY protocol / 可信 XFF 算出,或 socket 对端);用于 XFF/`${remote_addr}`。
    pub client_ip: IpAddr,
    /// 与 `client_ip` 已核对相等的连接级预编码值；普通直连/PROXY protocol 热路径可复用，
    /// trusted XFF 为每 stream 改写地址时为 None，并保持原逐请求安全路径。
    pub client_ip_header: Option<HeaderValue>,
    /// 直连入站是否可信(review L3:决定是否采信入站 traceparent)。
    pub trusted_inbound: bool,
    pub downstream_proto: &'static str,
    /// mTLS(§19):本连接是否出示了经 CA 校验的客户端证书;true 时向上游注入 `X-Client-Cert-Verified`。
    pub client_cert_verified: bool,
    pub request_id: &'a str,
    /// 已认证长连接 consumer；只用于 WS/gRPC registry，不进入上游或日志高基数标签。
    pub consumer: Option<Arc<str>>,
    pub downstream_upgrade: super::DownstreamUpgrade,
    /// WebSocket 等升级长连接的 `limit_conn` guard。普通 HTTP 响应由 proxy 外层 body 包装释放。
    pub limit_conn_guards: Vec<super::LimitConnGuard>,
    /// 当前请求 server span；后台/内部请求可为 None，普通上游 attempt 据此建 client child。
    pub trace: Option<&'a crate::telemetry::ServerTrace>,
}

/// forward 内部请求体封装。
pub(crate) enum ForwardBody {
    /// 原始下游 Incoming,默认流式快路径。
    Incoming(Incoming),
    /// 显式慢路径收集后重新构造的 boxed body。
    Boxed(BoxBody),
}

/// 单次主上游发送的不可变执行参数；收拢参数以避免 retry 调用点发生位置错配。
struct UpstreamSendContext<'a> {
    /// response head/TTFB 超时，0 表示关闭。
    ttfb_timeout_ms: u64,
    /// response body frame idle 超时，0 表示关闭。
    stream_idle_timeout_ms: u64,
    /// 下游协议版本；response head 回写时使用，不透传上游版本。
    downstream_version: http::Version,
    /// 当前 server span；None 只用于不属于前台请求的防御性调用。
    trace: Option<&'a crate::telemetry::ServerTrace>,
    /// 本次真实上游实例，仅写 span attribute，不作为 metric label。
    upstream: &'a str,
    /// retry 序号，从 1 开始。
    attempt: usize,
    /// 由本请求权威 request-id 计算的无状态 client 分片提示；retry 保持同一 shard 亲和。
    client_shard_hint: u64,
    /// 原生 gRPC 主上游响应的长流治理；内部/插件调用及非 gRPC 请求为空。
    grpc_drain: Option<&'a GrpcDrainContext>,
}

/// 在一次主请求的 retry attempts 间共享的 gRPC 长流登记参数。
#[derive(Clone)]
struct GrpcDrainContext {
    registry: Arc<ConnectionRegistry>,
    route_id: Arc<str>,
    client_ip: IpAddr,
    consumer: Option<Arc<str>>,
    snapshot_version: u64,
    max_lifetime_ms: u64,
}

/// 响应 extension 标记：gRPC drain 已融合进上游计数 body，proxy 外层不得重复包装。
#[derive(Clone, Copy)]
pub(super) struct GrpcDrainAttached;

/// 后台 mirror 发送参数；`ClientTrace` 随 spawned future 移动，父请求结束后仍能完成。
struct MirrorSendContext {
    /// response head 超时，0 表示关闭。
    ttfb_timeout_ms: u64,
    /// 下游请求版本，用于保持 mirror 请求原有协议 hint。
    downstream_version: http::Version,
    /// 已创建的 client span；None 表示调用方没有可用的 server span。
    client_trace: Option<crate::telemetry::ClientTrace>,
}

#[derive(Debug)]
pub(super) enum ForwardError {
    /// DNS/connect/protocol/上游 body 等通用代理错误，对下游映射 502。
    BadGateway(anyhow::Error),
    /// `lb://service` 没有可选择实例，对下游映射 503。
    NoHealthyUpstream(String),
    /// 每实例在途预算已满，对下游快速映射 503，不进入等待队列。
    Overloaded,
    /// connect/TTFB 等上游超时，对下游映射 504。
    Timeout,
}

/// 附着在响应 extension 上的轻量上游追踪信息。
///
/// 它只持有共享 URI 和计数，不触碰 body 帧；错误页内部重路由与最终 access log 可沿用同一份信息。
#[derive(Clone)]
pub(super) struct UpstreamTrace {
    /// 最终实例 URI；与配置快照/预留共享，直到写 access log 才转为其所有权字符串。
    pub final_upstream: Arc<str>,
    /// 本请求实际发送的上游尝试次数。
    pub attempts: usize,
}

/// ext_authz 外部鉴权决策。
pub(super) enum ExtAuthzDecision {
    /// 外部鉴权通过,主链路可继续转发。
    Allowed,
    /// 外部鉴权明确拒绝,下游应收到 401/403。
    Denied {
        /// 返回给下游的拒绝状态。
        status: StatusCode,
        /// 鉴权服务返回的 `WWW-Authenticate`,用于 Basic/Bearer challenge 透传。
        challenge: Option<HeaderValue>,
    },
    /// 鉴权服务不可达、超时或返回异常状态,且当前策略未 fail-open。
    Unavailable,
}

impl ForwardError {
    pub(super) fn status(&self) -> StatusCode {
        match self {
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::NoHealthyUpstream(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Overloaded => StatusCode::SERVICE_UNAVAILABLE,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    pub(super) fn message(&self) -> &'static str {
        match self {
            Self::BadGateway(_) => "bad gateway",
            Self::NoHealthyUpstream(_) => "no healthy upstream",
            Self::Overloaded => "upstream overloaded",
            Self::Timeout => "upstream timeout",
        }
    }

    pub(super) fn is_upstream_error(&self) -> bool {
        true
    }

    pub(super) fn fallback_reason(&self) -> &'static str {
        match self {
            Self::BadGateway(_) => "upstream_error",
            Self::NoHealthyUpstream(_) => "no_healthy_upstream",
            Self::Overloaded => "upstream_overloaded",
            Self::Timeout => "timeout",
        }
    }
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadGateway(e) => write!(f, "bad gateway: {e:#}"),
            Self::NoHealthyUpstream(svc) => write!(f, "no healthy upstream for `{svc}`"),
            Self::Overloaded => f.write_str("upstream pending limit reached"),
            Self::Timeout => f.write_str("upstream timeout"),
        }
    }
}

impl std::error::Error for ForwardError {}

/// 把 Hyper client error 归一成稳定网关错误码。
///
/// # 参数
/// - `context`: 低基数调用场景，例如 `client request`/`ext_authz request`。
/// - `error`: Hyper 返回的错误；source chain 中若含物理连接预算错误则映射 503。
fn map_client_error(context: &'static str, error: BoxError) -> ForwardError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error.as_ref());
    while let Some(current) = source {
        if current.downcast_ref::<ConnectionLimitReached>().is_some() {
            return ForwardError::Overloaded;
        }
        source = current.source();
    }
    // 保留完整 source chain；仅把错误格式化成字符串会丢掉 h2 reason / connector 根因，
    // 使并发故障注入和生产日志只能看到笼统的 `client error (SendRequest)`。
    ForwardError::BadGateway(anyhow::Error::from_boxed(error).context(context))
}

impl super::GatewayProxy {
    pub(super) async fn forward(
        &self,
        mut ctx: ForwardRequest<'_>,
    ) -> Result<Response<BoxBody>, ForwardError> {
        let downstream_version = ctx.parts.version;
        // request-id 本来就已为日志/追踪生成；Snowflake 十六进制末字节就是连续变化的 sequence
        // 低位，可直接作为最多 64 个 H2 shard 的稳定提示。无需再为每请求扫描 16 字节做 FNV，
        // 也不分配临时对象；非标准内部 ID 才回退完整稳定哈希。
        let client_shard_hint = super::request_id_shard_hint(ctx.request_id);
        let grpc_drain = (downstream_version == http::Version::HTTP_2
            && is_grpc_request(&ctx.parts))
        .then(|| GrpcDrainContext {
            registry: self.conn_registry.clone(),
            route_id: ctx.route.id_shared.clone(),
            client_ip: ctx.client_ip,
            consumer: ctx.consumer.clone(),
            snapshot_version: ctx.snap.version,
            max_lifetime_ms: ctx.route.long_stream_max_lifetime_ms,
        });
        let response_stream_idle_timeout_ms = ctx
            .route
            .long_stream_idle_timeout_ms
            .unwrap_or(ctx.proxy.timeouts.stream_idle_timeout_ms);
        let upstream_target = ctx.upstream_override.map(Cow::Borrowed).unwrap_or_else(|| {
            route_upstream_target(
                ctx.route,
                &ctx.parts,
                ctx.client_ip,
                ctx.downstream_proto,
                ctx.request_id,
            )
        });
        let dynamic_upstream =
            ctx.upstream_override.is_none() && matches!(upstream_target, Cow::Owned(_));
        validate_upstream_target(ctx.snap, upstream_target.as_ref(), dynamic_upstream)?;

        if !ctx.route.pass_request_headers {
            ctx.parts.headers.clear();
        }

        let mirror_body = if !ctx.route.mirrors.is_empty() && ctx.downstream_upgrade.is_none() {
            self.prepare_mirror_body(&mut ctx).await?
        } else {
            None
        };
        // 组上游 URI:base(http://host:port) + StripPrefix 后的 path + query。必须放在可能
        // 替换 mirror body 的可变借用之后，默认路径才能安全地直接借用 ctx.parts URI。
        let rewritten: Cow<'_, str> = if let Some(path) = ctx.path_override {
            Cow::Borrowed(path)
        } else if ctx.route.strip_prefix == 0 && ctx.route.rewrite_prefix.is_none() {
            // 绝大多数普通 route 不改 path；直接借用当前请求 URI，避免先由 strip 复制一次、
            // 再由 rewrite 的 no-op 分支复制第二次。最终 Uri parser 只做唯一必要 owned 构造。
            Cow::Borrowed(ctx.parts.uri.path())
        } else {
            let stripped = strip_n_segments(ctx.parts.uri.path(), ctx.route.strip_prefix);
            Cow::Owned(rewrite_prefix(stripped.as_ref(), ctx.route))
        };
        let query = if ctx.path_override.is_some() {
            String::new()
        } else {
            ctx.parts
                .uri
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default()
        };
        if !ctx.route.mirrors.is_empty() && ctx.downstream_upgrade.is_none() {
            self.spawn_mirror_requests(
                &ctx,
                &rewritten,
                &query,
                downstream_version,
                mirror_body.as_ref(),
            );
        }

        if let Some((downstream, downstream_connection_lease)) = ctx.downstream_upgrade {
            let ForwardBody::Incoming(body) = ctx.body else {
                return Err(ForwardError::BadGateway(anyhow::anyhow!(
                    "websocket body was pre-buffered unexpectedly"
                )));
            };
            let limit_conn_guards = std::mem::take(&mut ctx.limit_conn_guards);
            let reservation = self.resolve_upstream_base_excluding(
                ctx.snap,
                upstream_target.as_ref(),
                &[],
                &ctx.proxy.limits,
            )?;
            let uri = upstream_uri(&reservation.base, &rewritten, &query)?;
            let mut parts = prepare_attempt_parts(
                &ctx.parts,
                uri,
                ctx.route,
                reservation.protocol,
                ctx.client_ip,
                ctx.client_ip_header.as_ref(),
                ctx.trusted_inbound,
                ctx.client_cert_verified,
                ctx.downstream_proto,
                ctx.request_id,
                true,
            )?;
            let client_trace = ctx
                .trace
                .map(|trace| trace.begin_client(&mut parts.headers, reservation.base.as_ref(), 1));
            return self
                .forward_websocket(
                    parts,
                    body,
                    downstream,
                    downstream_connection_lease,
                    ctx.route.id.as_str(),
                    ctx.client_ip,
                    ctx.consumer,
                    ctx.snap.version,
                    reservation,
                    limit_conn_guards,
                    ctx.proxy.timeouts.websocket_idle_timeout_ms,
                    ctx.proxy.timeouts.websocket_max_lifetime_ms,
                    client_trace,
                )
                .await;
        }

        let lb_service = upstream_target.strip_prefix("lb://");
        let retry_policy = lb_service
            .and_then(|svc| ctx.snap.upstreams.next_upstream_policy(svc))
            .cloned();
        let passive_policy = lb_service
            .and_then(|svc| ctx.snap.upstreams.passive_health_policy(svc))
            .unwrap_or_else(PassiveHealthPolicy::disabled);
        if retry_policy
            .as_ref()
            .map(|policy| can_retry_request(&ctx.parts, policy, ctx.route.pass_request_body))
            .unwrap_or(false)
        {
            let mut attempted = Vec::new();
            let mut last_error = None;
            let mut last_response = None;
            let max_attempts = retry_policy
                .as_ref()
                .map(NextUpstreamPolicy::max_attempts)
                .unwrap_or(usize::MAX);
            loop {
                if attempted.len() >= max_attempts {
                    self.metrics.inc_upstream_retry_exhausted();
                    if let Some(resp) = last_response {
                        return Ok(resp);
                    }
                    if let Some(err) = last_error {
                        return Err(err);
                    }
                }
                let reservation = match self.resolve_upstream_base_excluding(
                    ctx.snap,
                    upstream_target.as_ref(),
                    &attempted,
                    &ctx.proxy.limits,
                ) {
                    Ok(reservation) => reservation,
                    Err(e) => {
                        if let Some(resp) = last_response {
                            self.metrics.inc_upstream_retry_exhausted();
                            return Ok(resp);
                        }
                        if let Some(err) = last_error {
                            self.metrics.inc_upstream_retry_exhausted();
                            return Err(err);
                        }
                        return Err(e);
                    }
                };
                let uri = upstream_uri(&reservation.base, &rewritten, &query)?;
                attempted.push(reservation.health_key.clone());
                let attempt_upstream = reservation.base.clone();
                let attempt_health_key = reservation.health_key.clone();
                let attempt_count = attempted.len();
                let parts = prepare_attempt_parts(
                    &ctx.parts,
                    uri,
                    ctx.route,
                    reservation.protocol,
                    ctx.client_ip,
                    ctx.client_ip_header.as_ref(),
                    ctx.trusted_inbound,
                    ctx.client_cert_verified,
                    ctx.downstream_proto,
                    ctx.request_id,
                    false,
                )?;
                match self
                    .send_upstream_request(
                        parts,
                        empty_body(),
                        reservation,
                        UpstreamSendContext {
                            ttfb_timeout_ms: ctx.proxy.timeouts.upstream_ttfb_timeout_ms,
                            stream_idle_timeout_ms: response_stream_idle_timeout_ms,
                            downstream_version,
                            trace: ctx.trace,
                            upstream: attempt_upstream.as_ref(),
                            attempt: attempt_count,
                            client_shard_hint,
                            grpc_drain: grpc_drain.as_ref(),
                        },
                    )
                    .await
                {
                    Ok(resp) => {
                        let should_retry = retry_policy
                            .as_ref()
                            .map(|policy| should_retry_status(policy, resp.status()))
                            .unwrap_or(false);
                        if resp.status().is_server_error() {
                            self.record_upstream_failure(&attempt_health_key, passive_policy);
                        } else {
                            self.record_upstream_success(&attempt_health_key);
                        }
                        let annotated =
                            annotate_upstream_trace(resp, attempt_upstream.clone(), attempt_count);
                        if should_retry && attempt_count < max_attempts {
                            self.metrics.inc_upstream_retry_status();
                            tracing::debug!(
                                route = %ctx.route.id,
                                status = annotated.status().as_u16(),
                                "retry next upstream by response status"
                            );
                            last_response = Some(annotated);
                            retry_backoff(retry_policy.as_ref()).await;
                            continue;
                        }
                        if should_retry {
                            self.metrics.inc_upstream_retry_exhausted();
                        }
                        return Ok(annotated);
                    }
                    Err(e) => {
                        self.record_upstream_failure(&attempt_health_key, passive_policy);
                        let should_retry = retry_policy
                            .as_ref()
                            .map(|policy| should_retry_error(policy, &e))
                            .unwrap_or(false);
                        if should_retry && attempt_count < max_attempts {
                            self.metrics.inc_upstream_retry_error();
                            tracing::debug!(
                                route = %ctx.route.id,
                                error = %e,
                                "retry next upstream by error"
                            );
                            last_error = Some(e);
                            retry_backoff(retry_policy.as_ref()).await;
                            continue;
                        }
                        if should_retry {
                            self.metrics.inc_upstream_retry_exhausted();
                        }
                        return Err(e);
                    }
                }
            }
        }

        let reservation = self.resolve_upstream_base_excluding(
            ctx.snap,
            upstream_target.as_ref(),
            &[],
            &ctx.proxy.limits,
        )?;
        let uri = upstream_uri(&reservation.base, &rewritten, &query)?;
        let attempt_upstream = reservation.base.clone();
        let attempt_health_key = reservation.health_key.clone();
        // 非重试主路径只发送一次，原始 downstream Parts 在此后不再读取；直接转移所有权并
        // 原地改写，避免每请求为整张 HeaderMap 重新分配 bucket。需要多个 attempt 的上方
        // retry 分支仍显式 clone，保证各次请求 head 相互隔离。
        let parts = prepare_attempt_parts_owned(
            ctx.parts,
            uri,
            ctx.route,
            reservation.protocol,
            ctx.client_ip,
            ctx.client_ip_header.as_ref(),
            ctx.trusted_inbound,
            ctx.client_cert_verified,
            ctx.downstream_proto,
            ctx.request_id,
            false,
        )?;
        let body = upstream_request_body(
            ctx.body,
            ctx.route.pass_request_body,
            ctx.proxy.limits.max_body_bytes,
            ctx.proxy.timeouts.stream_idle_timeout_ms,
        );
        let result = self
            .send_upstream_request(
                parts,
                body,
                reservation,
                UpstreamSendContext {
                    ttfb_timeout_ms: ctx.proxy.timeouts.upstream_ttfb_timeout_ms,
                    stream_idle_timeout_ms: response_stream_idle_timeout_ms,
                    downstream_version,
                    trace: ctx.trace,
                    upstream: attempt_upstream.as_ref(),
                    attempt: 1,
                    client_shard_hint,
                    grpc_drain: grpc_drain.as_ref(),
                },
            )
            .await;
        match result {
            Ok(resp) => {
                if resp.status().is_server_error() {
                    self.record_upstream_failure(&attempt_health_key, passive_policy);
                } else {
                    self.record_upstream_success(&attempt_health_key);
                }
                Ok(annotate_upstream_trace(resp, attempt_upstream, 1))
            }
            Err(e) => {
                self.record_upstream_failure(&attempt_health_key, passive_policy);
                Err(e)
            }
        }
    }

    async fn send_upstream_request(
        &self,
        mut parts: Parts,
        body: BoxBody,
        reservation: UpstreamReservation,
        ctx: UpstreamSendContext<'_>,
    ) -> Result<Response<BoxBody>, ForwardError> {
        self.metrics.inc_upstream_attempt();
        // 在用户 request-header 规则之后创建 client span：传播头由网关最终盖章，避免 retry
        // 复用 server span-id。只修改几个 header，不 clone HeaderMap 或请求 body。
        let client_trace = ctx
            .trace
            .map(|trace| trace.begin_client(&mut parts.headers, ctx.upstream, ctx.attempt));
        let ureq = Request::from_parts(parts, body);
        let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
        let h2_request = ureq.version() == http::Version::HTTP_2;
        let client = if use_h2c {
            None
        } else {
            Some(self.http_client_for(&reservation, h2_request, Some(ctx.client_shard_hint)))
        };
        let h2c_client =
            use_h2c.then(|| self.h2c_client_for(&reservation, Some(ctx.client_shard_hint)));
        let fut = async {
            if use_h2c {
                h2c_client.expect("h2c client prepared").request(ureq).await
            } else {
                client.expect("non-h2c client prepared").request(ureq).await
            }
        };
        let result = if ctx.ttfb_timeout_ms == 0 {
            fut.await
        } else {
            match tokio::time::timeout(Duration::from_millis(ctx.ttfb_timeout_ms), fut).await {
                Ok(result) => result,
                Err(_) => {
                    if let Some(trace) = client_trace {
                        trace.finish_error("upstream response-head timeout");
                    }
                    return Err(ForwardError::Timeout);
                }
            }
        }
        .map_err(|error| map_client_error("client request", error));
        let resp = match result {
            Ok(resp) => {
                if let Some(trace) = client_trace {
                    trace.finish_status(resp.status().as_u16());
                }
                resp
            }
            Err(mapped) => {
                if matches!(mapped, ForwardError::Overloaded) {
                    self.metrics.inc_upstream_overloaded();
                }
                if let Some(trace) = client_trace {
                    trace.finish_error(mapped.message());
                }
                return Err(mapped);
            }
        };

        let grpc_drain = ctx
            .grpc_drain
            .filter(|_| has_native_grpc_content_type(resp.headers()))
            .map(GrpcBodyState::register);
        // 保留原始 Incoming 到最终 wrapper：若先归一成 BoxBody，计数/drain 再 boxed 会形成
        // 两次堆分配和两层动态分发。wrap_body 在最外层统一把 Error 擦除，全程不 collect 帧。
        let mut resp = resp;
        // ★响应版本跟随下游请求(F5),不透传上游版本;h2 下游忽略该字段,故安全。
        *resp.version_mut() = ctx.downstream_version;
        if grpc_drain.is_some() {
            resp.extensions_mut().insert(GrpcDrainAttached);
        }
        Ok(resp.map(|body| reservation.wrap_body(body, ctx.stream_idle_timeout_ms, grpc_drain)))
    }

    /// 执行 route 的 ext_authz 外部鉴权策略。
    ///
    /// # 参数
    /// - `snap`: 当前配置快照,用于解析 `lb://auth-service`。
    /// - `proxy`: 当前入口运行参数。
    /// - `route`: 当前命中 route。
    /// - `parts`: 原始下游请求 head;鉴权通过后可注入 allowlist 上游 header。
    /// - `client_ip`: 真实客户端 IP。
    /// - `trusted_inbound`: 入站连接是否可信。
    /// - `downstream_proto`: 下游协议 scheme。
    /// - `request_id`: 当前请求 ID。
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn authorize_ext_authz(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        parts: &mut Parts,
        client_ip: IpAddr,
        trusted_inbound: bool,
        downstream_proto: &'static str,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
    ) -> ExtAuthzDecision {
        // 多个 ext_authz 策略属于同一种认证方式，按 OR 组合；它们作为一个认证组再参与 route 的
        // `satisfy any|all`。因此一个后端明确拒绝不能覆盖后续后端的成功，否则会把配置模型中的
        // 备选鉴权服务误实现成串联鉴权。非 fail-open 的异常先记下，仍尝试其余后端；仅当没有任何
        // 后端成功时才返回 Unavailable。指标按【最终请求决策】计 allowed/denied，error 按后端异常计。
        let mut denied: Option<(StatusCode, Option<http::HeaderValue>)> = None;
        let mut unavailable = false;
        for policy in &route.ext_authz {
            match self
                .send_ext_authz_request(
                    snap,
                    proxy,
                    route,
                    policy,
                    parts,
                    client_ip,
                    trusted_inbound,
                    downstream_proto,
                    request_id,
                    trace,
                )
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    copy_ext_authz_upstream_headers(parts, policy, &resp);
                    drop(resp);
                    self.metrics.inc_ext_authz_allowed();
                    return ExtAuthzDecision::Allowed;
                }
                Ok(resp)
                    if resp.status() == StatusCode::UNAUTHORIZED
                        || resp.status() == StatusCode::FORBIDDEN =>
                {
                    denied.get_or_insert_with(|| {
                        (
                            resp.status(),
                            resp.headers().get(http::header::WWW_AUTHENTICATE).cloned(),
                        )
                    });
                }
                Ok(resp) => {
                    self.metrics.inc_ext_authz_error();
                    if policy.fail_open {
                        tracing::warn!(
                            route = %route.id,
                            status = resp.status().as_u16(),
                            "ext_authz abnormal status, fail-open"
                        );
                        self.metrics.inc_ext_authz_allowed();
                        return ExtAuthzDecision::Allowed;
                    }
                    tracing::warn!(
                        route = %route.id,
                        status = resp.status().as_u16(),
                        "ext_authz abnormal status, fail-closed"
                    );
                    unavailable = true;
                }
                Err(err) => {
                    self.metrics.inc_ext_authz_error();
                    if policy.fail_open {
                        tracing::warn!(route = %route.id, error = %err, "ext_authz failed, fail-open");
                        self.metrics.inc_ext_authz_allowed();
                        return ExtAuthzDecision::Allowed;
                    }
                    tracing::warn!(route = %route.id, error = %err, "ext_authz failed, fail-closed");
                    unavailable = true;
                }
            }
        }
        if unavailable {
            return ExtAuthzDecision::Unavailable;
        }
        if let Some((status, challenge)) = denied {
            self.metrics.inc_ext_authz_denied();
            return ExtAuthzDecision::Denied { status, challenge };
        }
        // 空策略列表不会进入本函数(调用方已判空)，保留安全兜底以免未来调用约束变化。
        ExtAuthzDecision::Unavailable
    }

    /// 发送一次 ext_authz 子请求。
    ///
    /// # 参数
    /// - `snap`: 当前配置快照。
    /// - `proxy`: 当前入口运行参数。
    /// - `route`: 当前 route。
    /// - `policy`: 当前 ext_authz 策略。
    /// - `base_parts`: 原始下游请求 head。
    /// - `client_ip`: 真实客户端 IP。
    /// - `trusted_inbound`: 入站连接是否可信。
    /// - `downstream_proto`: 下游协议 scheme。
    /// - `request_id`: 当前请求 ID。
    #[allow(clippy::too_many_arguments)]
    async fn send_ext_authz_request(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        policy: &ExtAuthzPolicy,
        base_parts: &Parts,
        client_ip: IpAddr,
        trusted_inbound: bool,
        downstream_proto: &'static str,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
    ) -> Result<Response<BoxBody>, ForwardError> {
        let target = ext_authz_target(policy)?;
        validate_upstream_target(snap, target.upstream.as_ref(), false)?;
        let reservation = self.resolve_upstream_base_excluding(
            snap,
            target.upstream.as_ref(),
            &[],
            &proxy.limits,
        )?;
        let uri = upstream_uri(&reservation.base, target.path.as_ref(), "")?;
        let mut parts = build_ext_authz_parts(
            policy,
            base_parts,
            uri,
            reservation.protocol,
            route,
            client_ip,
            trusted_inbound,
            downstream_proto,
            request_id,
        )?;
        let client_trace = trace.begin_client(&mut parts.headers, reservation.base.as_ref(), 1);
        parts.extensions.clear();
        let request = Request::from_parts(parts, empty_body());
        let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
        let h2_request = request.version() == http::Version::HTTP_2;
        let client = if use_h2c {
            None
        } else {
            Some(self.http_client_for(&reservation, h2_request, None))
        };
        let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
        let fut = async {
            if use_h2c {
                h2c_client
                    .expect("h2c ext_authz client prepared")
                    .request(request)
                    .await
            } else {
                client
                    .expect("non-h2c ext_authz client prepared")
                    .request(request)
                    .await
            }
        };
        let timeout_ms = if policy.timeout_ms == 0 {
            proxy.timeouts.upstream_ttfb_timeout_ms
        } else {
            policy.timeout_ms
        };
        let result = if timeout_ms == 0 {
            fut.await
        } else {
            match tokio::time::timeout(Duration::from_millis(timeout_ms), fut).await {
                Ok(result) => result,
                Err(_) => {
                    client_trace.finish_error("ext_authz response-head timeout");
                    return Err(ForwardError::Timeout);
                }
            }
        }
        .map_err(|error| map_client_error("ext_authz request", error));
        let resp = match result {
            Ok(resp) => {
                client_trace.finish_status(resp.status().as_u16());
                resp
            }
            Err(mapped) => {
                if matches!(mapped, ForwardError::Overloaded) {
                    self.metrics.inc_upstream_overloaded();
                }
                client_trace.finish_error(mapped.message());
                return Err(mapped);
            }
        };
        Ok(resp.map(|b| reservation.wrap_body(b, 0, None)))
    }

    /// 发送一次 OPA Data API JSON 子请求并等待 response head。
    ///
    /// 请求 head 从空白 `Request` 构造，不复制下游 Authorization/Cookie/身份头；OPA 服务
    /// credential 只来自构建期 SecretSource。业务 body 也不进入此函数，payload 是 OPA input
    /// serializer 生成的唯一一份有界 [`Bytes`]。
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn send_opa_request(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        policy: &OpaPolicy,
        payload: OpaInputPayload,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
    ) -> Result<Response<BoxBody>, ForwardError> {
        validate_upstream_target(snap, policy.upstream.as_str(), false)?;
        let reservation = self.resolve_upstream_base_excluding(
            snap,
            policy.upstream.as_str(),
            &[],
            &proxy.limits,
        )?;
        let uri = upstream_uri(&reservation.base, policy.path.as_str(), "")?;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .body(())
            .map_err(|error| {
                ForwardError::BadGateway(anyhow::anyhow!("build OPA request: {error}"))
            })?;
        let (mut parts, _) = request.into_parts();
        if let Some(authority) = parts.uri.authority() {
            parts
                .headers
                .insert(HOST, header_value(authority.as_str(), "host")?);
        }
        parts
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        parts
            .headers
            .insert(ACCEPT, HeaderValue::from_static("application/json"));
        if let Some(authorization) = policy.authorization() {
            parts.headers.insert(AUTHORIZATION, authorization.clone());
        }
        parts.headers.insert(
            HeaderName::from_static("x-request-id"),
            header_value(request_id, "x-request-id")?,
        );
        parts.headers.insert(
            HeaderName::from_static("x-gateway-route-id"),
            header_value(route.id.as_str(), "x-gateway-route-id")?,
        );
        parts.version = upstream_request_version(reservation.protocol, &parts);
        let client_trace = trace.begin_client(&mut parts.headers, reservation.base.as_ref(), 1);
        parts.extensions.clear();
        let request = Request::from_parts(parts, full_body(payload.body));
        let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
        let h2_request = request.version() == http::Version::HTTP_2;
        let client = (!use_h2c).then(|| self.http_client_for(&reservation, h2_request, None));
        let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
        let send = async {
            if use_h2c {
                h2c_client
                    .expect("h2c OPA client prepared")
                    .request(request)
                    .await
            } else {
                client
                    .expect("non-h2c OPA client prepared")
                    .request(request)
                    .await
            }
        };
        let response = match tokio::time::timeout(policy.timeout(), send).await {
            Ok(Ok(response)) => {
                client_trace.finish_status(response.status().as_u16());
                response
            }
            Ok(Err(error)) => {
                let mapped = map_client_error("OPA request", error);
                if matches!(mapped, ForwardError::Overloaded) {
                    self.metrics.inc_upstream_overloaded();
                }
                client_trace.finish_error(mapped.message());
                return Err(mapped);
            }
            Err(_) => {
                client_trace.finish_error("OPA response-head timeout");
                return Err(ForwardError::Timeout);
            }
        };
        Ok(response.map(|body| reservation.wrap_body(body, 0, None)))
    }

    /// 发送一次 V7 外部头部插件 JSON 调用并等待 response head。
    ///
    /// 请求从空白 head 构造，绝不 clone 下游 Authorization/Cookie 或业务 body；唯一 body 是
    /// 有界 serializer 生成的 `Bytes`。目标解析、LB、主动/被动健康、物理连接和 pending
    /// 预算均复用普通上游设施，避免插件旁路连接治理。
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn send_external_plugin_request(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        plugin: &ExternalPlugin,
        payload: ExternalPluginPayload,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
    ) -> Result<Response<BoxBody>, ForwardError> {
        validate_upstream_target(snap, plugin.upstream(), false)?;
        let reservation =
            self.resolve_upstream_base_excluding(snap, plugin.upstream(), &[], &proxy.limits)?;
        let uri = upstream_uri(&reservation.base, plugin.path(), "")?;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .body(())
            .map_err(|error| {
                ForwardError::BadGateway(anyhow::anyhow!("build external plugin request: {error}"))
            })?;
        let (mut parts, _) = request.into_parts();
        if let Some(authority) = parts.uri.authority() {
            parts
                .headers
                .insert(HOST, header_value(authority.as_str(), "host")?);
        }
        parts
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        parts
            .headers
            .insert(ACCEPT, HeaderValue::from_static("application/json"));
        if let Some(authorization) = plugin.authorization() {
            parts.headers.insert(AUTHORIZATION, authorization.clone());
        }
        parts.headers.insert(
            HeaderName::from_static("x-request-id"),
            header_value(request_id, "x-request-id")?,
        );
        parts.headers.insert(
            HeaderName::from_static("x-gateway-route-id"),
            header_value(route.id.as_str(), "x-gateway-route-id")?,
        );
        parts.version = upstream_request_version(reservation.protocol, &parts);
        let client_trace = trace.begin_client(&mut parts.headers, reservation.base.as_ref(), 1);
        parts.extensions.clear();
        let request = Request::from_parts(parts, full_body(payload.body));
        let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
        let h2_request = request.version() == http::Version::HTTP_2;
        let client = (!use_h2c).then(|| self.http_client_for(&reservation, h2_request, None));
        let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
        let send = async {
            if use_h2c {
                h2c_client
                    .expect("h2c external plugin client prepared")
                    .request(request)
                    .await
            } else {
                client
                    .expect("non-h2c external plugin client prepared")
                    .request(request)
                    .await
            }
        };
        let response = match tokio::time::timeout(plugin.timeout(), send).await {
            Ok(Ok(response)) => {
                client_trace.finish_status(response.status().as_u16());
                response
            }
            Ok(Err(error)) => {
                let mapped = map_client_error("external plugin request", error);
                if matches!(mapped, ForwardError::Overloaded) {
                    self.metrics.inc_upstream_overloaded();
                }
                client_trace.finish_error(mapped.message());
                return Err(mapped);
            }
            Err(_) => {
                client_trace.finish_error("external plugin response-head timeout");
                return Err(ForwardError::Timeout);
            }
        };
        Ok(response.map(|body| reservation.wrap_body(body, 0, None)))
    }

    /// 发送一次已校验的 Dubbo2 generic invocation。
    ///
    /// 上游选择、主动/被动健康、least_conn 与 pending 预算复用普通 HTTP 数据面；真正
    /// transport 由 Dubbo plan 的有界原始 TCP pool 承担。完整响应 frame 在返回 HTTP head
    /// 前已经读完，因此 RAII reservation 可在本函数结束时安全归还。
    pub(super) async fn send_dubbo_request(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        arguments: &[serde_json::Value],
    ) -> Result<Response<BoxBody>, ForwardError> {
        let plan = route
            .dubbo
            .as_ref()
            .expect("Dubbo forward is called only for a Dubbo route");
        let reservation = self.resolve_upstream_base_excluding(
            snap,
            route.upstream.as_str(),
            &[],
            &proxy.limits,
        )?;
        let upstream = reservation.base.clone();
        let health_key = reservation.health_key.clone();
        let passive_policy = route
            .upstream
            .strip_prefix("lb://")
            .and_then(|service| snap.upstreams.passive_health_policy(service))
            .unwrap_or_else(PassiveHealthPolicy::disabled);
        let result = plan.invoke(upstream.clone(), arguments).await;
        let response = match result {
            Ok(DubboResult::Value(body)) => {
                self.metrics.inc_dubbo(DubboMetric::Success);
                self.record_upstream_success(health_key.as_ref());
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(full_body(body))
                    .expect("build Dubbo JSON response")
            }
            Ok(DubboResult::Null) => {
                self.metrics.inc_dubbo(DubboMetric::Success);
                self.record_upstream_success(health_key.as_ref());
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(full_body(Bytes::from_static(b"null")))
                    .expect("build Dubbo null response")
            }
            Err(DubboError::Timeout) => {
                self.metrics.inc_dubbo(DubboMetric::Timeout);
                self.record_upstream_failure(health_key.as_ref(), passive_policy);
                return Err(ForwardError::Timeout);
            }
            Err(DubboError::Remote { status }) => {
                self.metrics.inc_dubbo(DubboMetric::RemoteError);
                self.record_upstream_failure(health_key.as_ref(), passive_policy);
                return Err(ForwardError::BadGateway(anyhow::anyhow!(
                    "Dubbo remote status {status}"
                )));
            }
            Err(DubboError::RemoteException) => {
                self.metrics.inc_dubbo(DubboMetric::RemoteError);
                self.record_upstream_failure(health_key.as_ref(), passive_policy);
                return Err(ForwardError::BadGateway(anyhow::anyhow!(
                    "Dubbo remote exception"
                )));
            }
            Err(DubboError::InvalidInput(message)) => {
                self.metrics.inc_dubbo(DubboMetric::InvalidInput);
                return Err(ForwardError::BadGateway(anyhow::anyhow!(message)));
            }
            Err(DubboError::Protocol(message)) => {
                self.metrics.inc_dubbo(DubboMetric::ProtocolError);
                self.record_upstream_failure(health_key.as_ref(), passive_policy);
                return Err(ForwardError::BadGateway(anyhow::anyhow!(message)));
            }
            Err(DubboError::Connect | DubboError::Transport) => {
                self.metrics.inc_dubbo(DubboMetric::ProtocolError);
                self.record_upstream_failure(health_key.as_ref(), passive_policy);
                return Err(ForwardError::BadGateway(anyhow::anyhow!(
                    "Dubbo transport failed"
                )));
            }
        };
        Ok(annotate_upstream_trace(response, upstream, 1))
    }

    /// 启动 route 配置的 mirror 子请求。
    ///
    /// # 参数
    /// - `ctx`: 当前主请求转发上下文。
    /// - `path`: 已执行 StripPrefix/rewrite 后的 path。
    /// - `query`: 原始 query,包含可选前导 `?`。
    /// - `downstream_version`: 下游请求版本,用于 mirror 请求的版本 hint。
    fn spawn_mirror_requests(
        &self,
        ctx: &ForwardRequest<'_>,
        path: &str,
        query: &str,
        downstream_version: http::Version,
        mirror_body: Option<&Bytes>,
    ) {
        for mirror in &ctx.route.mirrors {
            if !mirror_sampled(ctx.request_id, mirror) {
                self.metrics.inc_mirror_skipped();
                continue;
            }
            let body_bytes = if mirror.body {
                let Some(bytes) = mirror_body else {
                    self.metrics.inc_mirror_skipped();
                    continue;
                };
                if bytes.len() as u64 > mirror.max_body_bytes {
                    self.metrics.inc_mirror_skipped();
                    continue;
                }
                Some(bytes.clone())
            } else {
                None
            };
            let body_len = body_bytes.as_ref().map(Bytes::len);
            match self.prepare_mirror_request(ctx, mirror, path, query, body_len) {
                Ok((parts, reservation, client_trace)) => {
                    self.metrics.inc_mirror_request();
                    let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
                    let h2_request = parts.version == http::Version::HTTP_2;
                    // 只给真正使用的协议池计一次 keepalive request；旧实现同时取两个 client，
                    // 会让未发送请求的 pool generation 也提前轮换。
                    let client =
                        (!use_h2c).then(|| self.http_client_for(&reservation, h2_request, None));
                    let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
                    let metrics = self.metrics.clone();
                    let ttfb_timeout_ms = ctx.proxy.timeouts.upstream_ttfb_timeout_ms;
                    let request_body = body_bytes.map(full_body).unwrap_or_else(empty_body);
                    tokio::spawn(async move {
                        if let Err(err) = send_mirror_request(
                            client,
                            h2c_client,
                            parts,
                            request_body,
                            reservation,
                            MirrorSendContext {
                                ttfb_timeout_ms,
                                downstream_version,
                                client_trace,
                            },
                        )
                        .await
                        {
                            metrics.inc_mirror_error();
                            tracing::debug!(error = %err, "mirror request failed");
                        }
                    });
                }
                Err(err) => {
                    self.metrics.inc_mirror_error();
                    tracing::warn!(route = %ctx.route.id, mirror = %mirror.target, error = %err, "skip mirror request");
                }
            }
        }
    }

    /// 为显式开启 body 的 mirror 准备可复用请求体。
    ///
    /// # 参数
    /// - `ctx`: 当前主请求转发上下文,函数可能把原始 `Incoming` 替换成可复用 `Bytes` body。
    async fn prepare_mirror_body(
        &self,
        ctx: &mut ForwardRequest<'_>,
    ) -> Result<Option<Bytes>, ForwardError> {
        let Some(max_body_bytes) = ctx
            .route
            .mirrors
            .iter()
            .filter(|mirror| mirror.body && mirror_sampled(ctx.request_id, mirror))
            .map(|mirror| mirror.max_body_bytes)
            .max()
        else {
            return Ok(None);
        };
        let Some(content_length) = request_content_length(&ctx.parts) else {
            return Ok(None);
        };
        if content_length > max_body_bytes {
            return Ok(None);
        }
        let body = std::mem::replace(&mut ctx.body, ForwardBody::Boxed(empty_body()));
        let bytes = collect_forward_body(body, max_body_bytes).await?;
        ctx.body = ForwardBody::Boxed(full_body(bytes.clone()));
        Ok(Some(bytes))
    }

    /// 构造单个 mirror 子请求。
    ///
    /// # 参数
    /// - `ctx`: 当前主请求转发上下文。
    /// - `mirror`: route 上的 mirror 规则。
    /// - `path`: 已执行 StripPrefix/rewrite 后的 path。
    /// - `query`: 原始 query,包含可选前导 `?`。
    /// - `body_len`: mirror 子请求 body 字节数;`None` 表示不复制请求体。
    fn prepare_mirror_request(
        &self,
        ctx: &ForwardRequest<'_>,
        mirror: &MirrorPolicy,
        path: &str,
        query: &str,
        body_len: Option<usize>,
    ) -> Result<
        (
            Parts,
            UpstreamReservation,
            Option<crate::telemetry::ClientTrace>,
        ),
        ForwardError,
    > {
        validate_upstream_target(ctx.snap, mirror.target.as_str(), false)?;
        let reservation = self.resolve_upstream_base_excluding(
            ctx.snap,
            mirror.target.as_str(),
            &[],
            &ctx.proxy.limits,
        )?;
        let uri = upstream_uri(&reservation.base, path, query)?;
        let mut parts = prepare_attempt_parts(
            &ctx.parts,
            uri,
            ctx.route,
            reservation.protocol,
            ctx.client_ip,
            ctx.client_ip_header.as_ref(),
            ctx.trusted_inbound,
            ctx.client_cert_verified,
            ctx.downstream_proto,
            ctx.request_id,
            false,
        )?;
        if let Some(body_len) = body_len {
            // WHY:body mirror 是显式慢路径;镜像子请求使用已收集的 Bytes,不能继续带原始 TE/Expect。
            parts.headers.remove(TRANSFER_ENCODING);
            parts.headers.remove(EXPECT);
            let value = HeaderValue::from_str(&body_len.to_string()).map_err(|e| {
                ForwardError::BadGateway(anyhow::anyhow!("mirror content-length: {e}"))
            })?;
            parts.headers.insert(CONTENT_LENGTH, value);
        } else {
            // WHY:默认 mirror 不复制 streaming body,避免为了影子流量阻塞或缓冲主请求。
            strip_request_body_headers(&mut parts);
        }
        let client_trace = ctx
            .trace
            .map(|trace| trace.begin_client(&mut parts.headers, reservation.base.as_ref(), 1));
        Ok((parts, reservation, client_trace))
    }

    /// 完成 WebSocket 上游握手，并在 101 后启动透明双向字节隧道。
    ///
    /// 数据帧不解码、不重组；`ActivityIo` 只在成功搬运字节时更新一个原子时间戳，因此 idle/max-lifetime
    /// 治理不会破坏 `copy_bidirectional` 的背压与少拷贝路径。注册表关闭会在取消 copy future 后串行写
    /// Close 控制帧，避免控制帧和数据帧交错。
    ///
    /// # 参数
    /// - `parts`: 已完成 hop-by-hop/Host/转发头处理的上游握手 head。
    /// - `body`: 下游原始 `Incoming`；握手期保持流式，不预收集。
    /// - `downstream_upgrade`: 下游 101 升级 future。
    /// - `downstream_connection_lease`: 101 后随 tunnel 持有的 listener 物理连接预算。
    /// - `route_id`: 登记长连接和日志使用的稳定路由 id。
    /// - `client_ip`: 经 PROXY protocol/可信代理链计算的真实客户端 IP。
    /// - `consumer`: Basic/API-Key/JWT 提取的稳定主体；未识别时为空。
    /// - `snapshot_version`: 建连时快照版本，供 stale drain。
    /// - `reservation`: 已占用上游 in-flight/pending 的实例预留。
    /// - `limit_conn_guards`: 隧道全生命周期持有的并发限额守卫。
    /// - `idle_timeout_ms`: 任一方向最后字节活动的空闲上限；0 表示关闭。
    /// - `max_lifetime_ms`: 升级后隧道最长寿命；0 表示关闭。
    ///
    /// 返回：握手响应；上游握手失败映射为 `ForwardError::BadGateway`。101 后隧道错误只记日志，
    /// 因为 HTTP 响应头已经发出，不能再改成普通错误响应。
    #[allow(clippy::too_many_arguments)]
    async fn forward_websocket(
        &self,
        parts: Parts,
        body: Incoming,
        downstream_upgrade: OnUpgrade,
        downstream_connection_lease: Option<super::DownstreamConnectionLease>,
        route_id: &str,
        client_ip: IpAddr,
        consumer: Option<Arc<str>>,
        snapshot_version: u64,
        reservation: UpstreamReservation,
        limit_conn_guards: Vec<super::LimitConnGuard>,
        idle_timeout_ms: u64,
        max_lifetime_ms: u64,
        client_trace: Option<crate::telemetry::ClientTrace>,
    ) -> Result<Response<BoxBody>, ForwardError> {
        self.metrics.inc_upstream_attempt();
        let final_upstream = reservation.base.clone();
        let body = body.map_err(|e| Box::new(e) as BoxError).boxed();
        let ureq = Request::from_parts(parts, body);
        // WebSocket upgrade 固定使用 HTTP/1.1，不得因 route protocol=auto 扩大成 h2 shard 池。
        let client = self.http_client_for(&reservation, false, None);
        let mut resp = match client.request(ureq).await {
            Ok(resp) => {
                if let Some(trace) = client_trace {
                    trace.finish_status(resp.status().as_u16());
                }
                resp
            }
            Err(error) => {
                let mapped = map_client_error("ws handshake", error);
                if matches!(mapped, ForwardError::Overloaded) {
                    self.metrics.inc_upstream_overloaded();
                }
                if let Some(trace) = client_trace {
                    trace.finish_error(mapped.message());
                }
                return Err(mapped);
            }
        };
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let upstream_upgrade = hyper::upgrade::on(&mut resp);
            // WebSocket task 与注册表共享一份 route id；长连接生命周期内日志和关闭匹配都只
            // clone Arc，不能先造 String、register 时再复制第二份相同字节。
            let route_id: Arc<str> = Arc::from(route_id);
            let registry = self.conn_registry.clone();
            let activity_clock = self.ws_activity_clock.clone();
            tokio::spawn(async move {
                // 101 后 Hyper connection future 已结束；lease 必须由 tunnel task 持有到双向 copy/
                // close 完成，才能让 listener max_connections 与 gw_active_connections 反映真实 socket。
                let _downstream_connection_lease = downstream_connection_lease;
                let _limit_conn_guards = limit_conn_guards;
                let downstream = match downstream_upgrade.await {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!(route = %route_id, error = %e, "ws downstream upgrade failed");
                        return;
                    }
                };
                let upstream = match upstream_upgrade.await {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::debug!(route = %route_id, error = %e, "ws upstream upgrade failed");
                        return;
                    }
                };
                let activity = WsActivity::new(activity_clock);
                let mut downstream = ActivityIo::new(TokioIo::new(downstream), activity.clone());
                let mut upstream = ActivityIo::new(TokioIo::new(upstream), activity.clone());
                // 登记长连接(§6.1 / L2):guard Drop 自动注销;close 收到信号即发标准 Close 帧收尾。
                let guard = registry.register(
                    route_id.clone(),
                    client_ip,
                    consumer,
                    snapshot_version,
                    crate::conn_registry::LongProto::Ws,
                );
                let close = guard.closed();
                tokio::pin!(close);
                tokio::select! {
                    r = io::copy_bidirectional(&mut downstream, &mut upstream) => {
                        if let Err(e) = r { tracing::debug!(route = %route_id, error = %e, "websocket tunnel closed"); }
                    }
                    // select 先取消 copy future，再写控制帧；同一 write half 不会发生帧交错。
                    _ = &mut close => {
                        close_websocket(&mut downstream, &mut upstream, guard.ws_close_code()).await;
                        tracing::debug!(route = %route_id, "websocket tunnel closed by registry");
                    }
                    _ = wait_for_ws_inactivity(activity, idle_timeout_ms), if idle_timeout_ms > 0 => {
                        close_websocket(&mut downstream, &mut upstream, 1001).await;
                        tracing::debug!(route = %route_id, idle_timeout_ms, "websocket tunnel idle timeout");
                    }
                    _ = tokio::time::sleep(Duration::from_millis(max_lifetime_ms)), if max_lifetime_ms > 0 => {
                        close_websocket(&mut downstream, &mut upstream, 1001).await;
                        tracing::debug!(route = %route_id, max_lifetime_ms, "websocket tunnel max lifetime reached");
                    }
                }
                drop(guard);
            });
            return Ok(annotate_upstream_trace(
                resp.map(|b| reservation.wrap_body(b, 0, None)),
                final_upstream,
                1,
            ));
        }
        let resp = annotate_upstream_trace(
            resp.map(|b| reservation.wrap_body(b, 0, None)),
            final_upstream,
            1,
        );
        Ok(super::wrap_limit_conn_response(resp, limit_conn_guards))
    }
}

/// 一条 WS 隧道共享的最近活动状态。
///
/// 两个转发方向只 clone 这个小对象的 `Arc`。全局 clock 的值由单一后台 worker 每 10ms 更新；
/// 同一 tick 内无论搬运多少帧，连接时间戳最多写一次，避免双向高吞吐在一个 cache line 上反复
/// 写入。数据 buffer 不进入本对象，也不会发生帧复制。
struct WsActivity {
    /// 进程级粗粒度单调毫秒值。
    clock_ms: Arc<AtomicU64>,
    /// 本连接最近一次活动对应的 clock tick。
    last_activity_ms: AtomicU64,
}

impl WsActivity {
    /// 创建连接状态；初值取当前 tick，使无数据的新隧道从升级完成时开始计算 idle。
    fn new(clock_ms: Arc<AtomicU64>) -> Arc<Self> {
        let initial = clock_ms.load(Ordering::Relaxed);
        Arc::new(Self {
            clock_ms,
            last_activity_ms: AtomicU64::new(initial),
        })
    }

    /// 记录当前 tick。先 load 再按需 store；一次 echo 的多次 read/write 通常落在同一个 tick，
    /// 因而只有第一次进展写连接 cache line。Relaxed 足够：idle 只依赖最终数值，不发布其它状态。
    fn record(&self) {
        let now_ms = self.clock_ms.load(Ordering::Relaxed);
        if self.last_activity_ms.load(Ordering::Relaxed) != now_ms {
            self.last_activity_ms.store(now_ms, Ordering::Relaxed);
        }
    }
}

/// 为透明字节流记录最近一次成功读/写活动的 IO 装饰器。
///
/// wrapper 不创建中间缓冲，也不改变 `ReadBuf`/write slice；有正字节进展时只通知共享的
/// [`WsActivity`]，供 WS idle 监控读取。
struct ActivityIo<T> {
    /// 实际下游或上游字节流。
    inner: T,
    /// 两个方向共享的连接活动状态。
    activity: Arc<WsActivity>,
}

impl<T> ActivityIo<T> {
    /// 包装一个 IO，并接入指定隧道的共享活动时间戳。
    ///
    /// # 参数
    /// - `inner`: 原始异步 IO；数据仍直接读写它。
    /// - `activity`: 两个方向共享的粗粒度活动时间。
    ///
    /// 返回：不分配数据缓冲的透明 IO wrapper。
    fn new(inner: T, activity: Arc<WsActivity>) -> Self {
        Self { inner, activity }
    }

    /// 记录本次确有字节进展的单调毫秒值。
    fn record_activity(&self) {
        self.activity.record();
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityIo<T> {
    /// 原样委托读操作；仅在 `ReadBuf` 实际增长时更新活动时间。
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.record_activity();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityIo<T> {
    /// 原样委托写操作；正字节完成时更新共享活动时间。
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(&result, Poll::Ready(Ok(written)) if *written > 0) {
            this.record_activity();
        }
        result
    }

    /// flush 不代表新增字节活动，故仅透明委托。
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    /// shutdown 不计入业务活动，避免关闭过程反向延长 idle 生命周期。
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    /// 保留底层 vectored-write 能力，避免 wrapper 让批量写退化。
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    /// vectored write 原样委托，并按实际写入字节数更新时间。
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if matches!(&result, Poll::Ready(Ok(written)) if *written > 0) {
            this.record_activity();
        }
        result
    }
}

/// 等待 WS 隧道达到“任一方向都没有字节活动”的 idle 上限。
///
/// # 参数
/// - `activity`: 与 `ActivityIo` 共享的粗粒度单调时钟和最近活动值。
/// - `idle_timeout_ms`: 空闲上限；0 时永久等待，调用者通常会禁用对应 select 分支。
async fn wait_for_ws_inactivity(activity: Arc<WsActivity>, idle_timeout_ms: u64) {
    if idle_timeout_ms == 0 {
        std::future::pending::<()>().await;
        return;
    }
    loop {
        let now_ms = activity.clock_ms.load(Ordering::Relaxed);
        let last_ms = activity.last_activity_ms.load(Ordering::Relaxed);
        let inactive_ms = now_ms.saturating_sub(last_ms);
        if inactive_ms >= idle_timeout_ms {
            return;
        }
        tokio::time::sleep(Duration::from_millis(idle_timeout_ms - inactive_ms)).await;
    }
}

/// 按 WebSocket 两端角色分别发送合规 Close 帧并半关闭写方向。
///
/// # 参数
/// - `downstream`: 网关作为 server 的客户端连接，Close 帧不得 mask。
/// - `upstream`: 网关作为 client 的上游连接，Close 帧必须使用新随机 mask。
/// - `code`: 1001（drain/idle/lifetime）或 1008（策略封禁）。
///
/// 系统随机源失败时不发送不合规的上游帧，直接依靠随后 Drop 终止上游；下游仍收到标准状态码。
async fn close_websocket<D, U>(downstream: &mut D, upstream: &mut U, code: u16)
where
    D: AsyncWrite + Unpin,
    U: AsyncWrite + Unpin,
{
    let _ = downstream
        .write_all(&crate::conn_registry::ws_close_frame(code))
        .await;
    let mut mask = [0_u8; 4];
    if getrandom::getrandom(&mut mask).is_ok() {
        let _ = upstream
            .write_all(&crate::conn_registry::ws_masked_close_frame(code, mask))
            .await;
    }
    let _ = downstream.shutdown().await;
    let _ = upstream.shutdown().await;
}

/// 判断 mirror 是否命中采样。
///
/// # 参数
/// - `request_id`: 当前请求 ID。
/// - `mirror`: mirror 策略。
fn mirror_sampled(request_id: &str, mirror: &MirrorPolicy) -> bool {
    if mirror.sample >= 1.0 {
        return true;
    }
    if mirror.sample <= 0.0 {
        return false;
    }
    let key = format!("{request_id}:{}", mirror.target);
    let bucket = super::stable_hash64(key.as_bytes()) % 1_000_000;
    bucket < (mirror.sample * 1_000_000.0).round() as u64
}

/// 发送后台 mirror 请求。
///
/// # 参数
/// - `client`: 普通 h1/h2 上游连接池。
/// - `h2c_client`: h2c prior-knowledge 上游连接池。
/// - `parts`: 已构造好的 mirror 请求 head。
/// - `reservation`: 镜像上游实例预留计数。
/// - `upstream_ttfb_timeout_ms`: mirror 响应头超时,0 表示关闭。
/// - `downstream_version`: 下游请求版本,用于保持请求版本 hint 一致。
async fn send_mirror_request(
    client: Option<super::UpstreamHttpClient>,
    h2c_client: Option<super::UpstreamH2cClient>,
    parts: Parts,
    body: BoxBody,
    reservation: UpstreamReservation,
    ctx: MirrorSendContext,
) -> Result<(), ForwardError> {
    let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
    let request = Request::from_parts(parts, body);
    let fut = async {
        if use_h2c {
            h2c_client
                .expect("h2c mirror client prepared")
                .request(request)
                .await
        } else {
            client
                .expect("http mirror client prepared")
                .request(request)
                .await
        }
    };
    let result = if ctx.ttfb_timeout_ms == 0 {
        fut.await
    } else {
        match tokio::time::timeout(Duration::from_millis(ctx.ttfb_timeout_ms), fut).await {
            Ok(result) => result,
            Err(_) => {
                if let Some(trace) = ctx.client_trace {
                    trace.finish_error("mirror response-head timeout");
                }
                return Err(ForwardError::Timeout);
            }
        }
    }
    .map_err(|error| map_client_error("mirror request", error));
    let response = match result {
        Ok(response) => {
            if let Some(trace) = ctx.client_trace {
                trace.finish_status(response.status().as_u16());
            }
            response
        }
        Err(error) => {
            if let Some(trace) = ctx.client_trace {
                trace.finish_error(error.message());
            }
            return Err(error);
        }
    };
    let mut response = response;
    *response.version_mut() = ctx.downstream_version;
    drop(response.map(|body| reservation.wrap_body(body, 0, None)));
    Ok(())
}

struct ExtAuthzTarget<'a> {
    upstream: Cow<'a, str>,
    path: Cow<'a, str>,
}

/// 把 ext_authz 目标拆成上游 base 与鉴权 path。
///
/// # 参数
/// - `policy`: 已编译 ext_authz 策略。
fn ext_authz_target(policy: &ExtAuthzPolicy) -> Result<ExtAuthzTarget<'_>, ForwardError> {
    if policy.target.starts_with("lb://") {
        return Ok(ExtAuthzTarget {
            upstream: Cow::Borrowed(policy.target.as_str()),
            path: policy
                .path
                .as_deref()
                .map(Cow::Borrowed)
                .unwrap_or_else(|| Cow::Borrowed("/")),
        });
    }
    let uri = policy
        .target
        .parse::<http::Uri>()
        .map_err(|e| ForwardError::BadGateway(anyhow::anyhow!("bad ext_authz uri: {e}")))?;
    let scheme = uri.scheme_str().unwrap_or_default();
    let Some(authority) = uri.authority() else {
        return Err(ForwardError::BadGateway(anyhow::anyhow!(
            "ext_authz uri requires authority"
        )));
    };
    let upstream = format!("{scheme}://{authority}");
    let path = policy
        .path
        .as_deref()
        .map(Cow::Borrowed)
        .unwrap_or_else(|| {
            uri.path_and_query()
                .map(|value| Cow::Owned(value.as_str().to_string()))
                .unwrap_or_else(|| Cow::Borrowed("/"))
        });
    Ok(ExtAuthzTarget {
        upstream: Cow::Owned(upstream),
        path,
    })
}

/// 构造 ext_authz 鉴权子请求 head。
///
/// # 参数
/// - `policy`: 已编译 ext_authz 策略。
/// - `base_parts`: 原始下游请求 head。
/// - `uri`: 鉴权服务完整 URI。
/// - `protocol`: 鉴权服务上游协议偏好。
/// - `route`: 当前 route。
/// - `client_ip`: 真实客户端 IP。
/// - `trusted_inbound`: 入站连接是否可信。
/// - `downstream_proto`: 下游协议 scheme。
/// - `request_id`: 当前请求 ID。
#[allow(clippy::too_many_arguments)]
fn build_ext_authz_parts(
    policy: &ExtAuthzPolicy,
    base_parts: &Parts,
    uri: http::Uri,
    protocol: UpstreamProtocol,
    route: &Route,
    client_ip: IpAddr,
    trusted_inbound: bool,
    downstream_proto: &'static str,
    request_id: &str,
) -> Result<Parts, ForwardError> {
    let request = Request::builder()
        .method(policy.method.clone())
        .uri(uri)
        .body(())
        .map_err(|e| ForwardError::BadGateway(anyhow::anyhow!("build ext_authz request: {e}")))?;
    let (mut parts, _) = request.into_parts();
    for name in &policy.request_headers {
        for value in base_parts.headers.get_all(name).iter() {
            parts.headers.append(name.clone(), value.clone());
        }
    }
    if let Some(auth) = parts.uri.authority() {
        parts
            .headers
            .insert(HOST, header_value(auth.as_str(), "host")?);
    }
    parts.headers.insert(
        HeaderName::from_static("x-original-method"),
        header_value(base_parts.method.as_str(), "x-original-method")?,
    );
    parts.headers.insert(
        HeaderName::from_static("x-original-uri"),
        header_value(&base_parts.uri.to_string(), "x-original-uri")?,
    );
    if let Some(host) = base_parts.headers.get(HOST).cloned() {
        parts
            .headers
            .insert(HeaderName::from_static("x-original-host"), host);
    }
    parts.headers.insert(
        HeaderName::from_static("x-gateway-route-id"),
        header_value(route.id.as_str(), "x-gateway-route-id")?,
    );
    inject_forward_headers(
        &mut parts,
        client_ip,
        None,
        trusted_inbound,
        downstream_proto,
        request_id,
    )?;
    strip_request_body_headers(&mut parts);
    sanitize_hop_headers(&mut parts, false);
    parts.version = upstream_request_version(protocol, &parts);
    Ok(parts)
}

/// 把鉴权响应中 allowlist header 注入主上游请求。
///
/// # 参数
/// - `parts`: 主请求 head。
/// - `policy`: 当前 ext_authz 策略。
/// - `resp`: 鉴权服务响应。
fn copy_ext_authz_upstream_headers(
    parts: &mut Parts,
    policy: &ExtAuthzPolicy,
    resp: &Response<BoxBody>,
) {
    for name in &policy.upstream_headers {
        if let Some(value) = resp.headers().get(name).cloned() {
            parts.headers.insert(name.clone(), value);
        }
    }
}

/// 应用 route 级 path 前缀改写。
///
/// # 参数
/// - `path`: 已经执行 `StripPrefix` 后的 path。
/// - `route`: 当前命中的 route。
fn rewrite_prefix(path: &str, route: &Route) -> String {
    let Some(rewrite) = &route.rewrite_prefix else {
        return path.to_string();
    };
    let Some(rest) = path.strip_prefix(&rewrite.from) else {
        return path.to_string();
    };
    let mut out = String::with_capacity(rewrite.to.len() + rest.len() + 1);
    if rewrite.to.starts_with('/') {
        out.push_str(&rewrite.to);
    } else {
        out.push('/');
        out.push_str(&rewrite.to);
    }
    if !out.ends_with('/') && !rest.starts_with('/') && !rest.is_empty() {
        out.push('/');
    }
    out.push_str(rest);
    out
}

/// 组装最终发往上游的 URI。
///
/// # 参数
/// - `base`: 上游实例或直连 upstream base URI。
/// - `path`: 转发后的 path。
/// - `query`: 原始 query,包含可选前导 `?`。
fn upstream_uri(base: &str, path: &str, query: &str) -> Result<http::Uri, ForwardError> {
    format!("{base}{path}{query}")
        .parse()
        .map_err(|e| ForwardError::BadGateway(anyhow::anyhow!("bad upstream uri: {e}")))
}

/// 为单次上游尝试构造请求 head。
///
/// # 参数
/// - `base_parts`: 原始下游请求 head,作为变量求值上下文。
/// - `uri`: 本次尝试的完整上游 URI。
/// - `route`: 当前命中 route。
/// - `protocol`: 上游协议配置。
/// - `client_ip`: 真实客户端 IP。
/// - `client_ip_header`: 与真实 IP 核对过的连接级预编码 HeaderValue。
/// - `trusted_inbound`: 入站连接是否可信。
/// - `client_cert_verified`: TLS 握手阶段客户端证书是否校验通过(mTLS),决定是否向上游盖章 `X-Client-Cert-Verified: SUCCESS`。
/// - `downstream_proto`: 下游协议 scheme。
/// - `request_id`: 网关生成的 request id。
/// - `is_ws`: 是否 WebSocket upgrade 请求。
#[allow(clippy::too_many_arguments)]
fn prepare_attempt_parts(
    base_parts: &Parts,
    uri: http::Uri,
    route: &Route,
    protocol: UpstreamProtocol,
    client_ip: IpAddr,
    client_ip_header: Option<&HeaderValue>,
    trusted_inbound: bool,
    client_cert_verified: bool,
    downstream_proto: &'static str,
    request_id: &str,
    is_ws: bool,
) -> Result<Parts, ForwardError> {
    let eval_ctx = crate::variable::EvalContext {
        parts: base_parts,
        client_ip,
        downstream_proto,
        request_id,
        route_id: route.id.as_str(),
    };
    let request_headers =
        render_request_headers(&route.request_headers, route.variables.as_ref(), &eval_ctx)?;
    prepare_attempt_parts_rendered(
        base_parts.clone(),
        uri,
        route,
        protocol,
        client_ip,
        client_ip_header,
        trusted_inbound,
        client_cert_verified,
        downstream_proto,
        request_id,
        is_ws,
        request_headers,
    )
}

/// 为单次、不可重试的上游请求原地改写 downstream head。
///
/// 变量必须在 Host/XFF 等代理头覆盖前按原始请求求值，因此先借用 `parts` 渲染少量显式
/// `proxy_set_header`，借用结束后才移动并修改它。默认没有此类规则时空 Vec 不分配；Method、
/// Uri、Extensions 和 HeaderMap 全部沿用原 allocation，不复制 body 或 header table。
#[allow(clippy::too_many_arguments)]
fn prepare_attempt_parts_owned(
    parts: Parts,
    uri: http::Uri,
    route: &Route,
    protocol: UpstreamProtocol,
    client_ip: IpAddr,
    client_ip_header: Option<&HeaderValue>,
    trusted_inbound: bool,
    client_cert_verified: bool,
    downstream_proto: &'static str,
    request_id: &str,
    is_ws: bool,
) -> Result<Parts, ForwardError> {
    let request_headers = {
        let eval_ctx = crate::variable::EvalContext {
            parts: &parts,
            client_ip,
            downstream_proto,
            request_id,
            route_id: route.id.as_str(),
        };
        render_request_headers(&route.request_headers, route.variables.as_ref(), &eval_ctx)?
    };
    prepare_attempt_parts_rendered(
        parts,
        uri,
        route,
        protocol,
        client_ip,
        client_ip_header,
        trusted_inbound,
        client_cert_verified,
        downstream_proto,
        request_id,
        is_ws,
        request_headers,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_attempt_parts_rendered(
    mut parts: Parts,
    uri: http::Uri,
    route: &Route,
    protocol: UpstreamProtocol,
    client_ip: IpAddr,
    client_ip_header: Option<&HeaderValue>,
    trusted_inbound: bool,
    client_cert_verified: bool,
    downstream_proto: &'static str,
    request_id: &str,
    is_ws: bool,
    request_headers: Vec<(HeaderName, HeaderValue)>,
) -> Result<Parts, ForwardError> {
    // Host 头改成本次尝试的上游 authority(否则重试换实例后仍会带旧 Host)。
    if let Some(auth) = uri.authority() {
        parts
            .headers
            .insert(HOST, header_value(auth.as_str(), "host")?);
    }
    inject_forward_headers(
        &mut parts,
        client_ip,
        client_ip_header,
        trusted_inbound,
        downstream_proto,
        request_id,
    )?;
    // mTLS 证书校验结果透传(§19 双向认证):把 TLS 握手阶段的客户端证书校验结论
    // 以 `X-Client-Cert-Verified` 头告知上游,便于上游做“证书即身份”的鉴权决策。
    // WHY:先无条件删除下游可能伪造的同名头,再仅在本网关握手确认证书有效时写入 SUCCESS,
    //      否则不写。这样上游看到该头就必然是网关盖章的可信结论,杜绝客户端自带头绕过 mTLS。
    parts.headers.remove(X_CLIENT_CERT_VERIFIED);
    if client_cert_verified {
        parts
            .headers
            .insert(X_CLIENT_CERT_VERIFIED, HeaderValue::from_static("SUCCESS"));
    }
    for (name, value) in request_headers {
        parts.headers.insert(name, value);
    }
    if !route.pass_request_body {
        strip_request_body_headers(&mut parts);
    }
    // 先固定最终上游协议，再决定由哪一层清洗 hop-by-hop 头。Hyper 的 HTTP/2 client 在
    // 编码 HEADERS frame 前必定按 RFC 9113 再清一次 Connection/TE/Upgrade 等字段；这里若
    // 仍走 H1 的完整清洗，会让每条 gRPC stream 对同一 HeaderMap 重复做约十次哈希查表。
    // HTTP/1.1（含 WS）没有这层协议兜底，仍严格执行 Nate 的完整 Connection-token 清洗。
    let upstream_version = if is_ws {
        http::Version::HTTP_11
    } else {
        upstream_request_version(protocol, &parts)
    };
    sanitize_hop_headers_for_upstream(&mut parts, is_ws, upstream_version);
    parts.uri = uri;
    // ★上游请求版本按【上游 protocol 配置】设(review L1):auto 时 gRPC 走 h2、普通 http 走 h1;
    //   WS 是 h1 upgrade 固定 1.1。避免把下游版本误传给 h1 上游。
    parts.version = upstream_version;
    Ok(parts)
}

/// 删除请求体相关头,避免 `proxy_pass_request_body off` 时上游继续等待 body。
///
/// # 参数
/// - `parts`: 将要发送给上游的请求 head。
fn strip_request_body_headers(parts: &mut Parts) {
    // WHY:空 body 不能携带原始 Content-Length/Transfer-Encoding,否则 h1 上游可能按旧长度阻塞等待读取。
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.remove(EXPECT);
}

/// 按 route 配置构造发往上游的请求体。
///
/// # 参数
/// - `body`: 下游请求体。
/// - `pass_request_body`: 是否透传下游请求体。
/// - `max_body_bytes`: 流式请求体上限,0 表示不限制。
/// - `stream_idle_timeout_ms`: 请求体帧间空闲超时,0 表示关闭。
fn upstream_request_body(
    body: ForwardBody,
    pass_request_body: bool,
    max_body_bytes: u64,
    stream_idle_timeout_ms: u64,
) -> BoxBody {
    if !pass_request_body {
        // WHY:proxy_pass_request_body=off 的目标是“不读、不缓冲、不转发”请求体;丢弃 Incoming 即可让上游看到空 body。
        return empty_body();
    }
    // 流式转发:下游 body(Incoming)直接作上游请求 body,不全量 buffer(背压天然)。
    // ★body 上限对【流式 / chunked】也生效(据 review M2):有 Content-Length 的已在入口 413 预拦;
    //   无 Content-Length 的 chunked 上传靠 Limited 在超过 max_body_bytes 时中止,防无界上传打爆带宽/上游。
    idle_timeout_body(
        limited_forward_body(body, max_body_bytes),
        stream_idle_timeout_ms,
    )
}

/// 为透传请求体包上可选大小限制。
///
/// # 参数
/// - `body`: 下游请求体,可能是原始 `Incoming` 或显式慢路径复用 body。
/// - `max_body_bytes`: 最大允许字节数,0 表示不限制。
fn limited_forward_body(body: ForwardBody, max_body_bytes: u64) -> BoxBody {
    match body {
        ForwardBody::Incoming(body) => {
            if max_body_bytes > 0 {
                Limited::new(body, max_body_bytes as usize).boxed()
            } else {
                body.map_err(|e| Box::new(e) as BoxError).boxed()
            }
        }
        ForwardBody::Boxed(body) => {
            // Schema/GraphQL/degraphql 等显式慢路径会把已验证的 Bytes 重新包装成 BoxBody。
            // 它们仍必须服从 proxy 级总 body 上限；尤其 chunked 请求没有入口
            // Content-Length 预检，不能因一次有界重包装就绕过更小的全局限制。
            if max_body_bytes > 0 {
                LimitedBoxBody::new(body, max_body_bytes as usize).boxed()
            } else {
                body
            }
        }
    }
}

/// 收集显式 body mirror 的小请求体。
///
/// # 参数
/// - `body`: 待收集的当前请求体。
/// - `max_body_bytes`: mirror body 上限,超过会返回错误并中止本次请求。
async fn collect_forward_body(
    body: ForwardBody,
    max_body_bytes: u64,
) -> Result<Bytes, ForwardError> {
    let collected = match body {
        ForwardBody::Incoming(body) => Limited::new(body, max_body_bytes as usize)
            .collect()
            .await
            .map_err(|e| ForwardError::BadGateway(anyhow::anyhow!("mirror body collect: {e}")))?,
        ForwardBody::Boxed(body) => LimitedBoxBody::new(body, max_body_bytes as usize)
            .collect()
            .await
            .map_err(|e| ForwardError::BadGateway(anyhow::anyhow!("mirror body collect: {e}")))?,
    };
    Ok(collected.to_bytes())
}

/// 已擦除请求体的零拷贝字节限界层。
///
/// `http_body_util::Limited<BoxBody>` 会要求 `BoxError: Into<BoxError>` 满足高阶生命周期；该约束
/// 在后台 `tokio::spawn` 的 `'static` 检查中无法成立。这里直接保留 `BoxBody` 的拥有型错误，
/// 逐帧只读取 `Bytes::len()` 并原样返回 frame，不 collect、不复制 payload。超过上限后产生一次
/// 拥有型错误并终止，避免错误后的内层 body 继续被意外轮询。
struct LimitedBoxBody {
    inner: BoxBody,
    remaining: usize,
    done: bool,
}

impl LimitedBoxBody {
    fn new(inner: BoxBody, limit: usize) -> Self {
        Self {
            inner,
            remaining: limit,
            done: false,
        }
    }
}

impl Body for LimitedBoxBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if data.len() > self.remaining {
                        self.done = true;
                        return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                            "request body length limit exceeded",
                        )))));
                    }
                    self.remaining -= data.len();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.done = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.done {
            return SizeHint::with_exact(0);
        }
        let mut hint = self.inner.size_hint();
        let remaining = self.remaining as u64;
        if hint.lower() >= remaining {
            hint.set_exact(remaining);
        } else if let Some(upper) = hint.upper() {
            hint.set_upper(upper.min(remaining));
        } else {
            hint.set_upper(remaining);
        }
        hint
    }
}

/// 为任意流式 body 包上帧间空闲超时。
///
/// # 参数
/// - `body`: 待包装 body。
/// - `timeout_ms`: 空闲超时毫秒,0 表示关闭。
fn idle_timeout_body<B>(body: B, timeout_ms: u64) -> BoxBody
where
    B: Body<Data = Bytes> + Send + Sync + Unpin + 'static,
    B::Error: Into<BoxError>,
{
    if timeout_ms == 0 {
        return body.map_err(Into::into).boxed();
    }
    let timeout = Duration::from_millis(timeout_ms);
    IdleTimeoutBody {
        // BoxBody 已经固定住其动态 body，外层无需再 `Pin<Box<BoxBody>>`。
        inner: body,
        timeout,
        deadline: None,
        // 短 body 可能在已有 socket buffer 中连续返回 data+EOF；首次 Pending 才读单调
        // 时钟并进入 Tokio timer wheel，避免每个 unary 请求创建/清理 Sleep 或逐帧查时钟。
        sleep: None,
        done: false,
    }
    .boxed()
}

/// 把最终上游和尝试次数写入响应扩展,供 access log/指标读取。
///
/// # 参数
/// - `resp`: 上游响应。
/// - `final_upstream`: 最终命中的上游实例 URI。
/// - `attempts`: 本次请求的上游尝试次数。
fn annotate_upstream_trace(
    mut resp: Response<BoxBody>,
    final_upstream: Arc<str>,
    attempts: usize,
) -> Response<BoxBody> {
    resp.extensions_mut().insert(UpstreamTrace {
        final_upstream,
        attempts,
    });
    resp
}

/// 构造零字节 body。
fn empty_body() -> BoxBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// 判断当前请求是否允许尝试下一个上游实例。
///
/// # 参数
/// - `parts`: 原始下游请求 head。
/// - `policy`: 当前服务的 `next_upstream` 策略。
/// - `pass_request_body`: route 是否会把请求体发送给上游。
fn can_retry_request(parts: &Parts, policy: &NextUpstreamPolicy, pass_request_body: bool) -> bool {
    policy.has_trigger()
        && (parts.method == http::Method::GET
            || parts.method == http::Method::HEAD
            || policy.non_idempotent
            || parts
                .headers
                .contains_key(HeaderName::from_static("idempotency-key")))
        && (!pass_request_body || request_body_is_empty(parts))
}

/// 通过请求头判断下游请求体是否为空。
///
/// # 参数
/// - `parts`: 原始下游请求 head。
fn request_body_is_empty(parts: &Parts) -> bool {
    if parts.headers.contains_key(TRANSFER_ENCODING) {
        return false;
    }
    parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim() == "0")
        .unwrap_or(true)
}

/// 从请求头读取可信的 `Content-Length`。
///
/// # 参数
/// - `parts`: 原始下游请求 head。
fn request_content_length(parts: &Parts) -> Option<u64> {
    if parts.headers.contains_key(TRANSFER_ENCODING) {
        return None;
    }
    parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
}

fn should_retry_status(policy: &NextUpstreamPolicy, status: StatusCode) -> bool {
    match status {
        StatusCode::BAD_GATEWAY => policy.http_502,
        StatusCode::SERVICE_UNAVAILABLE => policy.http_503,
        StatusCode::GATEWAY_TIMEOUT => policy.http_504,
        _ => false,
    }
}

fn should_retry_error(policy: &NextUpstreamPolicy, err: &ForwardError) -> bool {
    match err {
        ForwardError::BadGateway(_) => policy.error,
        ForwardError::Timeout => policy.timeout,
        ForwardError::NoHealthyUpstream(_) | ForwardError::Overloaded => false,
    }
}

async fn retry_backoff(policy: Option<&NextUpstreamPolicy>) {
    let Some(policy) = policy else {
        return;
    };
    if policy.backoff_ms > 0 {
        tokio::time::sleep(Duration::from_millis(policy.backoff_ms)).await;
    }
}

impl super::GatewayProxy {
    /// 启动 V7 上游连接预热线程。每轮只处理尚未见过的完整实例/池身份；动态发现加入的新实例
    /// 会在下一轮被预热，已完成项不会周期性制造业务请求。
    pub fn spawn_upstream_prewarm(self: &Arc<Self>) {
        let gateway = self.clone();
        tokio::spawn(async move {
            loop {
                let snapshot = gateway.snap.load_full();
                gateway.prewarm_snapshot(snapshot.as_ref()).await;
                let interval = snapshot.upstreams.prewarm_scan_interval_ms();
                drop(snapshot);
                tokio::time::sleep(Duration::from_millis(interval)).await;
            }
        });
    }

    /// 扫描一个不可变快照并并发预热所有新增实例。
    async fn prewarm_snapshot(&self, snapshot: &GatewaySnapshot) {
        let mut current = std::collections::HashSet::new();
        let mut candidates = Vec::new();
        for proxy in snapshot.proxies.iter() {
            let services = proxy
                .router
                .upstream_service_refs()
                .into_iter()
                .map(|(service, _)| service)
                .collect::<std::collections::HashSet<_>>();
            let pool_policy = HttpPoolPolicy::from_limits(&proxy.limits);
            for service in services {
                for target in snapshot.upstreams.prewarm_targets(service.as_str()) {
                    // h2/h2c 每条物理连接仍复用多个 stream，但最多预热到显式 shard 数；这既保留
                    // mux，又避免所有 runtime worker 争用 h2 crate 的单 connection mutex。
                    let mut connections = target.policy.connections;
                    if matches!(
                        target.protocol,
                        UpstreamProtocol::H2 | UpstreamProtocol::H2c
                    ) {
                        connections =
                            connections.min(pool_policy.h2_connection_shards_per_upstream);
                    }
                    connections = connections.min(pool_policy.max_idle_per_upstream);
                    if pool_policy.max_connections_per_upstream > 0 {
                        connections = connections.min(pool_policy.max_connections_per_upstream);
                    }
                    let key = super::PrewarmedUpstreamKey {
                        health_key: target.health_key.clone(),
                        protocol: target.protocol,
                        path: target.policy.path.clone(),
                        connections,
                        max_idle_per_upstream: pool_policy.max_idle_per_upstream,
                        h2_connection_shards_per_upstream: pool_policy
                            .h2_connection_shards_per_upstream,
                        h2_initial_stream_window_bytes: pool_policy.h2_initial_stream_window_bytes,
                        h2_initial_connection_window_bytes: pool_policy
                            .h2_initial_connection_window_bytes,
                        max_connections_per_upstream: pool_policy.max_connections_per_upstream,
                        keepalive_requests: pool_policy.keepalive_requests,
                        idle_timeout_ms: pool_policy.idle_timeout_ms,
                    };
                    if current.insert(key.clone()) {
                        candidates.push((key, target, pool_policy));
                    }
                }
            }
        }

        let pending = {
            let mut warmed = self.prewarmed_upstreams.lock();
            // 配置/发现中已消失的 identity 可删除；若将来重新加入，应重新预热新连接。
            warmed.retain(|key| current.contains(key));
            candidates
                .into_iter()
                .filter(|(key, _, _)| warmed.insert(key.clone()))
                .collect::<Vec<_>>()
        };

        let results = futures::future::join_all(pending.into_iter().map(
            |(key, target, pool_policy)| async move {
                let success = self
                    .prewarm_target(&target, pool_policy, key.connections)
                    .await;
                (key, target.health_key, success)
            },
        ))
        .await;
        for (key, health_key, success) in results {
            self.metrics.inc_upstream_prewarm(success);
            if success {
                tracing::debug!(upstream = %health_key, "upstream connection pool prewarmed");
            } else {
                // 失败项退出去重集，下一扫描轮会重试；成功项保持，避免把预热变成周期探测。
                self.prewarmed_upstreams.lock().remove(&key);
                tracing::warn!(upstream = %health_key, "upstream connection pool prewarm failed");
            }
        }
    }

    /// 使用真实 Hyper client cache 建立一批连接。HEAD 请求从空 head 构造，不复制任何下游
    /// header/body；只等待 response head，HTTP 规范保证 HEAD 没有响应正文，因此连接可直接回池。
    async fn prewarm_target(
        &self,
        target: &crate::upstream::UpstreamPrewarmTarget,
        pool_policy: HttpPoolPolicy,
        connections: usize,
    ) -> bool {
        if connections == 0 {
            return false;
        }
        let reservation = UpstreamReservation {
            base: target.base.clone(),
            health_key: target.health_key.clone(),
            protocol: target.protocol,
            tls_profile: target.tls_profile.clone(),
            pool_policy,
            counter: None,
            pending_counter: None,
            release_on_drop: false,
        };
        let Ok(uri) = upstream_uri(&reservation.base, target.policy.path.as_ref(), "") else {
            return false;
        };
        let timeout = Duration::from_millis(target.policy.timeout_ms);
        if target.protocol == UpstreamProtocol::H2c {
            let sends = (0..connections).map(|_| {
                // selector 轮转到独立 shard；请求/响应 body 仍由 Hyper 流式传递。
                let client = self.h2c_client_for(&reservation, None);
                let request = Request::builder()
                    .method(http::Method::HEAD)
                    .version(http::Version::HTTP_2)
                    .uri(uri.clone())
                    .body(empty_body())
                    .expect("build validated h2c prewarm request");
                async move {
                    matches!(
                        tokio::time::timeout(timeout, client.request(request)).await,
                        Ok(Ok(_))
                    )
                }
            });
            futures::future::join_all(sends)
                .await
                .into_iter()
                .all(|ok| ok)
        } else {
            let version = if target.protocol == UpstreamProtocol::H2 {
                http::Version::HTTP_2
            } else {
                http::Version::HTTP_11
            };
            let sends = (0..connections).map(|_| {
                let client =
                    self.http_client_for(&reservation, version == http::Version::HTTP_2, None);
                let request = Request::builder()
                    .method(http::Method::HEAD)
                    .version(version)
                    .uri(uri.clone())
                    .body(empty_body())
                    .expect("build validated upstream prewarm request");
                async move {
                    matches!(
                        tokio::time::timeout(timeout, client.request(request)).await,
                        Ok(Ok(_))
                    )
                }
            });
            futures::future::join_all(sends)
                .await
                .into_iter()
                .all(|ok| ok)
        }
    }
}

impl super::GatewayProxy {
    /// 获取匹配当前 TLS profile 与池参数的普通 HTTP(S) client。
    ///
    /// cache key 包含 profile 指纹与池参数：reload 改证书或预算会建立新池；旧请求持有的 client clone
    /// 继续 drain，cache 仅在超过 `old_pool_retain_ms` 后移除旧 handle，不会中断在途 body。
    ///
    /// # 参数
    /// - `reservation`: 本次已选中的实例预留，携带 TLS profile 与当前 proxy 的池预算。
    ///
    /// 返回：可直接发送本次请求的 Hyper client handle。
    fn http_client_for(
        &self,
        reservation: &UpstreamReservation,
        h2_request: bool,
        shard_hint: Option<u64>,
    ) -> super::UpstreamHttpClient {
        // protocol=auto 可能在同一 upstream 同时承载 h1 与 gRPC/h2；按本次 request version
        // 分开 cache，普通 h1 继续复用单池，只有 h2 才轮转独立 mux 连接。
        let shard_count = if h2_request {
            reservation.pool_policy.h2_connection_shards_per_upstream
        } else {
            1
        };
        let cache_key = super::UpstreamHttpClientCacheKey {
            health_key: reservation.health_key.clone(),
            protocol: reservation.protocol,
            profile_key: reservation
                .tls_profile
                .as_ref()
                .map(|profile| profile.key.clone()),
            max_idle_per_upstream: reservation.pool_policy.max_idle_per_upstream,
            h2_connection_shards_per_upstream: shard_count,
            h2_initial_stream_window_bytes: reservation.pool_policy.h2_initial_stream_window_bytes,
            h2_initial_connection_window_bytes: reservation
                .pool_policy
                .h2_initial_connection_window_bytes,
            max_connections_per_upstream: reservation.pool_policy.max_connections_per_upstream,
            keepalive_requests: reservation.pool_policy.keepalive_requests,
            idle_timeout_ms: reservation.pool_policy.idle_timeout_ms,
        };
        let now_ms = pool_clock_millis();
        {
            // 稳态只拿 parking_lot 共享读锁；请求序号由 entry 内原子占位。不同 Tokio worker
            // 可并行选择 client，不再被 std::Mutex 串行，也不触碰物理预算/清旧表。
            let clients = self.http_clients.read();
            if let Some(entry) = clients.get(&cache_key) {
                if let Some(request_no) = reserve_client_request(
                    &entry.requests_served,
                    reservation.pool_policy.keepalive_requests,
                    shard_hint,
                ) {
                    entry.last_used_ms.store(now_ms, Ordering::Relaxed);
                    let shard = client_shard_index(request_no, entry.clients.len());
                    return entry.clients[shard].clone();
                }
            }
        }

        // miss/严格 generation 轮换才进入写路径。物理预算的独占表也只在这里查询，避免每个
        // 请求为一个已稳定存在的 connector 重复加锁和全表 retain。
        let physical_budget = self.physical_connection_budget_for(reservation);
        let mut clients = self.http_clients.write();
        // 在等写锁期间其它 worker 可能已建好/轮换；必须复查后复用，不能重复建立 generation。
        if let Some(entry) = clients.get(&cache_key) {
            if let Some(request_no) = reserve_client_request(
                &entry.requests_served,
                reservation.pool_policy.keepalive_requests,
                shard_hint,
            ) {
                entry.last_used_ms.store(now_ms, Ordering::Relaxed);
                let shard = client_shard_index(request_no, entry.clients.len());
                return entry.clients[shard].clone();
            }
        }
        retain_recent_http_clients(
            &mut clients,
            &cache_key,
            now_ms,
            reservation.pool_policy.old_pool_retain_ms,
        );
        // 达到 keepalive_requests 后替换 cache handle；旧 clone 只完成已分配请求，不能再接新请求。
        let client_shards = (0..shard_count)
            .map(|_| {
                build_upstream_http_client(
                    reservation.tls_profile.as_ref(),
                    reservation.pool_policy,
                    physical_budget.clone(),
                    h2_request,
                )
            })
            .collect::<Vec<_>>();
        let client = client_shards[0].clone();
        clients.insert(
            cache_key,
            super::CachedUpstreamHttpClient {
                clients: client_shards,
                last_used_ms: AtomicU64::new(now_ms),
                requests_served: AtomicU64::new(1),
            },
        );
        client
    }

    /// 获取一个跨 HTTP client generation 共享的物理连接预算。
    ///
    /// # 参数
    /// - `reservation`: 已选实例；完整 health_key + protocol 构成预算身份。
    fn physical_connection_budget_for(
        &self,
        reservation: &UpstreamReservation,
    ) -> Arc<PhysicalConnectionBudget> {
        let key = (reservation.health_key.clone(), reservation.protocol);
        let mut budgets = self.upstream_connection_budgets.lock();
        let retain = Duration::from_millis(reservation.pool_policy.old_pool_retain_ms);
        budgets.retain(|candidate, entry| {
            candidate == &key
                || Arc::strong_count(&entry.budget) > 1
                || (retain > Duration::ZERO && entry.last_used.elapsed() <= retain)
        });
        if let Some(entry) = budgets.get_mut(&key) {
            entry
                .budget
                .set_limit(reservation.pool_policy.max_connections_per_upstream);
            entry.last_used = std::time::Instant::now();
            return entry.budget.clone();
        }
        let budget =
            PhysicalConnectionBudget::new(reservation.pool_policy.max_connections_per_upstream);
        budgets.insert(
            key,
            super::CachedPhysicalConnectionBudget {
                budget: budget.clone(),
                last_used: std::time::Instant::now(),
            },
        );
        budget
    }

    /// 获取匹配当前池参数的 h2c prior-knowledge client。
    ///
    /// # 参数
    /// - `reservation`: 本次实例预留；h2c 不使用 TLS profile，但复用其中的池预算与旧池保留期。
    ///
    /// 返回：已强制 `http2_only` 的 Hyper client，保证不会静默退化成 HTTP/1.1。
    fn h2c_client_for(
        &self,
        reservation: &UpstreamReservation,
        shard_hint: Option<u64>,
    ) -> super::UpstreamH2cClient {
        let cache_key = super::UpstreamH2cClientCacheKey {
            health_key: reservation.health_key.clone(),
            max_idle_per_upstream: reservation.pool_policy.max_idle_per_upstream,
            h2_connection_shards_per_upstream: reservation
                .pool_policy
                .h2_connection_shards_per_upstream,
            h2_initial_stream_window_bytes: reservation.pool_policy.h2_initial_stream_window_bytes,
            h2_initial_connection_window_bytes: reservation
                .pool_policy
                .h2_initial_connection_window_bytes,
            max_connections_per_upstream: reservation.pool_policy.max_connections_per_upstream,
            keepalive_requests: reservation.pool_policy.keepalive_requests,
            idle_timeout_ms: reservation.pool_policy.idle_timeout_ms,
        };
        let now_ms = pool_clock_millis();

        // 稳态先命中最近 generation：ArcSwap guard 只借用不可变 entry，不 clone 整个分片表，
        // 也不进入共享 RwLock/HashMap。选择结果仅 clone 一个轻量 client handle；请求 head/body
        // 所有权随后直接移入 Hyper，payload `Bytes` frame 仍保持零聚合、零内容复制。
        {
            let hot = self.h2c_client_hot.load();
            if let Some(entry) = hot.as_ref().filter(|entry| entry.key == cache_key) {
                if let Some(request_no) = reserve_client_request(
                    &entry.requests_served,
                    reservation.pool_policy.keepalive_requests,
                    shard_hint,
                ) {
                    entry.last_used_ms.store(now_ms, Ordering::Relaxed);
                    let shard = client_shard_index(request_no, entry.clients.len());
                    return entry.clients[shard].clone();
                }
            }
        }

        {
            let clients = self.h2c_clients.read();
            if let Some(entry) = clients.get(&cache_key) {
                if let Some(request_no) = reserve_client_request(
                    &entry.requests_served,
                    reservation.pool_policy.keepalive_requests,
                    shard_hint,
                ) {
                    entry.last_used_ms.store(now_ms, Ordering::Relaxed);
                    let shard = client_shard_index(request_no, entry.clients.len());
                    let client = entry.clients[shard].clone();
                    self.h2c_client_hot.store(Some(entry.clone()));
                    return client;
                }
            }
        }

        let physical_budget = self.physical_connection_budget_for(reservation);
        let mut clients = self.h2c_clients.write();
        if let Some(entry) = clients.get(&cache_key) {
            if let Some(request_no) = reserve_client_request(
                &entry.requests_served,
                reservation.pool_policy.keepalive_requests,
                shard_hint,
            ) {
                entry.last_used_ms.store(now_ms, Ordering::Relaxed);
                let shard = client_shard_index(request_no, entry.clients.len());
                let client = entry.clients[shard].clone();
                self.h2c_client_hot.store(Some(entry.clone()));
                return client;
            }
        }
        retain_recent_h2c_clients(
            &mut clients,
            &cache_key,
            now_ms,
            reservation.pool_policy.old_pool_retain_ms,
        );
        let client_shards = (0..reservation.pool_policy.h2_connection_shards_per_upstream)
            .map(|_| build_h2c_client(reservation.pool_policy, physical_budget.clone()))
            .collect::<Vec<_>>();
        let client = client_shards[0].clone();
        let entry = Arc::new(super::CachedUpstreamH2cClient {
            key: cache_key.clone(),
            clients: client_shards,
            last_used_ms: AtomicU64::new(now_ms),
            requests_served: AtomicU64::new(1),
        });
        clients.insert(cache_key, entry.clone());
        self.h2c_client_hot.store(Some(entry));
        client
    }

    /// 解析直连或 `lb://service` 上游、执行健康/LB 选择，并同时占用 least_conn 与过载预算。
    ///
    /// # 参数
    /// - `snap`: 当前请求固定持有的配置快照；整个重试链不得跨版本读取新快照。
    /// - `upstream`: route 渲染后的上游目标，允许静态 http(s) URI 或已声明的 `lb://service`。
    /// - `excluded`: 当前重试链已经尝试的完整 `health_key`，避免再次命中同一逻辑实例。
    /// - `limits`: 当前 proxy 的资源预算；pending 与连接池参数都随本次预留固化。
    ///
    /// 返回：成功时给出 RAII `UpstreamReservation`；无健康实例或预算满时返回 503 类错误。
    fn resolve_upstream_base_excluding(
        &self,
        snap: &GatewaySnapshot,
        upstream: &str,
        excluded: &[Arc<str>],
        limits: &crate::config::model::ServerLimitsCfg,
    ) -> Result<UpstreamReservation, ForwardError> {
        if let Some(service) = upstream.strip_prefix("lb://") {
            let passive_policy = snap
                .upstreams
                .passive_health_policy(service)
                .unwrap_or_else(PassiveHealthPolicy::disabled);
            // ★主动健康探测(§5.1):被后台探测判为不健康的实例也排除,与被动摘除叠加成双保险。
            // 这里直接持有 Arc<HashSet> 迭代,不把整份主动不健康集合克隆进 Vec,保持请求热路径少分配。
            let passive_excluded = self.ejected_upstreams(passive_policy);
            let active_unhealthy = self.active_health.unhealthy_set();
            let has_attempted = !excluded.is_empty();
            let has_passive_excluded = !passive_excluded.is_empty();
            let has_active_unhealthy = !active_unhealthy.is_empty();
            // least_conn 计数放在 DashMap entry 的 AtomicU64 中：不同 hash shard 可并行，命中
            // 同一实例也只拿共享读 guard。选择仍是并发近似快照；最终 reserve 在 Arc 原子上完成。
            let inst = snap
                .upstreams
                .select_instance_where(
                    service,
                    |health_key| {
                        // 重试/被动摘除集合通常很短，直接借用扫描比每请求合并 HashSet 更省分配；
                        // 主动健康集合本身已是快照 HashSet，保持 O(1) 查询。三个 `has_*`
                        // 分支在无故障首请求上都稳定为 false，避免为已知空集合计算字符串哈希；
                        // 这里只借用现有 slice/ArcSwap 快照，不合并、不复制任何身份字符串。
                        (has_attempted && excluded.iter().any(|excluded| &**excluded == health_key))
                            || (has_passive_excluded
                                && passive_excluded
                                    .iter()
                                    .any(|excluded| excluded == health_key))
                            || (has_active_unhealthy && active_unhealthy.contains(health_key))
                    },
                    |health_key| {
                        self.upstream_inflight
                            .get(health_key)
                            .map(|counter| counter.load(Ordering::Relaxed))
                            .unwrap_or(0)
                    },
                    || self.upstream_rr_next(service),
                )
                .ok_or_else(|| ForwardError::NoHealthyUpstream(service.to_string()))?;
            let base = inst.uri.clone();
            let health_key = inst.health_key.clone();
            let protocol = inst.protocol;
            let tls_profile = inst.tls_profile.clone();
            // 只有 least_conn 会读取 in-flight；RR/first 为每请求维护一份永不读取的计数既增加
            // DashMap 查找，也让所有响应 body 在同一 atomic 上增减。单候选 least_conn 在选择时
            // 虽不读 load，仍维护计数，以便热更加入第二个实例后立即获得真实基线。
            let counter = snap.upstreams.uses_least_conn(service).then(|| {
                self.upstream_inflight
                    .get(health_key.as_ref())
                    .map(|counter| counter.value().clone())
                    .unwrap_or_else(|| {
                        self.upstream_inflight
                            .entry(health_key.clone())
                            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                            .value()
                            .clone()
                    })
            });
            if let Some(counter) = &counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            return self.reserve_upstream_pending(
                UpstreamReservation {
                    base,
                    health_key,
                    protocol,
                    tls_profile,
                    pool_policy: HttpPoolPolicy::from_limits(limits),
                    counter,
                    pending_counter: None,
                    release_on_drop: true,
                },
                limits.upstream_pending_limit,
            );
        }
        let base = Arc::<str>::from(upstream.trim_end_matches('/'));
        self.reserve_upstream_pending(
            UpstreamReservation {
                health_key: base.clone(),
                base,
                protocol: UpstreamProtocol::Auto,
                tls_profile: None,
                pool_policy: HttpPoolPolicy::from_limits(limits),
                counter: None,
                pending_counter: None,
                release_on_drop: false,
            },
            limits.upstream_pending_limit,
        )
    }

    /// 为解析出的实例占用一个在途请求槽。limit=0 表示关闭限制；达到上限直接 503，
    /// 不在 Hyper 连接池前堆无界等待队列（架构规范 §23）。
    ///
    /// # 参数
    /// - `reservation`: 已占用 least_conn 计数的实例预留；失败返回时由 Drop 自动回滚该计数。
    /// - `limit`: 每个完整 `health_key` 的在途上限；`0` 表示不限但不创建 pending 计数。
    ///
    /// 返回：占槽成功返回补全后的预留；满额返回 `ForwardError::Overloaded` 并累加低基数指标。
    fn reserve_upstream_pending(
        &self,
        mut reservation: UpstreamReservation,
        limit: usize,
    ) -> Result<UpstreamReservation, ForwardError> {
        if limit == 0 {
            return Ok(reservation);
        }
        let counter = {
            let hot = self.upstream_pending_hot.load();
            if let Some(entry) = hot.as_ref().filter(|entry| {
                Arc::ptr_eq(&entry.health_key, &reservation.health_key)
                    || entry.health_key == reservation.health_key
            }) {
                // clone 只增加计数器 owner；response body 必须持有它直到 EOF/cancel，不能借用
                // ArcSwap guard 跨 await，也不能把计数器生命周期缩短到 response head。
                entry.counter.clone()
            } else {
                use dashmap::mapref::entry::Entry;

                match self.upstream_pending.entry(reservation.health_key.clone()) {
                    Entry::Occupied(entry) => {
                        let counter = entry.get().clone();
                        // reconcile 可能因 identity 下线清空 hot；同一 identity 再次启用时，从
                        // 仍存活的权威 map entry 恢复缓存。只在 slot 为空时分配包装器，不让
                        // 多实例正常轮询来回覆盖最近项。
                        if self.upstream_pending_hot.load().is_none() {
                            self.upstream_pending_hot.store(Some(Arc::new(
                                super::CachedUpstreamPendingCounter {
                                    health_key: reservation.health_key.clone(),
                                    counter: counter.clone(),
                                },
                            )));
                        }
                        counter
                    }
                    Entry::Vacant(entry) => {
                        let counter = Arc::new(AtomicU64::new(0));
                        entry.insert(counter.clone());
                        // 只在首次创建 identity 时发布，避免多实例轮转在 hot slot 上反复分配。
                        self.upstream_pending_hot.store(Some(Arc::new(
                            super::CachedUpstreamPendingCounter {
                                health_key: reservation.health_key.clone(),
                                counter: counter.clone(),
                            },
                        )));
                        counter
                    }
                }
            }
        };
        let limit = limit.min(u64::MAX as usize) as u64;
        if counter
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |active| {
                (active < limit).then_some(active.saturating_add(1))
            })
            .is_err()
        {
            self.metrics.inc_upstream_overloaded();
            return Err(ForwardError::Overloaded);
        }
        reservation.pending_counter = Some(counter);
        reservation.release_on_drop = true;
        Ok(reservation)
    }
}

/// 构建普通 HTTP(S) 上游 client。证书/CA 已在配置构建期解析校验,这里不做文件 IO。
///
/// # 参数
/// - `profile`: 可选 HTTP 上游 TLS profile；None 使用系统根证书。
/// - `policy`: 显式连接池参数。
/// - `physical_budget`: 当前 health_key/protocol 跨 generation 共享的物理 socket 预算。
///
/// 返回：同时支持 h1/h2 的 Hyper client；实际 pool 仍由 scheme + authority 隔离。
///
/// # Panic
/// 仅当操作系统根证书无法加载时 panic；启动/首请求无法建立安全默认 TLS 信任属于不可恢复环境错误。
fn build_upstream_http_client(
    profile: Option<&UpstreamTlsProfile>,
    policy: HttpPoolPolicy,
    physical_budget: Arc<PhysicalConnectionBudget>,
    h2_request: bool,
) -> super::UpstreamHttpClient {
    let connector = match profile {
        Some(profile) => {
            let mut config = profile.client_config.as_ref().clone();
            config.alpn_protocols.clear();
            let builder = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_or_http();
            if let Some(server_name) = &profile.server_name {
                let name = ServerName::try_from(server_name.as_ref().to_string())
                    .expect("validated upstream tls server_name");
                builder
                    .with_server_name_resolver(FixedServerNameResolver::new(name))
                    .enable_http1()
                    .enable_http2()
                    .build()
            } else {
                builder.enable_http1().enable_http2().build()
            }
        }
        None => hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("load native TLS roots")
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build(),
    };
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        // 与下游 server 使用同一份显式资源预算；不启用 adaptive window，避免运行时越过
        // 配置上界。该设置只影响协商为 h2 的 transport，HTTP/1 池语义不变。
        .http2_initial_stream_window_size(Some(policy.h2_initial_stream_window_bytes))
        .http2_initial_connection_window_size(Some(policy.h2_initial_connection_window_bytes))
        .pool_max_idle_per_host(policy.max_idle_per_upstream)
        .pool_idle_timeout(
            (policy.idle_timeout_ms > 0).then(|| Duration::from_millis(policy.idle_timeout_ms)),
        )
        .pool_timer(TokioTimer::new());
    UpstreamHttpClient {
        inner: builder.build(BudgetedConnector::new(connector, physical_budget)),
        // protocol=auto 的 H1 与 H2 cache key 已分离；只有明确按 H2 建立的 generation 才需
        // 冷启动单飞。H1 保持 Hyper 原生的多连接并发拨号能力。
        h2_gate: h2_request.then(H2ColdStartGate::new),
    }
}

/// 构建明文 HTTP/2 prior-knowledge direct sender，并把物理连接预算落实到 connector。
///
/// # 参数
/// - `policy`: 当前 proxy 快照固化的窗口、idle 与连接分片预算。
/// - `physical_budget`: 当前 h2c 实例跨 generation 共享的物理 socket 预算。
///
/// 返回：每个 shard 只保存一条显式 H2 sender；不经过 legacy pool 的 authority 查找和
/// dispatch，配置为 h2c 时也不会尝试 HTTP/1.1。`BudgetedIo` 跟随 connection driver 的
/// 生命周期释放物理 socket 配额，响应 frame 始终由 Hyper `Incoming` 原样向下游移动。
fn build_h2c_client(
    policy: HttpPoolPolicy,
    physical_budget: Arc<PhysicalConnectionBudget>,
) -> super::UpstreamH2cClient {
    let mut connector = HttpConnector::new();
    // hyper-util 的 HttpConnector 默认保留 Nagle。对 direct h2c/gRPC，这会让同一 transport 上的
    // 短 HEADERS/DATA/WINDOW_UPDATE 与 Linux delayed ACK 形成约 40ms 台阶；连接越少、mux 越深
    // 越明显。H2 driver 已负责 coalesce 同一轮 ready frame，因此关闭 Nagle 不等于逐 frame
    // syscall，也不增加用户态 buffer/复制。该标志只在建物理 socket 时设置，request/frame 热路径
    // 没有分支；物理连接 cap、GOAWAY/RST、flow-control 和 idle 回收语义保持不变。
    connector.set_nodelay(true);
    UpstreamH2cClient {
        state: Arc::new(DirectH2cState {
            current: ArcSwapOption::empty(),
            connector: BudgetedConnector::new(connector, physical_budget),
            policy,
        }),
        h2_gate: H2ColdStartGate::new(),
    }
}

/// 计算当前请求实际使用的 route upstream。
///
/// 静态 URI 直接借用 `route.upstream`;动态 URI 才执行模板渲染,避免静态热路径付额外分配成本。
///
/// # 参数
/// - `route`: 当前命中 route。
/// - `parts`: 原始下游请求 parts。
/// - `client_ip`: 真实客户端 IP。
/// - `downstream_proto`: 下游协议 scheme。
/// - `request_id`: 网关生成的 request id。
fn route_upstream_target<'a>(
    route: &'a Route,
    parts: &Parts,
    client_ip: IpAddr,
    downstream_proto: &'static str,
    request_id: &str,
) -> Cow<'a, str> {
    if route.upstream_template.static_literal().is_some() {
        return Cow::Borrowed(route.upstream.as_str());
    }
    let eval_ctx = crate::variable::EvalContext {
        parts,
        client_ip,
        downstream_proto,
        request_id,
        route_id: route.id.as_str(),
    };
    Cow::Owned(
        route
            .upstream_template
            .render(&eval_ctx, route.variables.as_ref()),
    )
}

/// 校验渲染后的 upstream target。
///
/// 动态 target 只允许 `lb://已声明服务`,防止把 header/query 拼成任意外网 URL 形成 SSRF。
///
/// # 参数
/// - `snap`: 当前配置快照,用于校验服务是否已声明。
/// - `target`: 静态或模板渲染后的 upstream target。
/// - `dynamic`: target 是否来自运行期模板渲染。
fn validate_upstream_target(
    snap: &GatewaySnapshot,
    target: &str,
    dynamic: bool,
) -> Result<(), ForwardError> {
    if let Some(service) = target.strip_prefix("lb://") {
        if service.is_empty() || !snap.upstreams.has_service(service) {
            return Err(ForwardError::BadGateway(anyhow::anyhow!(
                "unknown upstream service `{service}`"
            )));
        }
        return Ok(());
    }
    if dynamic {
        return Err(ForwardError::BadGateway(anyhow::anyhow!(
            "dynamic route upstream must resolve to lb://<declared-service>"
        )));
    }
    let uri = target
        .parse::<http::Uri>()
        .map_err(|e| ForwardError::BadGateway(anyhow::anyhow!("bad route upstream uri: {e}")))?;
    let scheme = uri.scheme_str().unwrap_or_default();
    if scheme != "http" && scheme != "https" {
        return Err(ForwardError::BadGateway(anyhow::anyhow!(
            "unsupported route upstream scheme `{scheme}`"
        )));
    }
    if uri.authority().is_none() {
        return Err(ForwardError::BadGateway(anyhow::anyhow!(
            "route upstream uri requires authority"
        )));
    }
    Ok(())
}

/// 固化在单次上游预留中的 Hyper 连接池策略。
#[derive(Clone, Copy)]
struct HttpPoolPolicy {
    /// 每 authority 最多保留的 idle 连接数。
    max_idle_per_upstream: usize,
    /// h2/h2c 独立 Hyper client 数；每个 client 在 authority 内仍多路复用 stream。
    h2_connection_shards_per_upstream: usize,
    /// H2 单 stream 初始接收窗口；显式有界，不启用 adaptive window。
    h2_initial_stream_window_bytes: u32,
    /// H2 单物理连接初始接收窗口；用于减少并发 stream 的 WINDOW_UPDATE 争用。
    h2_initial_connection_window_bytes: u32,
    /// 每个 health_key + protocol 的物理 socket 总上限。
    max_connections_per_upstream: usize,
    /// 单 client generation 的请求数上限；0 表示不按请求数轮换。
    keepalive_requests: u64,
    /// idle 连接回收超时(ms)；0 表示 Hyper 不设 idle timeout。
    idle_timeout_ms: u64,
    /// 换版后旧 cache entry 最长保留时间(ms)。
    old_pool_retain_ms: u64,
}

impl HttpPoolPolicy {
    /// 从当前 proxy 资源配置复制池策略，确保一次请求内不受 reload 影响。
    ///
    /// # 参数
    /// - `limits`: 当前请求快照中的 listener 资源预算。
    ///
    /// 返回：可复制、无堆分配的池策略值。
    fn from_limits(limits: &crate::config::model::ServerLimitsCfg) -> Self {
        let h2_connection_shards_per_upstream = if limits.pool_max_connections_per_upstream == 0 {
            limits.h2_connection_shards_per_upstream
        } else {
            limits
                .h2_connection_shards_per_upstream
                .min(limits.pool_max_connections_per_upstream)
        };
        Self {
            max_idle_per_upstream: limits.pool_max_per_upstream,
            h2_connection_shards_per_upstream,
            h2_initial_stream_window_bytes: limits.h2_initial_stream_window_bytes,
            h2_initial_connection_window_bytes: limits.h2_initial_connection_window_bytes,
            max_connections_per_upstream: limits.pool_max_connections_per_upstream,
            keepalive_requests: limits.keepalive_requests,
            idle_timeout_ms: limits.pool_idle_timeout_ms,
            old_pool_retain_ms: limits.old_pool_retain_ms,
        }
    }
}

/// 返回进程内连接池时钟的相对毫秒。只比较同一进程内的 age，不读取墙钟，也不受 NTP 跳变影响。
fn pool_clock_millis() -> u64 {
    static STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let elapsed = STARTED.get_or_init(std::time::Instant::now).elapsed();
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

/// 为一个不可变 client generation 严格占用请求序号。
///
/// `limit=0` 且调用方有 request-id hash 时完全不写共享 cache line；后台/内部请求没有 hint
/// 才退回 relaxed 轮转。有限预算必须用 CAS，保证并发 worker 合计不会超过 generation 边界。
/// 返回值只用于 shard 取模；None 表示调用方必须进入写锁轮换 generation。
fn reserve_client_request(
    requests_served: &AtomicU64,
    limit: u64,
    shard_hint: Option<u64>,
) -> Option<u64> {
    if limit == 0 {
        return Some(shard_hint.unwrap_or_else(|| requests_served.fetch_add(1, Ordering::Relaxed)));
    }
    requests_served
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |served| {
            (served < limit).then_some(served + 1)
        })
        .ok()
}

/// 写路径回收已经不再匹配当前配置、且超过保留期的普通 HTTP client handle。
fn retain_recent_http_clients(
    clients: &mut super::UpstreamHttpClientPool,
    current: &super::UpstreamHttpClientCacheKey,
    now_ms: u64,
    retain_ms: u64,
) {
    clients.retain(|key, entry| {
        key == current
            || (retain_ms > 0
                && now_ms.saturating_sub(entry.last_used_ms.load(Ordering::Relaxed)) <= retain_ms)
    });
}

/// 写路径回收已经不再匹配当前配置、且超过保留期的 h2c client handle。
fn retain_recent_h2c_clients(
    clients: &mut super::UpstreamH2cClientPool,
    current: &super::UpstreamH2cClientCacheKey,
    now_ms: u64,
    retain_ms: u64,
) {
    clients.retain(|key, entry| {
        key == current
            || (retain_ms > 0
                && now_ms.saturating_sub(entry.last_used_ms.load(Ordering::Relaxed)) <= retain_ms)
    });
}

/// 选择当前 generation 的 client shard。
///
/// 请求序号在 entry 原子中递增；取模只在 request head 选择阶段执行，body/消息帧热路径不访问
/// client cache。`shard_count` 由配置构建期保证非零。
fn client_shard_index(requests_served: u64, shard_count: usize) -> usize {
    (requests_served % shard_count as u64) as usize
}

/// 一次上游选择的 RAII 预留。
///
/// invariant：构造成功后 least_conn/pending 已各自加一；预留在收到响应头后把计数器移交给
/// `CountedBody`，否则任何错误/取消路径都由自身 Drop 归还，不能泄漏并发名额。
struct UpstreamReservation {
    /// 实际 dial 与 URI 拼接使用的上游 base URI。
    base: Arc<str>,
    /// 被动健康、重试排除与 least_conn 共用的实例身份键。TLS profile 纳入身份,避免同 URI 串状态。
    health_key: Arc<str>,
    /// 选中实例的上游协议(review L1),供转发层设上游请求版本。
    protocol: UpstreamProtocol,
    /// HTTP 上游 TLS profile(§36 `proxy_ssl_*`)。
    tls_profile: Option<UpstreamTlsProfile>,
    /// 当前 proxy 快照给出的连接池预算；进入 cache key，reload 改参数会创建新池并延迟淘汰旧池。
    pool_policy: HttpPoolPolicy,
    /// least_conn 在途计数器；直连 URI 不参与服务级 LB，故为空。
    counter: Option<Arc<AtomicU64>>,
    /// §23 每实例在途请求预算计数器。
    pending_counter: Option<Arc<AtomicU64>>,
    /// true 表示计数器仍由 reservation 持有；移交 body 后必须置 false，避免重复释放。
    release_on_drop: bool,
}

impl UpstreamReservation {
    /// 把预留计数器移交给响应 body，使长流在真正结束/被下游取消时才释放。
    ///
    /// # 参数
    /// - `body`: 上游响应 body；保持原帧流和背压，不做 collect。
    /// - `idle_timeout_ms`: 帧间空闲预算；0 表示关闭。
    /// - `grpc`: 原生 gRPC 长流状态；存在时与计数/idle 共用同一个 wrapper。
    ///
    /// 返回：无计数器时原样返回；否则返回带 RAII 释放语义的 `CountedBody`。
    fn wrap_body<B>(mut self, body: B, idle_timeout_ms: u64, grpc: Option<GrpcBodyState>) -> BoxBody
    where
        B: Body<Data = Bytes> + Send + Sync + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        let counter = self.counter.take();
        let pending_counter = self.pending_counter.take();
        if counter.is_none() && pending_counter.is_none() && grpc.is_none() {
            self.release_on_drop = false;
            return idle_timeout_body(body, idle_timeout_ms);
        }
        self.release_on_drop = false;
        let idle_timeout = Duration::from_millis(idle_timeout_ms);
        CountedBody {
            // 直接持有具体 body（主路径为 hyper::Incoming）；最外层只 box 一次 CountedBody。
            // 不先构造 BoxBody，避免一次堆分配和后续每帧一次虚调用。
            inner: Some(body),
            counter,
            pending_counter,
            // 计数与帧间超时共享同一 wrapper，避免主路径先 box CountedBody、再 box
            // IdleTimeoutBody。deadline/Sleep 都只在 body 首次 Pending 时建立：如果 data +
            // trailer + EOF 已在 socket buffer 中连续就绪，就不读取单调时钟，也不进入 timer wheel。
            idle_timeout,
            idle_deadline: None,
            idle_sleep: None,
            grpc,
            done: false,
        }
        .boxed()
    }
}

impl Drop for UpstreamReservation {
    /// 请求在响应 body 建立前失败/取消时回滚全部已占计数；成功移交后不再释放。
    fn drop(&mut self) {
        if self.release_on_drop {
            if let Some(counter) = &self.counter {
                counter.fetch_sub(1, Ordering::Relaxed);
            }
            if let Some(counter) = &self.pending_counter {
                counter.fetch_sub(1, Ordering::Release);
            }
        }
    }
}

/// gRPC 长流状态；与计数 body 同寿命，不建立第二个 boxed body。
///
/// gRPC response head 无法可靠区分 unary 与 server-streaming，因此每个原生 gRPC response 都在
/// 返回下游前登记。不能延迟到 body 首次 `Pending`：管理面可能恰好在 response head 与首次 body
/// poll 之间关闭 route/IP/consumer，延迟登记会永久错过这次一次性关闭事件。登记只复制共享
/// `Arc` 元数据；消息 payload 仍由原始 `Bytes` frame 零拷贝透传。
struct GrpcBodyState {
    guard: ConnGuard,
    close_wait: CloseNotified,
    lifetime: Option<Pin<Box<Sleep>>>,
}

impl GrpcBodyState {
    /// 在 response head 交给下游前登记，封住管理面关闭与首次 body poll 的竞态。
    fn register(context: &GrpcDrainContext) -> Self {
        let guard = context.registry.register(
            context.route_id.clone(),
            context.client_ip,
            context.consumer.clone(),
            context.snapshot_version,
            LongProto::GrpcStream,
        );
        let close_wait = guard.closed();
        Self {
            guard,
            close_wait,
            lifetime: (context.max_lifetime_ms > 0).then(|| {
                Box::pin(tokio::time::sleep(Duration::from_millis(
                    context.max_lifetime_ms,
                )))
            }),
        }
    }

    /// 检查 max-age/管理面关闭并返回标准、已转义的 gRPC message。
    ///
    /// 同步 ready-frame 热路径只做一次关闭码原子读；payload/trailer 均不经过此状态复制。
    fn poll_close_message(&mut self, cx: &mut Context<'_>) -> Option<HeaderValue> {
        let max_age_reached = self
            .lifetime
            .as_mut()
            .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready());
        let registry_close = self.guard.requested_close_code().is_some();
        if !max_age_reached && !registry_close {
            return None;
        }
        Some(self.close_message(max_age_reached))
    }

    /// upstream Pending 时登记关闭 waker。稳定 task 只在第一次执行一次 AtomicWaker register；
    /// 后续 Pending 只比较 waker 身份，避免每个 gRPC frame 额外做两次关闭码原子读。
    fn subscribe_close(&mut self, cx: &Context<'_>) -> Option<HeaderValue> {
        self.close_wait
            .subscribe_if_needed(cx)
            .then(|| self.close_message(false))
    }

    fn close_message(&self, max_age_reached: bool) -> HeaderValue {
        let policy_violation = self.guard.ws_close_code() == 1008;
        if max_age_reached {
            HeaderValue::from_static("gateway%20max%20age")
        } else if policy_violation {
            HeaderValue::from_static("gateway%20policy%20violation")
        } else {
            HeaderValue::from_static("gateway%20draining")
        }
    }
}

/// 持有上游实例计数器、idle timer 与可选 gRPC drain 的单层流式响应 body。
struct CountedBody<B> {
    /// 原始具体 body；poll/size_hint 原样委托，保持 trailer 与背压语义。
    inner: Option<B>,
    /// least_conn 在途计数器；直连上游没有该计数器。
    counter: Option<Arc<AtomicU64>>,
    /// 每实例 pending 预算计数器；limit=0 时为空。
    pending_counter: Option<Arc<AtomicU64>>,
    /// 帧间空闲预算；仅在 `idle_sleep` 存在时读取。
    idle_timeout: Duration,
    /// 当前空闲 deadline；0 配置时为空，启用时先只保存这个无分配时间点。
    idle_deadline: Option<TokioInstant>,
    /// 惰性 timer；只有上游 body 真正返回 Pending 才创建，短响应不进入 Tokio timer wheel。
    idle_sleep: Option<Pin<Box<Sleep>>>,
    /// 原生 gRPC 才存在；关闭时生成一次 status 14 trailer。
    grpc: Option<GrpcBodyState>,
    /// inner 已结束或合成关闭 trailer 已发出。
    done: bool,
}

impl<B> Body for CountedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    /// 透明转发下一帧；正常数据只重置已有 timer，不复制 payload，也不改变上游背压与
    /// trailer 顺序。结束/错误分支立即归还计数器，避免等待 Hyper 稍后 Drop body 才释放名额。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        let mut grpc_close_message = None;
        if let Some(grpc) = self.grpc.as_mut() {
            grpc_close_message = grpc.poll_close_message(cx);
        }
        if let Some(message) = grpc_close_message {
            return Poll::Ready(Some(Ok(self.finish_grpc_close(message))));
        }

        let poll = Pin::new(
            self.inner
                .as_mut()
                .expect("counted response body exists until done"),
        )
        .poll_frame(cx);
        match poll {
            Poll::Ready(Some(Ok(frame))) => {
                // 已经进入过 Pending 才有需要重置的 idle timer。短 gRPC/unary body 常在一次
                // connection poll 中连续给出多帧；为这些同步 ready frame 逐帧读取时钟既没有
                // 超时语义收益，也会把 vDSO/Instant 转换放大为消息数倍的热路径成本。
                if self.idle_sleep.is_some() {
                    let deadline = TokioInstant::now() + self.idle_timeout;
                    self.idle_deadline = Some(deadline);
                    self.idle_sleep
                        .as_mut()
                        .expect("checked idle timer")
                        .as_mut()
                        .reset(deadline);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.grpc.take();
                self.inner.take();
                self.release_counters();
                self.done = true;
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(None) => {
                self.grpc.take();
                self.inner.take();
                self.release_counters();
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => {
                // 只有网络 body 真正 Pending 时才需要把当前 task waker 登记到连接表。关闭若
                // 恰好发生在上面的廉价检查之后，这里的 AtomicWaker“检查-注册-复查”仍会
                // 立即观察到它；若稍后发生，管理面 wake 会重新 poll 本 body。
                let close_message = self.grpc.as_mut().and_then(|grpc| grpc.subscribe_close(cx));
                if let Some(message) = close_message {
                    return Poll::Ready(Some(Ok(self.finish_grpc_close(message))));
                }
                let this = self.as_mut().get_mut();
                if poll_lazy_idle_timer(
                    this.idle_timeout,
                    &mut this.idle_deadline,
                    &mut this.idle_sleep,
                    cx,
                ) {
                    // 超时是终止状态：先丢弃 Incoming 以向 h2 上游传播 CANCEL，再注销 gRPC
                    // 长流并释放 least_conn/pending。若只返回 Err 而保留状态，恶意调用方可
                    // 继续 poll 出重复错误，且名额要拖到整个 Response 被 Drop 才能归还。
                    self.inner.take();
                    self.grpc.take();
                    self.release_counters();
                    self.done = true;
                    let error =
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "stream idle timeout");
                    Poll::Ready(Some(Err(Box::new(error) as BoxError)))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    /// 委托原 body 的结束提示，供 Hyper 保留零额外帧的快路径。
    fn is_end_stream(&self) -> bool {
        self.done || self.inner.as_ref().is_none_or(|body| body.is_end_stream())
    }

    /// 委托原 body 的大小提示，不伪造 Content-Length。
    fn size_hint(&self) -> SizeHint {
        if self.grpc.is_some() {
            // 管理面可能提前生成 trailer，不能承诺上游精确长度。
            SizeHint::default()
        } else {
            self.inner
                .as_ref()
                .map_or_else(SizeHint::default, |body| body.size_hint())
        }
    }
}

impl<B> CountedBody<B> {
    /// 终止上游流并生成唯一的标准关闭 trailer；所有关闭入口共用同一释放顺序。
    fn finish_grpc_close(&mut self, message: HeaderValue) -> Frame<Bytes> {
        // 先 Drop 上游 body 传播 h2 CANCEL，再注销 registry 并归还 least_conn/pending。
        self.inner.take();
        self.grpc.take();
        self.release_counters();
        self.done = true;
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("14"));
        trailers.insert("grpc-message", message);
        Frame::trailers(trailers)
    }

    /// 幂等归还上游名额；结束分支和 Drop 共用 `Option::take`，防止重复递减。
    fn release_counters(&mut self) {
        if let Some(counter) = self.counter.take() {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(counter) = self.pending_counter.take() {
            counter.fetch_sub(1, Ordering::Release);
        }
    }
}

impl<B> Drop for CountedBody<B> {
    /// body 正常结束或被下游提前丢弃时归还 least_conn 与 pending 名额。
    fn drop(&mut self) {
        self.release_counters();
    }
}

struct IdleTimeoutBody<B> {
    /// 直接持有具体 body，避免先擦除类型再包装造成双重 boxed body。
    inner: B,
    timeout: Duration,
    /// 首次 Pending 才建立的无分配 deadline；已有 timer 时成功 frame 才向后推进。
    deadline: Option<TokioInstant>,
    /// 首次 Pending 时才创建；避免短 body 为从未等待的超时注册 timer。
    sleep: Option<Pin<Box<Sleep>>>,
    /// 已转发 EOF/错误或已合成超时错误；Body 终止后不得再次产生帧。
    done: bool,
}

impl<B> Body for IdleTimeoutBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if self.sleep.is_some() {
                    let deadline = TokioInstant::now() + self.timeout;
                    self.deadline = Some(deadline);
                    self.sleep
                        .as_mut()
                        .expect("checked idle timer")
                        .as_mut()
                        .reset(deadline);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.done = true;
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => {
                let this = self.as_mut().get_mut();
                if poll_lazy_idle_timer(this.timeout, &mut this.deadline, &mut this.sleep, cx) {
                    self.done = true;
                    let err =
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "stream idle timeout");
                    Poll::Ready(Some(Err(Box::new(err) as BoxError)))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 在 body 真正 Pending 时才创建/轮询 idle timer。
///
/// `timeout=0` 表示关闭超时。deadline 和 `Sleep` 都在首次 Pending 时创建；已创建的 `Sleep`
/// 由后续成功 frame 原地 reset，不反复分配。返回 true 后调用方必须把 body 置为终止态。
fn poll_lazy_idle_timer(
    timeout: Duration,
    deadline: &mut Option<TokioInstant>,
    sleep: &mut Option<Pin<Box<Sleep>>>,
    cx: &mut Context<'_>,
) -> bool {
    if timeout.is_zero() {
        return false;
    }
    let deadline = *deadline.get_or_insert_with(|| TokioInstant::now() + timeout);
    let timer = sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
    timer.as_mut().poll(cx).is_ready()
}

fn inject_forward_headers(
    parts: &mut Parts,
    client_ip: IpAddr,
    cached_client_ip_header: Option<&HeaderValue>,
    trusted_inbound: bool,
    downstream_proto: &'static str,
    request_id: &str,
) -> Result<(), ForwardError> {
    // 命中连接缓存时不再执行 IP Display、HeaderValue parse/owned buffer 构造；clone 只共享
    // 不可变 header 字节。无缓存（trusted XFF 改写了 client_ip、后台内部请求或旧嵌入 API）
    // 仍使用 39-byte 栈缓冲，绝不为了 head 优化触碰/聚合 payload frame。
    let mut generated_ip_text = None;
    let client_ip_header = match cached_client_ip_header {
        Some(cached) => cached.clone(),
        None => {
            let text = IpText::new(client_ip);
            let value = HeaderValue::from_bytes(text.as_bytes()).map_err(|e| {
                ForwardError::BadGateway(anyhow::anyhow!("invalid client ip header: {e}"))
            })?;
            generated_ip_text = Some(text);
            value
        }
    };
    // X-Forwarded-For(review L6):可信入站则在原链后【追加】本跳客户端;不可信则用真实客户端 IP 覆盖
    // (忽略可伪造的入站 XFF)。X-Real-IP 始终为算出的真实客户端。
    let xff_header = match parts
        .headers
        .get(X_FORWARDED_FOR)
        .and_then(|v| v.to_str().ok())
    {
        Some(existing) if trusted_inbound && !existing.trim().is_empty() => {
            // 可信代理链本来就必须产生合并后的新值；这里只在该慢路径分配合并 String。
            let client_ip_text = generated_ip_text
                .get_or_insert_with(|| IpText::new(client_ip))
                .as_str();
            let xff = format!("{existing}, {client_ip_text}");
            header_value(&xff, "x-forwarded-for")?
        }
        // HeaderValue clone 共享底层字节；不可信/无 XFF 的常见路径无需再复制 IP String 并
        // 做第二次 header 解析。两个 header 仍是独立 map entry，后续修改不会互相影响。
        _ => client_ip_header.clone(),
    };
    parts.headers.insert(X_FORWARDED_FOR, xff_header);
    parts.headers.insert(X_REAL_IP, client_ip_header);
    parts.headers.insert(
        X_FORWARDED_PROTO,
        HeaderValue::from_static(downstream_proto),
    );
    // request-id(§22):入站值保留到 x-original-request-id,网关始终写自己的权威 x-request-id。
    if let Some(original) = parts.headers.get(X_REQUEST_ID).cloned() {
        parts
            .headers
            .entry(X_ORIGINAL_REQUEST_ID)
            .or_insert(original);
    }
    parts
        .headers
        .insert(X_REQUEST_ID, header_value(request_id, "x-request-id")?);
    Ok(())
}

/// `IpAddr` 规范文本的栈缓冲。IPv6 最长形式是 8 组四位十六进制加 7 个冒号，共 39 字节；
/// IPv4 最多 15 字节。只接收 `IpAddr` 的标准 `Display` 输出，因此内容恒为 ASCII/UTF-8。
struct IpText {
    bytes: [u8; 39],
    len: usize,
}

impl IpText {
    #[inline]
    fn new(ip: IpAddr) -> Self {
        let mut text = Self {
            bytes: [0; 39],
            len: 0,
        };
        // 缓冲区恰好覆盖标准库 IpAddr Display 的最大输出，fmt::Error 表示内部上界假设失效，
        // 属于编程错误而不是请求输入错误。
        fmt::write(&mut text, format_args!("{ip}"))
            .expect("IpAddr display must fit the 39-byte stack buffer");
        text
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[inline]
    fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("IpAddr display is ASCII")
    }
}

impl fmt::Write for IpText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn render_request_headers(
    ops: &[RequestHeaderSet],
    variables: &crate::variable::VariablePlan,
    eval_ctx: &crate::variable::EvalContext<'_>,
) -> Result<Vec<(HeaderName, HeaderValue)>, ForwardError> {
    ops.iter()
        .map(|op| {
            let value = op.value.render(eval_ctx, variables);
            Ok((op.name.clone(), header_value(&value, op.name.as_str())?))
        })
        .collect()
}

fn sanitize_hop_headers(parts: &mut Parts, keep_upgrade: bool) {
    let connection_tokens = parts
        .headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|token| token.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for token in connection_tokens {
        if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            if keep_upgrade && name == UPGRADE {
                continue;
            }
            parts.headers.remove(name);
        }
    }

    for name in [
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        TRANSFER_ENCODING,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
    ] {
        parts.headers.remove(name);
    }
    if keep_upgrade {
        parts
            .headers
            .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    } else {
        parts.headers.remove(CONNECTION);
        parts.headers.remove(UPGRADE);
    }
    sanitize_te(parts);
}

/// 按最终上游协议分工清理请求 hop-by-hop header。
///
/// HTTP/2 的 Hyper client 在真正编码 frame 的同一所有权链上强制移除 `Connection` 及其
/// token、`Keep-Alive`、`Proxy-Connection`、`Transfer-Encoding`、`Upgrade`，并只允许
/// `TE: trailers`。那一步无法绕过，也最接近 wire；Nate 不在前一层重复扫描这些字段，只补
/// Hyper 不负责、但不能泄漏给 origin 的代理认证头。整个过程原地修改 HeaderMap，不复制
/// header value，更不读取 body。HTTP/1.1 则继续由 Nate 完整清洗。
#[inline]
fn sanitize_hop_headers_for_upstream(
    parts: &mut Parts,
    keep_upgrade: bool,
    upstream_version: http::Version,
) {
    if upstream_version == http::Version::HTTP_2 {
        parts.headers.remove(PROXY_AUTHENTICATE);
        parts.headers.remove(PROXY_AUTHORIZATION);
        return;
    }
    sanitize_hop_headers(parts, keep_upgrade);
}

fn sanitize_te(parts: &mut Parts) {
    let keep_trailers = parts
        .headers
        .get(TE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
        })
        .unwrap_or(false);
    if keep_trailers {
        parts
            .headers
            .insert(TE, HeaderValue::from_static("trailers"));
    } else {
        parts.headers.remove(TE);
    }
}

fn header_value(value: &str, name: &str) -> Result<HeaderValue, ForwardError> {
    HeaderValue::from_str(value)
        .map_err(|e| ForwardError::BadGateway(anyhow::anyhow!("invalid {name} header: {e}")))
}

#[path = "../../tests/unit/proxy_forward.rs"]
#[cfg(test)]
mod tests;
