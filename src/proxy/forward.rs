//! 上游流式转发:StripPrefix + hop-by-hop 头处理 + body 流式直通(不全量 buffer,少拷贝)。

#[cfg(feature = "upstream-orca")]
mod orca;

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http::header::{
    HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE,
    EXPECT, HOST, TE, TRANSFER_ENCODING, UPGRADE,
};
use http::request::Parts;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode};
use hyper_rustls::{FixedServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use sha2::{Digest as _, Sha256};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, Sleep};
use tokio_rustls::rustls::pki_types::ServerName;
use tower_service::Service;

use crate::config::GatewaySnapshot;
use crate::config::ProxyRuntime;
#[cfg(feature = "ext-proc")]
use crate::extensions::ext_proc::{ExtProcError, ExtProcPlan, ExtProcWire};
use crate::extensions::external_plugin::{ExternalPlugin, ExternalPluginPayload};
use crate::observability::metrics::DubboMetric;
use crate::protocols::dubbo::{DubboError, DubboResult};
use crate::proxy::grpc_browser::{BrowserGrpc, BrowserGrpcError};
use crate::routing::{strip_n_segments, ExtAuthzPolicy, MirrorPolicy, RequestHeaderOp, Route};
use crate::runtime::connections::{CloseNotified, ConnGuard, ConnectionRegistry, LongProto};
use crate::security::opa::{OpaInputPayload, OpaPolicy};
use crate::tls::UpstreamTlsProfile;
use crate::upstream::{NextUpstreamPolicy, PassiveHealthPolicy, UpstreamProtocol};
use crate::{full_body, BoxBody, BoxError};

type RawUpstreamHttpClient =
    Client<BudgetedConnector<FixedDestinationConnector<HttpsConnector<HttpConnector>>>, BoxBody>;
type RawUpstreamH2cConnector = BudgetedConnector<FixedDestinationConnector<HttpConnector>>;

static DEFAULT_UPSTREAM_HTTPS_CONNECTOR: OnceLock<HttpsConnector<HttpConnector>> = OnceLock::new();

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

/// 业务作用：启动 WebSocket 活动时间的共享粗粒度单调时钟。
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
    /// 业务作用：建立 H2 连接分片的冷启动协调器，使同一分片只允许一个请求负责首次建连。
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(H2_SHARD_COLD),
            changed: Notify::new(),
        })
    }

    /// 业务作用：请求错误通常表示池中 transport 已不可用；仅由一个观察者把 shard 退回 cold，下一次
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
    /// 业务作用：发布本次冷启动的连接可用状态并唤醒等待者，失败时允许重新竞争建连。
    fn finish(mut self, ready: bool) {
        self.gate.state.store(
            if ready {
                H2_SHARD_READY
            } else {
                H2_SHARD_COLD
            },
            Ordering::Release,
        );
        self.completed = true;
        self.gate.changed.notify_waiters();
    }
}

impl Drop for H2ColdStartLeader<'_> {
    /// 业务作用：冷启动领跑者未完成时恢复待建连状态并唤醒等待者，防止连接分片永久卡在准备态。
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
    /// 非 HTTP 服务即使被扩展误引用，也不得发出 HTTP 字节。
    reject_non_http: bool,
}

impl UpstreamHttpClient {
    /// 业务作用：仅向 HTTP 兼容服务发起请求，并协调共享 H2 首次连接。
    ///
    /// 参数说明：
    /// - `request`：已完成上游头处理的请求和实体流。
    ///
    /// 返回：流式 HTTP 响应；记录协议误引用、拨号或协议失败均拒绝且不降级。
    async fn request(
        &self,
        request: Request<BoxBody>,
    ) -> Result<Response<UpstreamResponseBody>, BoxError> {
        if self.reject_non_http {
            return Err("CGI service cannot be used by an HTTP-only callout".into());
        }
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
    /// 业务作用：建立 H2c 活动流计数与空闲通知，供传输关闭和请求准入共用。
    fn new() -> Arc<Self> {
        Arc::new(Self {
            active_streams: AtomicU64::new(0),
            idle_since_ms: AtomicU64::new(pool_clock_millis()),
            changed: Notify::new(),
        })
    }

    /// 业务作用：在 H2c 连接尚未进入关闭态时占用活动流名额，避免新流进入已经排空的连接。
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

    /// 业务作用：由 RAII guard 结束已登记的 stream；最后一个 stream 退出时发布空闲时间并唤醒回收器。
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
    /// 业务作用：幂等结束当前活动流占位，在最后一条流退出时通知空闲管理器。
    #[inline]
    fn finish(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        connection.activity.finish_stream();
    }
}

impl Drop for H2cActiveStreamGuard {
    /// 业务作用：结束 H2c 活动流计数，使连接排空不受被取消请求的残留占位阻塞。
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

    /// 业务作用：按下游轮询推进正文流，把数据、trailers、失败和结束状态交给统一 HTTP 管线。
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

    /// 业务作用：向 HTTP 编码层报告流是否已经结束，避免省略尚未发送的正文或 trailers。
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    /// 业务作用：向 HTTP 编码层提供剩余实体长度约束，供帧传输选择定长或流式编码。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 各上游 transport 共用的静态响应 body 枚举；避免为了统一协议分支先 box
/// `Incoming`，最外层 `CountedBody` 仍只做一次必要类型擦除。
enum UpstreamResponseBody {
    Pooled(Incoming),
    DirectH2c(DirectH2cBody),
    #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
    Cgi(crate::protocols::cgi::CgiBody),
    #[cfg(feature = "http3")]
    Http3(super::http3_upstream::UpstreamH3Body),
}

impl Body for UpstreamResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：保持所选 transport 的流式背压及失败语义。
    ///
    /// 参数说明：
    /// - `cx`：当前响应消费任务的唤醒上下文。
    ///
    /// 返回：一个实体帧、协议错误、等待或已经确认的流结束。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut *self {
            Self::Pooled(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|frame| frame.map(|frame| frame.map_err(|error| Box::new(error) as BoxError))),
            Self::DirectH2c(body) => Pin::new(body).poll_frame(cx),
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            Self::Cgi(body) => Pin::new(body).poll_frame(cx),
            #[cfg(feature = "http3")]
            Self::Http3(body) => Pin::new(body).poll_frame(cx),
        }
    }

    /// 业务作用：将协议结束状态传递给响应期资源回收层。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅在具体 transport 确认结束时为 true。
    fn is_end_stream(&self) -> bool {
        match self {
            Self::Pooled(body) => body.is_end_stream(),
            Self::DirectH2c(body) => body.is_end_stream(),
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            Self::Cgi(body) => body.is_end_stream(),
            #[cfg(feature = "http3")]
            Self::Http3(body) => body.is_end_stream(),
        }
    }

    /// 业务作用：保留具体协议的可信实体长度提示，不由响应头推测结束。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层提供的长度界；CGI 在会话完成前不声明精确长度。
    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Pooled(body) => body.size_hint(),
            Self::DirectH2c(body) => body.size_hint(),
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            Self::Cgi(body) => body.size_hint(),
            #[cfg(feature = "http3")]
            Self::Http3(body) => body.size_hint(),
        }
    }
}

type DirectH2cSender = hyper::client::conn::http2::SendRequest<BoxBody>;

/// direct h2c 每请求上传 task 的轻量 executor。
///
/// Hyper 会把 `H2ClientFuture` 按值交给 executor；默认 `TokioExecutor` 随后又把这个较大的
/// future 搬进 Tokio task storage。先装箱可让 task 构造只移动一个指针，request body 的取消、
/// DATA/trailer 与 flow-control 仍由同一个 future 驱动。
#[derive(Clone, Copy, Debug, Default)]
struct BoxedH2ClientExecutor;

impl<Fut> hyper::rt::Executor<Fut> for BoxedH2ClientExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    /// 业务作用：把 Hyper 的上游 H2 上传 future 交给 Tokio，并避免 task 建立时复制整块状态机。
    ///
    /// 参数说明：
    /// - `future`：是 Hyper 为单个 H2 request body 创建的可取消上传任务。
    ///
    /// 返回：无返回值；任务在当前 Tokio runtime 异步执行，完成或取消时释放 Box 与 task storage。
    fn execute(&self, future: Fut) {
        tokio::spawn(Box::pin(future));
    }
}

struct DirectH2cConnection {
    sender: DirectH2cSender,
    activity: Arc<H2cConnectionActivity>,
}

struct DirectH2cState {
    current: ArcSwapOption<DirectH2cConnection>,
    connector: RawUpstreamH2cConnector,
    policy: HttpPoolPolicy,
}

impl DirectH2cState {
    /// 业务作用：向已选中的真实实例建立明文 HTTP/2 prior-knowledge transport，同时保留
    /// 请求 URI 中面向业务虚拟主机的 authority。
    ///
    /// 参数说明：
    /// - `uri`：是待发送请求的完整 URI；connector 已固定实际 Service Endpoint。
    ///
    /// 返回：握手成功后原子发布可复用 sender；拨号、预算或 HTTP/2 握手失败时不发布半成品连接。
    async fn connect(&self, uri: http::Uri) -> Result<(), BoxError> {
        let mut connector = self.connector.clone();
        std::future::poll_fn(|cx| connector.poll_ready(cx)).await?;
        let io = connector.call(uri).await?;
        let mut builder = hyper::client::conn::http2::Builder::new(BoxedH2ClientExecutor);
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

/// 业务作用：等待 direct h2c transport 连续空闲到配置上限；新 stream 与最后一个 body 结束都会唤醒并
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
            // 单次 CAS 把“确认空闲”和“决定关闭”变成同一个原子动作，避免新 stream
            // 在空闲检查之后进入、却被连接关闭分支中断。
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
    /// 业务作用：通过选定上游 HTTP 客户端发起请求，保留连接预算和统一响应流类型。
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
                            UpstreamResponseBody::DirectH2c(DirectH2cBody {
                                inner,
                                active,
                            })
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
    /// 业务作用：创建一个物理连接预算。
    ///
    /// 参数说明：
    /// - `limit`: 物理 socket 上限；0 表示不限制。
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicU64::new(0),
            limit: AtomicU64::new(limit.min(u64::MAX as usize) as u64),
        })
    }

    /// 业务作用：更新热配置上限；不会粗暴关闭已有连接，新拨号会按新值判定。
    ///
    /// 参数说明：
    /// - `limit`: 新物理 socket 上限；0 表示不限制。
    fn set_limit(&self, limit: usize) {
        self.limit
            .store(limit.min(u64::MAX as usize) as u64, Ordering::Release);
    }

    /// 业务作用：非阻塞占用一个 dial 名额。满载必须快速失败，不能在 connector 内形成隐藏等待队列。
    pub(crate) fn try_acquire(
        self: &Arc<Self>,
    ) -> Result<PhysicalConnectionSlot, ConnectionLimitReached> {
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
pub(crate) struct ConnectionLimitReached;

impl fmt::Display for ConnectionLimitReached {
    /// 业务作用：向连接层提供固定的物理连接容量拒绝信息。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("upstream physical connection limit reached")
    }
}

impl std::error::Error for ConnectionLimitReached {}

/// 一个已占用的物理 transport 名额。
pub(crate) struct PhysicalConnectionSlot {
    /// 跨 generation 共享的预算；Drop 是唯一归还路径。
    budget: Arc<PhysicalConnectionBudget>,
}

/// 让 Hyper 的请求 URI 可承载业务 authority，同时把物理连接固定到已选择的上游实例。
#[derive(Clone)]
struct FixedDestinationConnector<C> {
    inner: C,
    destination_scheme: http::uri::Scheme,
    destination_authority: http::uri::Authority,
}

impl<C> FixedDestinationConnector<C> {
    /// 业务作用：冻结当前健康实例的实际拨号 destination，供连接器与请求 authority 解耦。
    ///
    /// 参数说明：
    /// - `inner`：执行实际 TCP/TLS 连接
    /// - `destination`：是已验证的实例 base URI。
    ///
    /// 返回：destination 含 scheme 与 authority 时返回连接器；内部调用方传入坏实例时立即失败。
    fn new(inner: C, destination: &str) -> Self {
        let uri = destination
            .parse::<http::Uri>()
            .expect("validated upstream destination URI");
        Self {
            inner,
            destination_scheme: uri
                .scheme()
                .expect("validated upstream destination has scheme")
                .clone(),
            destination_authority: uri
                .authority()
                .expect("validated upstream destination has authority")
                .clone(),
        }
    }
}

impl<C> Service<http::Uri> for FixedDestinationConnector<C>
where
    C: Service<http::Uri>,
{
    type Response = C::Response;
    type Error = C::Error;
    type Future = C::Future;

    /// 业务作用：沿用底层 connector 的背压与就绪状态，不为 authority 改写另建队列。
    ///
    /// 参数说明：
    /// - `cx`：是 Tower 调度上下文。
    ///
    /// 返回：原样返回底层 connector 的就绪或错误状态。
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// 业务作用：仅在物理连接边界把业务 URI 的 destination 换回已选择实例，确保
    /// `preserve_host` 不改变 DNS、端口或 TLS 连接目标。
    ///
    /// 参数说明：
    /// - `uri`：可携带客户端 Host 作为 HTTP/2 authority，path/query 保持不变。
    ///
    /// 返回：返回底层 connector future；destination 来自已验证实例，因此重建 URI 不失败。
    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let mut parts = uri.into_parts();
        parts.scheme = Some(self.destination_scheme.clone());
        parts.authority = Some(self.destination_authority.clone());
        let destination = http::Uri::from_parts(parts)
            .expect("validated destination scheme and authority rebuild URI");
        self.inner.call(destination)
    }
}

impl Drop for PhysicalConnectionSlot {
    /// 业务作用：归还物理连接预算，使失败连接与正常关闭具有相同的容量结算。
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
    /// 业务作用：包装 connector；调用方保证 budget 与完整 health_key/protocol 绑定。
    fn new(inner: C, budget: Arc<PhysicalConnectionBudget>) -> Self {
        Self {
            inner,
            budget,
        }
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

    /// 业务作用：查询底层连接器的接入能力，使连接建立遵守服务背压。
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::poll_ready(&mut self.inner, cx).map_err(Into::into)
    }

    /// 业务作用：在连接预算成立后拨号固定 URI，失败与取消均通过租约归还连接名额。
    fn call(&mut self, uri: http::Uri) -> Self::Future {
        // 必须先占位再创建 inner future；`inner.call` 可能立即开始拨号，不能先产生 I/O 再等待额度。
        let slot = match self.budget.try_acquire() {
            Ok(slot) => slot,
            Err(error) => {
                return Box::pin(async move {
                    Err(Box::new(error) as BoxError)
                })
            }
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
    /// 业务作用：在底层连接与调用方缓冲之间推进异步读取，保留 Pending 和连接错误的传播语义。
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<I: HyperWrite + Unpin> HyperWrite for BudgetedIo<I> {
    /// 业务作用：向底层连接推进异步写入，通过 Pending 将背压传回调用方。
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    /// 业务作用：驱动已提交字节的异步刷新，把底层阻塞和传输错误传回连接状态机。
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    /// 业务作用：推进写方向的有序关闭，使待发送数据与底层连接关闭遵守异步协议。
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl<I: Connection> Connection for BudgetedIo<I> {
    /// 业务作用：向 HTTP 客户端暴露底层连接的协议属性，保持连接池复用判定一致。
    fn connected(&self) -> Connected {
        // 保留 HttpsConnector 的 negotiated_h2/proxy 元数据；重建 `Connected::new` 会破坏 ALPN h2 选择。
        self.inner.connected()
    }
}

/// 业务作用：按上游 protocol 配置决定给上游请求打什么 HTTP 版本 hint。
/// hyper-util legacy client 据请求版本 + 连接器 ALPN 选择 h1/h2。
fn upstream_request_version(protocol: UpstreamProtocol, parts: &Parts) -> http::Version {
    match protocol {
        UpstreamProtocol::H1 => http::Version::HTTP_11,
        UpstreamProtocol::Fastcgi | UpstreamProtocol::Uwsgi | UpstreamProtocol::Scgi => {
            http::Version::HTTP_11
        }
        // h2(TLS 经 ALPN)/ h2c(明文 prior-knowledge)都用 HTTP_2 版本 hint。
        UpstreamProtocol::H2 | UpstreamProtocol::H2c => http::Version::HTTP_2,
        UpstreamProtocol::H3 => http::Version::HTTP_3,
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

/// 业务作用：是否 gRPC 请求(content-type 以 `application/grpc` 开头)。
fn is_grpc_request(parts: &Parts) -> bool {
    has_native_grpc_content_type(&parts.headers)
}

/// 业务作用：精确识别 native gRPC media type，排除需要不同 framing 的 grpc-web。
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
    /// LLM provider 的显式模型上游；None 使用 route 常规 URI/template。
    pub upstream_override: Option<&'a str>,
    /// provider API path；设置时不继承下游 query，防客户端参数越过统一契约。
    pub path_override: Option<&'a str>,
    /// EPP 已验证的 endpoint 子集；None 表示普通 LB 或允许的依赖故障放行。
    pub inference_endpoints: Option<&'a InferenceEndpointSelection>,
    /// 真实客户端 IP（PROXY protocol / 可信 XFF 算出,或 socket 对端）；用于 XFF/`${remote_addr}`。
    pub client_ip: IpAddr,
    /// 与 `client_ip` 已核对相等的连接级预编码值；普通直连/PROXY protocol 热路径可复用，
    /// trusted XFF 为每 stream 改写地址时为 None，并保持原逐请求安全路径。
    pub client_ip_header: Option<HeaderValue>,
    /// 直连入站是否可信（决定是否采信入站 traceparent）。
    pub trusted_inbound: bool,
    pub downstream_proto: &'static str,
    /// mTLS:本连接是否出示了经 CA 校验的客户端证书;true 时向上游注入 `X-Client-Cert-Verified`。
    pub client_cert_verified: bool,
    pub request_id: &'a str,
    /// 已认证长连接 consumer；只用于 WS/gRPC registry，不进入上游或日志高基数标签。
    pub consumer: Option<Arc<str>>,
    pub downstream_upgrade: super::DownstreamUpgrade,
    /// WebSocket 等升级长连接的 `limit_conn` guard。普通 HTTP 响应由 proxy 外层 body 包装释放。
    pub limit_conn_guards: Vec<super::LimitConnGuard>,
    /// Realtime 等 route 可收紧全局 WebSocket 最长寿命；None 使用 proxy 默认值。
    pub websocket_max_lifetime_ms: Option<u64>,
    /// Realtime 等 route 可独立收紧 WebSocket `(单帧, 单消息)` 字节门；None 沿用 route 策略。
    pub websocket_frame_limits: Option<(u64, u64)>,
    /// 当前请求 server span；后台/内部请求可为 None，普通上游 attempt 据此建 client child。
    pub trace: Option<&'a crate::observability::telemetry::ServerTrace>,
}

/// EPP 返回的单个 endpoint 约束；纯 IP 允许池中该 Pod 的任一声明端口。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg(feature = "inference-gateway")]
enum InferenceEndpointTarget {
    Ip(IpAddr),
    Socket(std::net::SocketAddr),
}

/// 已去重、受数量硬门约束的 EPP endpoint 子集。
pub(super) struct InferenceEndpointSelection {
    #[cfg(feature = "inference-gateway")]
    targets: Arc<[InferenceEndpointTarget]>,
}

impl InferenceEndpointSelection {
    /// 业务作用：严格解析 EPP 的逗号分隔目标集合，只接受 IP 或 IP:port，拒绝主机名、UDS
    /// 和空元素，防止扩展把请求导向池目录之外。
    ///
    /// 参数说明：
    /// - `raw`：来自授权 header 或 `envoy.lb` metadata
    /// - `max_targets`：是 route 硬门。
    ///
    /// 返回：至少一个唯一目标且全部语法合法时返回不可变集合，否则返回协议错误。
    #[cfg(feature = "inference-gateway")]
    pub(super) fn parse(raw: &str, max_targets: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !raw.is_empty() && raw.len() <= 16 * 1024,
            "EPP endpoint selection has invalid length"
        );
        let mut targets = Vec::new();
        let mut unique = std::collections::HashSet::new();
        for item in raw.split(',') {
            let item = item.trim();
            anyhow::ensure!(
                !item.is_empty(),
                "EPP endpoint selection contains an empty target"
            );
            let target = if let Ok(address) = item.parse::<IpAddr>() {
                InferenceEndpointTarget::Ip(address)
            } else if let Ok(address) = item.parse::<std::net::SocketAddr>() {
                InferenceEndpointTarget::Socket(address)
            } else {
                anyhow::bail!("EPP endpoint selection must contain only IP or IP:port targets");
            };
            if unique.insert(target) {
                targets.push(target);
                anyhow::ensure!(
                    targets.len() <= max_targets,
                    "EPP endpoint selection exceeds route target limit"
                );
            }
        }
        anyhow::ensure!(!targets.is_empty(), "EPP endpoint selection is empty");
        Ok(Self {
            targets: Arc::from(targets),
        })
    }

    /// 业务作用：把 EPP 子集与当前快照中的真实池实例求交，保证重试、健康降级和负载均衡
    /// 都不能越出扩展授权范围。
    ///
    /// 参数说明：
    /// - `health_key`：是候选实例 URI；InferencePool 静态实例不携带额外 TLS 身份后缀。
    ///
    /// 返回：候选 authority 命中任一精确 socket 或同 IP 目标时返回 true。
    #[cfg(feature = "inference-gateway")]
    fn permits(&self, health_key: &str) -> bool {
        let raw_uri = health_key.split('#').next().unwrap_or(health_key);
        let Ok(uri) = raw_uri.parse::<http::Uri>() else {
            return false;
        };
        let Some(authority) = uri.authority() else {
            return false;
        };
        let Ok(ip) = authority.host().parse::<IpAddr>() else {
            return false;
        };
        let port = authority.port_u16().or_else(|| match uri.scheme_str() {
            Some("http") => Some(80),
            Some("https") => Some(443),
            _ => None,
        });
        self.targets.iter().any(|target| match target {
            InferenceEndpointTarget::Ip(expected) => *expected == ip,
            InferenceEndpointTarget::Socket(expected) => {
                expected.ip() == ip && Some(expected.port()) == port
            }
        })
    }

    /// 业务作用：未编译推理扩展时不能产生任何 endpoint 授权，保持转发约束失败关闭。
    ///
    /// 参数说明：
    /// - `_health_key`：普通上游选择流程提供的候选地址。
    ///
    /// 返回：始终拒绝；该构建也会在配置阶段拒绝 InferencePool 声明。
    #[cfg(not(feature = "inference-gateway"))]
    fn permits(&self, _health_key: &str) -> bool {
        false
    }
}

/// forward 内部统一请求体。
///
/// 业务作用：把 Hyper TCP/H2 `Incoming` 与 HTTP/3 request stream 擦除成同一流式 body，
/// 让全部 route/filter/upstream 只保留一套治理管线；擦除只移动 `Bytes` frame，不聚合 payload。
pub(crate) type ForwardBody = BoxBody;

/// 业务作用：从下游 `Cookie` 头按名取值,供一致性哈希键与会话亲和令牌读取。
///
/// 借用式扫描:不构造 map、不分配字符串。cookie 名按 RFC 6265 大小写敏感比较——
/// 大小写不敏感会让 `sid` 与 `SID` 互相顶替,给攻击者制造钉住实例的机会。
///
/// 参数说明：
/// - `parts`: 下游请求 head。
/// - `name`: 构建期声明的 cookie 名。
///
/// 返回：命中时返回借用值;缺失或非 UTF-8 时返回 `None`。
fn request_cookie_value<'a>(parts: &'a Parts, name: &str) -> Option<&'a str> {
    for header in parts.headers.get_all(http::header::COOKIE) {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for item in header.split(';') {
            let item = item.trim();
            let Some((key, value)) = item.split_once('=') else {
                continue;
            };
            if key.trim() == name {
                return Some(value.trim());
            }
        }
    }
    None
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
    trace: Option<&'a crate::observability::telemetry::ServerTrace>,
    /// 本次真实上游实例，仅写 span attribute，不作为 metric label。
    upstream: &'a str,
    /// retry 序号，从 1 开始。
    attempt: usize,
    /// 由本请求权威 request-id 计算的无状态 client 分片提示；retry 保持同一 shard 亲和。
    client_shard_hint: u64,
    /// 原生 gRPC 主上游响应的长流治理；内部/插件调用及非 gRPC 请求为空。
    grpc_drain: Option<&'a GrpcDrainContext>,
    /// 原始下游使用的浏览器 RPC wire mode；上游始终看到 native gRPC。
    browser_grpc: Option<BrowserGrpc>,
    /// Connect unary request/response 聚合预算；streaming 模式不使用该值。
    browser_grpc_unary_limit: u64,
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
    client_trace: Option<crate::observability::telemetry::ClientTrace>,
}

#[derive(Debug)]
pub(super) enum ForwardError {
    /// 显式请求解码的本地输入失败，不参与上游重试或健康判定。
    RequestDecompression(crate::io::request_decompression::Rejected),
    /// 请求无法无歧义映射为固定脚本协议；不计为上游故障。
    #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
    CgiInput(StatusCode, &'static str),
    /// gRPC-Web/Connect 客户端格式错误或上游 native gRPC 响应协议错误。
    BrowserGrpc(BrowserGrpcError),
    /// 本地流量预算或等待期限拒绝；不能作为后端故障、重试或熔断依据。
    LocalTraffic,
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
    /// 命中实例所属的逻辑服务名;直连 `http(s)://` 上游为 None(无 LB 也就无会话保持)。
    /// 响应期据此定位服务级会话保持策略,避免为找策略再解析一次上游目标。
    pub service: Option<Arc<str>>,
    /// 请求带入且已通过当前服务期限门禁的会话令牌；响应期据此保留首次建立时间。
    pub affinity: Option<crate::upstream::SessionAffinityToken>,
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

enum ExtAuthzRuntimeGate {
    Cached(super::ExtAuthzCachedDecision),
    CircuitOpen,
    Capacity,
    Call(ExtAuthzCallGuard),
}

struct ExtAuthzCallGuard {
    runtime: Arc<super::ExtAuthzRuntime>,
    key: String,
    fingerprint: [u8; 32],
    epoch: Arc<()>,
    half_open: bool,
    finished: std::sync::atomic::AtomicBool,
    _workspace_lease: Option<crate::control::ownership::state::Lease>,
}

impl ExtAuthzCallGuard {
    /// 业务作用：在锁内保留后端代次和状态名额，外呼未结束时不能被空闲回收。
    ///
    /// 参数说明：
    /// - `runtime`：定位后端
    /// - `key`：定位后端
    /// - `state`：是同锁内的当前策略状态。
    ///
    /// 返回：取消安全的外呼凭证，所有终止分支自动归还活动计数。
    fn new(
        runtime: Arc<super::ExtAuthzRuntime>,
        key: &str,
        state: &mut super::ExtAuthzBackendState,
    ) -> Self {
        state.active_calls = state.active_calls.saturating_add(1);
        Self {
            runtime,
            key: key.to_owned(),
            fingerprint: state.policy_fingerprint,
            epoch: state.epoch.clone(),
            half_open: state.half_open_probe,
            finished: std::sync::atomic::AtomicBool::new(false),
            _workspace_lease: state._workspace_lease.clone(),
        }
    }
}

impl Drop for ExtAuthzCallGuard {
    /// 业务作用：外呼完成、超时或取消都归还本次半开探测权，不能留下永不恢复的探测位。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只解除相同策略的探测占位，不改动新策略状态或缓存。
    fn drop(&mut self) {
        if let Some(state) = self.runtime.states.lock().get_mut(&self.key) {
            if state.policy_fingerprint == self.fingerprint
                && Arc::ptr_eq(&state.epoch, &self.epoch)
            {
                if self.half_open && !self.finished.load(Ordering::Acquire) {
                    state.half_open_probe = false;
                }
                state.active_calls = state.active_calls.saturating_sub(1);
            }
        }
    }
}

impl ForwardError {
    /// 业务作用：区分包含本地请求整形的混合超时与可归因上游的响应头超时。
    ///
    /// 参数说明：
    /// - `pacing`：本次转发由网关生成的请求整形事实。
    ///
    /// 返回：混入本地等待时保守记为本地拒绝；否则沿用上游超时，不推测未观测到的后端耗时。
    pub(super) fn timeout_for(
        pacing: Option<&crate::runtime::traffic_limit::pacing::RequestPacing>,
    ) -> Self {
        if pacing.is_some_and(|pacing| pacing.was_delayed()) {
            crate::runtime::traffic_limit::metrics::DEADLINE.fetch_add(1, Ordering::Relaxed);
            Self::LocalTraffic
        } else {
            Self::Timeout
        }
    }

    /// 业务作用：把转发失败映射为稳定下游状态，不把客户端 CGI 输入计为后端故障。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：对应错误类型的 HTTP 状态。
    pub(super) fn status(&self) -> StatusCode {
        match self {
            Self::RequestDecompression(error) => error.status(),
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            Self::CgiInput(status, _) => *status,
            Self::BrowserGrpc(error) => error.status(),
            Self::LocalTraffic => StatusCode::SERVICE_UNAVAILABLE,
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::NoHealthyUpstream(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Overloaded => StatusCode::SERVICE_UNAVAILABLE,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// 业务作用：提供不含内部错误或请求参数的响应描述。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定低敏错误说明。
    pub(super) fn message(&self) -> &'static str {
        match self {
            Self::RequestDecompression(error) => error.message(),
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            Self::CgiInput(_, message) => message,
            Self::BrowserGrpc(error) => error.message(),
            Self::LocalTraffic => "traffic stream resource limit reached",
            Self::BadGateway(_) => "bad gateway",
            Self::NoHealthyUpstream(_) => "no healthy upstream",
            Self::Overloaded => "upstream overloaded",
            Self::Timeout => "upstream timeout",
        }
    }

    /// 业务作用：区分调用方输入拒绝与后端不可用事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有后端错误才归入上游故障。
    pub(super) fn is_upstream_error(&self) -> bool {
        match self {
            Self::RequestDecompression(_) => false,
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            Self::CgiInput(_, _) => false,
            Self::BrowserGrpc(error) => error.is_upstream_error(),
            Self::LocalTraffic | Self::Overloaded => false,
            _ => true,
        }
    }

    /// 业务作用：向统一回退策略提供固定原因，不输出用户输入。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：错误类型对应的稳定原因。
    pub(super) fn fallback_reason(&self) -> &'static str {
        match self {
            Self::RequestDecompression(_) => "client_content_error",
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            Self::CgiInput(_, _) => "client_protocol_error",
            Self::BrowserGrpc(error) if error.is_upstream_error() => "upstream_protocol_error",
            Self::BrowserGrpc(_) => "client_protocol_error",
            Self::LocalTraffic => "traffic_limited",
            Self::BadGateway(_) => "upstream_error",
            Self::NoHealthyUpstream(_) => "no_healthy_upstream",
            Self::Overloaded => "upstream_overloaded",
            Self::Timeout => "timeout",
        }
    }
}

impl fmt::Display for ForwardError {
    /// 业务作用：生成内部诊断描述，保留后端错误链。
    ///
    /// 参数说明：
    /// - `f`：格式输出目标。
    ///
    /// 返回：格式写入状态。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            Self::CgiInput(_, message) => f.write_str(message),
            Self::RequestDecompression(error) => write!(f, "{error}"),
            Self::BrowserGrpc(error) => write!(f, "browser gRPC protocol error: {error}"),
            Self::LocalTraffic => f.write_str("traffic stream resource limit reached"),
            Self::BadGateway(e) => write!(f, "bad gateway: {e:#}"),
            Self::NoHealthyUpstream(svc) => write!(f, "no healthy upstream for `{svc}`"),
            Self::Overloaded => f.write_str("upstream pending limit reached"),
            Self::Timeout => f.write_str("upstream timeout"),
        }
    }
}

impl std::error::Error for ForwardError {}

/// 业务作用：把传输错误归一成稳定网关错误码，并分离本地输入拒绝与后端故障。
///
/// 参数说明：
/// - `context`: 低基数调用场景，例如 `client request`/`ext_authz request`。
/// - `error`: Hyper 返回的错误；source chain 中若含物理连接预算错误则映射 503。
///
/// 返回：物理容量及流量保护拒绝为503，CGI参数拒绝为400，其它错误保留诊断链并映射502。
fn map_client_error(context: &'static str, error: BoxError) -> ForwardError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error.as_ref());
    while let Some(current) = source {
        if let Some(error) = current.downcast_ref::<crate::io::request_decompression::Rejected>() {
            return ForwardError::RequestDecompression(*error);
        }
        if current
            .downcast_ref::<crate::runtime::traffic_limit::resources::Rejected>()
            .is_some()
        {
            // 本地流量门仍可能经过 Hyper 包装；必须按类型恢复归因，不能凭错误字符串猜测。
            return ForwardError::LocalTraffic;
        }
        #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
        if current
            .downcast_ref::<crate::protocols::cgi::InputRejected>()
            .is_some()
        {
            return ForwardError::CgiInput(
                StatusCode::BAD_REQUEST,
                "CGI request parameters rejected",
            );
        }
        if current.downcast_ref::<ConnectionLimitReached>().is_some() {
            return ForwardError::Overloaded;
        }
        // io::Error的source会跳过其直接持有的错误；先检查get_ref，避免本地实体拒绝丢失类型归因。
        source = current
            .downcast_ref::<std::io::Error>()
            .and_then(|error| {
                error
                    .get_ref()
                    .map(|inner| inner as &(dyn std::error::Error + 'static))
            })
            .or_else(|| current.source());
    }
    // 保留完整 source chain；仅把错误格式化成字符串会丢掉 h2 reason / connector 根因，
    // 使并发故障注入和生产日志只能看到笼统的 `client error (SendRequest)`。
    ForwardError::BadGateway(anyhow::Error::from_boxed(error).context(context))
}

impl super::GatewayProxy {
    /// 业务作用：执行单次路由的上游选择、转发和失败处理，统一约束重试、时限及流式资源生命周期。
    pub(super) async fn forward(
        &self,
        ctx: ForwardRequest<'_>,
    ) -> Result<Response<BoxBody>, ForwardError> {
        // 正文检查器的fail-open不能重新授权已经失败的编码实体；在取得上游之前拒绝。
        if let Some(error) = ctx
            .parts
            .extensions
            .get::<Arc<crate::io::request_decompression::State>>()
            .and_then(|state| state.failure())
        {
            return Err(ForwardError::RequestDecompression(error));
        }
        let timeout_ms = [
            ctx.route.request_timeout_ms,
            ctx.route.backend_request_timeout_ms,
        ]
        .into_iter()
        .flatten()
        .filter(|timeout| *timeout > 0)
        .min();
        let Some(timeout_ms) = timeout_ms else {
            return self.forward_inner(ctx).await;
        };
        let deadline = TokioInstant::now() + Duration::from_millis(timeout_ms);
        let pacing = ctx
            .parts
            .extensions
            .get::<crate::runtime::traffic_limit::pacing::RequestPacing>()
            .cloned();
        let response = tokio::time::timeout_at(deadline, self.forward_inner(ctx))
            .await
            .map_err(|_| ForwardError::timeout_for(pacing.as_ref()))??;
        Ok(response.map(|body| AbsoluteDeadlineBody::new(body, deadline).boxed()))
    }

    /// 业务作用：执行不含 route 总 deadline wrapper 的原始上游转发流程，供外层统一
    /// 约束 response head 与流式 body 的同一个绝对截止时刻。
    ///
    /// 参数说明：
    /// - `ctx`：已经完成路由和安全门判断的单次转发上下文。
    ///
    /// 返回：上游成功时返回流式响应；连接、协议、预算或阶段超时映射为稳定转发错误。
    async fn forward_inner(
        &self,
        mut ctx: ForwardRequest<'_>,
    ) -> Result<Response<BoxBody>, ForwardError> {
        #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
        if ctx.route.cgi.is_some() {
            if ctx.downstream_upgrade.is_some()
                || ctx.parts.method == http::Method::CONNECT
                || is_grpc_request(&ctx.parts)
            {
                return Err(ForwardError::CgiInput(
                    StatusCode::BAD_REQUEST,
                    "CGI does not support tunnels or RPC envelopes",
                ));
            }
            crate::protocols::cgi::request_length(&ctx.parts, &ctx.body).map_err(|_| {
                ForwardError::CgiInput(
                    StatusCode::LENGTH_REQUIRED,
                    "CGI requires an exact Content-Length",
                )
            })?;
        }
        let downstream_version = ctx.parts.version;
        #[cfg(feature = "grpc-descriptor")]
        let browser_grpc = BrowserGrpc::detect_with_transcoding(
            &ctx.parts.method,
            &ctx.parts.headers,
            &ctx.parts.uri,
            ctx.route.grpc_transcoding.as_deref(),
        )
        .map_err(ForwardError::BrowserGrpc)?;
        #[cfg(not(feature = "grpc-descriptor"))]
        let browser_grpc = BrowserGrpc::detect(&ctx.parts.method, &ctx.parts.headers)
            .map_err(ForwardError::BrowserGrpc)?;
        // request-id 本来就已为日志/追踪生成；Snowflake 十六进制末字节就是连续变化的 sequence
        // 低位，可直接作为最多 64 个 H2 shard 的稳定提示。无需再为每请求扫描 16 字节做 FNV，
        // 也不分配临时对象；非标准内部 ID 才回退完整稳定哈希。
        let client_shard_hint = super::request_id_shard_hint(ctx.request_id);
        let grpc_drain = (browser_grpc.is_some()
            || (downstream_version == http::Version::HTTP_2 && is_grpc_request(&ctx.parts)))
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
        // 一致性哈希键与会话亲和令牌在重试链开始前算一次:多次 attempt 必须共用同一键,
        // 否则换实例重试会把一致性哈希退化成随机选择,也会让会话在重试后漂移。
        let lb_hints = self.lb_select_hints(
            ctx.snap,
            upstream_target.as_ref(),
            &ctx.parts,
            ctx.client_ip,
            ctx.consumer.as_deref(),
            &ctx.route.id,
            ctx.request_id,
            ctx.downstream_proto,
        );

        if !ctx.route.pass_request_headers {
            ctx.parts.headers.clear();
        }
        if let Some(protocol) = browser_grpc.as_ref() {
            // 浏览器 envelope 必须在 header 清洗后重新盖成 native gRPC；否则
            // pass_request_headers=false 会删掉协议必需的 Content-Type/TE。Connect unary 的
            // 单消息 envelope 需要先知道长度，因此只在既有 max_body_bytes 内做有界读取。
            let body = std::mem::replace(&mut ctx.body, full_body(Bytes::new()));
            ctx.body = protocol
                .prepare_request(&mut ctx.parts, body, ctx.proxy.limits.max_body_bytes)
                .await
                .map_err(ForwardError::BrowserGrpc)?;
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
        } else if let Some(path) = ctx.route.gateway_rewrite_full_path.as_deref() {
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
            let body = ctx.body;
            let limit_conn_guards = std::mem::take(&mut ctx.limit_conn_guards);
            let reservation = self.resolve_upstream_base_excluding(
                ctx.snap,
                upstream_target.as_ref(),
                &[],
                &ctx.proxy.limits,
                lb_hints,
                ctx.inference_endpoints,
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
            let frame_policy = match ctx.websocket_frame_limits {
                Some((max_frame_bytes, max_message_bytes)) => {
                    // Realtime 的 API 预算必须在升级后继续生效；与 route 策略取更严格值，不能因
                    // 进入透明隧道而绕过模型专属的 frame/message 资源门。
                    let mut policy = ctx.route.ws_frame.as_deref().cloned().unwrap_or_default();
                    policy.max_frame_bytes = policy.max_frame_bytes.min(max_frame_bytes);
                    policy.max_message_bytes = policy.max_message_bytes.min(max_message_bytes);
                    Some(Arc::new(policy))
                }
                None => ctx.route.ws_frame.clone(),
            };
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
                    ctx.websocket_max_lifetime_ms
                        .unwrap_or(ctx.proxy.timeouts.websocket_max_lifetime_ms),
                    client_trace,
                    frame_policy,
                )
                .await;
        }

        let lb_service = upstream_target.strip_prefix("lb://");
        let retry_policy = lb_service
            .and_then(|svc| ctx.snap.upstreams.next_upstream_policy(svc))
            .cloned();
        // Agent 已在动作授权后预留一次副作用预算，通用实例重试不能隐式增加实际工具调用次数。
        #[cfg(feature = "ai-governance")]
        let retry_policy = retry_policy.filter(|_| {
            ctx.parts
                .extensions
                .get::<super::agent::SingleAttempt>()
                .is_none()
        });
        let passive_policy = lb_service
            .and_then(|svc| ctx.snap.upstreams.passive_health_policy(svc))
            .unwrap_or_else(PassiveHealthPolicy::disabled);
        // 文件写响应可能丢失在提交之后；显式 DAV 操作不能因客户端幂等头或服务重试选项重复执行。
        #[cfg(feature = "webdav")]
        let retry_policy = retry_policy.filter(|_| {
            ctx.route.webdav.is_none()
                || matches!(ctx.parts.method, http::Method::GET | http::Method::HEAD)
        });
        if let Some(hedge) = ctx
            .route
            .hedge
            .filter(|_| can_hedge_request(&ctx.parts, ctx.route.pass_request_body))
        {
            let primary = self.resolve_upstream_base_excluding(
                ctx.snap,
                upstream_target.as_ref(),
                &[],
                &ctx.proxy.limits,
                lb_hints,
                ctx.inference_endpoints,
            )?;
            let primary_health_key = primary.health_key.clone();
            let secondary = self.resolve_upstream_base_excluding(
                ctx.snap,
                upstream_target.as_ref(),
                std::slice::from_ref(&primary_health_key),
                &ctx.proxy.limits,
                lb_hints,
                ctx.inference_endpoints,
            );
            if let Ok(secondary) = secondary {
                let primary_uri = upstream_uri(&primary.base, &rewritten, &query)?;
                let secondary_uri = upstream_uri(&secondary.base, &rewritten, &query)?;
                let primary_upstream = primary.base.clone();
                let secondary_upstream = secondary.base.clone();
                let secondary_health_key = secondary.health_key.clone();
                let primary_parts = prepare_attempt_parts(
                    &ctx.parts,
                    primary_uri,
                    ctx.route,
                    primary.protocol,
                    ctx.client_ip,
                    ctx.client_ip_header.as_ref(),
                    ctx.trusted_inbound,
                    ctx.client_cert_verified,
                    ctx.downstream_proto,
                    ctx.request_id,
                    false,
                )?;
                let secondary_parts = prepare_attempt_parts(
                    &ctx.parts,
                    secondary_uri,
                    ctx.route,
                    secondary.protocol,
                    ctx.client_ip,
                    ctx.client_ip_header.as_ref(),
                    ctx.trusted_inbound,
                    ctx.client_cert_verified,
                    ctx.downstream_proto,
                    ctx.request_id,
                    false,
                )?;
                let primary_future = self.send_upstream_request(
                    primary_parts,
                    empty_body(),
                    primary,
                    UpstreamSendContext {
                        ttfb_timeout_ms: ctx.proxy.timeouts.upstream_ttfb_timeout_ms,
                        stream_idle_timeout_ms: response_stream_idle_timeout_ms,
                        downstream_version,
                        trace: ctx.trace,
                        upstream: primary_upstream.as_ref(),
                        attempt: 1,
                        client_shard_hint,
                        grpc_drain: grpc_drain.as_ref(),
                        browser_grpc: browser_grpc.clone(),
                        browser_grpc_unary_limit: ctx.proxy.limits.max_body_bytes,
                    },
                );
                tokio::pin!(primary_future);
                let delay = tokio::time::sleep(hedge.delay);
                tokio::pin!(delay);

                // 主请求在延迟窗内成功时绝不启动副本；失败则无需继续等待剩余延迟。
                let primary_early = tokio::select! {
                    result = &mut primary_future => Some(result),
                    _ = &mut delay => None,
                };
                if let Some(result) = primary_early {
                    if hedge_attempt_succeeded(&result) {
                        return self.finish_hedge_attempt(
                            result,
                            &primary_health_key,
                            passive_policy,
                            primary_upstream.clone(),
                            1,
                        );
                    }
                    self.metrics.inc_upstream_hedge_started();
                    let primary_result = self.finish_hedge_attempt(
                        result,
                        &primary_health_key,
                        passive_policy,
                        primary_upstream.clone(),
                        2,
                    );
                    let secondary_result = self
                        .send_upstream_request(
                            secondary_parts,
                            empty_body(),
                            secondary,
                            UpstreamSendContext {
                                ttfb_timeout_ms: ctx.proxy.timeouts.upstream_ttfb_timeout_ms,
                                stream_idle_timeout_ms: response_stream_idle_timeout_ms,
                                downstream_version,
                                trace: ctx.trace,
                                upstream: secondary_upstream.as_ref(),
                                attempt: 2,
                                client_shard_hint,
                                grpc_drain: grpc_drain.as_ref(),
                                browser_grpc: browser_grpc.clone(),
                                browser_grpc_unary_limit: ctx.proxy.limits.max_body_bytes,
                            },
                        )
                        .await;
                    let secondary_result = self.finish_hedge_attempt(
                        secondary_result,
                        &secondary_health_key,
                        passive_policy,
                        secondary_upstream,
                        2,
                    );
                    if hedge_attempt_succeeded(&secondary_result) {
                        self.metrics.inc_upstream_hedge_winner(true);
                    } else {
                        self.metrics.inc_upstream_hedge_failed();
                    }
                    return choose_hedge_result(primary_result, secondary_result);
                }

                self.metrics.inc_upstream_hedge_started();
                let secondary_future = self.send_upstream_request(
                    secondary_parts,
                    empty_body(),
                    secondary,
                    UpstreamSendContext {
                        ttfb_timeout_ms: ctx.proxy.timeouts.upstream_ttfb_timeout_ms,
                        stream_idle_timeout_ms: response_stream_idle_timeout_ms,
                        downstream_version,
                        trace: ctx.trace,
                        upstream: secondary_upstream.as_ref(),
                        attempt: 2,
                        client_shard_hint,
                        grpc_drain: grpc_drain.as_ref(),
                        browser_grpc: browser_grpc.clone(),
                        browser_grpc_unary_limit: ctx.proxy.limits.max_body_bytes,
                    },
                );
                tokio::pin!(secondary_future);
                enum HedgeWinner<T> {
                    Primary(T),
                    Secondary(T),
                }
                let first = tokio::select! {
                    result = &mut primary_future => HedgeWinner::Primary(result),
                    result = &mut secondary_future => HedgeWinner::Secondary(result),
                };
                match first {
                    HedgeWinner::Primary(result) => {
                        let primary_result = self.finish_hedge_attempt(
                            result,
                            &primary_health_key,
                            passive_policy,
                            primary_upstream.clone(),
                            2,
                        );
                        if hedge_attempt_succeeded(&primary_result) {
                            self.metrics.inc_upstream_hedge_winner(false);
                            // 丢弃未完成 future 会取消败方 response wait/QUIC stream，并由预留 RAII 归还预算。
                            return primary_result;
                        }
                        let secondary_result = self.finish_hedge_attempt(
                            secondary_future.await,
                            &secondary_health_key,
                            passive_policy,
                            secondary_upstream.clone(),
                            2,
                        );
                        if hedge_attempt_succeeded(&secondary_result) {
                            self.metrics.inc_upstream_hedge_winner(true);
                        } else {
                            self.metrics.inc_upstream_hedge_failed();
                        }
                        return choose_hedge_result(primary_result, secondary_result);
                    }
                    HedgeWinner::Secondary(result) => {
                        let secondary_result = self.finish_hedge_attempt(
                            result,
                            &secondary_health_key,
                            passive_policy,
                            secondary_upstream.clone(),
                            2,
                        );
                        if hedge_attempt_succeeded(&secondary_result) {
                            self.metrics.inc_upstream_hedge_winner(true);
                            // 同上，取消仍在途的主请求；不等待失败副本拖长下游 TTFB。
                            return secondary_result;
                        }
                        let primary_result = self.finish_hedge_attempt(
                            primary_future.await,
                            &primary_health_key,
                            passive_policy,
                            primary_upstream.clone(),
                            2,
                        );
                        if hedge_attempt_succeeded(&primary_result) {
                            self.metrics.inc_upstream_hedge_winner(false);
                        } else {
                            self.metrics.inc_upstream_hedge_failed();
                        }
                        return choose_hedge_result(secondary_result, primary_result);
                    }
                }
            }
        }
        if retry_policy
            .as_ref()
            .map(|policy| can_retry_request(&ctx.parts, policy, ctx.route.pass_request_body))
            .unwrap_or(false)
        {
            let mut attempted = Vec::new();
            let mut last_error = None;
            let mut last_response = None;
            // 预算状态在重试链外取一次:每次 attempt 重新查表既浪费,也可能在
            // 换代瞬间拿到不同实例,导致同一请求的重试被两份预算分别计数。
            let retry_budget_gate = lb_service.and_then(|service| {
                ctx.snap
                    .upstreams
                    .retry_budget(service)
                    .cloned()
                    .map(|policy| (policy, self.retry_budget_state(service)))
            });
            if let Some((policy, state)) = retry_budget_gate.as_ref() {
                // 滚动请求量只统计进入该 backend 的**请求**,不含重试自身,
                // 否则重试会抬高分母、反过来给自己放开更多预算。
                state.record_request(policy);
            }
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
                    lb_hints,
                    ctx.inference_endpoints,
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
                // retry budget：route 的 next_upstream 只决定「能不能重试」，
                //   预算决定「现在还能不能再发」。第一次尝试不占预算,只有真正的
                //   重试才申请名额;拿不到就停止重试并返回既有结果,而不是继续放大风暴。
                let retry_permit = if attempt_count > 1 {
                    match retry_budget_gate.as_ref() {
                        Some((policy, state)) => match state.try_acquire(policy) {
                            Some(permit) => Some(permit),
                            None => {
                                self.metrics.inc_upstream_retry_exhausted();
                                tracing::debug!(
                                    route = %ctx.route.id,
                                    "retry budget exhausted, stop retrying"
                                );
                                if let Some(resp) = last_response {
                                    return Ok(resp);
                                }
                                if let Some(err) = last_error {
                                    return Err(err);
                                }
                                return Err(ForwardError::Overloaded);
                            }
                        },
                        None => None,
                    }
                } else {
                    None
                };
                let admission_permit = self.acquire_admission(ctx.snap, lb_service).await?;
                // 每次 attempt 单独计时:重试后的耗时不能算到上一个实例头上。
                let attempt_started = std::time::Instant::now();
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
                let result = self
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
                            browser_grpc: browser_grpc.clone(),
                            browser_grpc_unary_limit: ctx.proxy.limits.max_body_bytes,
                        },
                    )
                    .await;
                let elapsed = attempt_started.elapsed();
                // 两类准入名额都只覆盖真实上游 attempt。响应头或连接错误已经给出结果后
                // 必须立即归还；把名额带进 retry backoff 会把等待时间误算成后端并发，
                // 在故障期反而挤掉仍可正常服务的首请求。
                drop(admission_permit);
                drop(retry_permit);
                match result {
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
                        self.record_admission(
                            ctx.snap,
                            lb_service,
                            crate::runtime::admission::AdmissionOutcome::UpstreamResponded,
                            elapsed,
                        );
                        let annotated = annotate_upstream_trace(
                            resp,
                            attempt_upstream.clone(),
                            attempt_count,
                            lb_service.map(Arc::from),
                            lb_hints.affinity,
                        );
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
                        // 本地输入、容量或流量门不是后端故障；不能触发摘除、重试或延迟学习。
                        if !e.is_upstream_error() {
                            return Err(e);
                        }
                        self.record_upstream_failure(&attempt_health_key, passive_policy);
                        self.record_admission(
                            ctx.snap,
                            lb_service,
                            crate::runtime::admission::AdmissionOutcome::UpstreamRejected,
                            elapsed,
                        );
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
            lb_hints,
            ctx.inference_endpoints,
        )?;
        let uri = upstream_uri(&reservation.base, &rewritten, &query)?;
        let attempt_upstream = reservation.base.clone();
        let attempt_health_key = reservation.health_key.clone();
        // 非重试主路径只发送一次，原始 downstream Parts 在此后不再读取；直接转移所有权并
        // 原地改写，避免每请求为整张 HeaderMap 重新分配 bucket。需要多个 attempt 的上方
        // retry 分支仍显式 clone，保证各次请求 head 相互隔离。
        let request_pacing = ctx
            .parts
            .extensions
            .get::<crate::runtime::traffic_limit::pacing::RequestPacing>()
            .cloned();
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
        // 自适应并发名额必须在发出请求之前取得:过载要挡在网关,而不是传导给后端。
        let admission_permit = self.acquire_admission(ctx.snap, lb_service).await?;
        // 反馈用「发出请求 → 拿到响应头」的耗时,而不是整请求耗时:后者被 body 大小
        // 与下游读取速度支配,反映的是流量特征而非后端负载。
        let attempt_started = std::time::Instant::now();
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
                    browser_grpc: browser_grpc.clone(),
                    browser_grpc_unary_limit: ctx.proxy.limits.max_body_bytes,
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
                let elapsed = attempt_started.elapsed();
                if !request_pacing
                    .as_ref()
                    .is_some_and(|pacing| pacing.was_delayed())
                {
                    // 混有本地限速的时间不是后端处理时间，不用于缩减健康后端的并发上限。
                    self.record_admission(
                        ctx.snap,
                        lb_service,
                        crate::runtime::admission::AdmissionOutcome::UpstreamResponded,
                        elapsed,
                    );
                }
                // 名额只覆盖到响应头:body 的流式传输由下游速度决定,继续占名额
                // 会让慢客户端把上限吃光,与 minRTT 的度量口径也不一致。
                drop(admission_permit);
                Ok(annotate_upstream_trace(
                    resp,
                    attempt_upstream,
                    1,
                    lb_service.map(Arc::from),
                    lb_hints.affinity,
                ))
            }
            Err(e) => {
                // 本地保护拒绝不代表后端失效，立即结束且只由 RAII 归还已占名额。
                if !e.is_upstream_error() {
                    return Err(e);
                }
                self.record_upstream_failure(&attempt_health_key, passive_policy);
                // 上游明确失败与超时是后端事实,但不能作为延迟样本:它们的耗时由
                // 超时配置而非后端能力决定,拿去调节并发只会得到错误的基线。
                self.record_admission(
                    ctx.snap,
                    lb_service,
                    crate::runtime::admission::AdmissionOutcome::UpstreamRejected,
                    attempt_started.elapsed(),
                );
                drop(admission_permit);
                Err(e)
            }
        }
    }

    /// 业务作用：在同一实例预留、超时和响应期治理下调度已选协议，不把 CGI 当作 HTTP 发送。
    ///
    /// 参数说明：
    /// - `parts`：安全处理后的请求 head。
    /// - `body`：保持背压的请求实体流。
    /// - `reservation`：实例权威与已取得的预算。
    /// - `ctx`：固定追踪和超时上下文。
    ///
    /// 返回：响应头成功后把预留移交实体流；失败或取消立即归还未转移资源。
    async fn send_upstream_request(
        &self,
        mut parts: Parts,
        body: BoxBody,
        mut reservation: UpstreamReservation,
        ctx: UpstreamSendContext<'_>,
    ) -> Result<Response<BoxBody>, ForwardError> {
        if reservation
            .tls_profile
            .as_ref()
            .is_some_and(|profile| !profile.allows_new_requests())
        {
            // 选择实例后到真正发送前仍可能跨过远程身份截止点；必须在上游 I/O 前再次复验，
            // 不能因连接池中已有可复用 transport 就继续使用已撤权身份。
            return Err(ForwardError::BadGateway(anyhow::anyhow!(
                "upstream TLS client identity is no longer valid"
            )));
        }
        self.metrics.inc_upstream_attempt();
        // 在用户 request-header 规则之后创建 client span：传播头由网关最终盖章，避免 retry
        // 复用 server span-id。只修改几个 header，不 clone HeaderMap 或请求 body。
        let client_trace = ctx
            .trace
            .map(|trace| trace.begin_client(&mut parts.headers, ctx.upstream, ctx.attempt));
        let request_pacing = parts
            .extensions
            .get::<crate::runtime::traffic_limit::pacing::RequestPacing>()
            .cloned();
        let usage_capture = parts
            .extensions
            .get::<crate::runtime::traffic_limit::usage::Capture>()
            .cloned();
        if let Some(capture) = &usage_capture {
            // 客户端与请求插件都不能把同名字段带给上游再通过回显取得响应计费权威。
            capture.strip_request(&mut parts.headers);
        }
        #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
        let cgi = parts.extensions.remove::<crate::protocols::cgi::Input>();
        let ureq = Request::from_parts(parts, body);
        let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
        #[cfg(feature = "http3")]
        let use_h3 = reservation.protocol == UpstreamProtocol::H3;
        #[cfg(not(feature = "http3"))]
        let use_h3 = false;
        let h2_request = ureq.version() == http::Version::HTTP_2;
        let client = if use_h2c || use_h3 || reservation.protocol.is_cgi() {
            None
        } else {
            Some(self.http_client_for(&reservation, h2_request, Some(ctx.client_shard_hint)))
        };
        let h2c_client =
            use_h2c.then(|| self.h2c_client_for(&reservation, Some(ctx.client_shard_hint)));
        #[cfg(feature = "http3")]
        let h3_client = if use_h3 {
            Some(
                self.h3_client_for(&reservation)
                    .map_err(|error| map_client_error("build HTTP/3 client", error))?,
            )
        } else {
            None
        };
        let feedback_started = reservation
            .feedback
            .as_ref()
            .map(|_| std::time::Instant::now());
        let outlier = reservation.outlier.take();
        let fut = async {
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            if let Some(input) = cgi {
                return crate::protocols::cgi::send(
                    ureq,
                    input,
                    reservation.base.clone(),
                    reservation.health_key.clone(),
                    self.physical_connection_budget_for(&reservation),
                    reservation.connect_timeout_ms,
                )
                .await
                .map(|response| response.map(UpstreamResponseBody::Cgi));
            }
            if reservation.protocol.is_cgi() {
                return Err("CGI service requires a fixed script plan".into());
            }
            #[cfg(feature = "http3")]
            if use_h3 {
                return h3_client
                    .expect("HTTP/3 client prepared")
                    .request(ureq)
                    .await
                    .map(|response| response.map(UpstreamResponseBody::Http3));
            }
            if use_h2c {
                h2c_client.expect("h2c client prepared").request(ureq).await
            } else {
                client.expect("non-h2c client prepared").request(ureq).await
            }
        };
        let result = super::health::observe_request(
            outlier,
            async {
                fut.await
                    .map_err(|error| map_client_error("client request", error))
            },
            ctx.ttfb_timeout_ms,
            request_pacing.clone(),
        )
        .await;
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

        if let (Some(feedback), Some(started)) = (reservation.feedback.as_mut(), feedback_started) {
            if request_pacing
                .as_ref()
                .is_some_and(|pacing| pacing.was_delayed())
            {
                // 利用率报告仍来自真实上游；混入本地等待的 TTFB 则不具备延迟反馈权威。
                feedback.trailers(resp.headers());
            } else {
                feedback.headers(resp.headers(), started.elapsed());
            }
        }
        let grpc_drain = ctx
            .grpc_drain
            .filter(|_| has_native_grpc_content_type(resp.headers()))
            .map(GrpcBodyState::register);
        // 保留原始 Incoming 到最终 wrapper：若先归一成 BoxBody，计数/drain 再 boxed 会形成
        // 两次堆分配和两层动态分发。wrap_body 在最外层统一把 Error 擦除，全程不 collect 帧。
        let mut resp = resp;
        if let Some(capture) = usage_capture {
            // 每个 attempt 只携带独立事实；等最终选择响应后再移交，落选 hedge 不污染账本。
            let captured = capture.headers(resp.headers());
            resp.extensions_mut().insert(captured);
        }
        // 响应版本跟随下游请求，不透传上游版本；h2 下游忽略该字段，故安全。
        *resp.version_mut() = ctx.downstream_version;
        if grpc_drain.is_some() {
            resp.extensions_mut().insert(GrpcDrainAttached);
        }
        let response =
            resp.map(|body| reservation.wrap_body(body, ctx.stream_idle_timeout_ms, grpc_drain));
        if let Some(protocol) = ctx.browser_grpc.as_ref() {
            // Connect unary 只有消费最终 grpc-status 后才能确定 HTTP 状态；转换必须留在
            // upstream attempt 内完成，不能先把 200 response head 发布给浏览器再尝试改写。
            protocol
                .translate_response(response, ctx.browser_grpc_unary_limit)
                .await
                .map_err(ForwardError::BrowserGrpc)
        } else {
            Ok(response)
        }
    }

    /// 业务作用：统一记录一个 hedge attempt 的健康结果并附着最终上游追踪信息，确保并发
    /// 分支与普通/retry 分支使用相同的被动健康语义。
    ///
    /// 参数说明：
    /// - `result`：是 response-head 结果
    /// - `health_key`：标识真实实例
    /// - `upstream`：标识真实实例
    /// - `passive_policy`：是服务摘除策略
    /// - `attempt`：是固定 1/2 序号。
    ///
    /// 返回：保留原成功/失败语义；成功响应额外带最终实例与 attempt 数。
    fn finish_hedge_attempt(
        &self,
        result: Result<Response<BoxBody>, ForwardError>,
        health_key: &str,
        passive_policy: PassiveHealthPolicy,
        upstream: Arc<str>,
        attempt: usize,
    ) -> Result<Response<BoxBody>, ForwardError> {
        match result {
            Ok(response) => {
                if response.status().is_server_error() {
                    self.record_upstream_failure(health_key, passive_policy);
                } else {
                    self.record_upstream_success(health_key);
                }
                Ok(annotate_upstream_trace(
                    response, upstream, attempt, None, None,
                ))
            }
            Err(error) => {
                self.record_upstream_failure(health_key, passive_policy);
                Err(error)
            }
        }
    }

    /// 业务作用：在单个 ext_authz 后端的缓存与熔断 owner 域内取得本请求执行权。
    ///
    /// 参数说明：
    /// - `state_key`：标识受信归属/入口/route/policy
    /// - `fingerprint`：绑定策略
    /// - `decision_key`：覆盖决策输入
    /// - `policy`：限制本地状态。
    /// - `budget`：限制本地状态。
    ///
    /// 返回：命中未过期决策、熔断拒绝或取得一次正常/half-open 外呼权。
    fn begin_ext_authz_runtime(
        &self,
        state_key: &str,
        fingerprint: [u8; 32],
        decision_key: [u8; 32],
        policy: &ExtAuthzPolicy,
        budget: Option<&crate::control::ownership::state::Budget>,
    ) -> ExtAuthzRuntimeGate {
        let now = std::time::Instant::now();
        if let Some(budget) = budget {
            if !budget.register_reclaimer(self.ext_authz_runtime.clone()) {
                return ExtAuthzRuntimeGate::Capacity;
            }
        }
        let mut runtimes = self.ext_authz_runtime.states.lock();
        if !runtimes.contains_key(state_key) {
            // 已有后端只检查自身缓存；新后端或容量压力才遍历目录，避免每次鉴权扫描其它租户。
            drop(runtimes);
            crate::control::ownership::state::ReclaimExpired::reclaim_expired(
                self.ext_authz_runtime.as_ref(),
            );
            runtimes = self.ext_authz_runtime.states.lock();
        }
        let expires_at = now
            + Duration::from_secs(60)
                .max(policy.circuit_open)
                .max(policy.cache_ttl.unwrap_or_default())
            + Duration::from_millis(policy.timeout_ms);
        let lease = if !runtimes.contains_key(state_key) {
            if budget.is_none()
                && runtimes
                    .values()
                    .filter(|state| state.budget.is_none())
                    .count()
                    >= 65_536
            {
                return ExtAuthzRuntimeGate::Capacity;
            }
            match budget.map(|budget| budget.acquire()).transpose() {
                Ok(lease) => lease,
                Err(_) => return ExtAuthzRuntimeGate::Capacity,
            }
        } else {
            None
        };
        let state =
            runtimes
                .entry(state_key.to_owned())
                .or_insert_with(|| super::ExtAuthzBackendState {
                    _workspace_lease: lease,
                    budget: budget.cloned(),
                    expires_at,
                    epoch: Arc::new(()),
                    active_calls: 0,
                    policy_fingerprint: fingerprint,
                    consecutive_failures: 0,
                    open_until: None,
                    half_open_probe: false,
                    cache: std::collections::HashMap::new(),
                });
        if state.policy_fingerprint != fingerprint {
            // 策略换代后旧 decision/failure 不能跨 owner 域影响新 endpoint 或新凭据输入。
            state.policy_fingerprint = fingerprint;
            state.consecutive_failures = 0;
            state.open_until = None;
            state.half_open_probe = false;
            state.cache.clear();
            state.epoch = Arc::new(());
            state.active_calls = 0;
        }
        state.budget = budget.cloned();
        state.expires_at = expires_at;
        state.cache.retain(|_, entry| entry.expires_at > now);
        if policy.cache_ttl.is_some() {
            if let Some(entry) = state.cache.get(&decision_key) {
                return ExtAuthzRuntimeGate::Cached(entry.clone());
            }
        } else {
            state.cache.clear();
        }
        if policy.circuit_failure_threshold == 0 {
            state.open_until = None;
            state.half_open_probe = false;
            return ExtAuthzRuntimeGate::Call(ExtAuthzCallGuard::new(
                self.ext_authz_runtime.clone(),
                state_key,
                state,
            ));
        }
        if let Some(open_until) = state.open_until {
            if now < open_until || state.half_open_probe {
                return ExtAuthzRuntimeGate::CircuitOpen;
            }
            // 到期后只授予一个 half-open 探测；其余请求继续失败闭合，避免恢复时惊群。
            state.half_open_probe = true;
        }
        ExtAuthzRuntimeGate::Call(ExtAuthzCallGuard::new(
            self.ext_authz_runtime.clone(),
            state_key,
            state,
        ))
    }

    /// 业务作用：提交 ext_authz 后端外呼结果，成功关闭熔断并可缓存明确决策，依赖故障推进独立熔断。
    ///
    /// 参数说明：
    /// - `call`：绑定同域策略代次
    /// - `decision_key`：定位决策
    /// - `policy`：定位决策
    /// - `cached`：只允许明确 allow/deny
    /// - `dependency_ok`：区分协议决定与依赖故障。
    ///
    /// 返回：无；迟到的旧策略结果无权修改新 owner 域。
    fn finish_ext_authz_runtime(
        &self,
        call: &ExtAuthzCallGuard,
        decision_key: [u8; 32],
        policy: &ExtAuthzPolicy,
        dependency_ok: bool,
        cached: Option<super::ExtAuthzCachedDecision>,
    ) {
        let mut runtimes = self.ext_authz_runtime.states.lock();
        let Some(state) = runtimes.get_mut(&call.key) else {
            return;
        };
        if state.policy_fingerprint != call.fingerprint || !Arc::ptr_eq(&state.epoch, &call.epoch) {
            return;
        }
        call.finished.store(true, Ordering::Release);
        if call.half_open {
            state.half_open_probe = false;
        }
        if dependency_ok {
            state.consecutive_failures = 0;
            state.open_until = None;
            if let Some(mut entry) = cached {
                if policy.cache_max_entries > 0 {
                    state
                        .cache
                        .retain(|_, entry| entry.expires_at > std::time::Instant::now());
                    state.cache.remove(&decision_key);
                    if state.cache.len() >= policy.cache_max_entries
                        && !state.cache.contains_key(&decision_key)
                    {
                        if let Some(oldest) = state
                            .cache
                            .iter()
                            .min_by_key(|(_, entry)| entry.expires_at)
                            .map(|(key, _)| *key)
                        {
                            state.cache.remove(&oldest);
                        }
                    }
                    // 先取得真实驻留名额再缓存；容量不足不能转成授权放行或依赖故障。
                    if let Ok(lease) = state
                        .budget
                        .as_ref()
                        .map(|budget| budget.acquire())
                        .transpose()
                    {
                        entry._workspace_lease = lease;
                        state.cache.insert(decision_key, entry);
                    }
                }
            }
            return;
        }
        if policy.circuit_failure_threshold == 0 {
            return;
        }
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= policy.circuit_failure_threshold {
            // 熔断只由超时、网络或异常状态触发；401/403 是业务拒绝，永远不会打开依赖熔断。
            state.open_until = std::time::Instant::now().checked_add(policy.circuit_open);
        }
    }

    /// 业务作用：执行 route 的 ext_authz 外部鉴权策略，并复用完整键缓存与每后端独立熔断。
    ///
    /// 参数说明：
    /// - `snap`: 当前配置快照,用于解析 `lb://auth-service`。
    /// - `proxy`: 当前入口运行参数。
    /// - `route`: 当前命中 route。
    /// - `parts`: 原始下游请求 head;鉴权通过后可注入 allowlist 上游 header。
    /// - `client_ip`: 真实客户端 IP。
    /// - `trusted_inbound`: 入站连接是否可信。
    /// - `downstream_proto`: 下游协议 scheme。
    /// - `request_id`: 当前请求 ID。
    /// - `trace`：已经验证并冻结的链路上下文。
    /// - `auth_body`：按共同鉴权上限聚合的可选原始正文。
    ///
    /// 返回：响应头到达后返回受预留额度约束的正文；连接、容量或探测期限失败返回分类错误。
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
        trace: &crate::observability::telemetry::ServerTrace,
        auth_body: Option<&Bytes>,
    ) -> ExtAuthzDecision {
        // 多个 ext_authz 策略属于同一种认证方式，按 OR 组合；它们作为一个认证组再参与 route 的
        // `satisfy any|all`。因此一个后端明确拒绝不能覆盖后续后端的成功，否则会把配置模型中的
        // 备选鉴权服务误实现成串联鉴权。非 fail-open 的异常先记下，仍尝试其余后端；仅当没有任何
        // 后端成功时才返回 Unavailable。指标按【最终请求决策】计 allowed/denied，error 按后端异常计。
        let mut denied: Option<(StatusCode, Option<http::HeaderValue>)> = None;
        let mut unavailable = false;
        for (index, policy) in route.ext_authz.iter().enumerate() {
            let state_key = format!(
                "{}:{}:{index}",
                proxy.id,
                super::route_state_scope(parts, route)
            );
            let fingerprint = ext_authz_policy_fingerprint(policy);
            let decision_key = ext_authz_decision_key(
                policy,
                parts,
                client_ip,
                trusted_inbound,
                downstream_proto,
                auth_body,
            );
            let call_guard = match self.begin_ext_authz_runtime(
                &state_key,
                fingerprint,
                decision_key,
                policy,
                parts
                    .extensions
                    .get::<crate::control::ownership::state::Budget>(),
            ) {
                ExtAuthzRuntimeGate::Cached(entry) => {
                    if entry.allowed {
                        apply_ext_authz_upstream_headers(parts, &entry.upstream_headers);
                        self.metrics.inc_ext_authz_allowed();
                        return ExtAuthzDecision::Allowed;
                    }
                    denied.get_or_insert((entry.status, entry.challenge));
                    continue;
                }
                ExtAuthzRuntimeGate::CircuitOpen => {
                    self.metrics.inc_ext_authz_error();
                    if policy.fail_open {
                        tracing::warn!(route = %route.id, policy = index, "ext_authz circuit open, fail-open");
                        self.metrics.inc_ext_authz_allowed();
                        return ExtAuthzDecision::Allowed;
                    }
                    unavailable = true;
                    continue;
                }
                ExtAuthzRuntimeGate::Call(guard) => guard,
                // 这是本地硬容量门，不属于允许 fail-open 的外部依赖故障。
                ExtAuthzRuntimeGate::Capacity => {
                    return ExtAuthzDecision::Denied {
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        challenge: None,
                    }
                }
            };
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
                    auth_body,
                )
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let upstream_headers = ext_authz_upstream_headers(policy, &resp);
                    let cached = policy.cache_ttl.map(|ttl| super::ExtAuthzCachedDecision {
                        _workspace_lease: None,
                        allowed: true,
                        status: resp.status(),
                        challenge: None,
                        upstream_headers: upstream_headers.clone(),
                        expires_at: std::time::Instant::now() + ttl,
                    });
                    self.finish_ext_authz_runtime(&call_guard, decision_key, policy, true, cached);
                    apply_ext_authz_upstream_headers(parts, &upstream_headers);
                    drop(resp);
                    self.metrics.inc_ext_authz_allowed();
                    return ExtAuthzDecision::Allowed;
                }
                Ok(resp)
                    if resp.status() == StatusCode::UNAUTHORIZED
                        || resp.status() == StatusCode::FORBIDDEN =>
                {
                    let status = resp.status();
                    let challenge = resp.headers().get(http::header::WWW_AUTHENTICATE).cloned();
                    let cached = policy.cache_ttl.map(|ttl| super::ExtAuthzCachedDecision {
                        _workspace_lease: None,
                        allowed: false,
                        status,
                        challenge: challenge.clone(),
                        upstream_headers: Vec::new(),
                        expires_at: std::time::Instant::now() + ttl,
                    });
                    self.finish_ext_authz_runtime(&call_guard, decision_key, policy, true, cached);
                    denied.get_or_insert((status, challenge));
                }
                Ok(resp) => {
                    self.finish_ext_authz_runtime(&call_guard, decision_key, policy, false, None);
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
                    self.finish_ext_authz_runtime(&call_guard, decision_key, policy, false, None);
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
            return ExtAuthzDecision::Denied {
                status,
                challenge,
            };
        }
        // 空策略列表不会进入本函数(调用方已判空)，保留安全兜底以免未来调用约束变化。
        ExtAuthzDecision::Unavailable
    }

    /// 业务作用：发送一次 ext_authz 子请求。
    ///
    /// 参数说明：
    /// - `snap`: 当前配置快照。
    /// - `proxy`: 当前入口运行参数。
    /// - `route`: 当前 route。
    /// - `policy`: 当前 ext_authz 策略。
    /// - `base_parts`: 原始下游请求 head。
    /// - `client_ip`: 真实客户端 IP。
    /// - `trusted_inbound`: 入站连接是否可信。
    /// - `downstream_proto`: 下游协议 scheme。
    /// - `request_id`: 当前请求 ID。
    /// - `trace`：已经验证并冻结的链路上下文。
    /// - `auth_body`：按共同鉴权上限聚合的可选原始正文。
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
        trace: &crate::observability::telemetry::ServerTrace,
        auth_body: Option<&Bytes>,
    ) -> Result<Response<BoxBody>, ForwardError> {
        let target = ext_authz_target(policy)?;
        validate_upstream_target(snap, target.upstream.as_ref(), false)?;
        let mut reservation = self.resolve_upstream_base_excluding(
            snap,
            target.upstream.as_ref(),
            &[],
            &proxy.limits,
            crate::upstream::LbSelectHints::default(),
            None,
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
        let request_body = if policy.body_max_bytes.is_some() {
            let body = auth_body.cloned().ok_or_else(|| {
                ForwardError::BadGateway(anyhow::anyhow!(
                    "ext_authz body policy is missing the collected request entity"
                ))
            })?;
            if let Some(content_type) = base_parts.headers.get(CONTENT_TYPE).cloned() {
                parts.headers.insert(CONTENT_TYPE, content_type);
            }
            parts.headers.insert(
                CONTENT_LENGTH,
                header_value(&body.len().to_string(), "content-length")?,
            );
            full_body(body)
        } else {
            empty_body()
        };
        let client_trace = trace.begin_client(&mut parts.headers, reservation.base.as_ref(), 1);
        parts.extensions.clear();
        let request = Request::from_parts(parts, request_body);
        let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
        #[cfg(feature = "http3")]
        let use_h3 = reservation.protocol == UpstreamProtocol::H3;
        #[cfg(not(feature = "http3"))]
        let use_h3 = false;
        let h2_request = request.version() == http::Version::HTTP_2;
        let client = if use_h2c || use_h3 {
            None
        } else {
            Some(self.http_client_for(&reservation, h2_request, None))
        };
        let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
        #[cfg(feature = "http3")]
        let h3_client = if use_h3 {
            Some(
                self.h3_client_for(&reservation)
                    .map_err(|error| map_client_error("build HTTP/3 ext_authz client", error))?,
            )
        } else {
            None
        };
        let fut = async {
            #[cfg(feature = "http3")]
            if use_h3 {
                return h3_client
                    .expect("HTTP/3 ext_authz client prepared")
                    .request(request)
                    .await
                    .map(|response| response.map(UpstreamResponseBody::Http3));
            }
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
        let result = super::health::observe(
            reservation.outlier.take(),
            async {
                fut.await
                    .map_err(|error| map_client_error("ext_authz request", error))
            },
            timeout_ms,
        )
        .await;
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

    /// 业务作用：发送一次 OPA Data API JSON 子请求并等待 response head。
    ///
    /// 请求 head 从空白 `Request` 构造，不复制下游 Authorization/Cookie/身份头；OPA 服务
    /// credential 只来自构建期 SecretSource。业务 body 也不进入此函数，payload 是 OPA input
    /// serializer 生成的唯一一份有界 [`Bytes`]。
    ///
    /// 参数说明：
    /// - `snap`：本次请求固定的配置快照与上游目录。
    /// - `proxy`：入口连接与响应头预算。
    /// - `route`：当前请求所属路由，供受控追踪使用。
    /// - `policy`：构建期验证的 OPA 目标与凭据策略。
    /// - `payload`：已完成脱敏和容量限制的 OPA 输入。
    /// - `request_id`：网关生成的请求关联标识。
    /// - `trace`：当前服务端追踪上下文。
    ///
    /// 返回：OPA 响应头和持有额度的正文；本地拒绝不记后端失败，实际连接或响应超时计入健康判断。
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn send_opa_request(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        policy: &OpaPolicy,
        payload: OpaInputPayload,
        request_id: &str,
        trace: &crate::observability::telemetry::ServerTrace,
    ) -> Result<Response<BoxBody>, ForwardError> {
        validate_upstream_target(snap, policy.upstream.as_str(), false)?;
        let mut reservation = self.resolve_upstream_base_excluding(
            snap,
            policy.upstream.as_str(),
            &[],
            &proxy.limits,
            crate::upstream::LbSelectHints::default(),
            None,
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
        #[cfg(feature = "http3")]
        let use_h3 = reservation.protocol == UpstreamProtocol::H3;
        #[cfg(not(feature = "http3"))]
        let use_h3 = false;
        let h2_request = request.version() == http::Version::HTTP_2;
        let client =
            (!use_h2c && !use_h3).then(|| self.http_client_for(&reservation, h2_request, None));
        let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
        #[cfg(feature = "http3")]
        let h3_client = if use_h3 {
            Some(
                self.h3_client_for(&reservation)
                    .map_err(|error| map_client_error("build HTTP/3 OPA client", error))?,
            )
        } else {
            None
        };
        let send = async {
            #[cfg(feature = "http3")]
            if use_h3 {
                return h3_client
                    .expect("HTTP/3 OPA client prepared")
                    .request(request)
                    .await
                    .map(|response| response.map(UpstreamResponseBody::Http3));
            }
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
        let result = super::health::observe(
            reservation.outlier.take(),
            async {
                send.await
                    .map_err(|error| map_client_error("OPA request", error))
            },
            policy.timeout().as_millis() as u64,
        )
        .await;
        let response = match result {
            Ok(response) => {
                client_trace.finish_status(response.status().as_u16());
                response
            }
            Err(mapped) => {
                if matches!(mapped, ForwardError::Overloaded) {
                    self.metrics.inc_upstream_overloaded();
                }
                client_trace.finish_error(mapped.message());
                return Err(mapped);
            }
        };
        Ok(response.map(|body| reservation.wrap_body(body, 0, None)))
    }

    /// 业务作用：发送一次 外部头部插件 JSON 调用并等待 response head。
    ///
    /// 请求从空白 head 构造，绝不 clone 下游 Authorization/Cookie 或业务 body；唯一 body 是
    /// 有界 serializer 生成的 `Bytes`。目标解析、LB、主动/被动健康、物理连接和 pending
    /// 预算均复用普通上游设施，避免插件旁路连接治理。
    ///
    /// 参数说明：
    /// - `snap`：本次请求固定的配置快照与上游目录。
    /// - `proxy`：入口连接与响应头预算。
    /// - `route`：当前请求所属路由，供受控追踪使用。
    /// - `plugin`：已验证的插件外呼目标、凭据与期限。
    /// - `payload`：只含显式允许字段的有界插件输入。
    /// - `request_id`：网关生成的请求关联标识。
    /// - `trace`：当前服务端追踪上下文。
    ///
    /// 返回：插件响应头和持有额度的正文；本地拒绝、真实上游失败与探测超时分别按原错误分类返回。
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn send_external_plugin_request(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        plugin: &ExternalPlugin,
        payload: ExternalPluginPayload,
        request_id: &str,
        trace: &crate::observability::telemetry::ServerTrace,
    ) -> Result<Response<BoxBody>, ForwardError> {
        validate_upstream_target(snap, plugin.upstream(), false)?;
        let mut reservation = self.resolve_upstream_base_excluding(
            snap,
            plugin.upstream(),
            &[],
            &proxy.limits,
            crate::upstream::LbSelectHints::default(),
            None,
        )?;
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
        #[cfg(feature = "http3")]
        let use_h3 = reservation.protocol == UpstreamProtocol::H3;
        #[cfg(not(feature = "http3"))]
        let use_h3 = false;
        let h2_request = request.version() == http::Version::HTTP_2;
        let client =
            (!use_h2c && !use_h3).then(|| self.http_client_for(&reservation, h2_request, None));
        let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
        #[cfg(feature = "http3")]
        let h3_client = if use_h3 {
            Some(
                self.h3_client_for(&reservation)
                    .map_err(|error| map_client_error("build HTTP/3 plugin client", error))?,
            )
        } else {
            None
        };
        let send = async {
            #[cfg(feature = "http3")]
            if use_h3 {
                return h3_client
                    .expect("HTTP/3 external plugin client prepared")
                    .request(request)
                    .await
                    .map(|response| response.map(UpstreamResponseBody::Http3));
            }
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
        let result = super::health::observe(
            reservation.outlier.take(),
            async {
                send.await
                    .map_err(|error| map_client_error("external plugin request", error))
            },
            plugin.timeout().as_millis() as u64,
        )
        .await;
        let response = match result {
            Ok(response) => {
                client_trace.finish_status(response.status().as_u16());
                response
            }
            Err(mapped) => {
                if matches!(mapped, ForwardError::Overloaded) {
                    self.metrics.inc_upstream_overloaded();
                }
                client_trace.finish_error(mapped.message());
                return Err(mapped);
            }
        };
        Ok(response.map(|body| reservation.wrap_body(body, 0, None)))
    }

    /// 业务作用：通过普通 upstream 选择、TLS、健康与连接预算建立标准 ExternalProcessor.Process
    /// 双向 gRPC 流，并让调用方可在 response head 到达前发送首条 `ProcessingRequest`。
    ///
    /// 参数说明：
    /// - `snap`：固定当前数据面权威
    /// - `proxy`：固定当前数据面权威
    /// - `route`：固定当前数据面权威
    /// - `plan`：提供扩展服务和凭据
    /// - `request_id`：只用于低敏链路观测。
    /// - `trace`：只用于低敏链路观测。
    ///
    /// 返回：建流准备成功返回可双向收发的 wire；目标、容量和请求构造失败返回 Dependency 错误。
    #[cfg(feature = "ext-proc")]
    pub(super) fn open_ext_proc_stream(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        plan: &ExtProcPlan,
        request_id: &str,
        trace: &crate::observability::telemetry::ServerTrace,
    ) -> Result<ExtProcWire, ExtProcError> {
        validate_upstream_target(snap, plan.upstream(), false)
            .map_err(|error| ExtProcError::dependency(anyhow::anyhow!(error.message())))?;
        let mut reservation = self
            .resolve_upstream_base_excluding(
                snap,
                plan.upstream(),
                &[],
                &proxy.limits,
                crate::upstream::LbSelectHints::default(),
                None,
            )
            .map_err(|error| ExtProcError::dependency(anyhow::anyhow!(error.message())))?;
        if reservation.protocol == UpstreamProtocol::H3 {
            return Err(ExtProcError::dependency(anyhow::anyhow!(
                "ext_proc requires an HTTP/2-capable upstream"
            )));
        }
        let uri = upstream_uri(&reservation.base, plan.process_path(), "")
            .map_err(|error| ExtProcError::dependency(anyhow::anyhow!(error.message())))?;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .version(http::Version::HTTP_2)
            .body(())
            .map_err(|error| {
                ExtProcError::dependency(anyhow::anyhow!("build ext_proc gRPC request: {error}"))
            })?;
        let (mut parts, _) = request.into_parts();
        if let Some(authority) = parts.uri.authority() {
            parts.headers.insert(
                HOST,
                header_value(authority.as_str(), "host")
                    .map_err(|error| ExtProcError::dependency(anyhow::anyhow!(error.message())))?,
            );
        }
        parts
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
        parts
            .headers
            .insert(TE, HeaderValue::from_static("trailers"));
        parts
            .headers
            .insert(ACCEPT, HeaderValue::from_static("application/grpc"));
        if let Some(authorization) = plan.authorization() {
            parts.headers.insert(AUTHORIZATION, authorization.clone());
        }
        parts.headers.insert(
            X_REQUEST_ID,
            header_value(request_id, "x-request-id")
                .map_err(|error| ExtProcError::dependency(anyhow::anyhow!(error.message())))?,
        );
        parts.headers.insert(
            HeaderName::from_static("x-gateway-route-id"),
            header_value(route.id.as_str(), "x-gateway-route-id")
                .map_err(|error| ExtProcError::dependency(anyhow::anyhow!(error.message())))?,
        );
        let client_trace = trace.begin_client(&mut parts.headers, reservation.base.as_ref(), 1);
        parts.extensions.clear();
        let (sender, body) = http_body_util::channel::Channel::<Bytes, crate::BoxError>::new(1);
        let request = Request::from_parts(parts, body.boxed());
        let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
        let client = (!use_h2c).then(|| self.http_client_for(&reservation, true, None));
        let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let sent = super::health::observe(
                reservation.outlier.take(),
                async {
                    let response = if use_h2c {
                        h2c_client
                            .expect("h2c ext_proc client prepared")
                            .request(request)
                            .await
                    } else {
                        client
                            .expect("TLS ext_proc client prepared")
                            .request(request)
                            .await
                    };
                    response.map_err(|error| map_client_error("ext_proc request", error))
                },
                0,
            )
            .await;
            let result = match sent {
                Ok(response) => {
                    client_trace.finish_status(response.status().as_u16());
                    if response.status() != StatusCode::OK {
                        Err(ExtProcError::dependency(anyhow::anyhow!(
                            "ext_proc returned HTTP status {}",
                            response.status()
                        )))
                    } else if !response
                        .headers()
                        .get(CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| value.starts_with("application/grpc"))
                    {
                        Err(ExtProcError::protocol(anyhow::anyhow!(
                            "ext_proc returned a non-gRPC content-type"
                        )))
                    } else {
                        let grpc_status = response
                            .headers()
                            .get("grpc-status")
                            .map(|_| {
                                crate::extensions::ext_proc::parse_grpc_status(response.headers())
                            })
                            .transpose();
                        if let Err(error) = grpc_status {
                            Err(error)
                        } else if grpc_status
                            .as_ref()
                            .expect("error handled above")
                            .is_some_and(|status| status != 0)
                        {
                            Err(crate::extensions::ext_proc::classify_grpc_status(
                                grpc_status
                                    .expect("error handled above")
                                    .expect("nonzero status checked above"),
                                true,
                            ))
                        } else {
                            Ok((
                                response
                                    .map(|body| reservation.wrap_body(body, 0, None))
                                    .into_body(),
                                grpc_status.expect("error handled above"),
                            ))
                        }
                    }
                }
                Err(mapped) => {
                    client_trace.finish_error(mapped.message());
                    Err(ExtProcError::dependency(
                        anyhow::anyhow!(mapped.to_string()),
                    ))
                }
            };
            let _ = response_tx.send(result);
        });
        Ok(ExtProcWire::new(sender, response_rx))
    }

    /// 业务作用：使用普通 upstream 选择/预算与 Dubbo 专用有界 TCP pool 发送一次已校验的
    /// generic invocation，并把 provider 结果映射为 HTTP JSON 与低基数指标。
    ///
    /// 参数说明：
    /// - `snap`：提供当前快照、数据面预算和固定 Dubbo plan
    /// - `proxy`：提供当前快照、数据面预算和固定 Dubbo plan
    /// - `route`：提供当前快照、数据面预算和固定 Dubbo plan
    /// - `invocation`：已在选择 upstream 前完成类型、资源上限与 wire 编码校验。
    ///
    /// 返回：provider 成功时返回 200 JSON；连接/超时/协议/远端异常返回分类后的
    /// `ForwardError`。完整 response frame 在返回前读完，RAII reservation 随函数退出归还。
    pub(super) async fn send_dubbo_request(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        invocation: &crate::protocols::dubbo::DubboInvocation,
    ) -> Result<Response<BoxBody>, ForwardError> {
        let plan = route
            .dubbo
            .as_ref()
            .expect("Dubbo forward is called only for a Dubbo route");
        let mut reservation = self.resolve_upstream_base_excluding(
            snap,
            route.upstream.as_str(),
            &[],
            &proxy.limits,
            crate::upstream::LbSelectHints::default(),
            None,
        )?;
        let upstream = reservation.base.clone();
        let health_key = reservation.health_key.clone();
        let passive_policy = route
            .upstream
            .strip_prefix("lb://")
            .and_then(|service| snap.upstreams.passive_health_policy(service))
            .unwrap_or_else(PassiveHealthPolicy::disabled);
        let result = crate::upstream::passive::window::Attempt::observe(
            reservation.outlier.take(),
            plan.invoke(upstream.clone(), invocation),
            |result| match result {
                Ok(_) => Some(false),
                Err(DubboError::InvalidInput(_)) => None,
                Err(_) => Some(true),
            },
        )
        .await
        .unwrap_or(Err(DubboError::Timeout));
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
            Err(DubboError::Remote {
                status,
            }) => {
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
                // 预编码调用已在占用 upstream 前排除客户端错误；此分支只防守内部契约失效，
                // 不把它计入被动健康，但仍避免向下游暴露内部细节。
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
        Ok(annotate_upstream_trace(response, upstream, 1, None, None))
    }

    /// 业务作用：按稳定采样结果异步发送 route 镜像请求，且镜像失败不阻塞主请求响应。
    ///
    /// 参数说明：
    /// - `ctx`：是主请求上下文
    /// - `path`：是最终上游路径
    /// - `query`：是最终上游路径
    /// - `downstream_version`：提供协议 hint
    /// - `mirror_body`：是与主请求共享的有界完整 body。
    ///
    /// 返回：无返回值；命中的子请求进入后台任务，跳过与失败只记录指标，不改变主链路结果。
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
                    #[cfg(feature = "http3")]
                    let use_h3 = reservation.protocol == UpstreamProtocol::H3;
                    #[cfg(not(feature = "http3"))]
                    let use_h3 = false;
                    let h2_request = parts.version == http::Version::HTTP_2;
                    // 只给真正使用的协议池计一次 keepalive request，不能让未发送请求的池提前轮换。
                    let client = (!use_h2c && !use_h3)
                        .then(|| self.http_client_for(&reservation, h2_request, None));
                    let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
                    #[cfg(feature = "http3")]
                    let h3_client = if use_h3 {
                        match self.h3_client_for(&reservation) {
                            Ok(client) => Some(client),
                            Err(error) => {
                                self.metrics.inc_mirror_error();
                                tracing::debug!(%error, "build HTTP/3 mirror client failed");
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    let metrics = self.metrics.clone();
                    let ttfb_timeout_ms = ctx.proxy.timeouts.upstream_ttfb_timeout_ms;
                    let request_body = body_bytes.map(full_body).unwrap_or_else(empty_body);
                    tokio::spawn(async move {
                        if let Err(err) = send_mirror_request(
                            client,
                            h2c_client,
                            #[cfg(feature = "http3")]
                            h3_client,
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

    /// 业务作用：为命中采样的 LLM shadow 模型建立独立后台请求；其状态、实体和失败永不进入
    /// 主模型 fallback 或下游响应，但保留固定模型身份与 provider 凭据。
    ///
    /// 参数说明：
    /// - `snap`：本请求持有的不可变网关快照。
    /// - `proxy`：同一快照内的入口计划。
    /// - `route`：同一快照内的路由计划。
    /// - `parts`：已转换为 shadow provider 协议的请求头。
    /// - `body`：已转换为 shadow provider 协议的有界正文。
    /// - `target`：可信计划固定的 shadow 后端。
    /// - `path`：可信计划固定的上游路径。
    /// - `client_ip`：已经验证的真实客户端 IP。
    /// - `trusted_inbound`：直连对端是否可信。
    /// - `client_cert_verified`：下游客户端证书是否完成验证。
    /// - `downstream_proto`：受信 listener 的下游协议。
    /// - `request_id`：贯穿本请求链路的请求标识。
    /// - `trace`：本请求冻结的 trace 上下文。
    /// - `max_duration`：shadow 调用的最长生命周期。
    /// - `model_id`：固定目录中的低基数模型标识。
    ///
    /// 返回：上游计划可同步构建时启动后台任务并返回成功；目标、request head 或 HTTP/3
    /// 客户端计划无效时返回错误，调用方只记录并继续主链路。
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_llm_shadow_request(
        &self,
        snap: &GatewaySnapshot,
        proxy: &ProxyRuntime,
        route: &Route,
        parts: Parts,
        body: Bytes,
        target: &str,
        path: &str,
        client_ip: IpAddr,
        trusted_inbound: bool,
        client_cert_verified: bool,
        downstream_proto: &'static str,
        request_id: &str,
        trace: &crate::observability::telemetry::ServerTrace,
        max_duration: Duration,
        model_id: Arc<str>,
    ) -> Result<(), ForwardError> {
        validate_upstream_target(snap, target, false)?;
        let reservation = self.resolve_upstream_base_excluding(
            snap,
            target,
            &[],
            &proxy.limits,
            crate::upstream::LbSelectHints::default(),
            None,
        )?;
        let uri = upstream_uri(&reservation.base, path, "")?;
        let downstream_version = parts.version;
        let mut parts = prepare_attempt_parts(
            &parts,
            uri,
            route,
            reservation.protocol,
            client_ip,
            None,
            trusted_inbound,
            client_cert_verified,
            downstream_proto,
            request_id,
            false,
        )?;
        let client_trace = trace.begin_client(&mut parts.headers, reservation.base.as_ref(), 1);
        parts.extensions.clear();
        let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
        #[cfg(feature = "http3")]
        let use_h3 = reservation.protocol == UpstreamProtocol::H3;
        #[cfg(not(feature = "http3"))]
        let use_h3 = false;
        let h2_request = parts.version == http::Version::HTTP_2;
        let client =
            (!use_h2c && !use_h3).then(|| self.http_client_for(&reservation, h2_request, None));
        let h2c_client = use_h2c.then(|| self.h2c_client_for(&reservation, None));
        #[cfg(feature = "http3")]
        let h3_client = use_h3
            .then(|| self.h3_client_for(&reservation))
            .transpose()
            // 保留 HTTP/3 客户端构建失败的原因链，交由调用方记录；shadow 请求不影响主模型响应。
            .map_err(|error| map_client_error("build HTTP/3 LLM shadow client", error))?;
        let ttfb_timeout_ms = proxy
            .timeouts
            .upstream_ttfb_timeout_ms
            .min(max_duration.as_millis().min(u128::from(u64::MAX)) as u64);
        tokio::spawn(async move {
            let result = tokio::time::timeout(
                max_duration,
                send_mirror_request(
                    client,
                    h2c_client,
                    #[cfg(feature = "http3")]
                    h3_client,
                    parts,
                    full_body(body),
                    reservation,
                    MirrorSendContext {
                        ttfb_timeout_ms,
                        downstream_version,
                        client_trace: Some(client_trace),
                    },
                ),
            )
            .await;
            match result {
                Ok(Ok(())) => tracing::debug!(model = %model_id, "LLM shadow evaluation completed"),
                Ok(Err(error)) => {
                    tracing::debug!(model = %model_id, %error, "LLM shadow evaluation failed")
                }
                Err(_) => tracing::debug!(model = %model_id, "LLM shadow evaluation timed out"),
            }
        });
        Ok(())
    }

    /// 业务作用：为显式开启 body 的 mirror 准备可复用请求体，同时保持主请求获得相同字节。
    ///
    /// 参数说明：
    /// - `ctx`：是当前主请求转发上下文，函数会把原始 body 替换成可复用 `Bytes` body。
    ///
    /// 返回：没有镜像策略命中时返回 `None`；命中时返回受上限约束的完整 body，超限或读取失败则拒绝主请求。
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
        if let Some(content_length) = request_content_length(&ctx.parts) {
            if content_length > max_body_bytes {
                return Ok(None);
            }
        }
        // 缺少 Content-Length 既可能是空 GET，也可能是 chunked/HTTP2 流；都必须实际读取，
        // 否则标准 RequestMirror 会静默漏掉无长度请求，破坏镜像比例与审计完整性。
        let body = std::mem::replace(&mut ctx.body, empty_body());
        let bytes = collect_forward_body(body, max_body_bytes).await?;
        ctx.body = full_body(bytes.clone());
        Ok(Some(bytes))
    }

    /// 业务作用：基于可信 route 和当前请求构造单个镜像上游请求，并复用正常代理的安全头处理。
    ///
    /// 参数说明：
    /// - `ctx`：主请求的可信转发上下文。
    /// - `mirror`：固定后端与头部策略的镜像计划。
    /// - `path`：最终上游路径。
    /// - `query`：最终上游查询串。
    /// - `body_len`：镜像正文字节数，None 表示发送空正文。
    ///
    /// 返回：目标可解析且 URI/header 合法时返回请求 head、上游占位和 tracing 上下文，否则拒绝该镜像。
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
            Option<crate::observability::telemetry::ClientTrace>,
        ),
        ForwardError,
    > {
        validate_upstream_target(ctx.snap, mirror.target.as_str(), false)?;
        let reservation = self.resolve_upstream_base_excluding(
            ctx.snap,
            mirror.target.as_str(),
            &[],
            &ctx.proxy.limits,
            crate::upstream::LbSelectHints::default(),
            None,
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

    /// 业务作用：完成 WebSocket 上游握手，并在 101 后启动持有连接与工作区名额的双向隧道。
    ///
    /// 数据帧不解码、不重组；`ActivityIo` 只在成功搬运字节时更新一个原子时间戳，因此 idle/max-lifetime
    /// 治理不会破坏 `copy_bidirectional` 的背压与少拷贝路径。注册表关闭会在取消 copy future 后串行写
    /// Close 控制帧，避免控制帧和数据帧交错。
    ///
    /// 参数说明：
    /// - `parts`: 已完成 hop-by-hop/Host/转发头处理的上游握手 head。
    /// - `body`: 下游统一流式 body；握手期不预收集。
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
    /// - `client_trace`：下游握手携带的可信链路上下文。
    /// - `frame_policy`：该路由固定的 WebSocket frame 安全与资源策略。
    ///
    /// 返回：握手响应；上游握手失败映射为 `ForwardError::BadGateway`。101 后隧道错误只记日志，
    /// 因为 HTTP 响应头已经发出，不能再改成普通错误响应。
    #[allow(clippy::too_many_arguments)]
    async fn forward_websocket(
        &self,
        mut parts: Parts,
        body: ForwardBody,
        downstream_upgrade: OnUpgrade,
        downstream_connection_lease: Option<super::DownstreamConnectionLease>,
        route_id: &str,
        client_ip: IpAddr,
        consumer: Option<Arc<str>>,
        snapshot_version: u64,
        mut reservation: UpstreamReservation,
        limit_conn_guards: Vec<super::LimitConnGuard>,
        idle_timeout_ms: u64,
        max_lifetime_ms: u64,
        client_trace: Option<crate::observability::telemetry::ClientTrace>,
        frame_policy: Option<Arc<crate::protocols::ws_frame::FramePolicy>>,
    ) -> Result<Response<BoxBody>, ForwardError> {
        let final_upstream = reservation.base.clone();
        let extension_offer = match frame_policy
            .as_ref()
            .map(|policy| {
                crate::protocols::ws_frame::handshake::Offer::prepare(
                    &mut parts.headers,
                    policy.permessage_deflate,
                )
            })
            .transpose()
        {
            Ok(offer) => offer,
            Err(_) => {
                // 非法客户端扩展必须在真实上游尝试之前拒绝，不能污染后端健康或产生无效升级。
                if let Some(trace) = client_trace {
                    trace.finish_status(400);
                }
                let mut response = Response::new(full_body(Bytes::from_static(
                    b"invalid WebSocket extension offer\n",
                )));
                *response.status_mut() = StatusCode::BAD_REQUEST;
                return Ok(super::wrap_limit_conn_response(response, limit_conn_guards));
            }
        };
        self.metrics.inc_upstream_attempt();
        let workspace_permit = parts
            .extensions
            .get::<crate::control::ownership::admission::Permit>()
            .cloned();
        let ureq = Request::from_parts(parts, body);
        // WebSocket upgrade 固定使用 HTTP/1.1，不得因 route protocol=auto 扩大成 h2 shard 池。
        let client = self.http_client_for(&reservation, false, None);
        let result = super::health::observe(
            reservation.outlier.take(),
            async {
                client
                    .request(ureq)
                    .await
                    .map_err(|error| map_client_error("ws handshake", error))
            },
            0,
        )
        .await;
        let mut resp = match result {
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
        // 101 发往下游之前验证扩展响应；不能以部分协商状态接收压缩消息。
        let deflate_negotiated = if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            extension_offer
                .map(|offer| offer.accept(resp.headers_mut()))
                .transpose()
                .map_err(ForwardError::BadGateway)?
                .unwrap_or(false)
        } else {
            false
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
                let _workspace_permit = workspace_permit;
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
                // 登记长连接后接收撤权信号；guard Drop 自动注销，关闭按当前可确认的帧边界收尾。
                let guard = registry.register(
                    route_id.clone(),
                    client_ip,
                    consumer.clone(),
                    snapshot_version,
                    crate::runtime::connections::LongProto::Ws,
                );
                let close = guard.closed();
                tokio::pin!(close);
                let writes = WsFrameWrites::default();
                tokio::select! {
                    // 透明模式(默认)与帧级模式共用同一套 idle/lifetime/撤权治理,
                    // 只有数据搬运方式不同:透明模式一个字节都不解析。
                    r = govern_or_copy(
                        &mut downstream,
                        &mut upstream,
                        frame_policy.as_deref(),
                        &route_id,
                        consumer.as_deref(),
                        deflate_negotiated,
                        &writes,
                    ) => {
                        if let Err(e) = r {
                            tracing::debug!(route = %route_id, error = %e, "websocket tunnel closed");
                        }
                    }
                    // 先取消转发，再按已记录的完整帧边界关闭，半帧方向只能断流。
                    _ = &mut close => {
                        close_websocket(&mut downstream, &mut upstream, guard.ws_close_code(), &writes).await;
                        tracing::debug!(route = %route_id, "websocket tunnel closed by registry");
                    }
                    _ = wait_for_ws_inactivity(activity, idle_timeout_ms), if idle_timeout_ms > 0 => {
                        close_websocket(&mut downstream, &mut upstream, 1001, &writes).await;
                        tracing::debug!(route = %route_id, idle_timeout_ms, "websocket tunnel idle timeout");
                    }
                    _ = tokio::time::sleep(Duration::from_millis(max_lifetime_ms)), if max_lifetime_ms > 0 => {
                        close_websocket(&mut downstream, &mut upstream, 1001, &writes).await;
                        tracing::debug!(route = %route_id, max_lifetime_ms, "websocket tunnel max lifetime reached");
                    }
                }
                drop(guard);
            });
            return Ok(annotate_upstream_trace(
                resp.map(|b| reservation.wrap_body(b, 0, None)),
                final_upstream,
                1,
                None,
                None,
            ));
        }
        let resp = annotate_upstream_trace(
            resp.map(|b| reservation.wrap_body(b, 0, None)),
            final_upstream,
            1,
            None,
            None,
        );
        Ok(super::wrap_limit_conn_response(resp, limit_conn_guards))
    }
}

/// 一条 WS 隧道共享的最近活动状态。
///
/// 两个转发方向只 clone 这个小对象的 `Arc`。全局 clock 的值由单一后台 worker 每 10ms 更新；
/// 同一 tick 内无论搬运多少帧，连接时间戳最多写一次，避免双向高吞吐在一个 cache line 上反复
/// 写入。数据 buffer 不进入本对象，也不会发生帧复制。
pub(super) struct WsActivity {
    /// 进程级粗粒度单调毫秒值。
    clock_ms: Arc<AtomicU64>,
    /// 本连接最近一次活动对应的 clock tick。
    last_activity_ms: AtomicU64,
}

impl WsActivity {
    /// 业务作用：创建 WebSocket 连接活动状态，使无数据隧道从升级完成时开始计算 idle。
    ///
    /// 参数说明：
    /// - `clock_ms`：是进程级粗粒度单调时钟。
    ///
    /// 返回：返回两个转发方向共享的活动状态。
    pub(super) fn new(clock_ms: Arc<AtomicU64>) -> Arc<Self> {
        let initial = clock_ms.load(Ordering::Relaxed);
        Arc::new(Self {
            clock_ms,
            last_activity_ms: AtomicU64::new(initial),
        })
    }

    /// 业务作用：记录本连接最近一次真实字节进展，供 idle 回收判断。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；同一 tick 只写一次，idle 只依赖最终数值而不发布其它状态。
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
pub(super) struct ActivityIo<T> {
    /// 实际下游或上游字节流。
    inner: T,
    /// 两个方向共享的连接活动状态。
    activity: Arc<WsActivity>,
}

impl<T> ActivityIo<T> {
    /// 业务作用：包装一个 IO 并接入隧道共享活动时间戳，同时保持透明读写语义。
    ///
    /// 参数说明：
    /// - `inner`: 原始异步 IO；数据仍直接读写它。
    /// - `activity`: 两个方向共享的粗粒度活动时间。
    ///
    /// 返回：不分配数据缓冲的透明 IO wrapper。
    pub(super) fn new(inner: T, activity: Arc<WsActivity>) -> Self {
        Self {
            inner,
            activity,
        }
    }

    /// 业务作用：把一次确有字节进展的读写提交到连接活动状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    fn record_activity(&self) {
        self.activity.record();
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityIo<T> {
    /// 业务作用：透明委托读操作，并仅在 `ReadBuf` 实际增长时更新活动时间。
    ///
    /// 参数说明：
    /// - `cx`：是异步任务上下文
    /// - `buf`：是调用方提供的读取缓冲。
    ///
    /// 返回：返回底层读取结果，不改变字节内容或背压。
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
    /// 业务作用：透明委托写操作，并在正字节完成时更新共享活动时间。
    ///
    /// 参数说明：
    /// - `cx`：是异步任务上下文
    /// - `buf`：是待写字节。
    ///
    /// 返回：返回底层实际写入字节数或错误。
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

    /// 业务作用：透明刷新底层 IO，且不把 flush 误记为业务活动。
    ///
    /// 参数说明：
    /// - `cx`：是异步任务上下文。
    ///
    /// 返回：返回底层 flush 结果。
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    /// 业务作用：透明关闭底层写方向，且不让关闭过程反向延长 idle 生命周期。
    ///
    /// 参数说明：
    /// - `cx`：是异步任务上下文。
    ///
    /// 返回：返回底层 shutdown 结果。
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    /// 业务作用：暴露底层 vectored-write 能力，避免活动记录 wrapper 让批量写退化。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层支持 vectored write 时返回 true。
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    /// 业务作用：透明执行 vectored write，并按实际写入字节数更新时间。
    ///
    /// 参数说明：
    /// - `cx`：是异步任务上下文
    /// - `bufs`：是待写切片集合。
    ///
    /// 返回：返回底层实际写入字节数或错误。
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

/// 业务作用：等待 WebSocket 隧道达到双向无字节活动的 idle 上限，供连接治理安全回收。
///
/// 参数说明：
/// - `activity`: 与 `ActivityIo` 共享的粗粒度单调时钟和最近活动值。
/// - `idle_timeout_ms`: 空闲上限；0 时永久等待，调用者通常会禁用对应 select 分支。
///
/// 返回：达到 idle 上限时返回；上限为零时永不自行完成。
pub(super) async fn wait_for_ws_inactivity(activity: Arc<WsActivity>, idle_timeout_ms: u64) {
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

/// 业务作用：按 WebSocket 两端角色分别发送合规 Close 帧并半关闭写方向。
///
/// 参数说明：
/// - `downstream`: 网关作为 server 的客户端连接，Close 帧不得 mask。
/// - `upstream`: 网关作为 client 的上游连接，Close 帧必须使用新随机 mask。
/// - `code`: 1001（drain/idle/lifetime）或 1008（策略封禁）。
/// - `writes`：两个方向尚未完成的帧写入事实；不能向半帧追加控制消息。
///
/// 系统随机源失败时不发送不合规的上游帧，直接依靠随后 Drop 终止上游；下游仍收到标准状态码。
async fn close_websocket<D, U>(
    downstream: &mut D,
    upstream: &mut U,
    code: u16,
    writes: &WsFrameWrites,
) where
    D: AsyncWrite + Unpin,
    U: AsyncWrite + Unpin,
{
    write_governance_close(downstream, upstream, code, true, writes).await;
}

/// 业务作用：判断 mirror 是否命中采样。
///
/// 参数说明：
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

/// 业务作用：发送后台 mirror 请求。
///
/// 参数说明：
/// - `client`: 普通 h1/h2 上游连接池。
/// - `h2c_client`: h2c prior-knowledge 上游连接池。
/// - `h3_client`: H3/QUIC multiplex 上游连接池。
/// - `parts`: 已构造好的 mirror 请求 head。
/// - `body`：受主请求镜像预算约束的正文。
/// - `reservation`: 镜像上游实例预留计数。
/// - `ctx`：固定镜像响应头超时、下游协议与持续传输权威的上下文。
///
/// 返回：镜像响应处理成功时完成；上游错误、响应头超时或传输权威失效终止镜像并释放额度。
async fn send_mirror_request(
    client: Option<super::UpstreamHttpClient>,
    h2c_client: Option<super::UpstreamH2cClient>,
    #[cfg(feature = "http3")] h3_client: Option<Arc<super::http3_upstream::UpstreamH3Client>>,
    parts: Parts,
    body: BoxBody,
    mut reservation: UpstreamReservation,
    ctx: MirrorSendContext,
) -> Result<(), ForwardError> {
    if reservation
        .tls_profile
        .as_ref()
        .is_some_and(|profile| !profile.allows_new_requests())
    {
        // mirror 不是豁免业务流量；若等待后台调度期间身份到期，同样必须在 I/O 前停止。
        return Err(ForwardError::BadGateway(anyhow::anyhow!(
            "upstream TLS client identity is no longer valid"
        )));
    }
    let use_h2c = reservation.protocol == UpstreamProtocol::H2c;
    #[cfg(feature = "http3")]
    let use_h3 = reservation.protocol == UpstreamProtocol::H3;
    let request = Request::from_parts(parts, body);
    let fut = async {
        #[cfg(feature = "http3")]
        if use_h3 {
            return h3_client
                .expect("HTTP/3 mirror client prepared")
                .request(request)
                .await
                .map(|response| response.map(UpstreamResponseBody::Http3));
        }
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
    let result = super::health::observe(
        reservation.outlier.take(),
        async {
            fut.await
                .map_err(|error| map_client_error("mirror request", error))
        },
        ctx.ttfb_timeout_ms,
    )
    .await;
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

/// 业务作用：把 ext_authz 目标拆成上游 base 与鉴权 path。
///
/// 参数说明：
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

/// 业务作用：构造 ext_authz 鉴权子请求 head。
///
/// 参数说明：
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

/// 业务作用：为 ext_authz 运行态生成绑定 endpoint、输入 allowlist、body 与缓存/熔断参数的策略指纹。
///
/// 参数说明：
/// - `policy`：是当前快照已编译策略。
///
/// 返回：任一影响决策或运行态所有权的配置变化都会产生不同 SHA-256。
fn ext_authz_policy_fingerprint(policy: &ExtAuthzPolicy) -> [u8; 32] {
    let mut digest = Sha256::new();
    for value in [
        policy.target.as_bytes(),
        policy.path.as_deref().unwrap_or_default().as_bytes(),
        policy.method.as_str().as_bytes(),
    ] {
        ext_authz_hash_field(&mut digest, value);
    }
    ext_authz_hash_field(&mut digest, &[u8::from(policy.fail_open)]);
    ext_authz_hash_field(
        &mut digest,
        &policy.body_max_bytes.unwrap_or_default().to_be_bytes(),
    );
    ext_authz_hash_field(
        &mut digest,
        &policy
            .cache_ttl
            .map(|ttl| ttl.as_millis() as u64)
            .unwrap_or_default()
            .to_be_bytes(),
    );
    ext_authz_hash_field(&mut digest, &policy.cache_max_entries.to_be_bytes());
    ext_authz_hash_field(&mut digest, &policy.circuit_failure_threshold.to_be_bytes());
    ext_authz_hash_field(
        &mut digest,
        &(policy.circuit_open.as_millis() as u64).to_be_bytes(),
    );
    for name in &policy.request_headers {
        ext_authz_hash_field(&mut digest, name.as_str().as_bytes());
    }
    ext_authz_hash_field(&mut digest, b"upstream-headers");
    for name in &policy.upstream_headers {
        ext_authz_hash_field(&mut digest, name.as_str().as_bytes());
    }
    digest.finalize().into()
}

/// 业务作用：构造 ext_authz 决策缓存的完整输入键，避免不同主体、URI、header 或 body 共享授权。
///
/// 参数说明：
/// - `policy`：限定外部鉴权可见字段与正文的策略。
/// - `parts`：外部鉴权看到的原始请求头。
/// - `client_ip`：经过可信代理规则解析的真实客户端 IP。
/// - `trusted_inbound`：直连对端是否属于可信代理。
/// - `downstream_proto`：可信 listener 确认的下游协议。
/// - `auth_body`：按路由上限聚合的可选鉴权正文。
///
/// 返回：长度分隔 SHA-256，不含原始凭据文本且稳定区分缺失、重复和顺序。
fn ext_authz_decision_key(
    policy: &ExtAuthzPolicy,
    parts: &Parts,
    client_ip: IpAddr,
    trusted_inbound: bool,
    downstream_proto: &str,
    auth_body: Option<&Bytes>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    ext_authz_hash_field(&mut digest, parts.method.as_str().as_bytes());
    ext_authz_hash_field(&mut digest, parts.uri.to_string().as_bytes());
    ext_authz_hash_field(&mut digest, client_ip.to_string().as_bytes());
    ext_authz_hash_field(&mut digest, &[u8::from(trusted_inbound)]);
    ext_authz_hash_field(&mut digest, downstream_proto.as_bytes());
    ext_authz_hash_field(
        &mut digest,
        parts
            .headers
            .get(HOST)
            .map(HeaderValue::as_bytes)
            .unwrap_or_default(),
    );
    for name in &policy.request_headers {
        ext_authz_hash_field(&mut digest, name.as_str().as_bytes());
        let values = parts.headers.get_all(name);
        ext_authz_hash_field(&mut digest, &values.iter().count().to_be_bytes());
        for value in values {
            ext_authz_hash_field(&mut digest, value.as_bytes());
        }
    }
    if policy.body_max_bytes.is_some() {
        ext_authz_hash_field(&mut digest, b"body-present");
        let body_digest = Sha256::digest(auth_body.map_or(&[][..], Bytes::as_ref));
        ext_authz_hash_field(&mut digest, &body_digest);
    } else {
        ext_authz_hash_field(&mut digest, b"body-absent");
    }
    digest.finalize().into()
}

/// 业务作用：以显式长度分隔字段写入摘要，防止字符串拼接边界碰撞。
///
/// 参数说明：
/// - `digest`：是当前 SHA-256
/// - `value`：是单个结构化字段。
///
/// 返回：无；先写八字节长度再写字段原值。
fn ext_authz_hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

/// 业务作用：从明确 allow 响应提取唯一 allowlist header 快照，供即时注入与缓存命中复用相同语义。
///
/// 参数说明：
/// - `policy`：声明可复制字段
/// - `resp`：是成功鉴权响应。
///
/// 返回：只包含响应实际出现的首值，不含未声明字段。
fn ext_authz_upstream_headers(
    policy: &ExtAuthzPolicy,
    resp: &Response<BoxBody>,
) -> Vec<(HeaderName, HeaderValue)> {
    policy
        .upstream_headers
        .iter()
        .filter_map(|name| {
            resp.headers()
                .get(name)
                .cloned()
                .map(|value| (name.clone(), value))
        })
        .collect()
}

/// 业务作用：把已验证或缓存的 ext_authz allowlist header 注入主上游请求。
///
/// 参数说明：
/// - `parts`：是主请求 head
/// - `headers`：只来自明确 allow 响应的已过滤快照。
///
/// 返回：无；同名客户端值被可信鉴权结果覆盖。
fn apply_ext_authz_upstream_headers(parts: &mut Parts, headers: &[(HeaderName, HeaderValue)]) {
    for (name, value) in headers {
        parts.headers.insert(name.clone(), value.clone());
    }
}

/// 业务作用：应用 route 级 path 前缀改写，并规范化替换前缀与剩余路径的连接边界。
///
/// 参数说明：
/// - `path`：是已经执行 `StripPrefix` 后的 path
/// - `route`：是当前命中的 route。
///
/// 返回：未配置或未命中改写前缀时保留原 path；命中时返回恰好一个 `/` 连接边界的 origin path。
fn rewrite_prefix(path: &str, route: &Route) -> String {
    let Some(rewrite) = &route.rewrite_prefix else {
        return path.to_string();
    };
    let Some(rest) = path.strip_prefix(&rewrite.from) else {
        return path.to_string();
    };
    join_rewrite_prefix(&rewrite.to, rest)
}

/// 业务作用：连接改写目标前缀与原路径剩余部分，避免产生双斜杠或缺失路径分隔符。
///
/// 参数说明：
/// - `replacement`：是替换后的前缀
/// - `rest`：是从原路径剥离匹配前缀后的剩余部分。
///
/// 返回：返回以 `/` 开头且连接边界恰好包含一个 `/` 的 origin path。
fn join_rewrite_prefix(replacement: &str, rest: &str) -> String {
    let mut out = String::with_capacity(replacement.len() + rest.len() + 1);
    if replacement.starts_with('/') {
        out.push_str(replacement);
    } else {
        out.push('/');
        out.push_str(replacement);
    }
    if !rest.is_empty() {
        match (out.ends_with('/'), rest.starts_with('/')) {
            // ReplacePrefixMatch `/` 与原路径剩余部分都带 `/` 时必须折叠边界，
            // 否则上游会收到 `//suffix`，违反 Gateway API 的前缀替换语义。
            (true, true) => out.push_str(&rest[1..]),
            (false, false) => {
                out.push('/');
                out.push_str(rest);
            }
            _ => out.push_str(rest),
        }
    }
    out
}

/// 业务作用：组装最终发往上游的 URI。
///
/// 参数说明：
/// - `base`: 上游实例或直连 upstream base URI。
/// - `path`: 转发后的 path。
/// - `query`: 原始 query,包含可选前导 `?`。
fn upstream_uri(base: &str, path: &str, query: &str) -> Result<http::Uri, ForwardError> {
    format!("{base}{path}{query}")
        .parse()
        .map_err(|e| ForwardError::BadGateway(anyhow::anyhow!("bad upstream uri: {e}")))
}

/// 业务作用：为单次上游尝试构造请求 head。
///
/// 参数说明：
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
    let eval_ctx = crate::routing::variable::EvalContext {
        parts: base_parts,
        client_ip,
        downstream_proto,
        request_id,
        route_id: route.id.as_str(),
        response_status: None,
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

/// 业务作用：为单次、不可重试的上游请求原地改写 downstream head。
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
        let eval_ctx = crate::routing::variable::EvalContext {
            parts: &parts,
            client_ip,
            downstream_proto,
            request_id,
            route_id: route.id.as_str(),
            response_status: None,
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

/// 业务作用：为一次具体上游尝试完成 Host、forwarded 头、mTLS 盖章与 route
/// header mutation，保证重试换实例时仍按当前 route 契约构造完整 head。
///
/// 参数说明：
/// - `parts`：下游请求 head，包含原始规范化 URI。
/// - `uri`：当次尝试已选择的上游 URI。
/// - `route`：当前快照编译后的路由契约。
/// - `protocol`：所选实例的协议身份。
/// - `client_ip`：入口信任链确定的客户端地址。
/// - `client_ip_header`：已经格式化的可信客户端地址头。
/// - `trusted_inbound`：入口是否允许保留受信代理链。
/// - `client_cert_verified`：下游客户端证书是否通过验证。
/// - `downstream_proto`：真实入口的 HTTP scheme。
/// - `request_id`：当前请求的稳定关联标识。
/// - `is_ws`：当前请求是否进入 WebSocket 升级流程。
/// - `request_headers`：变量已经渲染的请求头操作。
///
/// 返回：所有代理头与显式 mutation 合法时返回可发送 head；非法头值或变量渲染
/// 失败时在任何上游 I/O 前拒绝请求。
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
    request_headers: Vec<RenderedRequestHeaderOp>,
) -> Result<Parts, ForwardError> {
    #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
    if let Some(plan) = &route.cgi {
        let expected = match plan.config.protocol {
            crate::config::cgi::Protocol::Fastcgi => UpstreamProtocol::Fastcgi,
            crate::config::cgi::Protocol::Uwsgi => UpstreamProtocol::Uwsgi,
            crate::config::cgi::Protocol::Scgi => UpstreamProtocol::Scgi,
        };
        // 脚本计划与已选择实例必须同协议；升级不能绕过普通发送入口进入 HTTP 握手。
        if protocol != expected || is_ws {
            return Err(ForwardError::BadGateway(anyhow::anyhow!(
                "CGI script plan and selected transport mismatch"
            )));
        }
        parts.extensions.insert(crate::protocols::cgi::Input {
            plan: plan.clone(),
            uri: parts.uri.clone(),
            client_ip,
            https: downstream_proto == "https",
            version: parts.version,
        });
    } else if protocol.is_cgi() {
        return Err(ForwardError::BadGateway(anyhow::anyhow!(
            "CGI service cannot execute without a fixed script plan"
        )));
    }
    if !route.preserve_host {
        // 非保留模式必须按每次尝试重写 authority，否则重试换实例后会带旧 Host。
        if let Some(auth) = uri.authority() {
            parts
                .headers
                .insert(HOST, header_value(auth.as_str(), "host")?);
        }
    }
    inject_forward_headers(
        &mut parts,
        client_ip,
        client_ip_header,
        trusted_inbound,
        downstream_proto,
        request_id,
    )?;
    // mTLS 证书校验结果透传( 双向认证):把 TLS 握手阶段的客户端证书校验结论
    // 以 `X-Client-Cert-Verified` 头告知上游,便于上游做“证书即身份”的鉴权决策。
    // WHY:先无条件删除下游可能伪造的同名头,再仅在本网关握手确认证书有效时写入 SUCCESS,
    //      否则不写。这样上游看到该头就必然是网关盖章的可信结论,杜绝客户端自带头绕过 mTLS。
    parts.headers.remove(X_CLIENT_CERT_VERIFIED);
    if client_cert_verified {
        parts
            .headers
            .insert(X_CLIENT_CERT_VERIFIED, HeaderValue::from_static("SUCCESS"));
    }
    for operation in request_headers {
        match operation {
            RenderedRequestHeaderOp::Set(name, value) => {
                parts.headers.insert(name, value);
            }
            RenderedRequestHeaderOp::Add(name, value) => {
                parts.headers.append(name, value);
            }
            RenderedRequestHeaderOp::Remove(name) => {
                parts.headers.remove(name);
            }
        }
    }
    if !route.pass_request_body {
        strip_request_body_headers(&mut parts);
    }
    // 先固定最终上游协议，再决定由哪一层清洗 hop-by-hop 头。Hyper 的 HTTP/2 client 在
    // 编码 HEADERS frame 前必定按 RFC 9113 再清一次 Connection/TE/Upgrade 等字段；这里若
    // 仍走 H1 的完整清洗，会让每条 gRPC stream 对同一 HeaderMap 重复做约十次哈希查表。
    // HTTP/1.1（含 WS）没有这层协议兜底，仍严格执行 Naway 的完整 Connection-token 清洗。
    let upstream_version = if is_ws {
        http::Version::HTTP_11
    } else {
        upstream_request_version(protocol, &parts)
    };
    sanitize_hop_headers_for_upstream(&mut parts, is_ws, upstream_version);
    parts.uri = if route.preserve_host {
        preserve_request_uri_authority(uri, parts.headers.get(HOST))?
    } else {
        uri
    };
    if let Some(credentials) = &route.upstream_credentials {
        // 凭据必须是发送前最后一项业务 head 变更：客户端和普通 filter 的同名值均已确定，
        // 此处统一删除后注入，后续只允许协议级 hop-by-hop 处理，避免被再次覆盖或发往错误 backend。
        credentials
            .apply(&mut parts)
            .map_err(ForwardError::BadGateway)?;
    }
    // 上游请求版本按上游 protocol 配置设置：auto 时 gRPC 走 h2、普通 http 走 h1；
    //   WS 是 h1 upgrade 固定 1.1。避免把下游版本误传给 h1 上游。
    parts.version = upstream_version;
    #[cfg(feature = "webdav")]
    if let Some(mapping) = parts
        .extensions
        .get::<crate::io::webdav::proxy::Mapping>()
        .cloned()
    {
        let selected = parts.uri.clone();
        mapping
            .apply(&mut parts, &selected)
            .map_err(ForwardError::BadGateway)?;
    }
    Ok(parts)
}

/// 业务作用：在 `preserve_host` 路由上把原始 Host 同步到上游 URI authority，
/// 防止 HTTP/2 把实际拨号地址编码为 `:authority` 后改变虚拟主机语义。
///
/// 参数说明：
/// - `uri`：含实际上游 scheme/地址/path
/// - `host`：是已通过入口头部校验的原始 Host。
///
/// 返回：Host 存在且可作为 authority 时返回保留权威的新 URI；缺 Host 时保持实际 URI，非法值拒绝请求。
fn preserve_request_uri_authority(
    uri: http::Uri,
    host: Option<&HeaderValue>,
) -> Result<http::Uri, ForwardError> {
    let Some(host) = host else {
        return Ok(uri);
    };
    let authority = host
        .to_str()
        .map_err(|error| {
            ForwardError::BadGateway(anyhow::anyhow!("invalid preserved Host: {error}"))
        })?
        .parse::<http::uri::Authority>()
        .map_err(|error| {
            ForwardError::BadGateway(anyhow::anyhow!("invalid preserved authority: {error}"))
        })?;
    let mut parts = uri.into_parts();
    parts.authority = Some(authority);
    http::Uri::from_parts(parts).map_err(|error| {
        ForwardError::BadGateway(anyhow::anyhow!("build preserved upstream URI: {error}"))
    })
}

/// 业务作用：删除请求体相关头,避免 `proxy_pass_request_body off` 时上游继续等待 body。
///
/// 参数说明：
/// - `parts`: 将要发送给上游的请求 head。
fn strip_request_body_headers(parts: &mut Parts) {
    // WHY:空 body 不能携带原始 Content-Length/Transfer-Encoding,否则 h1 上游可能按旧长度阻塞等待读取。
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.remove(EXPECT);
}

/// 业务作用：按 route 配置构造发往上游的请求体。
///
/// 参数说明：
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
        // WHY:proxy_pass_request_body=off 的目标是“不读、不缓冲、不转发”请求体；丢弃下游流即可让上游看到空 body。
        return empty_body();
    }
    // 流式转发：下游统一 body 直接作上游请求 body，不全量 buffer（背压天然）。
    // body 上限对流式及 chunked 请求也生效：有 Content-Length 的已在入口以 413 拦截；
    //   无 Content-Length 的 chunked/H3 上传靠 LimitedBoxBody 在超过 max_body_bytes 时中止，防无界上传打爆带宽/上游。
    idle_timeout_body(
        limited_forward_body(body, max_body_bytes),
        stream_idle_timeout_ms,
    )
}

/// 业务作用：为透传请求体包上可选大小限制。
///
/// 参数说明：
/// - `body`: 下游或显式慢路径复用的统一流式 body。
/// - `max_body_bytes`: 最大允许字节数,0 表示不限制。
fn limited_forward_body(body: ForwardBody, max_body_bytes: u64) -> BoxBody {
    // Schema/GraphQL/degraphql 以及 H3 adapter 都会产生同一 BoxBody。它们仍必须服从 proxy
    // 总 body 上限；尤其无 Content-Length 的流不能因类型擦除绕过全局限制。
    if max_body_bytes > 0 {
        LimitedBoxBody::new(body, max_body_bytes as usize).boxed()
    } else {
        body
    }
}

/// 业务作用：收集显式 body mirror 的小请求体。
///
/// 参数说明：
/// - `body`: 待收集的当前请求体。
/// - `max_body_bytes`: mirror body 上限,超过会返回错误并中止本次请求。
async fn collect_forward_body(
    body: ForwardBody,
    max_body_bytes: u64,
) -> Result<Bytes, ForwardError> {
    let collected = LimitedBoxBody::new(body, max_body_bytes as usize)
        .collect()
        .await
        .map_err(|error| map_client_error("mirror body collect", error))?;
    Ok(collected.to_bytes())
}

/// 已擦除请求体的零拷贝字节限界层。
///
/// `http_body_util::Limited<BoxBody>` 会要求 `BoxError: Into<BoxError>` 满足高阶生命周期；该约束
/// 在后台 `tokio::spawn` 的 `'static` 检查中无法成立。这里直接保留 `BoxBody` 的拥有型错误，
/// 逐帧只读取 `Bytes::len` 并原样返回 frame，不 collect、不复制 payload。超过上限后产生一次
/// 拥有型错误并终止，避免错误后的内层 body 继续被意外轮询。
struct LimitedBoxBody {
    inner: BoxBody,
    remaining: usize,
    done: bool,
}

impl LimitedBoxBody {
    /// 业务作用：为请求正文绑定字节硬上限，声明长度未知的流也必须在发送中计费。
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

    /// 业务作用：按下游轮询推进正文流，把数据、trailers、失败和结束状态交给统一 HTTP 管线。
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

    /// 业务作用：向 HTTP 编码层报告流是否已经结束，避免省略尚未发送的正文或 trailers。
    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    /// 业务作用：向 HTTP 编码层提供剩余实体长度约束，供帧传输选择定长或流式编码。
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

/// 业务作用：为任意流式 body 包上帧间空闲超时。
///
/// 参数说明：
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

/// 业务作用：把最终上游和尝试次数写入响应扩展,供 access log/指标读取。
///
/// 参数说明：
/// - `resp`: 上游响应。
/// - `final_upstream`: 最终命中的上游实例 URI。
/// - `attempts`: 本次请求的上游尝试次数。
/// - `service`：最终选址对应的可选逻辑服务名。
/// - `affinity`：当前请求确认的可选会话亲和结果。
fn annotate_upstream_trace(
    mut resp: Response<BoxBody>,
    final_upstream: Arc<str>,
    attempts: usize,
    service: Option<Arc<str>>,
    affinity: Option<crate::upstream::SessionAffinityToken>,
) -> Response<BoxBody> {
    resp.extensions_mut().insert(UpstreamTrace {
        final_upstream,
        attempts,
        service,
        affinity,
    });
    resp
}

/// 业务作用：在响应上下发会话亲和载体,使同一会话的后续请求稳定回到同一实例。
///
/// 令牌由实例 URI 派生(见 [`SessionAffinityPolicy::token_for`]),**不携带任何地址信息**,
/// 因此下发给客户端不泄漏内网拓扑。仅当服务确实配置了会话保持时才写,避免给所有响应
/// 附加无意义的 `Set-Cookie`。
///
/// 参数说明：
/// - `resp`: 即将回写下游的响应。
/// - `snap`: 当前请求快照。
/// - `trace`: 上游追踪信息,提供服务名与最终实例 URI。
///
/// 返回：无；未配置亲和或响应头值无法安全编码时保持原响应不变。
pub(super) fn apply_session_affinity(
    resp: &mut Response<BoxBody>,
    snap: &GatewaySnapshot,
    trace: &UpstreamTrace,
) {
    use crate::upstream::SessionAffinityMode;
    let Some(service) = trace.service.as_deref() else {
        return;
    };
    let Some(policy) = snap.upstreams.session_affinity(service) else {
        return;
    };
    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (token, token_state) =
        policy.token_for(trace.final_upstream.as_ref(), trace.affinity, now_seconds);
    match &policy.mode {
        SessionAffinityMode::Cookie {
            name,
            ttl_seconds,
            permanent: _,
            path,
            domain,
            same_site,
            secure,
            http_only,
        } => {
            let mut value = format!("{name}={token}");
            if let Some(path) = path {
                value.push_str("; Path=");
                value.push_str(path);
            }
            if let Some(domain) = domain {
                value.push_str("; Domain=");
                value.push_str(domain);
            }
            // Gateway API 持久 cookie 的剩余期限必须随绝对期限递减；原生 ttl 配置保留
            // 既有滚动 Max-Age 语义，两者不能相互覆盖。
            if let Some(max_age) = policy.permanent_cookie_max_age(token_state, now_seconds) {
                value.push_str("; Max-Age=");
                value.push_str(&max_age.to_string());
            } else if *ttl_seconds > 0 {
                value.push_str("; Max-Age=");
                value.push_str(&ttl_seconds.to_string());
            }
            value.push_str("; SameSite=");
            value.push_str(same_site);
            if *secure {
                value.push_str("; Secure");
            }
            if *http_only {
                value.push_str("; HttpOnly");
            }
            if let Ok(header) = HeaderValue::from_str(&value) {
                // append 而非 insert:上游或 filter 可能已下发业务 cookie,不能被亲和 cookie 顶掉。
                resp.headers_mut().append(http::header::SET_COOKIE, header);
            }
        }
        SessionAffinityMode::Header {
            name,
        } => {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&token),
            ) {
                resp.headers_mut().insert(name, value);
            }
        }
    }
}

/// 业务作用：构造 CONNECT 等无实体成功响应使用的零字节 body，避免伪造内容长度。
///
/// 参数说明: 无。
///
/// 返回：返回立即结束且不产生 data frame 的统一 body。
pub(super) fn empty_body() -> BoxBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// 业务作用：执行 hedge 的最后一道请求级安全门，避免配置声明被 POST 等实际请求复用。
///
/// 参数说明：
/// - `parts`：是真实下游请求 head
/// - `pass_request_body`：是编译后的 route body 策略。
///
/// 返回：仅 GET/HEAD 且 route 明确不向上游发送 body 时允许启动副本。
fn can_hedge_request(parts: &Parts, pass_request_body: bool) -> bool {
    !pass_request_body && matches!(parts.method, http::Method::GET | http::Method::HEAD)
}

/// 业务作用：判定 hedge attempt 是否已经得到可交付的业务响应；5xx 继续等待另一实例，
/// 4xx 视为权威业务结果，避免错误请求被重复放大。
///
/// 参数说明：
/// - `result`：是已完成健康记账和追踪标注的 attempt 结果。
///
/// 返回：transport 成功且状态码不是 5xx 时返回 true。
fn hedge_attempt_succeeded(result: &Result<Response<BoxBody>, ForwardError>) -> bool {
    result
        .as_ref()
        .is_ok_and(|response| !response.status().is_server_error())
}

/// 业务作用：两个 hedge attempt 都未成功时选出对下游最有解释力的失败结果。
///
/// 参数说明：
/// - `first`：是先完成的失败
/// - `second`：是后完成的失败。
///
/// 返回：优先返回真实 5xx response；两者都是 transport 错误时保留先发生的错误。
fn choose_hedge_result(
    first: Result<Response<BoxBody>, ForwardError>,
    second: Result<Response<BoxBody>, ForwardError>,
) -> Result<Response<BoxBody>, ForwardError> {
    match (first, second) {
        (response @ Ok(_), _) => response,
        (_, response @ Ok(_)) => response,
        (Err(first), Err(_)) => Err(first),
    }
}

/// 业务作用：判断当前请求是否允许尝试下一个上游实例。
///
/// 参数说明：
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

/// 业务作用：通过请求头判断下游请求体是否为空。
///
/// 参数说明：
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

/// 业务作用：从请求头读取可信的 `Content-Length`。
///
/// 参数说明：
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

/// 业务作用：按路由声明判断响应状态是否允许重试，不把所有失败状态自动重发。
fn should_retry_status(policy: &NextUpstreamPolicy, status: StatusCode) -> bool {
    match status {
        StatusCode::BAD_GATEWAY => policy.http_502,
        StatusCode::SERVICE_UNAVAILABLE => policy.http_503,
        StatusCode::GATEWAY_TIMEOUT => policy.http_504,
        _ => false,
    }
}

/// 业务作用：按路由声明判断连接或传输错误的重试资格，保留不可重放请求的边界。
fn should_retry_error(policy: &NextUpstreamPolicy, err: &ForwardError) -> bool {
    match err {
        ForwardError::RequestDecompression(_) => false,
        ForwardError::BadGateway(_) => policy.error,
        #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
        ForwardError::CgiInput(_, _) => false,
        ForwardError::Timeout => policy.timeout,
        ForwardError::BrowserGrpc(_)
        | ForwardError::LocalTraffic
        | ForwardError::NoHealthyUpstream(_)
        | ForwardError::Overloaded => false,
    }
}

/// 业务作用：执行策略规定的重试间隔，避免依赖失败时形成无间隔请求风暴。
async fn retry_backoff(policy: Option<&NextUpstreamPolicy>) {
    let Some(policy) = policy else {
        return;
    };
    if policy.backoff_ms > 0 {
        tokio::time::sleep(Duration::from_millis(policy.backoff_ms)).await;
    }
}

impl super::GatewayProxy {
    /// 业务作用：启动上游低频维护任务，回收退场反馈并只预热尚未见过的完整实例/池身份。
    /// 动态发现加入的新实例在下一轮预热，已完成项不会周期性制造业务请求。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；后台 task 与 `GatewayProxy` 共享生命周期。
    pub fn spawn_upstream_prewarm(self: &Arc<Self>) {
        let gateway = self.clone();
        tokio::spawn(async move {
            loop {
                let snapshot = gateway.snap.load_full();
                // 发现成员可在配置版本不变时持续换代；定期撤下旧状态，不能依赖下一次文件热更回收。
                gateway
                    .upstream_health
                    .reconcile_loads(&snapshot.upstreams, snapshot.version);
                gateway.prewarm_snapshot(snapshot.as_ref()).await;
                let interval = snapshot.upstreams.prewarm_scan_interval_ms();
                drop(snapshot);
                tokio::time::sleep(Duration::from_millis(interval)).await;
            }
        });
    }

    /// 业务作用：扫描一个不可变快照并并发预热所有新增实例。
    ///
    /// 参数说明：
    /// - `snapshot`：是本轮固定的路由与上游快照。
    ///
    /// 返回：无；成功 identity 记入去重集，失败 identity 留给下轮重试。
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
                    if target.protocol == UpstreamProtocol::H3 {
                        // H3 client 在一条 QUIC connection 上 multiplex stream；预热多次只会制造
                        // 额外 HEAD，不会建立更多物理连接，因此将该 identity 收敛为一次握手。
                        connections = connections.min(1);
                    }
                    connections = connections.min(pool_policy.max_idle_per_upstream);
                    if pool_policy.max_connections_per_upstream > 0 {
                        connections = connections.min(pool_policy.max_connections_per_upstream);
                    }
                    let key = super::PrewarmedUpstreamKey {
                        health_key: target.health_key.clone(),
                        protocol: target.protocol,
                        connect_timeout_ms: target.connect_timeout_ms,
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

    /// 业务作用：使用真实 H1/H2/H2c/H3 client cache 建立连接；HEAD 从空 head
    /// 构造，不复制任何下游 header/body，只等待 response head 便允许连接回池。
    ///
    /// 参数说明：
    /// - `target`：是已验证的实例和预热策略
    /// - `pool_policy`：提供协议窗口与 物理连接预算
    /// - `connections`：是本轮希望预热的物理连接数。
    ///
    /// 返回：所有预热请求在 deadline 内拿到响应头时为 true，否则为 false。
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
            connect_timeout_ms: target.connect_timeout_ms,
            tls_profile: target.tls_profile.clone(),
            pool_policy,
            feedback: None,
            outlier: None,
            counter: None,
            pending_counter: None,
            release_on_drop: false,
        };
        if reservation
            .tls_profile
            .as_ref()
            .is_some_and(|profile| !profile.allows_new_requests())
        {
            // 预热也是新上游工作；身份过期时不能为旧 generation 建立或复用连接。
            return false;
        }
        let Ok(uri) = upstream_uri(&reservation.base, target.policy.path.as_ref(), "") else {
            return false;
        };
        let timeout = Duration::from_millis(target.policy.timeout_ms);
        #[cfg(feature = "http3")]
        if target.protocol == UpstreamProtocol::H3 {
            let Ok(client) = self.h3_client_for(&reservation) else {
                return false;
            };
            let request = Request::builder()
                .method(http::Method::HEAD)
                .version(http::Version::HTTP_3)
                .uri(uri)
                .body(empty_body())
                .expect("build validated HTTP/3 prewarm request");
            return matches!(
                tokio::time::timeout(timeout, client.request(request)).await,
                Ok(Ok(_))
            );
        }
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
    /// 业务作用：获取匹配当前 TLS profile 与池参数的普通 HTTP(S) client。
    ///
    /// cache key 包含 profile 指纹与池参数：reload 改证书或预算会建立新池；旧请求持有的 client clone
    /// 继续 drain，cache 仅在超过 `old_pool_retain_ms` 后移除旧 handle，不会中断在途 body。
    ///
    /// 参数说明：
    /// - `reservation`: 本次已选中的实例预留，携带 TLS profile 与当前 proxy 的池预算。
    /// - `h2_request`：本次上游请求是否使用 HTTP/2。
    /// - `shard_hint`：稳定连接池分片提示，限制单池竞争。
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
            connect_timeout_ms: reservation.connect_timeout_ms,
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
                let mut client = build_upstream_http_client(
                    reservation.tls_profile.as_ref(),
                    reservation.base.as_ref(),
                    reservation.pool_policy,
                    physical_budget.clone(),
                    h2_request,
                    reservation.connect_timeout_ms,
                );
                client.reject_non_http = reservation.protocol.is_cgi();
                client
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

    /// 业务作用：获取一个跨 HTTP client generation 共享的物理连接预算。
    ///
    /// 参数说明：
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

    /// 获取匹配 authority、TLS identity 与 transport 预算的 HTTP/3 multiplex client。
    ///
    /// 业务作用：稳定请求复用同一 QUIC connection；reload 改证书、header/window/idle/物理上限时
    /// 创建新 generation，并立即从 cache 撤下同 identity 旧 handle，既有 body 仍持连接自然 drain。
    ///
    /// 参数说明：
    /// - `reservation`：是本次上游选择的不可变身份与资源计划。
    ///
    /// 返回：成功时返回惰性拨号 client；缺少 TLS profile 或 URI 无效时返回上游错误。
    #[cfg(feature = "http3")]
    fn h3_client_for(
        &self,
        reservation: &UpstreamReservation,
    ) -> Result<Arc<super::http3_upstream::UpstreamH3Client>, BoxError> {
        let tls_profile = reservation.tls_profile.clone().ok_or_else(|| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HTTP/3 upstream is missing its validated TLS profile",
            )) as BoxError
        })?;
        let key = super::UpstreamH3ClientCacheKey {
            health_key: reservation.health_key.clone(),
            profile_key: tls_profile.key.clone(),
            max_response_header_bytes: reservation.pool_policy.max_header_bytes,
            stream_receive_window_bytes: reservation.pool_policy.h2_initial_stream_window_bytes,
            connection_receive_window_bytes: reservation
                .pool_policy
                .h2_initial_connection_window_bytes,
            max_connections_per_upstream: reservation.pool_policy.max_connections_per_upstream,
            idle_timeout_ms: reservation.pool_policy.idle_timeout_ms,
        };
        if let Some(client) = self.h3_clients.read().get(&key) {
            return Ok(client.clone());
        }
        let physical_budget = self.physical_connection_budget_for(reservation);
        let mut clients = self.h3_clients.write();
        if let Some(client) = clients.get(&key) {
            return Ok(client.clone());
        }
        // 同 identity 同时只保留一个可分配新 request 的 transport 计划；旧 Arc 可能仍被 response
        // body 持有，移除 cache 不会粗暴关闭在途 stream。
        clients.retain(|candidate, _| candidate.health_key != key.health_key);
        let client = super::http3_upstream::UpstreamH3Client::new(
            &reservation.base,
            tls_profile,
            key.max_response_header_bytes,
            key.stream_receive_window_bytes,
            key.connection_receive_window_bytes,
            key.idle_timeout_ms,
            physical_budget,
            self.metrics.clone(),
        )
        .map_err(Into::<BoxError>::into)?;
        clients.insert(key, client.clone());
        Ok(client)
    }

    /// 业务作用：获取匹配当前池参数的 h2c prior-knowledge client。
    ///
    /// 参数说明：
    /// - `reservation`: 本次实例预留；h2c 不使用 TLS profile，但复用其中的池预算与旧池保留期。
    /// - `shard_hint`：稳定连接池分片提示，限制单池竞争。
    ///
    /// 返回：已强制 `http2_only` 的 Hyper client，保证不会静默退化成 HTTP/1.1。
    fn h2c_client_for(
        &self,
        reservation: &UpstreamReservation,
        shard_hint: Option<u64>,
    ) -> super::UpstreamH2cClient {
        let cache_key = super::UpstreamH2cClientCacheKey {
            health_key: reservation.health_key.clone(),
            connect_timeout_ms: reservation.connect_timeout_ms,
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
            .map(|_| {
                build_h2c_client(
                    reservation.pool_policy,
                    physical_budget.clone(),
                    reservation.connect_timeout_ms,
                    reservation.base.as_ref(),
                )
            })
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

    /// 业务作用：为一次上游请求取得自适应并发名额,必要时在有界队列中短暂等待。
    ///
    /// 名额覆盖「发出请求 → 拿到响应头」这一段,与 minRTT 的度量口径一致;响应 body
    /// 的流式传输不占名额,否则慢客户端会把上限吃光。**队列必须有界且有 deadline**:
    /// 无界等待只是把过载从 503 变成超时,对下游更糟。
    ///
    /// 参数说明：
    /// - `snap`: 当前请求快照。
    /// - `service`: `lb://` 逻辑服务名;直连上游不参与自适应并发。
    ///
    /// 返回：取得名额返回 RAII 令牌;并发与队列都满时返回 `Overloaded`(503)。
    async fn acquire_admission(
        &self,
        snap: &GatewaySnapshot,
        service: Option<&str>,
    ) -> Result<Option<crate::runtime::admission::ConcurrencyPermit>, ForwardError> {
        let Some(service) = service else {
            return Ok(None);
        };
        let Some(policy) = snap.upstreams.adaptive_concurrency(service).cloned() else {
            return Ok(None);
        };
        let state = self.admission_state(service, &policy);
        if let Some(permit) = state.try_acquire() {
            return Ok(Some(permit));
        }
        // 并发已满:只有显式配置了队列才等待,且必须先占到有界队列位,
        // 否则等待本身就是一条无界资源。
        let Some(_slot) = state.try_enqueue(&policy) else {
            self.metrics.inc_upstream_overloaded();
            return Err(ForwardError::Overloaded);
        };
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(policy.queue_deadline_ms);
        loop {
            if let Some(permit) = state.try_acquire() {
                return Ok(Some(permit));
            }
            if tokio::time::Instant::now() >= deadline {
                self.metrics.inc_upstream_overloaded();
                return Err(ForwardError::Overloaded);
            }
            // 轮询间隔取队列 deadline 的一小段:既不空转烧 CPU,也保证在 deadline 内
            // 有足够次数的重试机会。名额释放是 Drop 触发的,没有可等待的唤醒点。
            tokio::time::sleep(Duration::from_millis(
                (policy.queue_deadline_ms / 10).max(1),
            ))
            .await;
        }
    }

    /// 业务作用：把一次上游结果并入自适应并发的采样,并推进上限调节。
    ///
    /// 参数说明：
    /// - `snap`：定位策略与状态
    /// - `service`：定位策略与状态
    /// - `outcome`：是结果分类
    /// - `rtt`：是响应头耗时。
    ///
    /// 返回：无；未配置自适应并发的服务不产生运行态写入。
    fn record_admission(
        &self,
        snap: &GatewaySnapshot,
        service: Option<&str>,
        outcome: crate::runtime::admission::AdmissionOutcome,
        rtt: Duration,
    ) {
        let Some(service) = service else {
            return;
        };
        let Some(policy) = snap.upstreams.adaptive_concurrency(service) else {
            return;
        };
        let state = self.admission_state(service, policy);
        state.record(policy, outcome, rtt.as_micros() as u64);
    }

    /// 业务作用：按服务声明的受控来源计算一致性哈希键与会话亲和令牌。
    ///
    /// 两者都在**整条重试链开始前算一次**:同一请求的多次 attempt 必须使用同一哈希键,
    /// 否则换实例重试会把一致性哈希变成随机选择。缺键时返回空提示,选择完全退回常规 LB,
    /// 不因缺键拒绝服务。
    ///
    /// 参数说明：
    /// - `snap`: 当前请求固定的配置快照。
    /// - `upstream_target`: 渲染后的上游目标;非 `lb://` 直连没有 LB 概念。
    /// - `parts`: 下游请求 head,用于读取 allowlist 内的 header/cookie。
    /// - `client_ip`: 经可信代理链与连接元数据判定的真实客户端 IP。
    /// - `consumer`: 已验证 consumer 身份;未认证时为 None。
    /// - `route_id`：变量求值所属的 route 标识。
    /// - `request_id`：变量求值使用的本次请求标识。
    /// - `downstream_proto`：变量求值使用的可信入口协议。
    ///
    /// 返回：本次请求的哈希键与亲和令牌;来源缺失时对应字段为 `None`。
    #[allow(clippy::too_many_arguments)]
    fn lb_select_hints(
        &self,
        snap: &GatewaySnapshot,
        upstream_target: &str,
        parts: &Parts,
        client_ip: IpAddr,
        consumer: Option<&str>,
        route_id: &str,
        request_id: &str,
        downstream_proto: &'static str,
    ) -> crate::upstream::LbSelectHints {
        use crate::upstream::{LbHashSource, SessionAffinityMode};
        let mut hints = crate::upstream::LbSelectHints::default();
        let Some(service) = upstream_target.strip_prefix("lb://") else {
            return hints;
        };
        if let Some(source) = snap.upstreams.hash_source(service) {
            let owned;
            let value: Option<&str> = match source {
                LbHashSource::Consumer => consumer,
                LbHashSource::Header(name) => parts
                    .headers
                    .get(name.as_ref())
                    .and_then(|value| value.to_str().ok()),
                LbHashSource::Cookie(name) => request_cookie_value(parts, name.as_ref()),
                LbHashSource::RemoteAddr => {
                    owned = client_ip.to_string();
                    Some(owned.as_str())
                }
                LbHashSource::Variable(name) => {
                    let eval_ctx = crate::routing::variable::EvalContext {
                        parts,
                        client_ip,
                        downstream_proto,
                        request_id,
                        route_id,
                        response_status: None,
                    };
                    match snap.variables.eval_named(name.as_ref(), &eval_ctx) {
                        Some(value) if !value.is_empty() => {
                            owned = value;
                            Some(owned.as_str())
                        }
                        _ => None,
                    }
                }
            };
            // 空值等同于缺键:把空串也算成合法键会让所有匿名请求钉到同一个实例。
            hints.hash = value
                .filter(|value| !value.is_empty())
                .map(|value| crate::upstream::hash::stable_hash(value.as_bytes()));
        }
        if let Some(policy) = snap.upstreams.session_affinity(service) {
            let raw = match &policy.mode {
                SessionAffinityMode::Cookie {
                    name,
                    ..
                } => request_cookie_value(parts, name.as_ref()),
                SessionAffinityMode::Header {
                    name,
                } => parts
                    .headers
                    .get(name.as_ref())
                    .and_then(|value| value.to_str().ok()),
            };
            let now_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            hints.affinity = raw.and_then(|raw| policy.parse_token(raw, now_seconds));
        }
        hints
    }

    /// 业务作用：解析直连或 `lb://service` 上游、执行健康/LB 选择，并同时占用 least_conn 与过载预算。
    ///
    /// 参数说明：
    /// - `snap`: 当前请求固定持有的配置快照；整个重试链不得跨版本读取新快照。
    /// - `upstream`: route 渲染后的上游目标，允许静态 http(s) URI 或已声明的 `lb://service`。
    /// - `excluded`: 当前重试链已经尝试的完整 `health_key`，避免再次命中同一逻辑实例。
    /// - `limits`: 当前 proxy 的资源预算；pending 与连接池参数都随本次预留固化。
    /// - `inference_endpoints`: EPP 已批准的当前池子集；存在时所有选择与重试都不得越界。
    /// - `hints`：本请求冻结的哈希、亲和与负载选择上下文。
    ///
    /// 返回：成功时给出 RAII `UpstreamReservation`；无健康实例或预算满时返回 503 类错误。
    fn resolve_upstream_base_excluding(
        &self,
        snap: &GatewaySnapshot,
        upstream: &str,
        excluded: &[Arc<str>],
        limits: &crate::config::model::ServerLimitsCfg,
        hints: crate::upstream::LbSelectHints,
        inference_endpoints: Option<&InferenceEndpointSelection>,
    ) -> Result<UpstreamReservation, ForwardError> {
        if let Some(service) = upstream.strip_prefix("lb://") {
            let passive_policy = snap
                .upstreams
                .passive_health_policy(service)
                .unwrap_or_else(PassiveHealthPolicy::disabled);
            let outlier_group = snap
                .upstreams
                .outlier_group(&self.upstream_health, service, snap.version)
                .map_err(|_| ForwardError::Overloaded)?;
            let window_excluded = outlier_group
                .as_ref()
                .map(|group| group.blocked())
                .unwrap_or_default();
            // 被后台探测判为不健康的实例也要排除，与被动摘除叠加后才能避免继续选择已失效目标。
            // 只借用本服务当前策略的拒绝集合，不把整份事实克隆进 Vec，也不沿用旧策略或其它服务状态。
            let passive_excluded = self.ejected_upstreams(passive_policy);
            let active_facts = self.active_health.unhealthy_set();
            let active_unhealthy =
                active_facts.service(service, snap.upstreams.active_health_identity(service));
            // 反馈基线与 panic 判定每请求算一次:选择内部的比较闭包必须看到一致口径,
            // 中途切换会让同一次 P2C 的两个候选用不同量纲比较。
            let load_policy = snap
                .upstreams
                .load_feedback(service)
                .cloned()
                .unwrap_or_else(crate::upstream::load::LoadFeedbackPolicy::disabled);
            let load_now_ms = crate::upstream::load::monotonic_ms();
            let load_baseline = load_policy
                .enabled()
                .then(|| {
                    snap.upstreams
                        .load_feedback_baseline_observed(service, |instance| {
                            self.upstream_load_score(
                                instance,
                                snap.version,
                                &load_policy,
                                load_now_ms,
                            )
                        })
                })
                .flatten();
            let has_attempted = !excluded.is_empty();
            let has_passive_excluded = !passive_excluded.is_empty();
            let has_active_unhealthy = !active_unhealthy.is_empty();
            let has_inference_subset = inference_endpoints.is_some();
            // least_conn 计数放在 DashMap entry 的 AtomicU64 中：不同 hash shard 可并行，命中
            // 同一实例也只拿共享读 guard。选择仍是并发近似快照；最终 reserve 在 Arc 原子上完成。
            let inst = snap
                .upstreams
                .select_instance_observed(
                    service,
                    hints,
                    |health_key| {
                        // 重试/被动摘除集合通常很短，直接借用扫描比每请求合并 HashSet 更省分配；
                        // 主动健康集合本身已是快照 HashSet，保持 O(1) 查询。三个 `has_*`
                        // 分支在无故障首请求上都稳定为 false，避免为已知空集合计算字符串哈希；
                        // 这里只借用现有 slice/ArcSwap 快照，不合并、不复制任何身份字符串。
                        (has_attempted && excluded.iter().any(|excluded| &**excluded == health_key))
                            || window_excluded
                                .iter()
                                .any(|excluded| excluded.as_ref() == health_key)
                            || (has_passive_excluded
                                && passive_excluded
                                    .iter()
                                    .any(|excluded| excluded == health_key))
                            || (has_active_unhealthy && active_unhealthy.contains(health_key))
                            || (has_inference_subset
                                && !inference_endpoints
                                    .expect("subset presence was checked")
                                    .permits(health_key))
                    },
                    |instance| {
                        // 反馈可用时整服务统一用反馈分数比较;不可用(未配置/样本不足/
                        // 过期/低于 panic 阈值)时统一回退在途请求数。两种口径**绝不混用**,
                        // 否则「微秒」与「计数」会被当成同一量纲比较,得出完全错误的择优。
                        if let Some(baseline) = load_baseline {
                            return self
                                .upstream_load_score(
                                    instance,
                                    snap.version,
                                    &load_policy,
                                    load_now_ms,
                                )
                                .unwrap_or(baseline);
                        }
                        self.upstream_inflight
                            .get(instance.health_key.as_ref())
                            .map(|counter| counter.load(Ordering::Relaxed))
                            .unwrap_or(0)
                    },
                    || self.upstream_rr_next(service),
                )
                .ok_or_else(|| ForwardError::NoHealthyUpstream(service.to_string()))?;
            let base = inst.uri.clone();
            let health_key = inst.health_key.clone();
            // 选择与发送之间可能已有并发请求取得恢复权；独占门再次拒绝，不能放大探测流量。
            let outlier = outlier_group
                .as_ref()
                .map(|group| group.acquire(&health_key).ok_or(ForwardError::Overloaded))
                .transpose()?;
            let protocol = inst.protocol;
            let connect_timeout_ms = inst.connect_timeout_ms;
            let tls_profile = inst.tls_profile.clone();
            // 反馈句柄必须在目录仍权威时固定。响应阶段按 key 重新查询会让旧代迟到响应
            // 在对账删除后重新创建同名条目，破坏目录换代隔离。
            let feedback = load_policy
                .enabled()
                .then(|| self.upstream_load_entry(&inst, snap.version))
                .flatten()
                .map(|entry| {
                    crate::upstream::load::observation::Observation::new(entry, load_policy)
                });
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
                    connect_timeout_ms,
                    tls_profile,
                    pool_policy: HttpPoolPolicy::from_limits(limits),
                    feedback,
                    outlier,
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
                connect_timeout_ms: 0,
                tls_profile: None,
                pool_policy: HttpPoolPolicy::from_limits(limits),
                feedback: None,
                outlier: None,
                counter: None,
                pending_counter: None,
                release_on_drop: false,
            },
            limits.upstream_pending_limit,
        )
    }

    /// 业务作用：为解析出的实例占用一个在途请求槽。limit=0 表示关闭限制；达到上限直接 503，
    /// 不在 Hyper 连接池前堆无界等待队列。
    ///
    /// 参数说明：
    /// - `reservation`: 已占用 least_conn 计数的实例预留；失败返回时由 Drop 自动回滚该计数。
    /// - `limit`: 每个完整 `health_key` 的在途上限；`0` 表示不限但不创建 pending 计数。
    ///
    /// 返回：占槽成功返回补全后的预留；满额返回 `ForwardError::Overloaded` 并累加低基数指标。
    fn reserve_upstream_pending(
        &self,
        mut reservation: UpstreamReservation,
        limit: usize,
    ) -> Result<UpstreamReservation, ForwardError> {
        if reservation
            .tls_profile
            .as_ref()
            .is_some_and(|profile| !profile.allows_new_requests())
        {
            // 在计入 pending 或建立 client 前关闭过期远程身份，避免无效请求占用容量或触发拨号。
            return Err(ForwardError::BadGateway(anyhow::anyhow!(
                "upstream TLS client identity is no longer valid"
            )));
        }
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

/// 业务作用：构建普通 HTTP(S) 上游 client，并把 TLS 身份、连接池和物理 socket 预算固化到
/// 同一个 generation client；最小容器没有 native roots 时回退内置 WebPKI 公共根，避免明文
/// HTTP 请求因初始化未使用的 TLS 分支而 panic。
///
/// 参数说明：
/// - `profile`：是可选 HTTP 上游 TLS profile
/// - `destination`：是实际实例 URI
/// - `policy`：是连接池/窗口预算
/// - `physical_budget`：是 health_key/protocol 跨 generation 共享的 物理 socket 预算
/// - `h2_request`：表示是否需要 H2 冷启动单飞门
/// - `connect_timeout_ms`：只限制拨号。
///
/// 返回：同时支持 h1/h2 的 Hyper client；实际 pool 仍由 scheme + authority 隔离。显式 TLS
/// profile 无效已在 Snapshot 构建期拒绝；无 profile 时优先 native roots，仅在环境完全无可用根
/// 时使用编译锁定的 WebPKI roots，并留下告警而不是中止 worker。
fn build_upstream_http_client(
    profile: Option<&UpstreamTlsProfile>,
    destination: &str,
    policy: HttpPoolPolicy,
    physical_budget: Arc<PhysicalConnectionBudget>,
    h2_request: bool,
    connect_timeout_ms: u64,
) -> super::UpstreamHttpClient {
    let mut tcp_connector = configured_http_connector(connect_timeout_ms);
    // `HttpsConnector` 会先判 scheme、再把同一 URI 交给底层 TCP connector。自定义
    // connector 不像 builder 的默认 connector 那样自动解除 `http` 单 scheme 门；若不在
    // 包装前关闭该底层检查，合法 `https://` 会在 TLS/SNI/mTLS 发生前被误拒为坏 URL。
    // 这里只用于 HTTPS-capable client；direct h2c connector 继续保留其明文 scheme 门禁。
    tcp_connector.enforce_http(false);
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
                    .wrap_connector(tcp_connector)
            } else {
                builder
                    .enable_http1()
                    .enable_http2()
                    .wrap_connector(tcp_connector)
            }
        }
        None if connect_timeout_ms == 0 => default_upstream_https_connector().clone(),
        None => default_upstream_https_connector_with(tcp_connector),
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
        inner: builder.build(BudgetedConnector::new(
            FixedDestinationConnector::new(connector, destination),
            physical_budget,
        )),
        // protocol=auto 的 H1 与 H2 cache key 已分离；只有明确按 H2 建立的 generation 才需
        // 冷启动单飞。H1 保持 Hyper 原生的多连接并发拨号能力。
        h2_gate: h2_request.then(H2ColdStartGate::new),
        reject_non_http: false,
    }
}

/// 业务作用：进程级构建并缓存默认 HTTP(S) connector，使系统根扫描、最小容器 WebPKI 回退
/// 和告警只发生一次；upstream client generation 后续只 clone 不可变 TLS 配置，避免冷连接
/// 风暴把文件扫描/日志开销放大到请求延迟。
///
/// 参数说明: 无。
///
/// 返回：支持 h1/h2 与 http/https 的共享 connector 引用；私有 CA、SNI、mTLS 等显式 profile
/// 仍走独立构建分支，不与该公共根身份混池。
fn default_upstream_https_connector() -> &'static HttpsConnector<HttpConnector> {
    DEFAULT_UPSTREAM_HTTPS_CONNECTOR.get_or_init(|| {
        let builder = match hyper_rustls::HttpsConnectorBuilder::new().with_native_roots() {
            Ok(builder) => builder,
            Err(error) => {
                // 明文上游同样复用 HTTPS-capable connector；native root 缺失不能让一个未走
                // TLS 的请求 panic。内置公共根保持 HTTPS fail-closed，私有 CA 仍必须显式配置。
                tracing::warn!(
                    error = %error,
                    "native TLS roots unavailable; falling back to bundled WebPKI roots"
                );
                hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots()
            }
        };
        builder
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build()
    })
}

/// 业务作用：构造带可选 TCP connect deadline 的底层 connector，CDS timeout 不挤占 response TTFB。
///
/// 参数说明：
/// - `connect_timeout_ms`：为 0 时不额外设 deadline，否则已由资源门限制在 1ms..=60s。
///
/// 返回：关闭 Nagle 且带对应 connect timeout 的 HttpConnector。
fn configured_http_connector(connect_timeout_ms: u64) -> HttpConnector {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(
        (connect_timeout_ms > 0).then(|| Duration::from_millis(connect_timeout_ms)),
    );
    connector
}

/// 业务作用：把指定 TCP connector 包进公共根 HTTPS 能力，供非默认 CDS timeout generation 使用。
///
/// 参数说明：
/// - `connector`：已固化本 generation 的 TCP 选项与 connect deadline。
///
/// 返回：支持 h1/h2 与 http/https；系统根缺失时使用编译锁定 WebPKI 根并留下告警。
fn default_upstream_https_connector_with(
    connector: HttpConnector,
) -> HttpsConnector<HttpConnector> {
    let builder = match hyper_rustls::HttpsConnectorBuilder::new().with_native_roots() {
        Ok(builder) => builder,
        Err(error) => {
            // 明文上游同样复用 HTTPS-capable connector；native root 缺失不能让一个未走
            // TLS 的请求 panic。内置公共根保持 HTTPS fail-closed，私有 CA 仍必须显式配置。
            tracing::warn!(
                error = %error,
                "native TLS roots unavailable; falling back to bundled WebPKI roots"
            );
            hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots()
        }
    };
    builder
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(connector)
}

/// 业务作用：构建固定拨号到已选实例的明文 HTTP/2 prior-knowledge sender，并把业务
/// authority、物理 Endpoint 与 socket 预算分别落实到正确边界。
///
/// 参数说明：
/// - `policy`：是当前快照固化的窗口和连接分片预算
/// - `physical_budget`：跨 generation 约束同一实例的物理 socket
/// - `connect_timeout_ms`：是 TCP connect deadline
/// - `destination`：是已选实例的 base URI。
///
/// 返回：每个 shard 只保存一条显式 H2 sender；实际拨号始终使用 `destination`，请求中的
/// authority 仍可承载 Route 虚拟主机。拨号失败由首次请求返回，且不会降级为 HTTP/1.1。
fn build_h2c_client(
    policy: HttpPoolPolicy,
    physical_budget: Arc<PhysicalConnectionBudget>,
    connect_timeout_ms: u64,
    destination: &str,
) -> super::UpstreamH2cClient {
    let mut connector = configured_http_connector(connect_timeout_ms);
    // hyper-util 的 HttpConnector 默认保留 Nagle。对 direct h2c/gRPC，这会让同一 transport 上的
    // 短 HEADERS/DATA/WINDOW_UPDATE 与 Linux delayed ACK 形成约 40ms 台阶；连接越少、mux 越深
    // 越明显。H2 driver 已负责 coalesce 同一轮 ready frame，因此关闭 Nagle 不等于逐 frame
    // syscall，也不增加用户态 buffer/复制。该标志只在建物理 socket 时设置，request/frame 热路径
    // 没有分支；物理连接 cap、GOAWAY/RST、flow-control 和 idle 回收语义保持不变。
    connector.set_nodelay(true);
    UpstreamH2cClient {
        state: Arc::new(DirectH2cState {
            current: ArcSwapOption::empty(),
            connector: BudgetedConnector::new(
                FixedDestinationConnector::new(connector, destination),
                physical_budget,
            ),
            policy,
        }),
        h2_gate: H2ColdStartGate::new(),
    }
}

/// 业务作用：计算当前请求实际使用的 route upstream。
///
/// 静态 URI 直接借用 `route.upstream`;动态 URI 才执行模板渲染,避免静态热路径付额外分配成本。
///
/// 参数说明：
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
    let eval_ctx = crate::routing::variable::EvalContext {
        parts,
        client_ip,
        downstream_proto,
        request_id,
        route_id: route.id.as_str(),
        response_status: None,
    };
    Cow::Owned(
        route
            .upstream_template
            .render(&eval_ctx, route.variables.as_ref()),
    )
}

/// 业务作用：校验渲染后的 upstream target。
///
/// 动态 target 只允许 `lb://已声明服务`,防止把 header/query 拼成任意外网 URL 形成 SSRF。
///
/// 参数说明：
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
    /// H2/H3 响应 header section 上限；H3 client 直接发布为 SETTINGS 并在 QPACK decode 执行。
    #[cfg(feature = "http3")]
    max_header_bytes: usize,
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
    /// 业务作用：从当前 proxy 资源配置复制池策略，确保一次请求内不受 reload 影响。
    ///
    /// 参数说明：
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
            #[cfg(feature = "http3")]
            max_header_bytes: limits.max_header_bytes,
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

/// 业务作用：返回进程内连接池时钟的相对毫秒。只比较同一进程内的 age，不读取墙钟，也不受 NTP 跳变影响。
fn pool_clock_millis() -> u64 {
    static STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let elapsed = STARTED.get_or_init(std::time::Instant::now).elapsed();
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

/// 业务作用：为一个不可变 client generation 严格占用请求序号。
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

/// 业务作用：写路径回收已经不再匹配当前配置、且超过保留期的普通 HTTP client handle。
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

/// 业务作用：写路径回收已经不再匹配当前配置、且超过保留期的 h2c client handle。
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

/// 业务作用：选择当前 generation 的 client shard。
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
    /// 选中实例的上游协议,供转发层设上游请求版本。
    protocol: UpstreamProtocol,
    /// 仅约束新 TCP transport 建立阶段；0 保持 native connector 既有行为。
    connect_timeout_ms: u64,
    /// HTTP 上游 TLS profile( `proxy_ssl_*`)。
    tls_profile: Option<UpstreamTlsProfile>,
    /// 当前 proxy 快照给出的连接池预算；进入 cache key，reload 改参数会创建新池并延迟淘汰旧池。
    pool_policy: HttpPoolPolicy,
    /// 实例被选中时固定的反馈句柄；目录换代后旧响应只更新脱离权威表的旧对象。
    feedback: Option<crate::upstream::load::observation::Observation>,
    /// 当前实例窗口观察权；发送完成或取消时归还，不移交响应正文。
    outlier: Option<crate::upstream::passive::window::Attempt>,
    /// least_conn 在途计数器；直连 URI 不参与服务级 LB，故为空。
    counter: Option<Arc<AtomicU64>>,
    ///  每实例在途请求预算计数器。
    pending_counter: Option<Arc<AtomicU64>>,
    /// true 表示计数器仍由 reservation 持有；移交 body 后必须置 false，避免重复释放。
    release_on_drop: bool,
}

impl UpstreamReservation {
    /// 业务作用：把预留计数器移交给响应 body，使长流在真正结束/被下游取消时才释放。
    ///
    /// 参数说明：
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
        let feedback = self
            .feedback
            .take()
            .filter(|observation| observation.needs_trailers());
        if counter.is_none() && pending_counter.is_none() && grpc.is_none() && feedback.is_none() {
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
            feedback,
            done: false,
        }
        .boxed()
    }
}

impl Drop for UpstreamReservation {
    /// 业务作用：请求在响应 body 建立前失败/取消时回滚全部已占计数；成功移交后不再释放。
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
    /// 业务作用：在 response head 交给下游前登记，封住管理面关闭与首次 body poll 的竞态。
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

    /// 业务作用：检查 max-age/管理面关闭并返回标准、已转义的 gRPC message。
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

    /// 业务作用：upstream Pending 时登记关闭 waker。稳定 task 只在第一次执行一次 AtomicWaker register；
    /// 后续 Pending 只比较 waker 身份，避免每个 gRPC frame 额外做两次关闭码原子读。
    fn subscribe_close(&mut self, cx: &Context<'_>) -> Option<HeaderValue> {
        self.close_wait
            .subscribe_if_needed(cx)
            .then(|| self.close_message(false))
    }

    /// 业务作用：把治理关闭或最大存活时限转换为 gRPC trailer 文本，供已建立流有序结束。
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
    /// 仅真实上游 trailers 能更新实例反馈；本地合成关闭不会产生负载证据。
    feedback: Option<crate::upstream::load::observation::Observation>,
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

    /// 业务作用：透明转发下一帧；正常数据只重置已有 timer，不复制 payload，也不改变上游背压与
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
                if let Some(trailers) = frame.trailers_ref() {
                    if let Some(mut feedback) = self.feedback.take() {
                        feedback.trailers(trailers);
                    }
                }
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

    /// 业务作用：委托原 body 的结束提示，供 Hyper 保留零额外帧的快路径。
    fn is_end_stream(&self) -> bool {
        self.done || self.inner.as_ref().is_none_or(|body| body.is_end_stream())
    }

    /// 业务作用：委托原 body 的大小提示，不伪造 Content-Length。
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
    /// 业务作用：终止上游流并生成唯一的标准关闭 trailer；所有关闭入口共用同一释放顺序。
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

    /// 业务作用：幂等归还上游名额；结束分支和 Drop 共用 `Option::take`，防止重复递减。
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
    /// 业务作用：body 正常结束或被下游提前丢弃时归还 least_conn 与 pending 名额。
    fn drop(&mut self) {
        self.release_counters();
    }
}

struct AbsoluteDeadlineBody {
    /// 上游响应 body；deadline 到期时立即 Drop，向 H2/H3 传播取消并归还连接预算。
    inner: Option<BoxBody>,
    /// 与 response head 共用的绝对截止时刻，不能在每个 frame 后续期。
    deadline: TokioInstant,
    /// 单一 timer；创建响应 wrapper 时即注册，覆盖已返回 response head 后的静默 body。
    sleep: Pin<Box<Sleep>>,
    /// EOF、上游错误或 deadline 错误后进入终止态，防重复产生错误 frame。
    done: bool,
}

impl AbsoluteDeadlineBody {
    /// 业务作用：让 route request/backendRequest deadline 跨越 response head，继续约束
    /// 完整流式响应，避免慢 body 绕过只覆盖 TTFB 的超时。
    ///
    /// 参数说明：
    /// - `inner`：是已取得响应头的上游 body
    /// - `deadline`：与响应头等待共用。
    ///
    /// 返回：返回到期时先取消上游再产生唯一 TimedOut 错误的 body wrapper。
    fn new(inner: BoxBody, deadline: TokioInstant) -> Self {
        Self {
            inner: Some(inner),
            deadline,
            sleep: Box::pin(tokio::time::sleep_until(deadline)),
            done: false,
        }
    }
}

impl Body for AbsoluteDeadlineBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：按下游轮询推进正文流，把数据、trailers、失败和结束状态交给统一 HTTP 管线。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        // 已到期后必须先取消上游；即使同一轮 inner 偶然 Ready，也不能让调度延迟
        // 延长声明的绝对时限或继续向下游泄漏过期响应数据。
        if TokioInstant::now() >= self.deadline || self.sleep.as_mut().poll(cx).is_ready() {
            self.inner.take();
            self.done = true;
            let error = std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "route request deadline expired",
            );
            return Poll::Ready(Some(Err(Box::new(error) as BoxError)));
        }
        let result = Pin::new(
            self.inner
                .as_mut()
                .expect("deadline body remains present while active"),
        )
        .poll_frame(cx);
        match result {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => {
                self.inner.take();
                self.done = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.inner.take();
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// 业务作用：向 HTTP 编码层报告流是否已经结束，避免省略尚未发送的正文或 trailers。
    fn is_end_stream(&self) -> bool {
        self.done || self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    /// 业务作用：向 HTTP 编码层提供剩余实体长度约束，供帧传输选择定长或流式编码。
    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(SizeHint::default, Body::size_hint)
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

    /// 业务作用：按下游轮询推进正文流，把数据、trailers、失败和结束状态交给统一 HTTP 管线。
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

    /// 业务作用：向 HTTP 编码层报告流是否已经结束，避免省略尚未发送的正文或 trailers。
    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    /// 业务作用：向 HTTP 编码层提供剩余实体长度约束，供帧传输选择定长或流式编码。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 业务作用：在 body 真正 Pending 时才创建/轮询 idle timer。
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

/// 业务作用：按可信连接身份重建转发与追踪头，防止客户端自报来源越过信任边界。
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
    // X-Forwarded-For：可信入站则在原链后【追加】本跳客户端;不可信则用真实客户端 IP 覆盖
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
    // request-id:入站值保留到 x-original-request-id,网关始终写自己的权威 x-request-id。
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
    /// 业务作用：把客户端地址编码到固定栈缓冲，供高频转发头生成避免额外堆分配。
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

    /// 业务作用：借用已编码客户端地址的有效字节，保持格式化结果的生命周期与缓冲一致。
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// 业务作用：提供已验证地址文本的借用视图，供 HTTP 头生成复用同一编码结果。
    #[inline]
    fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("IpAddr display is ASCII")
    }
}

impl fmt::Write for IpText {
    /// 业务作用：把地址格式化片段写入固定缓冲，容量不足时返回格式化失败。
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

enum RenderedRequestHeaderOp {
    Set(HeaderName, HeaderValue),
    Add(HeaderName, HeaderValue),
    Remove(HeaderName),
}

/// 业务作用：在覆盖代理生成头之前，基于原始可信请求上下文渲染 Gateway/nginx 请求头操作。
///
/// 参数说明：
/// - `ops`：是构建期固定操作
/// - `variables`：提供受控模板求值上下文。
/// - `eval_ctx`：提供受控模板求值上下文。
///
/// 返回：全部动态值都是合法 HeaderValue 时返回有序操作；任一非法值时拒绝本次上游尝试。
fn render_request_headers(
    ops: &[RequestHeaderOp],
    variables: &crate::routing::variable::VariablePlan,
    eval_ctx: &crate::routing::variable::EvalContext<'_>,
) -> Result<Vec<RenderedRequestHeaderOp>, ForwardError> {
    ops.iter()
        .map(|op| {
            let render = |set: &crate::routing::RequestHeaderSet| {
                let value = set.value.render(eval_ctx, variables);
                Ok::<_, ForwardError>((set.name.clone(), header_value(&value, set.name.as_str())?))
            };
            match op {
                RequestHeaderOp::Set(set) => {
                    render(set).map(|(name, value)| RenderedRequestHeaderOp::Set(name, value))
                }
                RequestHeaderOp::Add(set) => {
                    render(set).map(|(name, value)| RenderedRequestHeaderOp::Add(name, value))
                }
                RequestHeaderOp::Remove(name) => Ok(RenderedRequestHeaderOp::Remove(name.clone())),
            }
        })
        .collect()
}

/// 业务作用：移除逐跳协议头及 Connection 声明的附加字段，防止连接级状态泄漏到下一跳。
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

/// 业务作用：按最终上游协议分工清理请求 hop-by-hop header，防止连接级字段泄漏到 origin。
///
/// HTTP/2 的 Hyper client 在真正编码 frame 的同一所有权链上强制移除 `Connection` 及其
/// token、`Keep-Alive`、`Proxy-Connection`、`Transfer-Encoding`、`Upgrade`，并只允许
/// `TE: trailers`。那一步无法绕过，也最接近 wire；Naway 不在前一层重复扫描这些字段，只补
/// Hyper 不负责、但不能泄漏给 origin 的代理认证头。整个过程原地修改 HeaderMap，不复制
/// header value，更不读取 body。HTTP/1.1 则继续由 Naway 完整清洗。
///
/// 参数说明：
/// - `parts`：是待转发请求头
/// - `keep_upgrade`：表示保留 WebSocket upgrade
/// - `upstream_version`：是已经冻结的最终上游 HTTP 版本。
///
/// 返回：无；函数原地清理请求头，HTTP/2 只补充移除 Hyper 不负责的代理认证字段。
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

/// 业务作用：只保留允许传播的 TE 语义，避免请求头改变下一跳实体分帧。
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

/// 业务作用：验证待注入头值的 HTTP 表示，非法字符必须在发送上游前明确拒绝。
fn header_value(value: &str, name: &str) -> Result<HeaderValue, ForwardError> {
    HeaderValue::from_str(value)
        .map_err(|e| ForwardError::BadGateway(anyhow::anyhow!("invalid {name} header: {e}")))
}

/// 为隧道施加**总字节预算**的 IO 装饰器。
///
/// 预算必须在搬运过程中生效,不能等隧道结束再统计:事后统计只能用于计费,
/// 挡不住一条隧道把出口带宽吃干。两个方向共享同一计数器,因此 `max_bytes`
/// 表示的是这条隧道的**总量**,而不是每个方向各一份。
pub(super) struct BudgetIo<T> {
    /// 原始下游或上游字节流。
    inner: T,
    /// 两个方向共享的累计实际搬运字节数。
    counter: Arc<AtomicU64>,
    /// 隧道总字节预算；0 表示不限制。
    limit: u64,
}

impl<T> BudgetIo<T> {
    /// 业务作用：包装一个隧道方向并接入共享字节预算。
    ///
    /// 参数说明：
    /// - `inner`: 原始字节流。
    /// - `counter`: 两个方向共享的已用字节计数。
    /// - `limit`: 总预算;0 表示不限制。
    ///
    /// 返回：透明 IO wrapper,不引入额外缓冲。
    pub(super) fn new(inner: T, counter: Arc<AtomicU64>, limit: u64) -> Self {
        Self {
            inner,
            counter,
            limit,
        }
    }

    /// 业务作用：为隧道实际搬运字节记账，并在总预算耗尽时终止继续传输。
    ///
    /// 参数说明：
    /// - `bytes`：是本次底层 IO 已实际完成的字节数。
    ///
    /// 返回：预算内返回成功；累计值超过上限时返回 IO 错误。
    fn charge(&self, bytes: usize) -> std::io::Result<()> {
        if self.limit == 0 || bytes == 0 {
            return Ok(());
        }
        let used = self
            .counter
            .fetch_add(bytes as u64, Ordering::Relaxed)
            .saturating_add(bytes as u64);
        if used > self.limit {
            return Err(std::io::Error::other("tunnel byte budget exhausted"));
        }
        Ok(())
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for BudgetIo<T> {
    /// 业务作用：透明读取隧道字节，并按真实读取量执行共享总预算门禁。
    ///
    /// 参数说明：
    /// - `cx`：是异步任务上下文
    /// - `buf`：是下游提供的读取缓冲。
    ///
    /// 返回：返回底层读取结果；读后超预算时返回错误终止隧道。
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len().saturating_sub(before);
            if let Err(error) = self.charge(read) {
                return Poll::Ready(Err(error));
            }
        }
        result
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for BudgetIo<T> {
    /// 业务作用：透明写入隧道字节，并按真实写入量执行共享总预算门禁。
    ///
    /// 参数说明：
    /// - `cx`：是异步任务上下文
    /// - `buf`：是待写字节。
    ///
    /// 返回：返回底层写入结果；写后超预算时返回错误终止隧道。
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            if let Err(error) = self.charge(*written) {
                return Poll::Ready(Err(error));
            }
        }
        result
    }

    /// 业务作用：透明刷新隧道写缓冲，且不对未产生的新字节重复计费。
    ///
    /// 参数说明：
    /// - `cx`：是异步任务上下文。
    ///
    /// 返回：返回底层 flush 结果。
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// 业务作用：透明关闭隧道写方向，保持半关闭语义且不重复计费。
    ///
    /// 参数说明：
    /// - `cx`：是异步任务上下文。
    ///
    /// 返回：返回底层 shutdown 结果。
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct WsFrameWrites {
    downstream: AtomicBool,
    upstream: AtomicBool,
}

/// 业务作用：按 route 是否开启帧级治理,选择透明搬运或 frame-aware 转发。
///
/// 透明模式仍然走 `copy_bidirectional`,**不引入任何解析或聚合**——帧级治理的开销
/// 只能落在显式开启它的 route 上,否则等于让所有 WebSocket 连接为一个可选功能买单。
///
/// 参数说明：
/// - `downstream`: 下游连接。
/// - `upstream`: 上游连接。
/// - `policy`: 帧级策略;`None` 表示透明模式。
/// - `route_id`: 日志用路由标识。
/// - `consumer`：握手认证完成时冻结的主体。
/// - `deflate_negotiated`：已完整校验的扩展协商结果。
/// - `writes`：每个写方向的帧边界，供外层撤权与超时共用。
///
/// 返回：隧道结束时返回 `Ok`;IO 错误上抛。帧级违规不作为错误返回,
/// 而是记录原因后正常收尾,由 close 帧把语义传达给对端。
async fn govern_or_copy<D, U>(
    downstream: &mut D,
    upstream: &mut U,
    policy: Option<&crate::protocols::ws_frame::FramePolicy>,
    route_id: &str,
    consumer: Option<&str>,
    deflate_negotiated: bool,
    writes: &WsFrameWrites,
) -> std::io::Result<()>
where
    D: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(policy) = policy else {
        // 透明搬运不解析帧头，取消时无法证明字节流位于帧边界；强制收尾只能关闭传输，
        // 不能把 Close 载荷插进可能尚未交付完整的数据帧。
        writes.downstream.store(true, Ordering::Release);
        writes.upstream.store(true, Ordering::Release);
        io::copy_bidirectional(downstream, upstream).await?;
        return Ok(());
    };
    let (down_read, mut down_write) = tokio::io::split(downstream);
    let (up_read, mut up_write) = tokio::io::split(upstream);
    let stats = crate::protocols::ws_frame::FrameStats::default();
    // 两个方向各自独立治理:客户端方向要求掩码,服务端方向要求无掩码,
    // 用同一份状态会让其中一个方向的判定必然出错。
    let (outcome, violation_from_client) = {
        let client_side = async {
            if policy.needs_message(true, deflate_negotiated) {
                crate::protocols::ws_frame::message::govern(
                    down_read,
                    &mut up_write,
                    crate::protocols::ws_frame::message::Context {
                        policy,
                        stats: &stats,
                        from_client: true,
                        compressed: deflate_negotiated,
                        consumer,
                        writing: &writes.upstream,
                    },
                )
                .await
            } else {
                crate::protocols::ws_frame::govern_stream_tracked(
                    down_read,
                    &mut up_write,
                    policy,
                    true,
                    false,
                    &stats,
                    &writes.upstream,
                )
                .await
            }
        };
        let server_side = async {
            if policy.needs_message(false, deflate_negotiated) {
                crate::protocols::ws_frame::message::govern(
                    up_read,
                    &mut down_write,
                    crate::protocols::ws_frame::message::Context {
                        policy,
                        stats: &stats,
                        from_client: false,
                        compressed: deflate_negotiated,
                        consumer,
                        writing: &writes.downstream,
                    },
                )
                .await
            } else {
                crate::protocols::ws_frame::govern_stream_tracked(
                    up_read,
                    &mut down_write,
                    policy,
                    false,
                    false,
                    &stats,
                    &writes.downstream,
                )
                .await
            }
        };
        tokio::pin!(client_side);
        tokio::pin!(server_side);
        // 任一方向结束即取消另一方向；借用在块末释放后，才能串行写 close 控制帧，
        // 避免治理转发与关闭帧同时写同一个 half 造成线路交错。
        tokio::select! {
            result = &mut client_side => (result?, true),
            result = &mut server_side => (result?, false),
        }
    };
    if let crate::protocols::ws_frame::GovernOutcome::Violation(error) = outcome {
        tracing::warn!(
            route = %route_id,
            reason = error.as_str(),
            close_code = error.close_code(),
            "websocket frame policy violation"
        );
        match crate::protocols::ws_frame::effective_action(policy, true) {
            crate::protocols::ws_frame::MessageAction::PolicyClose
            | crate::protocols::ws_frame::MessageAction::Drop => {
                write_governance_close(
                    &mut down_write,
                    &mut up_write,
                    error.close_code(),
                    !violation_from_client,
                    writes,
                )
                .await;
            }
            crate::protocols::ws_frame::MessageAction::UpstreamClose => {
                // 上游被策略关闭后隧道已无法继续；给下游明确的内部错误收尾，
                // 不让它把无响应 EOF 误判为可重连的正常结束。
                write_governance_close(
                    &mut down_write,
                    &mut up_write,
                    1011,
                    !violation_from_client,
                    writes,
                )
                .await;
            }
        }
    }
    Ok(())
}

/// 业务作用：向 WebSocket 两端按各自角色写入同一治理 close code，并半关闭写方向。
///
/// 参数说明：
/// - `downstream`：是 server 角色写端
/// - `upstream`：是 client 角色写端
/// - `code`：是协议或预算违规对应的 close code
/// - `notify_upstream`：仅在违规源自上游时 允许写上游 close，客户端违规时保持上游零字节并直接半关闭。
/// - `writes`：帧边界是否不可确认；半帧或透明写端只执行 shutdown，不能插入控制载荷。
///
/// 返回：无；任一写入失败仍继续关闭另一端，系统随机源失败时不发送不合规的上游帧。
async fn write_governance_close<D, U>(
    downstream: &mut D,
    upstream: &mut U,
    code: u16,
    notify_upstream: bool,
    writes: &WsFrameWrites,
) where
    D: tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncWrite + Unpin,
{
    let down = async {
        if !writes.downstream.load(Ordering::Acquire) {
            let _ = downstream
                .write_all(&crate::runtime::connections::ws_close_frame(code))
                .await;
        }
        let _ = downstream.shutdown().await;
    };
    let up = async {
        if notify_upstream && !writes.upstream.load(Ordering::Acquire) {
            let mut mask = [0_u8; 4];
            if getrandom::getrandom(&mut mask).is_ok() {
                let _ = upstream
                    .write_all(&crate::runtime::connections::ws_masked_close_frame(
                        code, mask,
                    ))
                    .await;
            }
        }
        let _ = upstream.shutdown().await;
    };
    // 对端持续背压不能让撤权或 drain 永久占用连接；两端独立收尾，超时由 socket Drop 完成终止。
    let _ = tokio::join!(
        tokio::time::timeout(Duration::from_secs(1), down),
        tokio::time::timeout(Duration::from_secs(1), up)
    );
}
