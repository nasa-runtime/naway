//! Naway gRPC 边缘模式Rust 客户端 SDK。
//!
//! wire 契约见 `proto/naway/edge/v1/edge.proto`。本 SDK **不引 prost/tonic**:
//! 业务 payload 对网关是不透明字节(「业务 payload 不解析」),使用方用自己
//! 的 protobuf 库编解码即可;SDK 只负责三件网关侧真正较真、而手写客户端最容易写错
//! 的事——**metadata 契约、gRPC 分帧、以及订阅断线后的退避重连**。
//!
//! # 必须先理解的产品语义
//!
//! - **at-most-once**:队满、peer 断线、节点重启、下游读得慢都允许丢消息。SDK
//!   **不会**替你重传。
//! - **无离线堆积**:不在线时没有任何队列为你保存消息,重连也不补发。
//! - **无最终客户端 ACK**:[`PublishSummary`] 的所有计数止于"已进入散出队列",
//!   **没有任何字段表示终端已收到**。这也是它不叫 `delivered` 的原因。
//!
//! 需要不丢的业务应当在 payload 里自带单调 `seq`/`event_id`,由订阅端发现空洞后
//! 向后端补拉。[`Subscription`] 的重连会在日志层面告诉你发生过断流,但**断流期间
//! 的消息就是没了**——这不是缺陷,是这条链路的设计取舍。

use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderName, Request};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// gRPC message 前缀:1 字节压缩位 + 4 字节大端长度。
const GRPC_PREFIX_BYTES: usize = 5;
const MAX_COALESCE_KEY_BYTES: usize = 256;
/// summary 是 7 个 varint 字段的平坦消息；保留演进余量但拒绝无界响应。
const MAX_SUMMARY_MESSAGE_BYTES: usize = 4096;

/// 统一请求 body 类型；unary 使用 Full，PublishStream 使用受 H2 flow-control 驱动的 channel body。
type RequestBody = UnsyncBoxBody<Bytes, std::io::Error>;

/// SDK 错误。
#[derive(Debug)]
pub enum EdgeError {
    /// 传输层失败(连不上、连接中断)。
    Transport(String),
    /// 网关以 gRPC 状态码拒绝。`status` 是数字码,`message` 是低基数原因短语。
    ///
    /// 常见:`7` = 无权访问该 group(route 的 `grpc_edge.authz` 策略);
    /// `16` = 缺少已验证身份;`8` = 预算耗尽;`3` = 元数据/分帧非法。
    Status {
        status: String,
        message: String,
    },
    /// 响应不符合契约(分帧错误、长度越界)。
    Protocol(String),
}

impl std::fmt::Display for EdgeError {
    /// 业务作用：把传输、gRPC 状态和协议失败转换为可显示的 SDK 错误，保留失败类别。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(detail) => write!(f, "transport: {detail}"),
            Self::Status {
                status,
                message,
            } => write!(f, "grpc-status {status}: {message}"),
            Self::Protocol(detail) => write!(f, "protocol: {detail}"),
        }
    }
}

impl std::error::Error for EdgeError {}

type Result<T> = std::result::Result<T, EdgeError>;

/// 群播回执。字段语义与 `.proto` 的 `PublishSummary` 一一对应。
///
/// **proto3 省零**:网关不发送值为 0 的字段,SDK 把缺失解析为 0(不是"未知")。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PublishSummary {
    /// 本地实际入队份数。**不是**"已送达"。
    pub accepted: u64,
    /// 未入队份数(队满丢弃 + 预算拒绝)。
    pub dropped: u64,
    /// 因慢消费被主动断流的成员数。
    pub closed_slow: u64,
    /// 已处理消息条数(unary 恒 1)。
    pub messages: u64,
    /// peer 侧实际入队份数。
    pub peers_accepted: u64,
    /// 明确拒绝的 peer 数。
    pub peers_rejected: u64,
    /// 断线或无回执的 peer 数;网关**不自动重试**。
    pub peers_unknown: u64,
}

/// 定向单播回执。与 [`PublishSummary`] 共用字段号空间,2/3/4 在 push 语义下无意义。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PushSummary {
    /// 目标 user 在线 session 中实际入队的份数;目标完全不在线时为 0,**这不是错误**。
    pub accepted: u64,
    /// peer 侧实际入队份数。
    pub peers_accepted: u64,
    /// 明确拒绝的 peer 数。
    pub peers_rejected: u64,
    /// 断线或无回执的 peer 数。
    pub peers_unknown: u64,
}

/// 认证方式。身份由网关从**已验证 principal** 推导,客户端自报的任何身份字段都不作数。
#[derive(Debug, Clone)]
pub enum Auth {
    /// API-Key:头名与值由 route 的 `api_key` filter 决定。
    ApiKey {
        header: String,
        value: String,
    },
    /// JWT bearer;网关按 route 的 `jwt` 策略校验并取 claim 作为 tenant/user。
    Bearer(String),
    /// 不带凭证。边缘面几乎总是要求认证(否则返回 16),仅用于本地联调。
    None,
}

/// 客户端配置。
#[derive(Debug, Clone)]
pub struct EdgeConfig {
    /// 网关数据面地址,如 `http://127.0.0.1:8080`。当前仅支持明文 h2c;
    /// TLS 请在前面放一层已有的 TLS 终结,或按需扩展本 SDK。
    pub endpoint: String,
    /// `authority`(即 `Host`),用于命中 route 的 Host predicate。
    pub authority: String,
    /// 认证方式。
    pub auth: Auth,
    /// 四个精确方法路径。**必须与 route 的 `grpc_edge.methods` 完全一致**——
    /// 网关按精确 `:path` 决定 action,前缀匹配会被拒绝。
    pub subscribe_path: String,
    /// 见 [`EdgeConfig::subscribe_path`]。
    pub publish_path: String,
    /// 见 [`EdgeConfig::subscribe_path`]。
    pub push_path: String,
    /// client-streaming PublishStream 精确方法路径。
    ///
    /// 该方法在 route 上是**可选**的(`grpc_edge.methods.publish_stream` 不配就没有),
    /// 路径写错会得到普通 L7 转发或 404,而不是 edge 语义——与另外三个方法同理。
    pub publish_stream_path: String,
    /// action 确认头名(默认 `x-naway-edge-action`)。
    pub action_header: String,
    /// group 头名(默认 `x-naway-group`)。
    pub group_header: String,
    /// 定向 target 头名。默认 `x-naway-target-user`——注意**不是** `x-naway-target`,
    /// 与网关 `default_grpc_edge_target_header` 保持一致；头名不一致会因缺少目标身份而拒绝推送。
    pub target_header: String,
    /// 单条 `FramePush` protobuf message 的 wire 字节上限，必须与 route 的
    /// `grpc_edge.limits.max_msg_bytes` 一致。默认 64 KiB。
    pub max_message_bytes: usize,
    /// 订阅断线后的首次重连退避;每次翻倍,上限 [`EdgeConfig::reconnect_max`]。
    pub reconnect_base: Duration,
    /// 重连退避上限。
    pub reconnect_max: Duration,
}

impl EdgeConfig {
    /// 业务作用：以默认头名与默认方法路径构造。
    ///
    /// 参数说明：
    /// - `endpoint`: 形如 `http://host:port`。
    /// - `authority`: Host 头。
    ///
    /// 返回：
    /// 一份可直接使用的配置；方法路径采用 NawayEdge 服务的默认值，
    /// route 若改过路径必须在此同步覆盖。
    pub fn new(endpoint: impl Into<String>, authority: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            authority: authority.into(),
            auth: Auth::None,
            subscribe_path: "/naway.edge.v1.NawayEdge/Subscribe".into(),
            publish_path: "/naway.edge.v1.NawayEdge/Publish".into(),
            push_path: "/naway.edge.v1.NawayEdge/Push".into(),
            publish_stream_path: "/naway.edge.v1.NawayEdge/PublishStream".into(),
            action_header: "x-naway-edge-action".into(),
            group_header: "x-naway-group".into(),
            target_header: "x-naway-target-user".into(),
            max_message_bytes: 64 * 1024,
            reconnect_base: Duration::from_millis(200),
            reconnect_max: Duration::from_secs(10),
        }
    }

    /// 业务作用：设置认证方式(链式)。
    pub fn with_auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    /// 业务作用：覆盖单条 `FramePush` wire message 上限。
    pub fn with_max_message_bytes(mut self, max_message_bytes: usize) -> Self {
        self.max_message_bytes = max_message_bytes;
        self
    }
}

/// 边缘客户端。内部持有一个 h2c 连接池,克隆代价很低。
#[derive(Clone)]
pub struct EdgeClient {
    cfg: Arc<EdgeConfig>,
    http: Client<hyper_util::client::legacy::connect::HttpConnector, RequestBody>,
}

/// 一条可携带 `latest_by_key` 合并键的 Publish/PublishStream 业务消息。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishFrame {
    /// 业务 protobuf 字节，不含 FramePush 与 gRPC 前缀。
    pub payload: Bytes,
    /// 有界合并键；`None` 用于非 keyed 队列。
    pub coalesce_key: Option<Bytes>,
}

impl PublishFrame {
    /// 业务作用：构造不参与 keyed 合并的普通发布消息。
    ///
    /// 参数说明：
    /// - `payload`：是业务 protobuf 字节。
    ///
    /// 返回：返回 `coalesce_key=None` 的消息。
    pub fn new(payload: Bytes) -> Self {
        Self {
            payload,
            coalesce_key: None,
        }
    }

    /// 业务作用：构造显式参与 `latest_by_key` 合并的发布消息。
    ///
    /// 参数说明：
    /// - `coalesce_key`：必须为 1..=256 字节
    /// - `payload`：是业务 protobuf 字节。
    ///
    /// 返回：返回尚未编码的 keyed 消息；长度门在发送前统一执行。
    pub fn keyed(coalesce_key: Bytes, payload: Bytes) -> Self {
        Self {
            payload,
            coalesce_key: Some(coalesce_key),
        }
    }
}

/// PublishStream 的增量请求体。每次 H2 请求更多 DATA 时才编码并产出下一条消息。
struct PublishRequestBody {
    receiver: tokio::sync::mpsc::Receiver<PublishFrame>,
    max_message_bytes: usize,
}

impl Body for PublishRequestBody {
    type Data = Bytes;
    type Error = std::io::Error;

    /// 业务作用：把调用方逐条送入的业务 payload 按 H2 flow-control 节奏封成 FramePush DATA。
    ///
    /// 参数说明：
    /// - `cx`：是 Hyper 请求体轮询上下文。
    ///
    /// 返回：有 payload 时返回恰一条 gRPC frame；发送端关闭后返回 EOS；越界消息返回错误并停止半完成流。
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(frame)) => Poll::Ready(Some(
                encode_frame_push_with_key(
                    &frame.payload,
                    frame.coalesce_key.as_deref(),
                    self.max_message_bytes,
                )
                .map(Frame::data)
                .map_err(|error| std::io::Error::other(error.to_string())),
            )),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    /// 业务作用：向 HTTP 编码层报告流是否已经结束，避免省略尚未发送的正文或 trailers。
    fn is_end_stream(&self) -> bool {
        self.receiver.is_closed() && self.receiver.is_empty()
    }

    /// 业务作用：向 HTTP 编码层提供剩余实体长度约束，供帧传输选择定长或流式编码。
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// 业务作用：把小型 unary 请求统一装箱为 SDK 请求 body，供同一 H2 client 与流式请求复用。
///
/// 参数说明：
/// - `bytes`：是已经完成 gRPC/FramePush 编码的请求字节。
///
/// 返回：返回不会失败、写完即 EOS 的 boxed body。
fn full_request_body(bytes: Bytes) -> RequestBody {
    Full::new(bytes)
        .map_err(|never| -> std::io::Error {
            match never {}
        })
        .boxed_unsync()
}

impl EdgeClient {
    /// 业务作用：建立客户端。
    ///
    /// 参数说明：
    /// - `cfg`: 端点、认证与方法路径。
    ///
    /// 返回：
    /// 客户端句柄。此处**不做**网络连接,首次请求才拨号;因此配置错误(如路径写错)
    /// 会在第一次调用时以 gRPC 状态码暴露,而不是在这里。
    pub fn new(cfg: EdgeConfig) -> Self {
        // 强制 h2 prior knowledge:边缘面只接受 HTTP/2,不做 h1 升级协商。
        let http = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http();
        Self {
            cfg: Arc::new(cfg),
            http,
        }
    }

    /// 业务作用：群播一条消息给 group 全体订阅者。
    ///
    /// 参数说明：
    /// - `group`: 目标 group;能否发布由 route 的 `grpc_edge.authz.publish_groups` 决定。
    /// - `payload`: 业务 protobuf 字节(**不含** gRPC 5 字节前缀,SDK 负责封帧)。
    ///
    /// 返回：
    /// [`PublishSummary`]。**注意 accepted 只表示入队份数,不代表任何终端已收到。**
    /// 被授权策略拒绝时返回 [`EdgeError::Status`] 且 status 为 `7`。
    pub async fn publish(&self, group: &str, payload: Bytes) -> Result<PublishSummary> {
        let body = self
            .unary(
                &self.cfg.publish_path,
                "publish",
                &self.cfg.group_header,
                group,
                payload,
            )
            .await?;
        let fields = decode_flat_message(&body)?;
        Ok(PublishSummary {
            accepted: fields.get(1),
            dropped: fields.get(2),
            closed_slow: fields.get(3),
            messages: fields.get(4),
            peers_accepted: fields.get(5),
            peers_rejected: fields.get(6),
            peers_unknown: fields.get(7),
        })
    }

    /// 业务作用：群播一条带 `coalesce_key` 的消息，使 `latest_by_key` 队列可按业务实体合并旧状态。
    ///
    /// 参数说明：
    /// - `group`：是授权 group
    /// - `coalesce_key`：必须为 1..=256 字节
    /// - `payload`：是业务字节。
    ///
    /// 返回：返回诚实入队回执；key 非法、越权或传输失败时返回对应错误。
    pub async fn publish_keyed(
        &self,
        group: &str,
        coalesce_key: Bytes,
        payload: Bytes,
    ) -> Result<PublishSummary> {
        let body = self
            .unary_frame(
                &self.cfg.publish_path,
                "publish",
                &self.cfg.group_header,
                group,
                PublishFrame::keyed(coalesce_key, payload),
            )
            .await?;
        let fields = decode_flat_message(&body)?;
        Ok(PublishSummary {
            accepted: fields.get(1),
            dropped: fields.get(2),
            closed_slow: fields.get(3),
            messages: fields.get(4),
            peers_accepted: fields.get(5),
            peers_rejected: fields.get(6),
            peers_unknown: fields.get(7),
        })
    }

    /// 业务作用：定向单播给某 user 的全部在线 session。
    ///
    /// 参数说明：
    /// - `target`: 目标 user;能否 push 由 `grpc_edge.authz.push_targets` 决定。
    /// - `payload`: 业务字节。
    ///
    /// 返回：
    /// [`PushSummary`]。目标完全不在线时 `accepted == 0`,**这是正常结果不是错误**——
    /// 边缘面无离线堆积,不会为离线用户排队。
    pub async fn push(&self, target: &str, payload: Bytes) -> Result<PushSummary> {
        let body = self
            .unary(
                &self.cfg.push_path,
                "push",
                &self.cfg.target_header,
                target,
                payload,
            )
            .await?;
        let fields = decode_flat_message(&body)?;
        Ok(PushSummary {
            accepted: fields.get(1),
            peers_accepted: fields.get(5),
            peers_rejected: fields.get(6),
            peers_unknown: fields.get(7),
        })
    }

    /// 业务作用：定向推送一条带 `coalesce_key` 的状态消息，供目标会话的 keyed 队列只保留最新值。
    ///
    /// 参数说明：
    /// - `target`：是授权 user
    /// - `coalesce_key`：必须为 1..=256 字节
    /// - `payload`：是业务字节。
    ///
    /// 返回：返回诚实入队回执；目标离线仍是 `accepted=0` 的正常结果。
    pub async fn push_keyed(
        &self,
        target: &str,
        coalesce_key: Bytes,
        payload: Bytes,
    ) -> Result<PushSummary> {
        let body = self
            .unary_frame(
                &self.cfg.push_path,
                "push",
                &self.cfg.target_header,
                target,
                PublishFrame::keyed(coalesce_key, payload),
            )
            .await?;
        let fields = decode_flat_message(&body)?;
        Ok(PushSummary {
            accepted: fields.get(1),
            peers_accepted: fields.get(5),
            peers_rejected: fields.get(6),
            peers_unknown: fields.get(7),
        })
    }

    /// 业务作用：以 client-streaming 长流持续群播,返回**本段**的聚合回执。
    ///
    /// 参数说明：
    /// - `group`: 目标 group;能否发布由 `grpc_edge.authz.publish_groups` 决定。
    /// - `payloads`: 本次要发的业务字节序列。SDK 逐条封成 `FramePush` 并按顺序写出,
    ///   写完即 half-close,由网关返回聚合 summary。
    ///
    /// 返回：
    /// [`PublishSummary`]。与 unary 的关键差别在 `messages`:**它不是恒 1**,而是网关
    /// **本段实际处理的条数**。网关按 route 的四门(生命周期 / 累计消息数 / 每秒速率 /
    /// 累计字节)做**优雅轮转**——到界即停读并返回已聚合结果,而不是报错;发布方要凭
    /// `messages` 判断进度,把**剩下没被处理的**继续用下一段发出去,否则会静默漏发。
    ///
    /// 速率门是**背压节流**不是丢弃:令牌不足时网关暂停读体,经 H2 流控传导回来,
    /// 因此本调用可能比预期慢,但不会丢消息。
    pub async fn publish_stream(&self, group: &str, payloads: &[Bytes]) -> Result<PublishSummary> {
        // 固定 slice API 先做无分配长度预检，保留“本地参数错时一条都不发”的确定性；
        // 真正 wire 编码仍在 body 被 H2 轮询时逐条发生，不再复制整段 payload。
        for payload in payloads {
            validate_frame_push_size(payload.len(), None, self.cfg.max_message_bytes)?;
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let owned = payloads.to_vec();
        tokio::spawn(async move {
            for payload in owned {
                if sender.send(PublishFrame::new(payload)).await.is_err() {
                    break;
                }
            }
        });
        self.publish_stream_keyed_receiver(group, receiver).await
    }

    /// 业务作用：用固定 slice 增量发送带可选 `coalesce_key` 的 PublishStream。
    ///
    /// 参数说明：
    /// - `group`：是授权 group
    /// - `frames`：按顺序发送，每项 key 必须为空缺或 1..=256 字节。
    ///
    /// 返回：本地先完整预检以保证参数错误时零发送，随后按 H2 flow-control 增量编码并返回聚合回执。
    pub async fn publish_stream_keyed(
        &self,
        group: &str,
        frames: &[PublishFrame],
    ) -> Result<PublishSummary> {
        for frame in frames {
            validate_frame_push_size(
                frame.payload.len(),
                frame.coalesce_key.as_deref(),
                self.cfg.max_message_bytes,
            )?;
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let owned = frames.to_vec();
        tokio::spawn(async move {
            for frame in owned {
                if sender.send(frame).await.is_err() {
                    break;
                }
            }
        });
        self.publish_stream_keyed_receiver(group, receiver).await
    }

    /// 业务作用：从有界 channel 真正增量发送 PublishStream，允许生产方边生成边发布。
    ///
    /// 参数说明：
    /// - `group`：是授权 group
    /// - `receiver`：每项是一条业务 payload，发送端 Drop 即 half-close。
    ///
    /// 返回：网关正常收尾时返回本段聚合回执；中途越界、传输失败或 gRPC 拒绝返回错误。
    /// 调用方必须使用有界 channel；这样网关背压会经 H2 和本 receiver 传回生产方，不形成 SDK 内存堆积。
    pub async fn publish_stream_receiver(
        &self,
        group: &str,
        mut receiver: tokio::sync::mpsc::Receiver<Bytes>,
    ) -> Result<PublishSummary> {
        let (sender, keyed_receiver) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            while let Some(payload) = receiver.recv().await {
                if sender.send(PublishFrame::new(payload)).await.is_err() {
                    break;
                }
            }
        });
        self.publish_stream_keyed_receiver(group, keyed_receiver)
            .await
    }

    /// 业务作用：从有界 channel 增量发送可选 keyed 的 PublishStream，并把 H2 背压传回生产方。
    ///
    /// 参数说明：
    /// - `group`：是授权 group
    /// - `receiver`：每项携带 payload 与可选 `coalesce_key`。
    ///
    /// 返回：网关正常收尾时返回本段聚合回执；非法 key、越界、传输失败或 gRPC 拒绝返回错误。
    pub async fn publish_stream_keyed_receiver(
        &self,
        group: &str,
        receiver: tokio::sync::mpsc::Receiver<PublishFrame>,
    ) -> Result<PublishSummary> {
        let request = self
            .base_request(
                &self.cfg.publish_stream_path,
                "publish",
                &self.cfg.group_header,
                group,
            )?
            .body(
                PublishRequestBody {
                    receiver,
                    max_message_bytes: self.cfg.max_message_bytes,
                }
                .boxed_unsync(),
            )
            .map_err(|e| EdgeError::Protocol(format!("build publish stream: {e}")))?;
        let message = self.send_unary_reply(request).await?;
        let fields = decode_flat_message(&message)?;
        Ok(PublishSummary {
            accepted: fields.get(1),
            dropped: fields.get(2),
            closed_slow: fields.get(3),
            messages: fields.get(4),
            peers_accepted: fields.get(5),
            peers_rejected: fields.get(6),
            peers_unknown: fields.get(7),
        })
    }

    /// 业务作用：创建订阅句柄(自动重连)。
    ///
    /// **注意:本方法不建立连接。**订阅流在**首次 [`Subscription::next`]** 时才真正打开
    /// (这样重连与首连才能共用同一条路径)。因此"先 subscribe 再 publish"存在竞态:
    /// 订阅还没登记时发布会诚实地返回 `accepted = 0`,而不是报错。要确保投递,
    /// 应先 `next` 起来(例如放进独立 task)并留出登记时间,再开始发布。
    ///
    /// 参数说明：
    /// - `group`: 目标 group;能否订阅由 `grpc_edge.authz.subscribe_groups` 决定。
    ///
    /// 返回：
    /// [`Subscription`]。**它不会在建立失败时返回错误**——首次连接同样走重连循环,
    /// 因为边缘面的正常运维(节点 drain/重启)必然造成断流,把首连失败与后续断线
    /// 区别对待只会让调用方写两套逻辑。授权被拒(7)属于**不可重试**错误,
    /// 会直接从 [`Subscription::next`] 返回,不会无限重试。
    pub fn subscribe(&self, group: impl Into<String>) -> Subscription {
        Subscription {
            client: self.clone(),
            group: group.into(),
            stream: None,
            buffer: BytesMut::new(),
            backoff: self.cfg.reconnect_base,
        }
    }

    /// 业务作用：组装并发出一次 unary edge 请求,返回响应 message 体(已去掉 gRPC 前缀)。
    async fn unary(
        &self,
        path: &str,
        action: &str,
        scope_header: &str,
        scope: &str,
        payload: Bytes,
    ) -> Result<Bytes> {
        self.unary_frame(
            path,
            action,
            scope_header,
            scope,
            PublishFrame::new(payload),
        )
        .await
    }

    /// 业务作用：组装并发出一条可携带合并键的 unary FramePush 请求。
    ///
    /// 参数说明：
    /// - `path`：精确 gRPC 方法路径。
    /// - `action`：网关必须确认的 edge 动作。
    /// - `scope_header`：承载 group 或 target 的 metadata 头名。
    /// - `scope`：本次动作的目标 group 或 user。
    /// - `frame`：业务 payload 与可选合并键。
    ///
    /// 返回：成功返回已去 gRPC 前缀的 summary message；编码、传输或状态错误原样返回。
    async fn unary_frame(
        &self,
        path: &str,
        action: &str,
        scope_header: &str,
        scope: &str,
        frame: PublishFrame,
    ) -> Result<Bytes> {
        let framed = match frame.coalesce_key.as_deref() {
            Some(key) => {
                encode_frame_push_with_key(&frame.payload, Some(key), self.cfg.max_message_bytes)?
            }
            None => encode_frame_push(&frame.payload, self.cfg.max_message_bytes)?,
        };
        let request = self
            .base_request(path, action, scope_header, scope)?
            .body(full_request_body(framed))
            .map_err(|e| EdgeError::Protocol(format!("build request: {e}")))?;
        self.send_unary_reply(request).await
    }

    /// 业务作用：发出请求并取回**恰一条**回执 message(已去 gRPC 前缀)。
    ///
    /// unary Publish/Push 与 client-streaming PublishStream 的**响应侧契约完全相同**
    /// (都是一条 summary + 成功 trailer),差别只在请求体是一条还是多条,因此这里共用
    /// 一份状态与上界校验,避免两条路径各自漏掉某一项检查。
    async fn send_unary_reply(&self, request: http::Request<RequestBody>) -> Result<Bytes> {
        let response = self
            .http
            .request(request)
            .await
            .map_err(|e| EdgeError::Transport(e.to_string()))?;
        // 立即拒绝把 grpc-status 放在 **header**;正常完成放在 trailer。两处都要看,
        // 只看一处会把"被拒"当成"空响应"。
        if let Some(status) = header_str(response.headers(), "grpc-status") {
            if status != "0" {
                return Err(EdgeError::Status {
                    status: status.to_string(),
                    message: header_str(response.headers(), "grpc-message")
                        .unwrap_or_default()
                        .to_string(),
                });
            }
        }
        // 方法路径未匹配 edge route 时可能收到普通 HTTP 错误页；先核对媒体类型，
        // 避免把 HTML 等非 gRPC 实体解释成帧前缀而掩盖真实的路由配置错误。
        let content_type = header_str(response.headers(), "content-type")
            .unwrap_or_default()
            .to_string();
        if !content_type.starts_with("application/grpc") {
            let status = response.status();
            return Err(EdgeError::Protocol(format!(
                "gateway replied HTTP {status} with content-type `{content_type}`, not a gRPC \
                 response; check that the method path matches the route's grpc_edge.methods"
            )));
        }
        let collected = http_body_util::Limited::new(
            response.into_body(),
            GRPC_PREFIX_BYTES + MAX_SUMMARY_MESSAGE_BYTES,
        )
        .collect()
        .await
        .map_err(|e| EdgeError::Protocol(format!("summary response exceeds limit: {e}")))?;
        let trailers = collected.trailers().cloned();
        let bytes = collected.to_bytes();
        let trailers = trailers
            .ok_or_else(|| EdgeError::Protocol("unary gRPC response is missing trailers".into()))?;
        let status = header_str(&trailers, "grpc-status").ok_or_else(|| {
            EdgeError::Protocol("unary gRPC trailers are missing grpc-status".into())
        })?;
        if status != "0" {
            return Err(EdgeError::Status {
                status: status.to_string(),
                message: header_str(&trailers, "grpc-message")
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        let (message, rest) = split_frame(&bytes, MAX_SUMMARY_MESSAGE_BYTES)?;
        if !rest.is_empty() {
            return Err(EdgeError::Protocol(
                "unary reply carried more than one message".into(),
            ));
        }
        Ok(message)
    }

    /// 业务作用：组装 edge 请求的公共 head(方法路径 + 三个 metadata + 认证)。
    fn base_request(
        &self,
        path: &str,
        action: &str,
        scope_header: &str,
        scope: &str,
    ) -> Result<http::request::Builder> {
        let uri = format!("{}{}", self.cfg.endpoint.trim_end_matches('/'), path);
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(http::header::HOST, self.cfg.authority.as_str())
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .header("te", "trailers")
            .header(header_name(&self.cfg.action_header)?, action)
            .header(header_name(scope_header)?, scope);
        builder = match &self.cfg.auth {
            Auth::ApiKey {
                header,
                value,
            } => builder.header(header_name(header)?, value.as_str()),
            Auth::Bearer(token) => {
                builder.header(http::header::AUTHORIZATION, format!("Bearer {token}"))
            }
            Auth::None => builder,
        };
        Ok(builder)
    }
}

/// 订阅句柄:内部维护一条服务端流,断线后按抖动退避自动重连。
pub struct Subscription {
    client: EdgeClient,
    group: String,
    stream: Option<hyper::body::Incoming>,
    /// 跨 DATA 帧的重组缓冲。
    ///
    /// HTTP/2 DATA 边界不等于 gRPC 消息边界；半条消息必须等待更多数据，不能视为断线。
    /// 断线时清空缓冲，避免旧流的半帧污染重连后的消息。
    buffer: BytesMut,
    backoff: Duration,
}

impl Subscription {
    /// 业务作用：取下一条业务消息(已去掉 gRPC 前缀)。
    ///
    /// 返回：
    /// - `Ok(bytes)`:一条完整业务消息。
    /// - `Err(Status)` 且 status 为 `7`/`16`:授权或身份问题,**不可重试**,直接返回。
    /// - 其它传输错误不返回给调用方,而是内部退避重连——因为节点 drain/重启造成的
    ///   断流是这条链路的常态。**断流期间的消息不会补发**(at-most-once,无离线堆积),
    ///   调用方若需补洞,应在业务 payload 里带 seq 并向后端补拉。
    pub async fn next(&mut self) -> Result<Bytes> {
        loop {
            if self.stream.is_none() {
                match self.open().await {
                    Ok(stream) => {
                        self.stream = Some(stream);
                        self.backoff = self.client.cfg.reconnect_base;
                    }
                    // 授权/身份类错误重试多少次都一样,立即上报,避免无声打转。
                    Err(
                        err @ EdgeError::Status {
                            ..
                        },
                    ) if is_terminal(&err) => return Err(err),
                    Err(_) => {
                        tokio::time::sleep(self.backoff).await;
                        self.backoff = (self.backoff * 2).min(self.client.cfg.reconnect_max);
                        continue;
                    }
                }
            }
            // 先看缓冲里是否已经攒够一条完整消息;攒够就直接给出,不必再等新帧。
            if let Some(message) =
                take_message(&mut self.buffer, self.client.cfg.max_message_bytes)?
            {
                return decode_frame_push(&message);
            }
            let stream = self.stream.as_mut().expect("stream present");
            match next_chunk(stream).await {
                Ok(Some(chunk)) => self.buffer.extend_from_slice(&chunk),
                // 流正常结束或出错都当作断线:重连,并**丢弃半帧**——
                // 截断的消息绝不能交给调用方,那会让业务拿到内容不全的 payload。
                Ok(None) | Err(_) => {
                    self.stream = None;
                    self.buffer.clear();
                }
            }
        }
    }

    /// 业务作用：建立一条新的订阅流。请求体是**恰好一条**空 SubReq 并立即 EOS( 契约)。
    async fn open(&self) -> Result<hyper::body::Incoming> {
        let request = self
            .client
            .base_request(
                &self.client.cfg.subscribe_path,
                "subscribe",
                &self.client.cfg.group_header,
                &self.group,
            )?
            // Full 体在写完后自动 EOS,正好满足"一条消息 + half-close"。
            .body(full_request_body(frame(&[])))
            .map_err(|e| EdgeError::Protocol(format!("build subscribe: {e}")))?;
        let response = self
            .client
            .http
            .request(request)
            .await
            .map_err(|e| EdgeError::Transport(e.to_string()))?;
        if let Some(status) = header_str(response.headers(), "grpc-status") {
            if status != "0" {
                return Err(EdgeError::Status {
                    status: status.to_string(),
                    message: header_str(response.headers(), "grpc-message")
                        .unwrap_or_default()
                        .to_string(),
                });
            }
        }
        // 同 unary:route 配错时是 HTTP 错误页而不是 gRPC 流,必须明说,
        // 否则会退化成"读到一条畸形帧"然后进入无意义的重连循环。
        let content_type = header_str(response.headers(), "content-type").unwrap_or_default();
        if !content_type.starts_with("application/grpc") {
            return Err(EdgeError::Protocol(format!(
                "gateway replied HTTP {} with content-type `{content_type}`, not a gRPC stream; \
                 check subscribe_path against the route's grpc_edge.methods",
                response.status()
            )));
        }
        Ok(response.into_body())
    }
}

/// 业务作用：授权/身份类错误重试无意义,应立刻上报给调用方。
fn is_terminal(err: &EdgeError) -> bool {
    matches!(err, EdgeError::Status {
        status, ..
    } if status == "7" || status == "16" || status == "3")
}

/// 业务作用：从服务端流读下一块 DATA 负载(不做分帧解释)。返回 `Ok(None)` 表示流结束。
async fn next_chunk(stream: &mut hyper::body::Incoming) -> Result<Option<Bytes>> {
    use http_body_util::BodyExt as _;
    while let Some(frame) = stream.frame().await {
        let frame = frame.map_err(|e| EdgeError::Transport(e.to_string()))?;
        match frame.into_data() {
            Ok(chunk) => {
                if chunk.is_empty() {
                    continue;
                }
                return Ok(Some(chunk));
            }
            // trailer 帧:流结束。
            Err(_) => return Ok(None),
        }
    }
    Ok(None)
}

/// 业务作用：若缓冲里已有一条完整 gRPC message,取走并返回;不足则 `Ok(None)` 等更多数据。
///
/// 一次 DATA 帧可能带来半条、一条或多条消息,三种都必须正确处理:边缘面既有超过
/// 单帧的大消息(默认上限 64 KiB > 帧上限 16 KiB),也有多条小广播被攒在同一次写出。
fn take_message(buffer: &mut BytesMut, max_message_bytes: usize) -> Result<Option<Bytes>> {
    if buffer.len() < GRPC_PREFIX_BYTES {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err(EdgeError::Protocol(
            "compressed grpc frames are not supported on the edge plane".into(),
        ));
    }
    let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if max_message_bytes == 0 || len > max_message_bytes {
        return Err(EdgeError::Protocol(format!(
            "grpc message length {len} exceeds configured limit {max_message_bytes}"
        )));
    }
    let total = GRPC_PREFIX_BYTES + len;
    if buffer.len() < total {
        return Ok(None);
    }
    let frame = buffer.split_to(total).freeze();
    Ok(Some(frame.slice(GRPC_PREFIX_BYTES..)))
}

/// 业务作用：给业务字节加上 gRPC 5 字节前缀。
fn frame(payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(GRPC_PREFIX_BYTES + payload.len());
    out.put_u8(0);
    out.put_u32(payload.len() as u32);
    out.extend_from_slice(payload);
    out.freeze()
}

/// 业务作用：拆掉 gRPC 前缀,返回 (message, 剩余字节)。
fn split_frame(bytes: &Bytes, max_message_bytes: usize) -> Result<(Bytes, Bytes)> {
    if bytes.len() < GRPC_PREFIX_BYTES {
        return Err(EdgeError::Protocol("grpc frame shorter than prefix".into()));
    }
    if bytes[0] != 0 {
        return Err(EdgeError::Protocol(
            "compressed grpc frames are not supported on the edge plane".into(),
        ));
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if max_message_bytes == 0 || len > max_message_bytes {
        return Err(EdgeError::Protocol(format!(
            "grpc message length {len} exceeds configured limit {max_message_bytes}"
        )));
    }
    let end = GRPC_PREFIX_BYTES
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| EdgeError::Protocol("grpc frame length exceeds payload".into()))?;
    Ok((bytes.slice(GRPC_PREFIX_BYTES..end), bytes.slice(end..)))
}

/// 业务作用：按统一 `.proto` 编码 `FramePush { bytes payload = 1; }`，再加 gRPC 前缀。
///
/// 业务字节必须放入 FramePush 的 payload 字段；仅添加 gRPC 前缀不能形成合法的 protobuf 信封。
fn encode_frame_push(payload: &Bytes, max_message_bytes: usize) -> Result<Bytes> {
    encode_frame_push_with_key(payload, None, max_message_bytes)
}

/// 业务作用：按统一 proto 编码 payload 与可选 `coalesce_key`，再添加 gRPC 前缀。
///
/// 参数说明：
/// - `payload`：是业务字节
/// - `coalesce_key`：为空缺或 1..=256 字节
/// - `max_message_bytes`：是完整 FramePush protobuf 上限。
///
/// 返回：合法时返回完整 gRPC 帧；key/总长非法时在分配前返回协议错误。
fn encode_frame_push_with_key(
    payload: &Bytes,
    coalesce_key: Option<&[u8]>,
    max_message_bytes: usize,
) -> Result<Bytes> {
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| EdgeError::Protocol("FramePush payload length does not fit u64".into()))?;
    let protobuf_len = validate_frame_push_size(payload.len(), coalesce_key, max_message_bytes)?;
    let mut out = BytesMut::with_capacity(GRPC_PREFIX_BYTES + protobuf_len);
    out.put_u8(0);
    out.put_u32(protobuf_len as u32);
    out.put_u8(0x0a);
    put_varint(payload_len, &mut out);
    out.extend_from_slice(payload);
    if let Some(key) = coalesce_key {
        out.put_u8(0x12);
        put_varint(key.len() as u64, &mut out);
        out.extend_from_slice(key);
    }
    Ok(out.freeze())
}

/// 业务作用：在不分配编码缓冲的前提下验证一条 FramePush 的精确 wire 长度。
///
/// 参数说明：
/// - `payload_len`：业务 payload 字节数。
/// - `coalesce_key`：可选业务实体合并键，非空时受键长度上限约束。
/// - `max_message_bytes`：整条 protobuf message 的字节上限，必须与 route 单消息门一致。
///
/// 返回：合法时返回 protobuf message 长度；算术溢出或超过任一协议上限时返回错误。
fn validate_frame_push_size(
    payload_len: usize,
    coalesce_key: Option<&[u8]>,
    max_message_bytes: usize,
) -> Result<usize> {
    let payload_len_u64 = u64::try_from(payload_len)
        .map_err(|_| EdgeError::Protocol("FramePush payload length does not fit u64".into()))?;
    let mut protobuf_len = 1usize
        .checked_add(varint_len(payload_len_u64))
        .and_then(|len| len.checked_add(payload_len))
        .ok_or_else(|| EdgeError::Protocol("FramePush length overflow".into()))?;
    if let Some(key) = coalesce_key {
        if key.is_empty() || key.len() > MAX_COALESCE_KEY_BYTES {
            return Err(EdgeError::Protocol(format!(
                "FramePush coalesce_key length {} is outside 1..={MAX_COALESCE_KEY_BYTES}",
                key.len()
            )));
        }
        protobuf_len = protobuf_len
            .checked_add(1 + varint_len(key.len() as u64))
            .and_then(|len| len.checked_add(key.len()))
            .ok_or_else(|| EdgeError::Protocol("FramePush length overflow".into()))?;
    }
    if max_message_bytes == 0
        || protobuf_len > max_message_bytes
        || protobuf_len > u32::MAX as usize
    {
        return Err(EdgeError::Protocol(format!(
            "FramePush wire length {protobuf_len} exceeds configured limit {max_message_bytes}"
        )));
    }
    Ok(protobuf_len)
}

/// 业务作用：从统一 `FramePush` protobuf message 取出 field 1，未知字段按 protobuf 规则跳过。
fn decode_frame_push(message: &Bytes) -> Result<Bytes> {
    let mut cursor = 0usize;
    let mut payload = None;
    while cursor < message.len() {
        let (key, next) = read_varint(message, cursor)?;
        cursor = next;
        let tag = key >> 3;
        let wire = key & 0x7;
        if tag == 1 {
            if wire != 2 || payload.is_some() {
                return Err(EdgeError::Protocol(
                    "FramePush.payload must be one length-delimited field".into(),
                ));
            }
            let (len, next) = read_varint(message, cursor)?;
            cursor = next;
            let len = usize::try_from(len)
                .map_err(|_| EdgeError::Protocol("FramePush payload length overflow".into()))?;
            let end = cursor
                .checked_add(len)
                .filter(|end| *end <= message.len())
                .ok_or_else(|| EdgeError::Protocol("FramePush payload overruns message".into()))?;
            payload = Some(message.slice(cursor..end));
            cursor = end;
            continue;
        }
        cursor = skip_protobuf_field(message, cursor, wire)?;
    }
    // proto3 省零:`bytes payload = 1` 取默认值(空)时 protoc **不上 wire**,
    // 因此"字段缺失"必须解释为**空 payload**,而不是错误。把它当错误会直接拒掉
    // 第三方 protoc 客户端发来的空帧(心跳/ping 就是这形态)——那正是引入
    // FramePush 信封本来要解决的互通问题。
    Ok(payload.unwrap_or_else(Bytes::new))
}

/// 业务作用：按 wire type 跳过未知 protobuf 字段，保留信封的向前兼容性并拒绝越界载荷。
fn skip_protobuf_field(message: &Bytes, cursor: usize, wire: u64) -> Result<usize> {
    match wire {
        0 => read_varint(message, cursor).map(|(_, next)| next),
        1 => cursor
            .checked_add(8)
            .filter(|end| *end <= message.len())
            .ok_or_else(|| EdgeError::Protocol("fixed64 field overruns FramePush".into())),
        2 => {
            let (len, next) = read_varint(message, cursor)?;
            next.checked_add(len as usize)
                .filter(|end| *end <= message.len())
                .ok_or_else(|| EdgeError::Protocol("bytes field overruns FramePush".into()))
        }
        5 => cursor
            .checked_add(4)
            .filter(|end| *end <= message.len())
            .ok_or_else(|| EdgeError::Protocol("fixed32 field overruns FramePush".into())),
        _ => Err(EdgeError::Protocol(format!(
            "unsupported protobuf wire type {wire} in FramePush"
        ))),
    }
}

/// 业务作用：在分配 FramePush 缓冲前计算长度字段的编码开销，使消息上限包含完整信封。
fn varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

/// 业务作用：编码 protobuf 无符号整数，供业务信封长度与回执字段共享 wire 格式。
fn put_varint(mut value: u64, out: &mut BytesMut) {
    while value >= 0x80 {
        out.put_u8((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

/// 平坦 varint-only 消息的解析结果。
///
/// 只支持 varint 字段:两个回执消息就是这个形状。遇到其它 wire type 会跳过而不是
/// 报错——这样网关将来往回执里加非 varint 字段时,旧 SDK 仍能读懂已有字段
/// (protobuf 的前向兼容语义)。
struct FlatMessage {
    fields: Vec<(u32, u64)>,
}

impl FlatMessage {
    /// 业务作用：取字段值;**缺失即 0**(proto3 省零),不是"未知"。
    fn get(&self, tag: u32) -> u64 {
        self.fields
            .iter()
            .find(|(field, _)| *field == tag)
            .map(|(_, value)| *value)
            .unwrap_or(0)
    }
}

/// 业务作用：解析边缘入队回执的整数域，未知字段可跳过且缺省字段保持 proto3 零值语义。
fn decode_flat_message(body: &Bytes) -> Result<FlatMessage> {
    let mut fields = Vec::new();
    let mut cursor = 0usize;
    while cursor < body.len() {
        let (key, next) = read_varint(body, cursor)?;
        cursor = next;
        let tag = (key >> 3) as u32;
        match key & 0x7 {
            0 => {
                let (value, next) = read_varint(body, cursor)?;
                cursor = next;
                fields.push((tag, value));
            }
            // 前向兼容:长度前缀字段整段跳过,不影响已认识的 varint 字段。
            2 => {
                let (len, next) = read_varint(body, cursor)?;
                cursor = next
                    .checked_add(len as usize)
                    .filter(|end| *end <= body.len())
                    .ok_or_else(|| EdgeError::Protocol("length-delimited field overruns".into()))?;
            }
            other => {
                return Err(EdgeError::Protocol(format!(
                    "unsupported protobuf wire type {other} in summary"
                )))
            }
        }
    }
    Ok(FlatMessage {
        fields,
    })
}

/// 业务作用：有界读取 protobuf 整数，拒绝截断和溢出而不消费未证明完整的字段。
fn read_varint(body: &Bytes, mut cursor: usize) -> Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *body
            .get(cursor)
            .ok_or_else(|| EdgeError::Protocol("varint truncated".into()))?;
        cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, cursor));
        }
        shift += 7;
        if shift >= 64 {
            return Err(EdgeError::Protocol("varint too long".into()));
        }
    }
}

/// 业务作用：读取合法文本形式的响应元数据，供 gRPC 状态判定使用。
fn header_str<'h>(headers: &'h http::HeaderMap, name: &str) -> Option<&'h str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// 业务作用：把端点契约中的头名转换为 HTTP 类型，让非法配置在请求构造时明确失败。
fn header_name(raw: &str) -> Result<HeaderName> {
    HeaderName::try_from(raw).map_err(|_| EdgeError::Protocol(format!("invalid header name {raw}")))
}
