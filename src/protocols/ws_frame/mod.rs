//! WebSocket 帧级治理:可选 frame-aware 模式下的解析、预算与失败动作。
//!
//! 透明模式(默认)一个字节都不多碰,`copy_bidirectional` 直接搬运。只有显式开启
//! frame-aware 后才进入本模块,因此这里的每一处开销都只落在自愿承担它的 route 上。
//!
//! 帧级治理最容易出的安全问题不是"解析错了",而是**按对端声明的长度分配内存**:
//! WebSocket 的载荷长度字段最大 2^63-1,照着它 `with_capacity` 一次就能把进程打死。
//! 本模块的所有长度判定都在分配之前完成。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{bail, Result};

pub(crate) mod deflate;
pub(crate) mod handshake;
pub(crate) mod message;
pub(crate) mod plugins;
mod policy;

/// 控制帧载荷上限：RFC 6455 第 5.5 节要求控制帧不超过 125 字节且不可分片。
pub const MAX_CONTROL_PAYLOAD: usize = 125;
/// 解析单帧头部需要的最大字节数(2 + 8 长度 + 4 掩码)。
const MAX_HEADER_BYTES: usize = 14;

/// WebSocket opcode。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpCode {
    /// 分片续帧。
    Continuation,
    /// 文本消息。
    Text,
    /// 二进制消息。
    Binary,
    /// 关闭。
    Close,
    /// Ping。
    Ping,
    /// Pong。
    Pong,
}

impl OpCode {
    /// 业务作用：把 4 位 opcode 映射为已知类型。
    ///
    /// 参数说明：
    /// - `raw`：为帧首字节低 4 位。
    ///
    /// 返回：已知 opcode;保留值返回 `None`——保留 opcode 必须按协议错误处理,
    /// 而不是"当作二进制帧转发",后者会把未定义语义原样透传给上游。
    pub fn from_bits(raw: u8) -> Option<Self> {
        match raw {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xa => Some(Self::Pong),
            _ => None,
        }
    }

    /// 业务作用：判断 opcode 是否属于不可分片的控制帧类别。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：Close、Ping 或 Pong 返回 `true`。
    pub fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// 帧解析错误。全部对应必须关闭连接的协议违规。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameError {
    /// 使用了保留 opcode。
    ReservedOpcode,
    /// 控制帧被分片。
    FragmentedControlFrame,
    /// 控制帧载荷超过 125 字节。
    OversizedControlFrame,
    /// 未协商扩展却置位 RSV。
    UnexpectedRsv,
    /// 帧长度超出策略上限。
    FrameTooLarge,
    /// 扩展长度未使用最短编码。
    NonCanonicalLength,
    /// 消息累计长度超出策略上限。
    MessageTooLarge,
    /// 分片数超出策略上限。
    TooManyFragments,
    /// 续帧之前没有起始帧。
    OrphanContinuation,
    /// 消息进行中收到新的起始帧。
    InterleavedMessage,
    /// 掩码方向不符(客户端必须掩码,服务端必须不掩码)。
    MaskingViolation,
    /// close 帧的 code 非法。
    InvalidCloseCode,
    /// 文本帧不是合法 UTF-8。
    InvalidUtf8,
    /// 解压后体积超过上限(压缩炸弹)。
    DecompressionBomb,
    /// 压缩载荷不能形成完整 DEFLATE 消息。
    InvalidCompression,
    /// 进程保留预算不足，不能继续聚合消息。
    ResourceCapacity,
    /// 完整消息被业务策略拒绝。
    PolicyDenied,
    /// 消息或插件超过固定的处理期限。
    MessageDeadline,
    /// 外部消息插件未返回有效且有权限的动作。
    PluginFailure,
}

impl FrameError {
    /// 业务作用：给出低基数错误标签,可安全用作指标维度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：稳定标签。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReservedOpcode => "reserved_opcode",
            Self::FragmentedControlFrame => "fragmented_control_frame",
            Self::OversizedControlFrame => "oversized_control_frame",
            Self::UnexpectedRsv => "unexpected_rsv",
            Self::FrameTooLarge => "frame_too_large",
            Self::NonCanonicalLength => "non_canonical_length",
            Self::MessageTooLarge => "message_too_large",
            Self::TooManyFragments => "too_many_fragments",
            Self::OrphanContinuation => "orphan_continuation",
            Self::InterleavedMessage => "interleaved_message",
            Self::MaskingViolation => "masking_violation",
            Self::InvalidCloseCode => "invalid_close_code",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::DecompressionBomb => "decompression_bomb",
            Self::InvalidCompression => "invalid_compression",
            Self::ResourceCapacity => "resource_capacity",
            Self::PolicyDenied => "message_policy_denied",
            Self::MessageDeadline => "message_deadline",
            Self::PluginFailure => "message_plugin_failure",
        }
    }

    /// 业务作用：给出该违规对应的 WebSocket close code。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：1002 表示协议错误，1007 表示文本编码错误，1009 表示消息过大。
    pub fn close_code(self) -> u16 {
        match self {
            Self::FrameTooLarge
            | Self::MessageTooLarge
            | Self::TooManyFragments
            | Self::DecompressionBomb => 1009,
            Self::InvalidUtf8 => 1007,
            Self::ResourceCapacity => 1013,
            Self::PolicyDenied | Self::MessageDeadline => 1008,
            Self::PluginFailure => 1011,
            _ => 1002,
        }
    }
}

/// 帧头解析结果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameHeader {
    /// 是否为消息最后一帧。
    pub fin: bool,
    /// RSV1;permessage-deflate 用它标记压缩帧。
    pub rsv1: bool,
    /// opcode。
    pub opcode: OpCode,
    /// 是否带掩码。
    pub masked: bool,
    /// 载荷长度。
    pub payload_len: u64,
    /// 帧头总字节数。
    pub header_len: usize,
}

/// 帧头解析产出。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderOutcome {
    /// 解析出完整帧头。
    Header(FrameHeader),
    /// 字节不足,需要更多数据。
    Incomplete,
    /// 协议违规。
    Invalid(FrameError),
}

/// 业务作用：解析 RFC 6455 第 5.2 节定义的 WebSocket 帧头。
///
/// **只解析头部,不触碰载荷**:载荷长度由对端声明,最大可到 2^63-1。
/// 任何"先按声明长度准备缓冲"的写法都是一次远程 OOM,因此长度校验必须
/// 全部发生在读取载荷之前。
///
/// 参数说明：
/// - `input`：是已接收字节
/// - `from_client`：决定掩码要求
/// - `deflate_negotiated`：决定 RSV1 是否合法。
///
/// 返回：解析结果。
pub fn parse_header(input: &[u8], from_client: bool, deflate_negotiated: bool) -> HeaderOutcome {
    if input.len() < 2 {
        return HeaderOutcome::Incomplete;
    }
    let first = input[0];
    let second = input[1];
    let fin = first & 0x80 != 0;
    let rsv1 = first & 0x40 != 0;
    let rsv2 = first & 0x20 != 0;
    let rsv3 = first & 0x10 != 0;
    // 未协商扩展时 RSV 必须为 0。放行未知 RSV 等于把未定义的帧语义透传给上游。
    if rsv2 || rsv3 || (rsv1 && !deflate_negotiated) {
        return HeaderOutcome::Invalid(FrameError::UnexpectedRsv);
    }
    let Some(opcode) = OpCode::from_bits(first & 0x0f) else {
        return HeaderOutcome::Invalid(FrameError::ReservedOpcode);
    };
    let masked = second & 0x80 != 0;
    // 掩码方向是协议强制:客户端必须掩码,服务端必须不掩码。
    // 放宽任一方向都会让代理与端点对同一字节流的解释产生分歧。
    if masked != from_client {
        return HeaderOutcome::Invalid(FrameError::MaskingViolation);
    }
    let short_len = second & 0x7f;
    let (payload_len, mut header_len) = match short_len {
        126 => {
            if input.len() < 4 {
                return HeaderOutcome::Incomplete;
            }
            let len = u16::from_be_bytes([input[2], input[3]]) as u64;
            if len < 126 {
                return HeaderOutcome::Invalid(FrameError::NonCanonicalLength);
            }
            (len, 4)
        }
        127 => {
            if input.len() < 10 {
                return HeaderOutcome::Incomplete;
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&input[2..10]);
            let len = u64::from_be_bytes(bytes);
            // 最高位必须为 0(RFC 6455 第 5.2 节)。
            if len & 0x8000_0000_0000_0000 != 0 {
                return HeaderOutcome::Invalid(FrameError::FrameTooLarge);
            }
            if len <= u16::MAX as u64 {
                return HeaderOutcome::Invalid(FrameError::NonCanonicalLength);
            }
            (len, 10)
        }
        other => (other as u64, 2),
    };
    if masked {
        header_len += 4;
        if input.len() < header_len {
            return HeaderOutcome::Incomplete;
        }
    }
    // 控制帧的两条硬约束:不可分片、载荷 ≤125。违反必须断连,
    // 因为分片的控制帧会让 close/ping 的语义变得不可判定。
    if opcode.is_control() {
        if !fin {
            return HeaderOutcome::Invalid(FrameError::FragmentedControlFrame);
        }
        if payload_len > MAX_CONTROL_PAYLOAD as u64 {
            return HeaderOutcome::Invalid(FrameError::OversizedControlFrame);
        }
    }
    debug_assert!(header_len <= MAX_HEADER_BYTES);
    HeaderOutcome::Header(FrameHeader {
        fin,
        rsv1,
        opcode,
        masked,
        payload_len,
        header_len,
    })
}

/// 消息失败动作。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageAction {
    /// 丢弃该消息,连接继续。
    Drop,
    /// 按策略关闭下游连接(发送 close 帧)。
    PolicyClose,
    /// 关闭到上游的连接。
    UpstreamClose,
}

impl MessageAction {
    /// 业务作用：解析配置中的失败动作。
    ///
    /// 参数说明：
    /// - `raw`：为配置字符串。
    ///
    /// 返回：识别成功返回动作;未知取值返回错误。
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "drop" => Ok(Self::Drop),
            "policy_close" | "close" => Ok(Self::PolicyClose),
            "upstream_close" => Ok(Self::UpstreamClose),
            other => {
                bail!("未知 WebSocket 失败动作 `{other}`,可选 drop|policy_close|upstream_close")
            }
        }
    }
}

/// 帧级治理策略。
#[derive(Clone, Debug)]
pub struct FramePolicy {
    /// 单帧载荷上限。
    pub max_frame_bytes: u64,
    /// 单条消息(所有分片之和)上限。
    pub max_message_bytes: u64,
    /// 单条消息允许的最大分片数。
    pub max_fragments: u32,
    /// 交给插件的完整载荷上限；超界拒绝，不向插件提供截断视野。
    pub max_plugin_payload_bytes: usize,
    /// 单个插件处理一条完整消息的时限。
    pub plugin_timeout_ms: u64,
    /// permessage-deflate 允许的最大解压比。
    pub max_decompress_ratio: u32,
    /// 校验失败时的动作。
    pub on_violation: MessageAction,
    /// 显式接受不跨消息复用字典的 permessage-deflate。
    pub permessage_deflate: bool,
    /// 从首个字节到完整交付的总预算，控制帧不得延长正在装配的消息期限。
    pub message_timeout_ms: u64,
    /// 两个方向分别编译，连接冻结握手时的策略和身份。
    pub(crate) client_plugins: plugins::Chain,
    pub(crate) server_plugins: plugins::Chain,
}

impl FramePolicy {
    /// 业务作用：校验帧级策略,拒绝会导致无界聚合或永久阻塞的取值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法返回 `Ok`;任一上限为 0 时返回错误。0 在这里不是“不限制”，
    /// 否则攻击者可用超长帧或海量微小分片持续占用连接与解析资源。
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            usize::try_from(self.max_message_bytes).is_ok(),
            "WebSocket message bound exceeds platform capacity"
        );
        anyhow::ensure!(
            (1..=60_000).contains(&self.message_timeout_ms)
                && (1..=60_000).contains(&self.plugin_timeout_ms),
            "invalid WebSocket message deadline"
        );
        anyhow::ensure!(
            (1..=1024 * 1024).contains(&self.max_plugin_payload_bytes),
            "invalid WebSocket plugin payload bound"
        );
        if self.max_frame_bytes == 0 {
            bail!("ws_frame.max_frame_bytes 必须大于 0");
        }
        if self.max_message_bytes == 0 {
            bail!("ws_frame.max_message_bytes 必须大于 0");
        }
        if self.max_fragments == 0 {
            bail!("ws_frame.max_fragments 必须大于 0:分片数无上限会形成分片炸弹");
        }
        if self.plugin_timeout_ms == 0 {
            bail!("ws_frame.plugin_timeout_ms 必须大于 0:无时限的插件会挂住连接");
        }
        if self.max_decompress_ratio == 0 {
            bail!("ws_frame.max_decompress_ratio 必须大于 0");
        }
        if self.max_frame_bytes > self.max_message_bytes {
            bail!("ws_frame.max_frame_bytes 不得大于 max_message_bytes");
        }
        Ok(())
    }

    /// 业务作用：把插件处理时限转换为运行期时长，并保证不会出现零时长竞态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：至少 1ms 的插件处理预算。
    pub fn plugin_timeout(&self) -> Duration {
        Duration::from_millis(self.plugin_timeout_ms.max(1))
    }
}

impl Default for FramePolicy {
    /// 业务作用：构造显式启用 frame-aware 模式时的有界默认策略。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：帧、消息、分片、插件视野与解压比均有硬上限的策略。
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_message_bytes: 8 * 1024 * 1024,
            max_fragments: 256,
            max_plugin_payload_bytes: 64 * 1024,
            plugin_timeout_ms: 100,
            max_decompress_ratio: 100,
            on_violation: MessageAction::PolicyClose,
            permessage_deflate: false,
            message_timeout_ms: 5000,
            client_plugins: plugins::Chain::default(),
            server_plugins: plugins::Chain::default(),
        }
    }
}

/// 单方向的消息装配状态。
#[derive(Debug, Default)]
pub struct MessageAssembler {
    /// 当前消息累计字节。
    accumulated: u64,
    /// 当前消息已收分片数。
    fragments: u32,
    /// 当前消息的起始 opcode;None 表示不在消息中。
    started: Option<OpCode>,
    /// 当前消息是否为压缩消息。
    compressed: bool,
}

/// 一帧被接受后的处置建议。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameDisposition {
    /// 控制帧:直接透传,不参与消息装配。
    ControlPassthrough,
    /// 消息尚未结束,继续装配。
    NeedMoreFragments,
    /// 消息在本帧结束,可交给插件相位。
    MessageComplete {
        /// 消息类型。
        opcode: OpCode,
        /// 消息总字节。
        total_bytes: u64,
        /// 是否为压缩消息。
        compressed: bool,
    },
}

impl MessageAssembler {
    /// 业务作用：按策略接纳一帧,并推进消息装配状态。
    ///
    /// 所有上限都在**接纳之前**判定;一旦超限立即返回错误,不把这一帧计入累计,
    /// 也不为它准备任何缓冲。分片炸弹(海量微小分片)正是靠分片数上限挡住的——
    /// 只看总字节数拦不住它,因为每片都很小。
    ///
    /// 参数说明：
    /// - `policy`：是帧级策略
    /// - `header`：是已解析帧头。
    ///
    /// 返回：接纳后的处置建议;违规返回具体 `FrameError`。
    pub fn accept(
        &mut self,
        policy: &FramePolicy,
        header: &FrameHeader,
    ) -> Result<FrameDisposition, FrameError> {
        // 控制帧可以插在分片消息中间,不影响装配状态,也不计入消息预算。
        if header.opcode.is_control() {
            return Ok(FrameDisposition::ControlPassthrough);
        }
        if header.payload_len > policy.max_frame_bytes {
            return Err(FrameError::FrameTooLarge);
        }
        match header.opcode {
            OpCode::Continuation => {
                if self.started.is_none() {
                    return Err(FrameError::OrphanContinuation);
                }
                // RSV1 只允许出现在消息的第一帧上。
                if header.rsv1 {
                    return Err(FrameError::UnexpectedRsv);
                }
            }
            OpCode::Text | OpCode::Binary => {
                if self.started.is_some() {
                    // 上一条消息还没收完就来了新的起始帧:这不是合法交错,
                    // 因为 WebSocket 同一方向只允许一条消息在装配中。
                    return Err(FrameError::InterleavedMessage);
                }
                self.started = Some(header.opcode);
                self.compressed = header.rsv1;
            }
            OpCode::Close | OpCode::Ping | OpCode::Pong => unreachable!("控制帧已提前返回"),
        }

        self.fragments = self.fragments.saturating_add(1);
        if self.fragments > policy.max_fragments {
            self.reset();
            return Err(FrameError::TooManyFragments);
        }
        self.accumulated = self.accumulated.saturating_add(header.payload_len);
        if self.accumulated > policy.max_message_bytes {
            self.reset();
            return Err(FrameError::MessageTooLarge);
        }
        if !header.fin {
            return Ok(FrameDisposition::NeedMoreFragments);
        }
        let opcode = self.started.unwrap_or(OpCode::Binary);
        let total_bytes = self.accumulated;
        let compressed = self.compressed;
        self.reset();
        Ok(FrameDisposition::MessageComplete {
            opcode,
            total_bytes,
            compressed,
        })
    }

    /// 业务作用：在消息完成或违规后清空装配状态，防止下一消息继承旧预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    fn reset(&mut self) {
        self.accumulated = 0;
        self.fragments = 0;
        self.started = None;
        self.compressed = false;
    }

    /// 业务作用：判断当前方向是否正在接收一条分片消息。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：起始帧已接收但 FIN 尚未到达时返回 `true`。
    pub fn in_message(&self) -> bool {
        self.started.is_some()
    }
}

/// 业务作用：校验 close 帧载荷:code 合法性与 reason 的 UTF-8 有效性。
///
/// 参数说明：
/// - `payload`：是已解除掩码的 close 帧载荷。
///
/// 返回：合法返回 close code(无载荷时返回 1005 的等价语义 `None`);
/// 非法返回 `InvalidCloseCode` 或 `InvalidUtf8`。坏 close code 必须拦住,
/// 否则会被原样转发给对端,把协议违规传播到连接两侧。
pub fn validate_close_payload(payload: &[u8]) -> Result<Option<u16>, FrameError> {
    if payload.is_empty() {
        return Ok(None);
    }
    if payload.len() == 1 {
        // 只有 1 字节无法构成 code。
        return Err(FrameError::InvalidCloseCode);
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    // 1005/1006/1015 是"保留给实现使用"的伪 code,不得出现在线路上。
    let allowed = matches!(code, 1000..=1003 | 1007..=1011 | 1012..=1014 | 3000..=4999);
    if !allowed {
        return Err(FrameError::InvalidCloseCode);
    }
    if std::str::from_utf8(&payload[2..]).is_err() {
        return Err(FrameError::InvalidUtf8);
    }
    Ok(Some(code))
}

/// 业务作用：判定一次解压是否属于压缩炸弹。
///
/// 参数说明：
/// - `policy`：是帧级策略
/// - `compressed_len`：是增量观测到的 压缩前后字节数。
/// - `decompressed_len`：是增量观测到的 压缩前后字节数。
///
/// 返回：正常返回 `Ok`;超过允许解压比或超过消息上限返回 `DecompressionBomb`。
/// 这个判定必须**在解压过程中**按增量执行,而不是解压完再看大小——
/// 解压完再判断时内存已经被占用了,判断本身来不及救。
pub fn check_decompression(
    policy: &FramePolicy,
    compressed_len: u64,
    decompressed_len: u64,
) -> Result<(), FrameError> {
    if decompressed_len > policy.max_message_bytes {
        return Err(FrameError::DecompressionBomb);
    }
    let budget = compressed_len
        .max(1)
        .saturating_mul(policy.max_decompress_ratio as u64);
    if decompressed_len > budget {
        return Err(FrameError::DecompressionBomb);
    }
    Ok(())
}

/// 有界载荷预览；真实消息插件只接受通过大小门的完整载荷。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginView<'a> {
    /// 消息类型。
    pub opcode: OpCode,
    /// 可用于展示的载荷片段；截断内容不能作为消息授权依据。
    pub payload: &'a [u8],
    /// 载荷是否被截断。
    pub truncated: bool,
}

/// 业务作用：生成有界借用预览，避免展示调用方复制完整消息。
///
/// 截断标志必须随预览保留。实际消息治理独立执行完整载荷大小门，不以此预览批准剩余内容。
///
/// 参数说明：
/// - `policy`：是帧级策略
/// - `opcode`：是消息类型
/// - `payload`：是完整载荷。
///
/// 返回：借用的载荷前缀及是否截断；不执行消息策略或授权。
pub fn plugin_view<'a>(policy: &FramePolicy, opcode: OpCode, payload: &'a [u8]) -> PluginView<'a> {
    let limit = policy.max_plugin_payload_bytes;
    if payload.len() <= limit {
        return PluginView {
            opcode,
            payload,
            truncated: false,
        };
    }
    PluginView {
        opcode,
        payload: &payload[..limit],
        truncated: true,
    }
}

/// 帧级治理的观测计数。
#[derive(Debug, Default)]
pub struct FrameStats {
    /// 通过治理的消息数。
    pub messages_passed: AtomicU64,
    /// 因违规被处置的消息数。
    pub messages_rejected: AtomicU64,
    /// 插件超时次数。
    pub plugin_timeouts: AtomicU64,
}

impl FrameStats {
    /// 业务作用：登记一次插件超时。
    ///
    /// 超时必须单独计数；仅显式声明 fail_open 的外部插件允许保留输入并继续。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值。
    pub fn record_plugin_timeout(&self) {
        increment_counter(&self.plugin_timeouts);
    }

    /// 业务作用：登记一次消息处置结果。
    ///
    /// 参数说明：
    /// - `passed`：表示消息是否通过治理。
    ///
    /// 返回：无返回值。
    pub fn record_message(&self, passed: bool) {
        if passed {
            increment_counter(&self.messages_passed);
        } else {
            increment_counter(&self.messages_rejected);
        }
    }
}

/// 单方向治理结束的原因。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GovernOutcome {
    /// 对端正常关闭。
    Closed,
    /// 命中协议或预算违规,调用方应按 `FramePolicy::on_violation` 处置。
    Violation(FrameError),
}

/// 单次 read 的缓冲大小。帧头最多 14 字节,这个缓冲只影响吞吐,不影响正确性。
const READ_CHUNK: usize = 16 * 1024;

/// 业务作用：在一个方向上做 frame-aware 治理转发。
///
/// **载荷是流式透传的,不做整条消息聚合**:治理只需要帧头和累计计数,把整条消息
/// 攒在内存里既没必要,又会把 `max_message_bytes` 变成"每连接实际内存占用",
/// 那正是帧级模式最容易引入的退化。
///
/// 参数说明：
/// - `reader`：是该方向的读写端
/// - `writer`：是该方向的读写端
/// - `policy`：是帧级策略
/// - `from_client`：决定掩码要求
/// - `deflate_negotiated`：决定 RSV1 语义
/// - `stats`：是观测计数。
///
/// 返回：对端正常关闭返回 `Closed`;命中违规返回 `Violation`。
/// IO 错误按 `std::io::Error` 上抛,由调用方结束隧道。
pub async fn govern_stream<R, W>(
    reader: R,
    writer: W,
    policy: &FramePolicy,
    from_client: bool,
    deflate_negotiated: bool,
    stats: &FrameStats,
) -> std::io::Result<GovernOutcome>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let writing = std::sync::atomic::AtomicBool::new(false);
    govern_stream_tracked(
        reader,
        writer,
        policy,
        from_client,
        deflate_negotiated,
        stats,
        &writing,
    )
    .await
}

/// 业务作用：向隧道 owner 暴露已开始但尚未写完的帧，取消转发后不能在半帧中插入 Close。
///
/// 参数说明：
/// - `reader`：该方向的源读端。
/// - `writer`：该方向的目标写端。
/// - `policy`：当前连接固定的帧策略。
/// - `from_client`：控制掩码方向。
/// - `deflate_negotiated`：扩展协商状态；压缩消息由完整消息路径处理。
/// - `stats`：当前连接的有界计数器。
/// - `writing`：帧开始写出后置真，只有完整帧交付才清零。
///
/// 返回：关闭或协议拒绝的分类；I/O 失败保持原类型，取消时保留写入事实。
pub(crate) async fn govern_stream_tracked<R, W>(
    mut reader: R,
    mut writer: W,
    policy: &FramePolicy,
    from_client: bool,
    deflate_negotiated: bool,
    stats: &FrameStats,
    writing: &std::sync::atomic::AtomicBool,
) -> std::io::Result<GovernOutcome>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut pending = Vec::with_capacity(READ_CHUNK);
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut assembler = MessageAssembler::default();
    let mut remaining_payload: u64 = 0;
    let mut frame_mask: Option<[u8; 4]> = None;
    let mut frame_payload_offset = 0_u64;
    let mut frame_text = false;
    let mut frame_finishes_message = false;
    let mut message_text = false;
    let mut utf8_tail = Vec::with_capacity(4);
    let mut control_frame: Option<(OpCode, Vec<u8>, Vec<u8>)> = None;
    let mut message_completes_after_payload = false;

    loop {
        if remaining_payload > 0 {
            let (payload, from_pending) = if !pending.is_empty() {
                let take = (pending.len() as u64).min(remaining_payload) as usize;
                (&pending[..take], true)
            } else {
                let want = remaining_payload.min(chunk.len() as u64) as usize;
                let read = reader.read(&mut chunk[..want]).await?;
                if read == 0 {
                    return Ok(GovernOutcome::Closed);
                }
                (&chunk[..read], false)
            };
            if let Some((_, raw, decoded)) = control_frame.as_mut() {
                raw.extend_from_slice(payload);
                append_unmasked(decoded, payload, frame_mask, frame_payload_offset);
            } else {
                if frame_text
                    && validate_utf8_incremental(
                        &mut utf8_tail,
                        payload,
                        frame_mask,
                        frame_payload_offset,
                        frame_finishes_message && payload.len() as u64 == remaining_payload,
                    )
                    .is_err()
                {
                    stats.record_message(false);
                    return Ok(GovernOutcome::Violation(FrameError::InvalidUtf8));
                }
                // 数据先完成协议校验再交给对端，避免把当前 chunk 中已经发现的非法
                // UTF-8 原样传播；只保留最多三个未完成 code point 字节。
                writer.write_all(payload).await?;
            }
            let consumed = payload.len();
            if from_pending {
                pending.drain(..consumed);
            }
            remaining_payload -= consumed as u64;
            frame_payload_offset = frame_payload_offset.saturating_add(consumed as u64);
            if remaining_payload == 0 {
                if let Some((opcode, raw, decoded)) = control_frame.take() {
                    if opcode == OpCode::Close {
                        if let Err(error) = validate_close_payload(&decoded) {
                            stats.record_message(false);
                            return Ok(GovernOutcome::Violation(error));
                        }
                    }
                    writing.store(true, Ordering::Release);
                    writer.write_all(&raw).await?;
                }
                writing.store(false, Ordering::Release);
                if message_completes_after_payload {
                    stats.record_message(true);
                }
                if frame_finishes_message {
                    message_text = false;
                    utf8_tail.clear();
                }
            }
            continue;
        }

        match parse_header(&pending, from_client, deflate_negotiated) {
            HeaderOutcome::Header(header) => {
                let mask = header.masked.then(|| {
                    let start = header.header_len - 4;
                    [
                        pending[start],
                        pending[start + 1],
                        pending[start + 2],
                        pending[start + 3],
                    ]
                });
                match assembler.accept(policy, &header) {
                    Ok(disposition) => {
                        message_completes_after_payload =
                            matches!(disposition, FrameDisposition::MessageComplete {
                                ..
                            });
                        match header.opcode {
                            OpCode::Text => {
                                message_text = true;
                                utf8_tail.clear();
                            }
                            OpCode::Binary => {
                                message_text = false;
                                utf8_tail.clear();
                            }
                            OpCode::Continuation => {}
                            OpCode::Close | OpCode::Ping | OpCode::Pong => {}
                        }
                        frame_text = message_text && !header.opcode.is_control();
                        frame_finishes_message = header.fin && !header.opcode.is_control();
                        frame_mask = mask;
                        frame_payload_offset = 0;
                        let raw_header = pending[..header.header_len].to_vec();
                        pending.drain(..header.header_len);
                        if header.opcode.is_control() {
                            // 控制帧最多 125 字节，完整保留到 close code/reason 校验结束后
                            // 再一次写出；这避免非法 close 在发现前已经到达另一端。
                            control_frame = Some((header.opcode, raw_header, Vec::new()));
                        } else {
                            // header 一旦开始写入，后续任何取消都必须按半帧处理，直至 payload 全部交付。
                            writing.store(true, Ordering::Release);
                            writer.write_all(&raw_header).await?;
                        }
                        remaining_payload = header.payload_len;
                        if remaining_payload == 0 {
                            if let Some((opcode, raw, decoded)) = control_frame.take() {
                                if opcode == OpCode::Close {
                                    if let Err(error) = validate_close_payload(&decoded) {
                                        stats.record_message(false);
                                        return Ok(GovernOutcome::Violation(error));
                                    }
                                }
                                writing.store(true, Ordering::Release);
                                writer.write_all(&raw).await?;
                            }
                            writing.store(false, Ordering::Release);
                            if frame_text && frame_finishes_message && !utf8_tail.is_empty() {
                                stats.record_message(false);
                                return Ok(GovernOutcome::Violation(FrameError::InvalidUtf8));
                            }
                            if message_completes_after_payload {
                                stats.record_message(true);
                            }
                            if frame_finishes_message {
                                message_text = false;
                                utf8_tail.clear();
                            }
                        }
                    }
                    Err(error) => {
                        stats.record_message(false);
                        return Ok(GovernOutcome::Violation(error));
                    }
                }
            }
            HeaderOutcome::Incomplete => {
                let read = reader.read(&mut chunk).await?;
                if read == 0 {
                    return Ok(GovernOutcome::Closed);
                }
                pending.extend_from_slice(&chunk[..read]);
            }
            HeaderOutcome::Invalid(error) => {
                stats.record_message(false);
                return Ok(GovernOutcome::Violation(error));
            }
        }
    }
}

/// 业务作用：按 WebSocket 掩码位置把原始载荷追加为协议可见字节，供控制帧与文本校验。
///
/// 参数说明：
/// - `out`：是解码缓冲
/// - `raw`：是线路字节
/// - `mask`：是可选掩码
/// - `offset`：是当前 chunk 在帧载荷中的起始位置。
///
/// 返回：无；输出长度与输入相同。
fn append_unmasked(out: &mut Vec<u8>, raw: &[u8], mask: Option<[u8; 4]>, offset: u64) {
    match mask {
        None => out.extend_from_slice(raw),
        Some(mask) => out.extend(
            raw.iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[(offset as usize + index) % mask.len()]),
        ),
    }
}

/// 业务作用：增量校验文本消息 UTF-8，仅跨 chunk 保留一个未完成 code point 的尾部。
///
/// 参数说明：
/// - `tail`：是上次未完成字节
/// - `raw`：是线路载荷
/// - `mask`：用于还原 客户端掩码
/// - `offset`：用于还原 客户端掩码
/// - `final_chunk`：表示该 chunk 结束整条文本消息。
///
/// 返回：当前前缀仍可能形成合法 UTF-8 时成功；确定非法或消息结束仍残缺时返回错误。
fn validate_utf8_incremental(
    tail: &mut Vec<u8>,
    raw: &[u8],
    mask: Option<[u8; 4]>,
    offset: u64,
    final_chunk: bool,
) -> Result<(), FrameError> {
    let mut decoded = Vec::with_capacity(tail.len().saturating_add(raw.len()));
    decoded.extend_from_slice(tail);
    append_unmasked(&mut decoded, raw, mask, offset);
    match std::str::from_utf8(&decoded) {
        Ok(_) => tail.clear(),
        Err(error) if error.error_len().is_some() => return Err(FrameError::InvalidUtf8),
        Err(error) => {
            let suffix = &decoded[error.valid_up_to()..];
            if suffix.len() > 3 {
                return Err(FrameError::InvalidUtf8);
            }
            tail.clear();
            tail.extend_from_slice(suffix);
        }
    }
    if final_chunk && !tail.is_empty() {
        return Err(FrameError::InvalidUtf8);
    }
    Ok(())
}

/// 业务作用：判定一次违规在**流式**治理下的实际处置动作。
///
/// `drop` 在流式模式下只对"尚未开始转发的消息"成立。一旦已有分片被转发出去,
/// 再丢弃剩余部分会给对端留下一条永远收不全的消息,连接进入不可恢复状态——
/// 那比直接关闭更糟。因此消息进行中的违规一律升级为关闭。
///
/// 参数说明：
/// - `policy`：是帧级策略
/// - `mid_message`：表示违规前是否已有消息分片被转发。
///
/// 返回：实际执行的动作。
pub fn effective_action(policy: &FramePolicy, mid_message: bool) -> MessageAction {
    match policy.on_violation {
        MessageAction::Drop if mid_message => MessageAction::PolicyClose,
        other => other,
    }
}

/// 业务作用：饱和递增 WebSocket 观测计数，避免极长运行后回绕为低值。
///
/// 参数说明：
/// - `counter`：是待递增原子计数器。
///
/// 返回：无；达到 `u64::MAX` 后保持最大值。
fn increment_counter(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}
