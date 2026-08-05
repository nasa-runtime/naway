//! V8-3 集群中继(架构规范 §25.2.6):RelayRecord v1 编解码与静态 peers 运行时。
//!
//! 本模块随 feature `grpc-edge` 编译,单机(无 `grpc_edge_cluster` 计划)零构造。
//! wire 协议自带 record 边界(固定头 + 双段长度),不依赖 HTTP/2 DATA 帧边界;
//! 业务 payload 全程 opaque——发送侧 record 拆〔头+元数据〕与〔payload〕两段写出,
//! payload 只持共享 `Bytes` 引用;接收侧同 chunk 完整时 payload 零拷贝 slice,
//! 跨 DATA 才有界重组并如实计数(§25.2.4 同款纪律)。
//!
//! 一跳规则(§25.2.6):ingress 散出创建 `hop=0`,上 wire 置 `hop=1`;接收侧只做
//! 本地散出,任何情况下不再二次 relay。

use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};

use crate::edge_hub::put_varint;

/// record 魔数("NAWY" 大端)。
pub const RELAY_MAGIC: u32 = 0x4E41_5759;
/// 协议版本;不兼容演进必须升版本,v1 内新增元数据字段按未知字段跳过。
pub const RELAY_PROTOCOL_VERSION: u8 = 1;
/// 固定头长度:magic(4)+version(1)+kind(1)+flags(1)+hop(1)+record_len(4)+metadata_len(4)+payload_len(4)。
pub const RELAY_FIXED_BYTES: usize = 20;
/// 元数据段硬上限(路由信封是小字段集合,4 KiB 已远超需要)。
pub const RELAY_MAX_METADATA_BYTES: usize = 4_096;
/// payload 段硬上限:单条业务消息硬上限(16 MiB)+ 5 字节 gRPC 前缀。
pub const RELAY_MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024 + 5;
// 解码层按本常量拒收超尺寸 record,构建期按 grpc_edge 侧的 RELAY_FANOUT_MAX_MSG_BYTES
// 校验 relay 面预算。两者一旦不一致,就会出现「配置校验通过但运行时必拒」的死角,
// 因此在编译期钉死,而不是靠注释约定。
const _: () = assert!(RELAY_MAX_PAYLOAD_BYTES - 5 == crate::grpc_edge::RELAY_FANOUT_MAX_MSG_BYTES);

// ── 帧模型 ──

/// 中继 action(data record 专用；Publish 与 V8-4 Push broadcast-probe 共用该协议)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayAction {
    /// 群播:scope = group id。
    Publish,
    /// 定向单播:scope = 目标 user(V8-4 broadcast-probe 使用)。
    Push,
}

/// enqueue-ack 结果(§25.2.6:ack 只表示"peer 接受进本地 fanout",绝不叫 delivered)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayAckOutcome {
    /// peer 已接受并完成本地散出。
    Accepted,
    /// peer 节点预算耗尽拒绝(fanout jobs/payload 预算)。
    RejectedOverload,
    /// record 语义非法(身份/水位线冲突等);计数并拒绝,不断连接。
    RejectedInvalid,
}

/// 握手帧:连接建立后双方各发恰一条,身份不符立即关闭(§25.2.6 成员身份)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayHello {
    /// 协议版本(与固定头 version 一致,冗余进元数据便于日志)。
    pub protocol_version: u64,
    /// 集群身份;跨 cluster 一律拒绝。
    pub cluster_id: Box<str>,
    /// 对端节点身份;重复 node_id、错向拨号在此判定。
    pub node_id: Box<str>,
    /// 进程代际(随机);event 去重水位线按 (node_id, boot_id) 维护。
    pub boot_id: u64,
    /// 能力位掩码(v1 恒 0,保留演进)。
    pub capabilities: u64,
    /// relay 关键配置指纹;不一致拒绝,防两边队列/顺序语义静默劈叉。
    pub config_fingerprint: u64,
}

/// 业务散出帧:seq 为发送方 boot 内单调序列,与握手 boot_id 组成 128 位事件身份。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayData {
    /// 发送方 boot 内单调序列(1 起);接收侧按水位线去重。
    pub seq: u64,
    /// 散出种类。
    pub action: RelayAction,
    /// 租户(与本地散出同一索引口径)。
    pub tenant: Box<str>,
    /// group id(publish)或目标 user(push)。
    pub scope: Box<str>,
    /// 原样业务 gRPC 帧 `[5B prefix + body]`;同 chunk 到达时是零拷贝 slice。
    pub payload: Bytes,
}

/// 回执帧。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayAck {
    /// 对应 data 的 seq。
    pub seq: u64,
    /// 结果。
    pub outcome: RelayAckOutcome,
    /// peer 本地入队份数(观测用;RejectedOverload/Invalid 恒 0)。
    pub copies: u64,
}

/// 解码产出的一条完整 record。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayFrame {
    /// 握手。
    Hello(RelayHello),
    /// 业务散出。
    Data(RelayData),
    /// 回执。
    Ack(RelayAck),
}

/// 解码错误;任何一条即视为对端不可信,关闭连接(不是丢弃单条)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayDecodeError {
    /// 魔数不符(端口被非 relay 流量命中)。
    BadMagic,
    /// 协议版本不兼容。
    BadVersion,
    /// 未知 kind。
    BadKind,
    /// v1 未定义的 flags/hop 取值。
    BadFlags,
    /// 三段长度自洽性/硬上限violated。
    BadLength,
    /// 元数据段 varint/UTF-8/必填字段非法。
    BadMetadata,
    /// EOS 停在半条 record 中间。
    TruncatedRecord,
}

// ── 编码(发送侧) ──

/// data record 的出线形态:〔固定头+元数据〕小段自有,payload 只持共享引用,
/// 逐 peer 复制的只有小段;两段按序写出即一条完整 record。
#[derive(Clone, Debug)]
pub struct EncodedRelayData {
    /// 固定头 + 元数据段。
    pub head: Bytes,
    /// 共享业务帧(可为空,例如未来的控制 data)。
    pub payload: Bytes,
}

impl EncodedRelayData {
    /// record 全长(队列双维记账用)。
    pub fn total_len(&self) -> usize {
        self.head.len() + self.payload.len()
    }
}

fn put_len_delimited(buf: &mut BytesMut, tag: u32, value: &[u8]) {
    put_varint(buf, (u64::from(tag) << 3) | 2);
    put_varint(buf, value.len() as u64);
    buf.extend_from_slice(value);
}

fn put_varint_field(buf: &mut BytesMut, tag: u32, value: u64) {
    // proto3 语义:0 值省略;必填字段的"存在性"由解码侧默认值+校验兜底。
    if value == 0 {
        return;
    }
    put_varint(buf, u64::from(tag) << 3);
    put_varint(buf, value);
}

fn fixed_header(kind: u8, hop: u8, metadata_len: usize, payload_len: usize) -> BytesMut {
    let record_len = RELAY_FIXED_BYTES + metadata_len + payload_len;
    let mut head = BytesMut::with_capacity(RELAY_FIXED_BYTES + metadata_len);
    head.put_u32(RELAY_MAGIC);
    head.put_u8(RELAY_PROTOCOL_VERSION);
    head.put_u8(kind);
    head.put_u8(0); // flags:v1 恒 0。
    head.put_u8(hop);
    head.put_u32(record_len as u32);
    head.put_u32(metadata_len as u32);
    head.put_u32(payload_len as u32);
    head
}

const KIND_HELLO: u8 = 1;
const KIND_DATA: u8 = 2;
const KIND_ACK: u8 = 3;

/// 编码握手 record(单段,无 payload)。
pub fn encode_hello(hello: &RelayHello) -> Bytes {
    let mut meta = BytesMut::new();
    put_varint_field(&mut meta, 1, hello.protocol_version);
    put_len_delimited(&mut meta, 2, hello.cluster_id.as_bytes());
    put_len_delimited(&mut meta, 3, hello.node_id.as_bytes());
    put_varint_field(&mut meta, 4, hello.boot_id);
    put_varint_field(&mut meta, 5, hello.capabilities);
    put_varint_field(&mut meta, 6, hello.config_fingerprint);
    let mut record = fixed_header(KIND_HELLO, 0, meta.len(), 0);
    record.extend_from_slice(&meta);
    record.freeze()
}

/// 编码业务散出 record:头段自有、payload 共享(§25.2 少拷贝散出)。
pub fn encode_data(
    seq: u64,
    action: RelayAction,
    tenant: &str,
    scope: &str,
    payload: Bytes,
) -> EncodedRelayData {
    let mut meta = BytesMut::new();
    put_varint_field(&mut meta, 1, seq);
    put_varint_field(
        &mut meta,
        2,
        match action {
            RelayAction::Publish => 1,
            RelayAction::Push => 2,
        },
    );
    put_len_delimited(&mut meta, 3, tenant.as_bytes());
    put_len_delimited(&mut meta, 4, scope.as_bytes());
    // 上 wire 即已被中继一跳(§25.2.6:ingress hop=0,发 peer 后 hop=1)。
    let mut head = fixed_header(KIND_DATA, 1, meta.len(), payload.len());
    head.extend_from_slice(&meta);
    EncodedRelayData {
        head: head.freeze(),
        payload,
    }
}

/// 编码回执 record(单段)。
pub fn encode_ack(ack: &RelayAck) -> Bytes {
    let mut meta = BytesMut::new();
    put_varint_field(&mut meta, 1, ack.seq);
    put_varint_field(
        &mut meta,
        2,
        match ack.outcome {
            RelayAckOutcome::Accepted => 1,
            RelayAckOutcome::RejectedOverload => 2,
            RelayAckOutcome::RejectedInvalid => 3,
        },
    );
    put_varint_field(&mut meta, 3, ack.copies);
    let mut record = fixed_header(KIND_ACK, 0, meta.len(), 0);
    record.extend_from_slice(&meta);
    record.freeze()
}

// ── 解码(接收侧,增量状态机) ──

enum RelayDecodeState {
    /// 收集固定头。
    Fixed {
        header: [u8; RELAY_FIXED_BYTES],
        filled: usize,
    },
    /// 头已定,收集元数据+payload(`total = metadata_len + payload_len`)。
    Body {
        kind: u8,
        hop: u8,
        metadata_len: usize,
        total: usize,
        /// 有界重组缓冲(容量恰为 total;快路径不经过这里)。
        buf: BytesMut,
    },
}

/// RelayRecord v1 增量解码器;任意 DATA 切分下产出恒等(§25.2.6)。
pub struct RelayRecordDecoder {
    state: RelayDecodeState,
    /// 跨 chunk 重组累计复制字节(诚实观测;零拷贝快路径不累计)。
    reassembled_bytes: u64,
}

impl Default for RelayRecordDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayRecordDecoder {
    /// 新建解码器。
    pub fn new() -> Self {
        Self {
            state: RelayDecodeState::Fixed {
                header: [0; RELAY_FIXED_BYTES],
                filled: 0,
            },
            reassembled_bytes: 0,
        }
    }

    /// 跨 chunk 重组累计复制字节。
    pub fn reassembled_bytes(&self) -> u64 {
        self.reassembled_bytes
    }

    /// 送入一个 DATA chunk,解出的完整帧追加进 `out`。
    pub fn feed(
        &mut self,
        chunk: &mut Bytes,
        out: &mut Vec<RelayFrame>,
    ) -> Result<(), RelayDecodeError> {
        while !chunk.is_empty() {
            match &mut self.state {
                RelayDecodeState::Fixed { header, filled } => {
                    // 快路径:缓冲为空且 chunk 含完整 record → 元数据小复制 + payload 零拷贝 slice。
                    if *filled == 0 && chunk.len() >= RELAY_FIXED_BYTES {
                        let parsed = parse_fixed(&chunk[..RELAY_FIXED_BYTES])?;
                        let total = parsed.metadata_len + parsed.payload_len;
                        if chunk.len() >= RELAY_FIXED_BYTES + total {
                            let record = chunk.split_to(RELAY_FIXED_BYTES + total);
                            let body = record.slice(RELAY_FIXED_BYTES..);
                            out.push(parse_body(
                                parsed.kind,
                                parsed.hop,
                                parsed.metadata_len,
                                body,
                            )?);
                            continue;
                        }
                        // 跨 chunk:恰量分配 body 重组缓冲(固定头已解析完不再保留)。
                        let mut buf = BytesMut::with_capacity(total);
                        let take = chunk.len() - RELAY_FIXED_BYTES;
                        buf.extend_from_slice(&chunk[RELAY_FIXED_BYTES..]);
                        self.reassembled_bytes += take as u64;
                        chunk.clear();
                        self.state = RelayDecodeState::Body {
                            kind: parsed.kind,
                            hop: parsed.hop,
                            metadata_len: parsed.metadata_len,
                            total,
                            buf,
                        };
                        continue;
                    }
                    // 慢路径:固定头本身被切开,逐字节凑齐。
                    let need = RELAY_FIXED_BYTES - *filled;
                    let take = need.min(chunk.len());
                    header[*filled..*filled + take].copy_from_slice(&chunk[..take]);
                    *filled += take;
                    let _ = chunk.split_to(take);
                    self.reassembled_bytes += take as u64;
                    if *filled < RELAY_FIXED_BYTES {
                        continue;
                    }
                    let parsed = parse_fixed(&header[..])?;
                    let total = parsed.metadata_len + parsed.payload_len;
                    self.state = RelayDecodeState::Body {
                        kind: parsed.kind,
                        hop: parsed.hop,
                        metadata_len: parsed.metadata_len,
                        total,
                        buf: BytesMut::with_capacity(total),
                    };
                }
                RelayDecodeState::Body {
                    kind,
                    hop,
                    metadata_len,
                    total,
                    buf,
                } => {
                    let need = *total - buf.len();
                    let take = need.min(chunk.len());
                    buf.extend_from_slice(&chunk[..take]);
                    self.reassembled_bytes += take as u64;
                    let _ = chunk.split_to(take);
                    if buf.len() < *total {
                        continue;
                    }
                    let body = std::mem::take(buf).freeze();
                    let frame = parse_body(*kind, *hop, *metadata_len, body)?;
                    out.push(frame);
                    self.state = RelayDecodeState::Fixed {
                        header: [0; RELAY_FIXED_BYTES],
                        filled: 0,
                    };
                }
            }
        }
        Ok(())
    }

    /// EOS 合法性:只有停在"无半条 record"处才合法。
    pub fn finish(&self) -> Result<(), RelayDecodeError> {
        match &self.state {
            RelayDecodeState::Fixed { filled: 0, .. } => Ok(()),
            _ => Err(RelayDecodeError::TruncatedRecord),
        }
    }
}

struct ParsedFixed {
    kind: u8,
    hop: u8,
    metadata_len: usize,
    payload_len: usize,
}

fn parse_fixed(header: &[u8]) -> Result<ParsedFixed, RelayDecodeError> {
    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if magic != RELAY_MAGIC {
        return Err(RelayDecodeError::BadMagic);
    }
    if header[4] != RELAY_PROTOCOL_VERSION {
        return Err(RelayDecodeError::BadVersion);
    }
    let kind = header[5];
    if !(KIND_HELLO..=KIND_ACK).contains(&kind) {
        return Err(RelayDecodeError::BadKind);
    }
    let flags = header[6];
    let hop = header[7];
    // v1:flags 恒 0;hop 只允许 data=1、hello/ack=0(一跳规则,§25.2.6)。
    if flags != 0 {
        return Err(RelayDecodeError::BadFlags);
    }
    let expected_hop = if kind == KIND_DATA { 1 } else { 0 };
    if hop != expected_hop {
        return Err(RelayDecodeError::BadFlags);
    }
    let record_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let metadata_len =
        u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
    let payload_len = u32::from_be_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if metadata_len > RELAY_MAX_METADATA_BYTES
        || payload_len > RELAY_MAX_PAYLOAD_BYTES
        || record_len != RELAY_FIXED_BYTES + metadata_len + payload_len
    {
        return Err(RelayDecodeError::BadLength);
    }
    // payload 只属于 data。
    if kind != KIND_DATA && payload_len != 0 {
        return Err(RelayDecodeError::BadLength);
    }
    Ok(ParsedFixed {
        kind,
        hop,
        metadata_len,
        payload_len,
    })
}

/// 解析 body(元数据 + payload);`body.len()` 已在固定头处校验等于两段之和。
fn parse_body(
    kind: u8,
    _hop: u8,
    metadata_len: usize,
    body: Bytes,
) -> Result<RelayFrame, RelayDecodeError> {
    let meta = &body[..metadata_len];
    let fields = parse_flat_fields(meta)?;
    match kind {
        KIND_HELLO => {
            let hello = RelayHello {
                protocol_version: fields.varint(1),
                cluster_id: fields.text(2)?,
                node_id: fields.text(3)?,
                boot_id: fields.varint(4),
                capabilities: fields.varint(5),
                config_fingerprint: fields.varint(6),
            };
            if hello.protocol_version != u64::from(RELAY_PROTOCOL_VERSION)
                || hello.cluster_id.is_empty()
                || hello.node_id.is_empty()
                || hello.boot_id == 0
            {
                return Err(RelayDecodeError::BadMetadata);
            }
            Ok(RelayFrame::Hello(hello))
        }
        KIND_DATA => {
            let seq = fields.varint(1);
            let action = match fields.varint(2) {
                1 => RelayAction::Publish,
                2 => RelayAction::Push,
                _ => return Err(RelayDecodeError::BadMetadata),
            };
            let tenant = fields.text(3)?;
            let scope = fields.text(4)?;
            if seq == 0 || tenant.is_empty() || scope.is_empty() {
                return Err(RelayDecodeError::BadMetadata);
            }
            Ok(RelayFrame::Data(RelayData {
                seq,
                action,
                tenant,
                scope,
                // payload 是 body 的尾部子 slice:快路径下与网络 chunk 共享存储。
                payload: body.slice(metadata_len..),
            }))
        }
        KIND_ACK => {
            let seq = fields.varint(1);
            let outcome = match fields.varint(2) {
                1 => RelayAckOutcome::Accepted,
                2 => RelayAckOutcome::RejectedOverload,
                3 => RelayAckOutcome::RejectedInvalid,
                _ => return Err(RelayDecodeError::BadMetadata),
            };
            if seq == 0 {
                return Err(RelayDecodeError::BadMetadata);
            }
            Ok(RelayFrame::Ack(RelayAck {
                seq,
                outcome,
                copies: fields.varint(3),
            }))
        }
        _ => Err(RelayDecodeError::BadKind),
    }
}

/// 平坦字段表:v1 只用 tag 1..=8,数组直存;未知字段按 wire type 跳过(前向兼容)。
struct FlatFields {
    varints: [u64; 8],
    texts: [Option<(usize, usize)>; 8],
}

struct FlatFieldsView<'m> {
    fields: FlatFields,
    meta: &'m [u8],
}

impl FlatFieldsView<'_> {
    fn varint(&self, tag: usize) -> u64 {
        self.fields.varints[tag - 1]
    }

    fn text(&self, tag: usize) -> Result<Box<str>, RelayDecodeError> {
        let Some((start, end)) = self.fields.texts[tag - 1] else {
            return Ok(Box::from(""));
        };
        std::str::from_utf8(&self.meta[start..end])
            .map(Box::from)
            .map_err(|_| RelayDecodeError::BadMetadata)
    }
}

fn parse_flat_fields(meta: &[u8]) -> Result<FlatFieldsView<'_>, RelayDecodeError> {
    let mut fields = FlatFields {
        varints: [0; 8],
        texts: [None; 8],
    };
    let mut pos = 0usize;
    while pos < meta.len() {
        let key = read_varint(meta, &mut pos)?;
        let tag = (key >> 3) as usize;
        match key & 7 {
            0 => {
                let value = read_varint(meta, &mut pos)?;
                if (1..=8).contains(&tag) {
                    fields.varints[tag - 1] = value;
                }
            }
            2 => {
                let len = read_varint(meta, &mut pos)? as usize;
                let end = pos.checked_add(len).ok_or(RelayDecodeError::BadMetadata)?;
                if end > meta.len() {
                    return Err(RelayDecodeError::BadMetadata);
                }
                if (1..=8).contains(&tag) {
                    fields.texts[tag - 1] = Some((pos, end));
                }
                pos = end;
            }
            // v1 元数据只产生 varint/len-delimited;其余 wire type 一律拒绝。
            _ => return Err(RelayDecodeError::BadMetadata),
        }
    }
    Ok(FlatFieldsView { fields, meta })
}

fn read_varint(meta: &[u8], pos: &mut usize) -> Result<u64, RelayDecodeError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *meta.get(*pos).ok_or(RelayDecodeError::BadMetadata)?;
        *pos += 1;
        if shift >= 64 {
            return Err(RelayDecodeError::BadMetadata);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// relay 关键配置指纹(FNV-1a 64):两边不一致即握手拒绝,防队列/顺序语义静默劈叉。
/// 覆盖 cluster_id 与中继语义参数;peers 列表不参与(成员滚动不应硬分裂)。
///
/// `fanout_limits` 同样**刻意不参与**:它是本节点的容量预算,不是两端必须一致的
/// wire/语义契约。不同规格的节点本来就该有不同预算,收方按自己的预算准入、超出部分
/// 经 summary 的 dropped_budget 如实回报,不会造成语义分歧;若纳入指纹,给单个节点
/// 扩容就会把 mesh 裂开,与"成员滚动不应硬分裂"是同一条理由。
pub fn config_fingerprint(plan: &crate::grpc_edge::GrpcEdgeClusterPlan) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    eat(plan.cluster_id.as_bytes());
    eat(&[RELAY_PROTOCOL_VERSION]);
    eat(&(plan.relay_queue_max_messages as u64).to_be_bytes());
    eat(&(plan.relay_queue_max_bytes as u64).to_be_bytes());
    eat(&[plan.relay_overflow as u8]);
    eat(&plan.ack_deadline_ms.to_be_bytes());
    eat(&[plan.ordering as u8, plan.session_mode as u8]);
    hash
}

/// 供握手构造的本端 hello。
pub fn local_hello(plan: &crate::grpc_edge::GrpcEdgeClusterPlan, boot_id: u64) -> RelayHello {
    RelayHello {
        protocol_version: u64::from(RELAY_PROTOCOL_VERSION),
        cluster_id: plan.cluster_id.clone(),
        node_id: plan.node_id.clone(),
        boot_id,
        capabilities: 0,
        config_fingerprint: config_fingerprint(plan),
    }
}

/// 供 `Arc<str>` 场景复用的小工具:tenant/scope 解码后转共享字符串。
pub fn shared(text: Box<str>) -> Arc<str> {
    Arc::from(text)
}

// ── 运行时:静态 peers 中继(§25.2.6) ──

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use http::header::HeaderValue;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::Instant as TokioInstant;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::edge_hub::EdgeHub;
use crate::grpc_edge::GrpcEdgeClusterPlan;

/// relay 固定路径(内部端点,不进业务路由表)。
pub const RELAY_HTTP_PATH: &str = "/naway.relay.v1/stream";
/// cluster_secret 模式的凭证头。
pub const RELAY_SECRET_HEADER: &str = "x-naway-relay-secret";
/// 握手读取预算:秒级足够,失败连接不占资源。
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
/// 拨号退避区间(不盲重试:指数退避,断线期间 enqueue 立即诚实失败)。
const DIAL_BACKOFF_MIN: Duration = Duration::from_millis(500);
const DIAL_BACKOFF_MAX: Duration = Duration::from_secs(10);
/// 被动侧低频重探间隔:同 addr 的对端可能重建换 node_id 使拨号方向翻转
/// (较小者变本端),低频重探自愈;错向重探由对端身份交换后礼貌关闭,代价极小。
const PASSIVE_REPROBE_INTERVAL: Duration = Duration::from_secs(60);
/// 出线 chunk 通道深度(head+payload 各一发;背压经 H2 流控传导)。
const OUTBOUND_CHANNEL_CHUNKS: usize = 64;

/// 单条 record 在单个 peer 上的最终结果(§25.2.6 回执口径,绝不叫 delivered)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRecordOutcome {
    /// peer 已接受进本地散出;copies = 其本地入队份数。
    Accepted {
        /// peer 本地入队份数。
        copies: u64,
    },
    /// 过载拒绝(本端 relay 队列 drop_new 或 peer 预算耗尽)。
    RejectedOverload,
    /// record 被 peer 判非法(语义冲突;不断本端流程)。
    RejectedInvalid,
    /// deadline 内无回执;不自动重试,诚实上报(§25.2.6)。
    Unknown,
    /// peer 断线/不可达。
    Down,
}

/// 一次广播在全部 peers 上的聚合(unary 直接进 summary;stream 逐消息累加)。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerBroadcastSummary {
    /// 配置的 peer 总数(静态成员表)。
    pub peers_total: u32,
    /// ack=accepted 的 peer 数。
    pub peers_accepted: u32,
    /// 全部 accepted peer 的本地入队份数之和。
    pub accepted_copies: u64,
    /// 过载/非法拒绝的 peer 数(含本端队列 drop)。
    pub peers_rejected: u32,
    /// 断线或 deadline 内无回执的 peer 数。
    pub peers_unknown: u32,
}

/// /metrics 渲染快照(低基数,无 per-peer label,§25.2.6)。
#[derive(Clone, Copy, Debug, Default)]
pub struct RelayMetricsSnapshot {
    /// 当前已握手存活的 peer 连接数。
    pub connected_peers: usize,
    /// 全部 peer 队列滞留 record 数。
    pub queued_records: usize,
    /// 已写上 wire 的 data record 总数。
    pub sent_total: u64,
    /// 明确失败份数(peer down / 过载拒绝 / 非法拒绝)。
    pub failed_total: u64,
    /// deadline 内无回执份数。
    pub unknown_total: u64,
    /// 水位线去重丢弃份数。
    pub dedup_total: u64,
    /// broadcast-probe 全体未命中次数(§25.2.7;目标不在线不是错误,但要可观测)。
    pub probe_miss_total: u64,
}

/// mpsc 支撑的流式 body:请求(拨号侧)与响应(受话侧)共用;sender 落地即 EOS。
struct RelayBody {
    rx: mpsc::Receiver<Bytes>,
}

impl Body for RelayBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.rx
            .poll_recv(cx)
            .map(|next| next.map(|chunk| Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// 队列元素:head 自有、payload 共享引用;ack_tx 由 sweep/回执/teardown 恰好消费一次。
struct QueuedRecord {
    seq: u64,
    head: Bytes,
    payload: Bytes,
    ack_tx: oneshot::Sender<PeerRecordOutcome>,
}

/// 在途等待回执的 record。
struct PendingAck {
    deadline: TokioInstant,
    record_len: usize,
    ack_tx: oneshot::Sender<PeerRecordOutcome>,
}

struct RelayInFlight {
    entries: HashMap<u64, PendingAck>,
    bytes: usize,
}

struct RelayQueue {
    items: VecDeque<QueuedRecord>,
    bytes: usize,
}

/// 一条已握手的 peer 链路(唯一双向 stream 的本端句柄)。
struct PeerLink {
    node_id: Box<str>,
    peer_boot_id: u64,
    generation: u64,
    outbound: mpsc::Sender<Bytes>,
    queue: Mutex<RelayQueue>,
    queue_notify: Notify,
    in_flight: Mutex<RelayInFlight>,
    closed: AtomicBool,
    closed_notify: Notify,
}

impl PeerLink {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.closed_notify.notify_waiters();
            self.queue_notify.notify_waiters();
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn take_pending(&self, seq: u64) -> Option<PendingAck> {
        let mut in_flight = self.in_flight.lock();
        let pending = in_flight.entries.remove(&seq)?;
        in_flight.bytes -= pending.record_len;
        Some(pending)
    }
}

/// 去重水位线:按 (node_id → boot_id, last_seq) 维护,boot 换代即重置;
/// 条目数被成员上限钉死(≤ full_mesh_max_nodes),天然有界。
struct Watermark {
    boot_id: u64,
    last_seq: u64,
}

/// 静态 peers 中继运行时。进程一份,持有与数据面相同的 [`EdgeHub`];
/// 接收侧只做本地散出(hop=1),结构上不存在二次 relay 路径。
pub struct EdgeRelay {
    plan: Arc<GrpcEdgeClusterPlan>,
    hub: Arc<EdgeHub>,
    boot_id: u64,
    fingerprint: u64,
    next_seq: AtomicU64,
    dial_generation: AtomicU64,
    desired_peers: Mutex<HashSet<SocketAddr>>,
    /// 期望成员 node_id 集(Nacos 提供;static 无从得知 = None,不做成员级执行)。
    /// Some 时:握手校验成员资格、reconcile 定向关停出集链路并回收其水位线。
    desired_nodes: Mutex<Option<HashSet<Box<str>>>>,
    dial_tasks: Mutex<HashMap<SocketAddr, tokio::task::JoinHandle<()>>>,
    membership_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    peer_count: AtomicUsize,
    links: Mutex<HashMap<Box<str>, Arc<PeerLink>>>,
    watermarks: Mutex<HashMap<Box<str>, Watermark>>,
    connected_peers: AtomicUsize,
    queued_records: AtomicUsize,
    sent_total: AtomicU64,
    failed_total: AtomicU64,
    unknown_total: AtomicU64,
    dedup_total: AtomicU64,
    /// V8-4 broadcast-probe 全体未命中计数(本地 + 全部 peers 入队皆 0)。
    probe_miss_total: AtomicU64,
}

impl EdgeRelay {
    /// 绑定 relay listener、为每个静态 peer 启动拨号任务,返回运行时句柄。
    ///
    /// bind 失败即启动失败(relay 是发布阻塞面,静默降级会把集群裂成孤岛)。
    pub async fn start(
        plan: Arc<GrpcEdgeClusterPlan>,
        hub: Arc<EdgeHub>,
    ) -> anyhow::Result<Arc<Self>> {
        let listener = TcpListener::bind(plan.relay_listen)
            .await
            .map_err(|error| {
                anyhow::anyhow!("bind relay listener {}: {error}", plan.relay_listen)
            })?;
        let fingerprint = config_fingerprint(&plan);
        let relay = Arc::new(Self {
            boot_id: random_boot_id(),
            fingerprint,
            next_seq: AtomicU64::new(1),
            dial_generation: AtomicU64::new(1),
            desired_peers: Mutex::new(HashSet::new()),
            desired_nodes: Mutex::new(None),
            dial_tasks: Mutex::new(HashMap::new()),
            membership_task: Mutex::new(None),
            peer_count: AtomicUsize::new(0),
            links: Mutex::new(HashMap::new()),
            watermarks: Mutex::new(HashMap::new()),
            connected_peers: AtomicUsize::new(0),
            queued_records: AtomicUsize::new(0),
            sent_total: AtomicU64::new(0),
            failed_total: AtomicU64::new(0),
            unknown_total: AtomicU64::new(0),
            dedup_total: AtomicU64::new(0),
            probe_miss_total: AtomicU64::new(0),
            plan,
            hub,
        });
        tokio::spawn(accept_loop(relay.clone(), listener));
        relay.reconcile_peers(relay.plan.static_peers.clone())?;
        Ok(relay)
    }

    /// /metrics 快照。
    pub fn metrics(&self) -> RelayMetricsSnapshot {
        RelayMetricsSnapshot {
            connected_peers: self.connected_peers.load(Ordering::Relaxed),
            queued_records: self.queued_records.load(Ordering::Relaxed),
            sent_total: self.sent_total.load(Ordering::Relaxed),
            failed_total: self.failed_total.load(Ordering::Relaxed),
            unknown_total: self.unknown_total.load(Ordering::Relaxed),
            dedup_total: self.dedup_total.load(Ordering::Relaxed),
            probe_miss_total: self.probe_miss_total.load(Ordering::Relaxed),
        }
    }

    /// 记一次 broadcast-probe 全体未命中(调用方在本地+peer 聚合都为 0 时判定)。
    pub fn note_probe_miss(&self) {
        self.probe_miss_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 本进程 relay boot 身份(V8-7 目录 field 用它区分重启代际)。
    pub fn boot_id(&self) -> u64 {
        self.boot_id
    }

    /// ingress 聚合 deadline(ms → Duration)。
    pub fn ack_deadline(&self) -> Duration {
        Duration::from_millis(self.plan.ack_deadline_ms)
    }

    /// 原子对账期望 peer 地址集合，并为新增地址启动唯一拨号任务(static 入口,
    /// 无 node_id 情报,成员级执行关闭)。
    pub fn reconcile_peers(self: &Arc<Self>, peers: Vec<SocketAddr>) -> anyhow::Result<()> {
        self.reconcile_membership(peers, None)
    }

    /// 原子对账期望成员:地址集驱动拨号任务,node_id 集(若有)驱动成员级执行——
    /// 握手拒绝出集节点、定向关停其存量链路、回收其去重水位线(防长期换代把
    /// 有界水位表填满后将新成员永久拒为 RejectedInvalid)。
    ///
    /// 调用方只能提交已经过 Nacos metadata 校验的数据;本方法仍执行 self、去重和
    /// full-mesh 上限的最后防线。
    fn reconcile_membership(
        self: &Arc<Self>,
        peers: Vec<SocketAddr>,
        nodes: Option<HashSet<Box<str>>>,
    ) -> anyhow::Result<()> {
        let mut desired = HashSet::with_capacity(peers.len());
        for peer in peers {
            anyhow::ensure!(
                peer != self.plan.relay_listen,
                "edge relay dynamic peers must not contain self address {}",
                self.plan.relay_listen
            );
            desired.insert(peer);
        }
        anyhow::ensure!(
            desired.len().saturating_add(1) <= self.plan.full_mesh_max_nodes,
            "edge relay dynamic peer count {} exceeds full_mesh_max_nodes={} including self",
            desired.len(),
            self.plan.full_mesh_max_nodes
        );

        let mut tasks = self.dial_tasks.lock();
        let removed = tasks
            .keys()
            .filter(|peer| !desired.contains(peer))
            .copied()
            .collect::<Vec<_>>();
        for peer in &removed {
            if let Some(task) = tasks.remove(peer) {
                task.abort();
            }
        }
        // 先落成员集再关链:入站握手在此之后即按新集合裁决,无窗口放行旧成员。
        let node_view = nodes.clone();
        *self.desired_nodes.lock() = nodes;
        match &node_view {
            Some(nodes) => {
                // 成员级定向执行:出集链路关停(含对端主动拨入的),水位线同步回收。
                for (node_id, link) in self.links.lock().iter() {
                    if !nodes.contains(node_id) {
                        link.close();
                    }
                }
                self.watermarks
                    .lock()
                    .retain(|node_id, _| nodes.contains(node_id));
            }
            None => {
                if !removed.is_empty() {
                    // WHY：static 模式没有 addr→node_id 映射,只能整体关链后由保留
                    // dial tasks 重连;static 成员表启动后基本不变,代价可接受。
                    for link in self.links.lock().values() {
                        link.close();
                    }
                }
            }
        }
        let added = desired
            .iter()
            .filter(|peer| !tasks.contains_key(peer))
            .copied()
            .collect::<Vec<_>>();
        for addr in added {
            let relay = self.clone();
            tasks.insert(
                addr,
                tokio::spawn(async move { dial_loop(relay, addr).await }),
            );
        }
        self.peer_count.store(desired.len(), Ordering::Release);
        *self.desired_peers.lock() = desired;
        Ok(())
    }

    /// 启动 V8-5 Nacos membership watch，并以 discovered gateway metadata 驱动 peer reconcile。
    pub fn start_nacos_membership(
        self: &Arc<Self>,
        cfg: crate::config::model::NacosDiscoveryCfg,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.plan.membership == crate::config::model::GrpcEdgeMembershipCfg::Nacos,
            "edge relay Nacos membership can only start when membership=nacos"
        );
        let service_name = crate::discovery::self_register_service_name(&cfg)
            .ok_or_else(|| anyhow::anyhow!(
                "grpc_edge_cluster.membership=nacos requires discovery.nacos.self_register.enabled=true and a service_name/app_name"
            ))?;
        let relay = self.clone();
        let task = tokio::spawn(async move {
            let backoff = Duration::from_millis(cfg.reconnect_backoff_ms.max(100));
            loop {
                if let Err(error) =
                    run_nacos_membership_once(relay.clone(), &cfg, &service_name).await
                {
                    tracing::warn!(
                        service = %service_name,
                        error = %error,
                        "edge relay Nacos membership watch failed; keeping last-known-good peers"
                    );
                }
                tokio::time::sleep(backoff).await;
            }
        });
        if let Some(previous) = self.membership_task.lock().replace(task) {
            previous.abort();
        }
        Ok(())
    }

    /// 向全部 peers 广播一条群播 record,在固定 deadline 内聚合回执(§25.2.6)。
    ///
    /// 返回 `'static` future:PublishStream 把它挂进 FuturesUnordered 异步聚合,
    /// 不阻塞逐消息散出。
    pub fn broadcast_publish(
        self: &Arc<Self>,
        tenant: Arc<str>,
        group: Arc<str>,
        payload: Bytes,
    ) -> impl Future<Output = PeerBroadcastSummary> + Send + 'static {
        self.broadcast(RelayAction::Publish, tenant, group, payload, None)
    }

    /// 向全部 peers 广播一条定向 Push record；无 Redis 指路条时这是 V8-4 的有界探测路径。
    pub fn broadcast_push(
        self: &Arc<Self>,
        tenant: Arc<str>,
        user: Arc<str>,
        payload: Bytes,
    ) -> impl Future<Output = PeerBroadcastSummary> + Send + 'static {
        self.broadcast(RelayAction::Push, tenant, user, payload, None)
    }

    /// V8-7:按指路条给出的节点集**定向** push,不打扰其余 peers。
    ///
    /// `targets` 只是加速提示:目录脏(节点已不在线/已迁移)时本次可能零投递,
    /// 调用方据此回落一次全量 broadcast-probe——正确性不依赖目录(§25.2.7)。
    /// 与本地节点重合的部分由调用方直接本地散出,不进这里。
    pub fn push_to_nodes(
        self: &Arc<Self>,
        tenant: Arc<str>,
        user: Arc<str>,
        payload: Bytes,
        targets: HashSet<Box<str>>,
    ) -> impl Future<Output = PeerBroadcastSummary> + Send + 'static {
        self.broadcast(RelayAction::Push, tenant, user, payload, Some(targets))
    }

    /// 广播一个 hop=1 record，并在固定 deadline 内聚合各 peer 的本地 enqueue-ack。
    fn broadcast(
        self: &Arc<Self>,
        action: RelayAction,
        tenant: Arc<str>,
        scope: Arc<str>,
        payload: Bytes,
        targets: Option<HashSet<Box<str>>>,
    ) -> impl Future<Output = PeerBroadcastSummary> + Send + 'static {
        let relay = self.clone();
        async move {
            let mut summary = PeerBroadcastSummary {
                // 定向模式的分母是"被寻址的 peer 数",不是全体成员——否则未被寻址的
                // 节点会被记成 down/unknown,把加速路径伪装成故障。
                peers_total: match &targets {
                    Some(targets) => targets.len() as u32,
                    None => relay.peer_count.load(Ordering::Acquire) as u32,
                },
                ..PeerBroadcastSummary::default()
            };
            let seq = relay.next_seq.fetch_add(1, Ordering::Relaxed);
            if seq == 0 {
                // event id 的 seq=0 在 wire 上非法；极端回绕时拒绝复用旧事件空间。
                summary.peers_rejected = summary.peers_total;
                relay
                    .failed_total
                    .fetch_add(u64::from(summary.peers_total), Ordering::Relaxed);
                return summary;
            }
            let encoded = encode_data(seq, action, &tenant, &scope, payload);
            let links: Vec<Arc<PeerLink>> = {
                let links = relay.links.lock();
                match &targets {
                    Some(targets) => links
                        .iter()
                        .filter(|(node_id, _)| targets.contains(*node_id))
                        .map(|(_, link)| link.clone())
                        .collect(),
                    None => links.values().cloned().collect(),
                }
            };
            // 已配置但当前无链路的 peer:断线不盲重试,立即按 FAIL 计(§25.2.6)。
            let down = (summary.peers_total as usize).saturating_sub(links.len()) as u32;
            summary.peers_unknown += down;
            relay
                .failed_total
                .fetch_add(u64::from(down), Ordering::Relaxed);
            let mut pending = FuturesUnordered::new();
            for link in links {
                match relay.enqueue(&link, seq, &encoded) {
                    Ok(rx) => pending.push(rx),
                    Err(outcome) => tally(&relay, &mut summary, outcome),
                }
            }
            // 固定 deadline 聚合;在此之外迟到的 ack 只更新指标语义(oneshot 被丢弃)。
            let deadline = TokioInstant::now() + relay.ack_deadline();
            loop {
                match tokio::time::timeout_at(deadline, pending.next()).await {
                    Ok(Some(received)) => {
                        let outcome = received.unwrap_or(PeerRecordOutcome::Unknown);
                        tally(&relay, &mut summary, outcome);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        // 剩余在途按 unknown 诚实计;链路侧 sweep 会做同样结算。
                        let rest = pending.len() as u32;
                        summary.peers_unknown += rest;
                        relay
                            .unknown_total
                            .fetch_add(u64::from(rest), Ordering::Relaxed);
                        break;
                    }
                }
            }
            summary
        }
    }

    /// 入队一条 record 到指定链路;满按策略处理,断线立即失败。
    fn enqueue(
        &self,
        link: &Arc<PeerLink>,
        seq: u64,
        encoded: &EncodedRelayData,
    ) -> Result<oneshot::Receiver<PeerRecordOutcome>, PeerRecordOutcome> {
        if link.is_closed() {
            return Err(PeerRecordOutcome::Down);
        }
        let record_len = encoded.total_len();
        let (ack_tx, ack_rx) = oneshot::channel();
        let mut queue = link.queue.lock();
        let in_flight = link.in_flight.lock();
        let over = |queue: &RelayQueue, in_flight: &RelayInFlight| {
            queue.items.len() + in_flight.entries.len() >= self.plan.relay_queue_max_messages
                || queue.bytes + in_flight.bytes + record_len > self.plan.relay_queue_max_bytes
        };
        if over(&queue, &in_flight) {
            match self.plan.relay_overflow {
                // drop_new(默认):拒新保旧 FIFO,诚实回过载。
                crate::config::model::GrpcEdgeOverflowCfg::DropNew
                | crate::config::model::GrpcEdgeOverflowCfg::CloseSlow => {
                    return Err(PeerRecordOutcome::RejectedOverload);
                }
                // 显式弹旧:被弹 record 立刻按过载结算,绝不静默消失。
                crate::config::model::GrpcEdgeOverflowCfg::DropOldest
                | crate::config::model::GrpcEdgeOverflowCfg::LatestByKey => {
                    while over(&queue, &in_flight) {
                        let Some(old) = queue.items.pop_front() else {
                            break;
                        };
                        queue.bytes -= old.head.len() + old.payload.len();
                        self.queued_records.fetch_sub(1, Ordering::Relaxed);
                        let _ = old.ack_tx.send(PeerRecordOutcome::RejectedOverload);
                    }
                    if over(&queue, &in_flight) {
                        return Err(PeerRecordOutcome::RejectedOverload);
                    }
                }
            }
        }
        queue.bytes += record_len;
        queue.items.push_back(QueuedRecord {
            seq,
            head: encoded.head.clone(),
            payload: encoded.payload.clone(),
            ack_tx,
        });
        drop(in_flight);
        drop(queue);
        self.queued_records.fetch_add(1, Ordering::Relaxed);
        link.queue_notify.notify_one();
        Ok(ack_rx)
    }

    /// 注册链路:同 node_id 已存在时,新 boot/更高 generation 原子替换旧连接
    /// (§25.2.6 连接去重),否则判定本次为陈旧连接拒绝。
    fn register_link(&self, link: Arc<PeerLink>) -> bool {
        let mut links = self.links.lock();
        if let Some(existing) = links.get(&link.node_id) {
            // boot_id 可比较且随进程启动单调生成；旧进程迟到的握手不得反向替换新连接。
            let newer = link.peer_boot_id > existing.peer_boot_id
                || (link.peer_boot_id == existing.peer_boot_id
                    && link.generation > existing.generation);
            if !newer {
                return false;
            }
            existing.close();
        } else {
            if links.len() >= self.plan.full_mesh_max_nodes.saturating_sub(1) {
                // cluster_secret 泄漏或错误节点不能把 links/watermarks 变成无界身份表。
                return false;
            }
            self.connected_peers.fetch_add(1, Ordering::Relaxed);
        }
        links.insert(link.node_id.clone(), link);
        true
    }

    /// 摘除链路(仅当注册表里仍是同一实例)并结算残余 record。
    fn teardown_link(&self, link: &Arc<PeerLink>) {
        link.close();
        {
            let mut links = self.links.lock();
            if links
                .get(&link.node_id)
                .is_some_and(|current| Arc::ptr_eq(current, link))
            {
                links.remove(&link.node_id);
                self.connected_peers.fetch_sub(1, Ordering::Relaxed);
            }
        }
        let drained: Vec<QueuedRecord> = {
            let mut queue = link.queue.lock();
            queue.bytes = 0;
            queue.items.drain(..).collect()
        };
        let queued = drained.len();
        if queued > 0 {
            self.queued_records.fetch_sub(queued, Ordering::Relaxed);
        }
        for record in drained {
            let _ = record.ack_tx.send(PeerRecordOutcome::Down);
        }
        let pending: Vec<PendingAck> = {
            let mut in_flight = link.in_flight.lock();
            in_flight.bytes = 0;
            in_flight
                .entries
                .drain()
                .map(|(_, pending)| pending)
                .collect()
        };
        for entry in pending {
            let _ = entry.ack_tx.send(PeerRecordOutcome::Unknown);
        }
    }

    /// 接收侧处理一条 data record:水位线去重 → 本地散出(hop=1,不再 relay)→ 回执。
    async fn handle_inbound_data(&self, link: &Arc<PeerLink>, data: RelayData, reassembled: u64) {
        if link.is_closed()
            || !self
                .links
                .lock()
                .get(&link.node_id)
                .is_some_and(|current| Arc::ptr_eq(current, link))
        {
            return;
        }
        let semantic_valid = valid_grpc_payload(&data.payload)
            && valid_runtime_id(&data.tenant, self.plan.fanout_limits.max_id_bytes)
            && valid_runtime_id(&data.scope, self.plan.fanout_limits.max_id_bytes);
        if !semantic_valid {
            let ack = RelayAck {
                seq: data.seq,
                outcome: RelayAckOutcome::RejectedInvalid,
                copies: 0,
            };
            if link.outbound.send(encode_ack(&ack)).await.is_err() {
                link.close();
            }
            return;
        }
        // 先分类、成功散出后才推进水位。过载失败若提前推进，调用方重试同一事件会被
        // 错误当成已处理并回 Accepted(copies=0)，形成不可观测黑洞。
        let (duplicate, watermark_full) = {
            let marks = self.watermarks.lock();
            if let Some(mark) = marks.get(&link.node_id) {
                (
                    mark.boot_id == link.peer_boot_id && data.seq <= mark.last_seq,
                    false,
                )
            } else if marks.len() >= self.plan.full_mesh_max_nodes.saturating_sub(1) {
                (false, true)
            } else {
                (false, false)
            }
        };
        if watermark_full {
            let ack = RelayAck {
                seq: data.seq,
                outcome: RelayAckOutcome::RejectedInvalid,
                copies: 0,
            };
            if link.outbound.send(encode_ack(&ack)).await.is_err() {
                link.close();
            }
            return;
        }
        let ack = if duplicate {
            self.dedup_total.fetch_add(1, Ordering::Relaxed);
            // 幂等成功:已处理过,copies=0(不重复散出,不承诺 exactly-once 之外的语义)。
            RelayAck {
                seq: data.seq,
                outcome: RelayAckOutcome::Accepted,
                copies: 0,
            }
        } else {
            let RelayData {
                seq,
                action,
                tenant,
                scope,
                payload,
            } = data;
            let outcome = match action {
                RelayAction::Publish => {
                    self.hub
                        .publish_group(
                            &self.plan.fanout_limits,
                            shared(tenant),
                            shared(scope),
                            payload,
                            reassembled,
                        )
                        .await
                }
                RelayAction::Push => {
                    self.hub
                        .push_user(
                            &self.plan.fanout_limits,
                            shared(tenant),
                            shared(scope),
                            payload,
                            reassembled,
                        )
                        .await
                }
            };
            match outcome {
                Ok(fanned) => {
                    self.watermarks.lock().insert(
                        link.node_id.clone(),
                        Watermark {
                            boot_id: link.peer_boot_id,
                            last_seq: seq,
                        },
                    );
                    RelayAck {
                        seq,
                        outcome: RelayAckOutcome::Accepted,
                        copies: u64::from(fanned.accepted),
                    }
                }
                Err(_budget) => RelayAck {
                    seq,
                    outcome: RelayAckOutcome::RejectedOverload,
                    copies: 0,
                },
            }
        };
        if link.outbound.send(encode_ack(&ack)).await.is_err() {
            link.close();
        }
    }
}

/// relay data 的 payload 必须恰好是一条 identity gRPC frame。业务 protobuf 保持
/// opaque，但错误长度/压缩位不能被转发给全部终端连接。
fn valid_grpc_payload(payload: &[u8]) -> bool {
    if payload.len() < 5 || payload[0] != 0 {
        return false;
    }
    let declared = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
    declared <= RELAY_MAX_PAYLOAD_BYTES - 5 && declared + 5 == payload.len()
}

fn valid_runtime_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn tally(relay: &EdgeRelay, summary: &mut PeerBroadcastSummary, outcome: PeerRecordOutcome) {
    match outcome {
        PeerRecordOutcome::Accepted { copies } => {
            summary.peers_accepted += 1;
            summary.accepted_copies += copies;
        }
        PeerRecordOutcome::RejectedOverload | PeerRecordOutcome::RejectedInvalid => {
            summary.peers_rejected += 1;
            relay.failed_total.fetch_add(1, Ordering::Relaxed);
        }
        PeerRecordOutcome::Unknown => {
            summary.peers_unknown += 1;
            relay.unknown_total.fetch_add(1, Ordering::Relaxed);
        }
        PeerRecordOutcome::Down => {
            summary.peers_unknown += 1;
            relay.failed_total.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// 可比较的进程 boot 身份。相同 node_id 的新进程必须能拒绝旧进程迟到握手，因此不能
/// 使用无序随机数；Unix 纳秒在同一节点重启序列中单调，非零且远未达到 u64 上限。
fn random_boot_id() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
        | 1
}

/// 常数时间比较(长度不同直接假;逐字节 XOR 折叠,不短路)。
fn secret_matches(expected: &str, presented: &[u8]) -> bool {
    let expected = expected.as_bytes();
    if expected.len() != presented.len() {
        return false;
    }
    let mut acc = 0u8;
    for (a, b) in expected.iter().zip(presented) {
        acc |= a ^ b;
    }
    acc == 0
}

// ── 链路任务 ──

/// 发送任务:排空队列写 wire,登记在途,定期 sweep 过期在途为 unknown。
async fn sender_task(relay: Arc<EdgeRelay>, link: Arc<PeerLink>) {
    let ack_deadline = relay.ack_deadline();
    let sweep_tick = (ack_deadline / 2).max(Duration::from_millis(10));
    loop {
        if link.is_closed() {
            return;
        }
        // 在途上限 = 队列消息上限:peer 长期不回执时止步,不无界积攒等待表。
        let next = {
            let mut queue = link.queue.lock();
            let mut in_flight = link.in_flight.lock();
            if in_flight.entries.len() >= relay.plan.relay_queue_max_messages {
                None
            } else {
                let item = queue.items.pop_front();
                if let Some(record) = &item {
                    queue.bytes -= record.head.len() + record.payload.len();
                }
                item.map(|record| {
                    let record_len = record.head.len() + record.payload.len();
                    in_flight.bytes += record_len;
                    in_flight.entries.insert(
                        record.seq,
                        PendingAck {
                            deadline: TokioInstant::now() + ack_deadline,
                            record_len,
                            ack_tx: record.ack_tx,
                        },
                    );
                    (record.head, record.payload)
                })
            }
        };
        match next {
            Some((head, payload)) => {
                relay.queued_records.fetch_sub(1, Ordering::Relaxed);
                // 两段按序写出即一条完整 record;通道断 = 连接死。
                if link.outbound.send(head).await.is_err()
                    || (!payload.is_empty() && link.outbound.send(payload).await.is_err())
                {
                    relay.teardown_link(&link);
                    return;
                }
                relay.sent_total.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                // queue_notify 走 notify_one(带 permit,无丢失);closed 靠循环顶检查
                // + sweep_tick 兜底,最坏滞后一个 tick。
                tokio::select! {
                    _ = link.queue_notify.notified() => {}
                    _ = link.closed_notify.notified() => {}
                    _ = tokio::time::sleep(sweep_tick) => {}
                }
            }
        }
        // sweep:map 尺寸被在途上限钉死,线性扫描代价可控(V8-6 基准后再谈精化)。
        let now = TokioInstant::now();
        let expired: Vec<PendingAck> = {
            let in_flight = link.in_flight.lock();
            let dead: Vec<u64> = in_flight
                .entries
                .iter()
                .filter(|(_, pending)| pending.deadline <= now)
                .map(|(seq, _)| *seq)
                .collect();
            drop(in_flight);
            dead.into_iter()
                .filter_map(|seq| link.take_pending(seq))
                .collect()
        };
        if !expired.is_empty() {
            for pending in expired {
                let _ = pending.ack_tx.send(PeerRecordOutcome::Unknown);
            }
        }
    }
}

/// 端点角色:决定握手方向校验与代际来源。
enum EndpointRole {
    /// 本端拨号(node_id 必须更小);generation 为本端拨号代际。
    Dialer {
        /// 拨号代际(borne 在 hello.capabilities 低位)。
        generation: u64,
        /// 握手结果单次回报给 dial_loop。
        outcome_tx: oneshot::Sender<DialOutcome>,
    },
    /// 本端受话(对端 node_id 必须更小)。
    Acceptor,
}

/// 拨号一次的结果(经 oneshot 回报;drop 即 Failed)。
enum DialOutcome {
    /// 已建链;dial_loop 挂链路关闭后再重拨。
    Linked(Arc<PeerLink>),
    /// 对端 node_id 更小,连接方向归对端,本端转被动。
    Passive,
}

/// 统一链路端点:握手与稳态共享同一 decoder/body——同 chunk 里紧跟 hello 的
/// record 不会丢;握手失败的每条路径都在登记之前返回(不占成员表)。
async fn run_endpoint(
    relay: Arc<EdgeRelay>,
    inbound: Incoming,
    out_tx: mpsc::Sender<Bytes>,
    role: EndpointRole,
) {
    let mut body = std::pin::pin!(inbound);
    let mut decoder = RelayRecordDecoder::new();
    let mut frames: Vec<RelayFrame> = Vec::new();
    // — 握手:deadline 内读到第一帧,必须是 hello —
    let hello = tokio::time::timeout(HANDSHAKE_DEADLINE, async {
        loop {
            let next = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await?;
            let mut chunk = next.ok()?.into_data().ok()?;
            if decoder.feed(&mut chunk, &mut frames).is_err() {
                return None;
            }
            if !frames.is_empty() {
                return Some(frames.remove(0));
            }
        }
    })
    .await;
    let Ok(Some(RelayFrame::Hello(hello))) = hello else {
        return;
    };
    // 受话侧此刻回本端 hello:身份交换先于方向裁决,错向拨号方据此转被动;
    // 拨号侧的 hello 在发起请求前已入 body 队列。
    if matches!(role, EndpointRole::Acceptor)
        && out_tx
            .send(encode_hello(&local_hello_with_generation(&relay, 0)))
            .await
            .is_err()
    {
        return;
    }
    if !hello_acceptable(&relay, &hello) {
        return;
    }
    // 成员级执行(Nacos 模式):不在期望成员集的节点即便持有效凭证/证书也拒绝——
    // 摘除成员必须双向失效,不能靠"它不再拨我"单向兜底。static 模式无 node 情报,跳过。
    if relay
        .desired_nodes
        .lock()
        .as_ref()
        .is_some_and(|nodes| !nodes.contains(&hello.node_id))
    {
        return;
    }
    let generation = match &role {
        EndpointRole::Dialer { generation, .. } => {
            if hello.node_id.as_ref() < relay.plan.node_id.as_ref() {
                // 对端更小:方向归它(它的受话侧也会拒我们,双保险)。
                if let EndpointRole::Dialer { outcome_tx, .. } = role {
                    let _ = outcome_tx.send(DialOutcome::Passive);
                }
                return;
            }
            *generation
        }
        EndpointRole::Acceptor => {
            // 唯一连接方向:较小 node_id 拨号(§25.2.6);错向即关(hello 已回)。
            if hello.node_id.as_ref() >= relay.plan.node_id.as_ref() {
                return;
            }
            // 对端拨号代际借道 capabilities 低位(v1 约定)。
            hello.capabilities
        }
    };
    let link = Arc::new(PeerLink {
        node_id: hello.node_id.clone(),
        peer_boot_id: hello.boot_id,
        generation,
        outbound: out_tx,
        queue: Mutex::new(RelayQueue {
            items: VecDeque::new(),
            bytes: 0,
        }),
        queue_notify: Notify::new(),
        in_flight: Mutex::new(RelayInFlight {
            entries: HashMap::new(),
            bytes: 0,
        }),
        closed: AtomicBool::new(false),
        closed_notify: Notify::new(),
    });
    if !relay.register_link(link.clone()) {
        // 同 node 已有更新连接:本次为陈旧拨号,静默退场。
        return;
    }
    if let EndpointRole::Dialer { outcome_tx, .. } = role {
        let _ = outcome_tx.send(DialOutcome::Linked(link.clone()));
    }
    tokio::spawn(sender_task(relay.clone(), link.clone()));

    // — 稳态:先消化握手 chunk 里已解出的余帧,再继续同一 decoder/body —
    let mut reported_reassembly = 0u64;
    'stream: loop {
        for frame in frames.drain(..) {
            match frame {
                RelayFrame::Data(data) => {
                    let total = decoder.reassembled_bytes();
                    let delta = total - reported_reassembly;
                    reported_reassembly = total;
                    relay.handle_inbound_data(&link, data, delta).await;
                }
                RelayFrame::Ack(ack) => {
                    let pending = link.take_pending(ack.seq);
                    if let Some(pending) = pending {
                        let outcome = match ack.outcome {
                            RelayAckOutcome::Accepted => {
                                PeerRecordOutcome::Accepted { copies: ack.copies }
                            }
                            RelayAckOutcome::RejectedOverload => {
                                PeerRecordOutcome::RejectedOverload
                            }
                            RelayAckOutcome::RejectedInvalid => PeerRecordOutcome::RejectedInvalid,
                        };
                        let _ = pending.ack_tx.send(outcome);
                    }
                }
                // 二次 hello = 协议错误,拆链。
                RelayFrame::Hello(_) => break 'stream,
            }
        }
        if link.is_closed() {
            break;
        }
        let next = tokio::select! {
            next = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)) => next,
            _ = link.closed_notify.notified() => break,
        };
        let Some(Ok(frame)) = next else {
            break;
        };
        // 对端不该发 trailers;协议不符即拆链。
        let Ok(mut chunk) = frame.into_data() else {
            break;
        };
        if decoder.feed(&mut chunk, &mut frames).is_err() {
            break;
        }
    }
    relay.teardown_link(&link);
}

/// 校验对端 hello 与本端配置一致(§25.2.6 成员身份;方向另判)。
fn hello_acceptable(relay: &EdgeRelay, hello: &RelayHello) -> bool {
    hello.cluster_id == relay.plan.cluster_id
        && hello.config_fingerprint == relay.fingerprint
        && hello.node_id != relay.plan.node_id
        && valid_node_id(&hello.node_id)
}

fn valid_node_id(node_id: &str) -> bool {
    !node_id.is_empty()
        && node_id.len() <= 128
        && node_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn local_hello_with_generation(relay: &EdgeRelay, generation: u64) -> RelayHello {
    let mut hello = local_hello(&relay.plan, relay.boot_id);
    hello.capabilities = generation;
    hello
}

/// 受话循环：先完成可选 mTLS，再由固定 HTTP/2 路径进入 relay 链路任务。
async fn accept_loop(relay: Arc<EdgeRelay>, listener: TcpListener) {
    if let Some(tls) = relay.plan.tls.clone() {
        crate::tls::spawn_edge_relay_tls_watcher(tls);
    }
    loop {
        let Ok((stream, _peer_addr)) = listener.accept().await else {
            // accept 错误多为瞬时资源问题;小睡防热轮询。
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let relay = relay.clone();
        tokio::spawn(async move {
            if let Some(tls) = &relay.plan.tls {
                let acceptor = TlsAcceptor::from(tls.server_config.load_full());
                let Ok(Ok(stream)) =
                    tokio::time::timeout(relay.plan.tls_handshake_timeout, acceptor.accept(stream))
                        .await
                else {
                    // WHY：TLS 慢握手必须在 relay task 内终止，避免攻击者耗尽连接与任务预算。
                    return;
                };
                serve_relay_transport(relay, stream).await;
            } else {
                serve_relay_transport(relay, stream).await;
            }
        });
    }
}

/// 在已完成安全握手的 transport 上服务一条 relay HTTP/2 连接。
async fn serve_relay_transport<I>(relay: Arc<EdgeRelay>, stream: I)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |request| {
        let relay = relay.clone();
        async move { serve_relay_request(relay, request).await }
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// 单个入站 relay 请求:鉴别 → 双向流建链(端点任务接管请求体)。
async fn serve_relay_request(
    relay: Arc<EdgeRelay>,
    request: http::Request<Incoming>,
) -> Result<http::Response<RelayBody>, std::convert::Infallible> {
    let reject = |status: u16| {
        let (_tx, rx) = mpsc::channel(1);
        Ok(http::Response::builder()
            .status(status)
            .body(RelayBody { rx })
            .expect("build relay reject response"))
    };
    if request.method() != http::Method::POST || request.uri().path() != RELAY_HTTP_PATH {
        return reject(404);
    }
    // 平面隔离：mTLS 已在 HTTP 之前完成节点鉴别；兼容模式仍只认 cluster_secret。
    if let Some(secret) = relay.plan.cluster_secret.as_deref() {
        let presented = request
            .headers()
            .get(RELAY_SECRET_HEADER)
            .map(HeaderValue::as_bytes)
            .unwrap_or_default();
        if !secret_matches(secret, presented) {
            return reject(403);
        }
    } else if relay.plan.tls.is_none() {
        // WHY：配置构建虽保证该状态不可达，仍在数据面 fail closed，防未来构造路径绕过。
        return reject(403);
    }
    let (out_tx, out_rx) = mpsc::channel::<Bytes>(OUTBOUND_CHANNEL_CHUNKS);
    let inbound = request.into_body();
    tokio::spawn(run_endpoint(relay, inbound, out_tx, EndpointRole::Acceptor));
    Ok(http::Response::builder()
        .status(200)
        .header(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/naway-relay"),
        )
        .body(RelayBody { rx: out_rx })
        .expect("build relay stream response"))
}

/// 拨号循环:指数退避;学到对端 node_id 更小即转被动(由对端拨入),任务退出。
async fn dial_loop(relay: Arc<EdgeRelay>, addr: SocketAddr) {
    let mut backoff = DIAL_BACKOFF_MIN;
    loop {
        match dial_once(&relay, addr).await {
            Some(DialOutcome::Passive) => {
                // 不退出:对端重建换 node_id 可翻转拨号方向,低频重探自愈;
                // 任务常驻也让 reconcile 的 dial_tasks 语义保持"每 addr 恰一个"。
                tokio::time::sleep(PASSIVE_REPROBE_INTERVAL).await;
                backoff = DIAL_BACKOFF_MIN;
                continue;
            }
            Some(DialOutcome::Linked(link)) => {
                backoff = DIAL_BACKOFF_MIN;
                // enable 先登记 waker 再查状态,封住 close 与等待之间的丢唤醒窗口。
                let notified = link.closed_notify.notified();
                let mut notified = std::pin::pin!(notified);
                notified.as_mut().enable();
                if !link.is_closed() {
                    notified.await;
                }
            }
            None => {}
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(DIAL_BACKOFF_MAX);
    }
}

/// 拨号一次:None = 失败退避;Some(Passive/Linked) 见 [`DialOutcome`]。
async fn dial_once(relay: &Arc<EdgeRelay>, addr: SocketAddr) -> Option<DialOutcome> {
    let stream = TcpStream::connect(addr).await.ok()?;
    if let Some(tls) = &relay.plan.tls {
        let connector = TlsConnector::from(tls.client_config.load_full());
        let stream = tokio::time::timeout(
            relay.plan.tls_handshake_timeout,
            connector.connect(tls.server_name.clone(), stream),
        )
        .await
        .ok()?
        .ok()?;
        dial_transport(relay, stream).await
    } else {
        dial_transport(relay, stream).await
    }
}

/// 在已完成可选 TLS 握手的 transport 上建立 relay HTTP/2 双向流。
async fn dial_transport<I>(relay: &Arc<EdgeRelay>, stream: I) -> Option<DialOutcome>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, RelayBody>(TokioIo::new(stream))
        .await
        .ok()?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let (out_tx, out_rx) = mpsc::channel::<Bytes>(OUTBOUND_CHANNEL_CHUNKS);
    let generation = relay.dial_generation.fetch_add(1, Ordering::Relaxed);
    // 先入队 hello 再发起请求:body 一旦被拉取,首帧即握手。
    out_tx
        .send(encode_hello(&local_hello_with_generation(
            relay, generation,
        )))
        .await
        .ok()?;
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(RELAY_HTTP_PATH)
        .header(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/naway-relay"),
        );
    if let Some(secret) = relay.plan.cluster_secret.as_deref() {
        request = request.header(RELAY_SECRET_HEADER, secret);
    }
    let request = request
        .body(RelayBody { rx: out_rx })
        .expect("build relay dial request");
    let response = sender.send_request(request).await.ok()?;
    if response.status() != 200 {
        return None;
    }
    let (outcome_tx, outcome_rx) = oneshot::channel();
    tokio::spawn(run_endpoint(
        relay.clone(),
        response.into_body(),
        out_tx,
        EndpointRole::Dialer {
            generation,
            outcome_tx,
        },
    ));
    // 握手预算 + 余量;端点任务任何早退路径都会 drop outcome_tx → 此处得 None。
    tokio::time::timeout(HANDSHAKE_DEADLINE + Duration::from_secs(1), outcome_rx)
        .await
        .ok()?
        .ok()
}

#[path = "../../tests/unit/edge_relay.rs"]
#[cfg(test)]
mod tests;

const EDGE_META_PROTOCOL: &str = "gateway.edge.protocol";
const EDGE_META_CLUSTER_ID: &str = "gateway.edge.cluster_id";
const EDGE_META_NODE_ID: &str = "gateway.edge.node_id";
const EDGE_META_RELAY_ADDR: &str = "gateway.edge.relay_addr";

/// 建立一次 Nacos gateway service watch，断开时由外层退避重连。
async fn run_nacos_membership_once(
    relay: Arc<EdgeRelay>,
    cfg: &crate::config::model::NacosDiscoveryCfg,
    service_name: &str,
) -> anyhow::Result<()> {
    let props = crate::discovery::nacos_props(cfg);
    let client = nasa::discovery::nacos::NacosDiscoveryClient::connect(&props).await?;
    let options = nasa::discovery::nacos::SubscribeOptions::new()
        .with_poll_interval(Duration::from_millis(cfg.poll_interval_ms.max(100)));
    let (_guard, mut rx) = client
        .subscribe_channel_with_options(service_name, options)
        .await?;
    apply_nacos_membership_snapshot(&relay, &rx.borrow());
    loop {
        rx.changed().await?;
        apply_nacos_membership_snapshot(&relay, &rx.borrow());
    }
}

/// 校验并应用一份 Nacos membership；坏快照保留 last-known-good peers。
fn apply_nacos_membership_snapshot(
    relay: &Arc<EdgeRelay>,
    instances: &[nasa::discovery::Instance],
) {
    match discovered_nacos_peers(&relay.plan, instances) {
        Ok((peers, nodes)) => {
            let count = peers.len();
            if let Err(error) = relay.reconcile_membership(peers, Some(nodes)) {
                tracing::warn!(error = %error, "edge relay Nacos peers rejected; keeping last-known-good peers");
            } else {
                tracing::info!(peers = count, "edge relay Nacos membership reconciled");
            }
        }
        Err(error) => tracing::warn!(
            error = %error,
            "edge relay Nacos membership snapshot invalid; keeping last-known-good peers"
        ),
    }
}

/// 从 gateway service instances 提取同 cluster 的 edge relay 地址。
fn discovered_nacos_peers(
    plan: &GrpcEdgeClusterPlan,
    instances: &[nasa::discovery::Instance],
) -> anyhow::Result<(Vec<SocketAddr>, HashSet<Box<str>>)> {
    let mut by_node = HashMap::<String, SocketAddr>::new();
    let mut addresses = HashSet::new();
    for instance in instances {
        if !instance.healthy || !instance.enabled {
            continue;
        }
        let metadata = &instance.metadata;
        if metadata.get(EDGE_META_PROTOCOL).map(String::as_str) != Some("1")
            || metadata.get(EDGE_META_CLUSTER_ID).map(String::as_str)
                != Some(plan.cluster_id.as_ref())
        {
            continue;
        }
        let Some(node_id) = metadata.get(EDGE_META_NODE_ID) else {
            continue;
        };
        anyhow::ensure!(
            valid_node_id(node_id),
            "Nacos edge instance contains invalid node_id"
        );
        if node_id == plan.node_id.as_ref() {
            continue;
        }
        let raw_addr = metadata
            .get(EDGE_META_RELAY_ADDR)
            .ok_or_else(|| anyhow::anyhow!("Nacos edge instance is missing relay_addr"))?;
        let addr: SocketAddr = raw_addr
            .parse()
            .map_err(|_| anyhow::anyhow!("Nacos edge instance has invalid relay_addr"))?;
        anyhow::ensure!(
            !addr.ip().is_unspecified() && addr.port() != 0,
            "Nacos edge instance relay_addr must be dialable"
        );
        if let Some(previous) = by_node.get(node_id) {
            anyhow::ensure!(
                *previous == addr,
                "Nacos edge membership contains one node_id with multiple relay addresses"
            );
            continue;
        }
        anyhow::ensure!(
            addresses.insert(addr),
            "Nacos edge membership contains multiple node_ids with one relay address"
        );
        by_node.insert(node_id.clone(), addr);
    }
    anyhow::ensure!(
        by_node.len().saturating_add(1) <= plan.full_mesh_max_nodes,
        "Nacos edge membership exceeds full_mesh_max_nodes"
    );
    let mut nodes = HashSet::with_capacity(by_node.len());
    let mut peers = Vec::with_capacity(by_node.len());
    for (node_id, addr) in by_node {
        nodes.insert(Box::from(node_id.as_str()));
        peers.push(addr);
    }
    peers.sort_unstable();
    Ok((peers, nodes))
}
