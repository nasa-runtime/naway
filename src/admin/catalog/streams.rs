//! 监听器目录独立协商；原有对象摘要与旧目标的读取合同保持不变。

use super::model::{self, MAX_BYTES, MAX_OBJECTS};
use super::{Catalog, Entry};
use crate::config::{GatewaySnapshot, StreamProtocolRuntime};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone)]
pub(in crate::admin) struct StreamDirectory {
    pub capacity: bool,
    pub entries: Arc<[Entry]>,
}

/// 业务作用：在原目录余量内冻结完整 L4 清单，额外对象不能使原目录变成半份集合。
///
/// 参数说明：
/// - `snapshot`：与对象归属同代的完整配置。
/// - `base_objects`：原 HTTP 入口、路由与服务已经占用的对象数。
/// - `base_bytes`：原目录与权限证明的实际保留成本。
/// - `base_capacity`：原目录本身是否已经超限。
///
/// 返回：完整清单及额外保留字节；数量或字节余量不足只返回监听器 capacity，不截断。
pub(super) fn collect(
    snapshot: &GatewaySnapshot,
    base_objects: usize,
    base_bytes: usize,
    base_capacity: bool,
) -> (StreamDirectory, usize) {
    let count = snapshot.stream_listeners.len();
    let reserved = count.saturating_mul(std::mem::size_of::<Entry>());
    if base_capacity
        || count > crate::observability::stream_traffic::MAX_LISTENERS
        || count > MAX_OBJECTS.saturating_sub(base_objects)
        || reserved > MAX_BYTES.saturating_sub(base_bytes)
    {
        return (
            StreamDirectory {
                capacity: true,
                entries: Arc::from([]),
            },
            0,
        );
    }
    let mut entries = Vec::with_capacity(count);
    let mut bytes = reserved;
    for runtime in snapshot.stream_listeners.iter() {
        let mut entry = model::new_entry("stream_listener", &runtime.id, "", snapshot);
        entry.flags = u64::from(runtime.protocol == StreamProtocolRuntime::Udp);
        let next = bytes.saturating_add(entry.bytes() - std::mem::size_of::<Entry>());
        if !entry.valid() || next > MAX_BYTES.saturating_sub(base_bytes) {
            return (
                StreamDirectory {
                    capacity: true,
                    entries: Arc::from([]),
                },
                0,
            );
        }
        bytes = next;
        entries.push(entry);
    }
    entries.sort_unstable_by(|left, right| left.key().cmp(&right.key()));
    (
        StreamDirectory {
            capacity: false,
            entries: entries.into(),
        },
        bytes,
    )
}

impl Catalog {
    /// 业务作用：为明确支持监听器目录的目标组合扩展摘要，旧目标仍读取原对象摘要。
    ///
    /// 参数说明：
    /// - `include_streams`：本次目标心跳是否确认监听器目录与事实接收能力。
    ///
    /// 返回：选定协议范围的固定摘要；目录缺少该能力时保留原摘要语义。
    pub(in crate::admin) fn wire_digest(&self, include_streams: bool) -> [u8; 32] {
        let Some(streams) = self.streams.as_ref().filter(|_| include_streams) else {
            return self.digest;
        };
        let mut hash = Sha256::new();
        hash.update(b"naway-catalog-with-streams\0");
        hash.update(self.digest);
        hash.update(model::digest(&streams.entries, streams.capacity));
        hash.finalize().into()
    }
}
