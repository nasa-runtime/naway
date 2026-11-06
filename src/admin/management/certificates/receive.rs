//! 只有完整有序目录才是可读事实；半份和矛盾重放不能表示证书不存在。

use super::{decode, protocol, CHUNK};
use crate::admin::certificates::{
    digest, targets_digest, valid_directory, Directory, Entry, MAX_BYTES, MAX_ENTRIES,
};
use nasa::grpc::Status;
use std::sync::Arc;

#[derive(Default)]
pub(in crate::admin::management) enum State {
    #[default]
    Empty,
    Partial(Partial),
    Complete(Arc<Directory>),
}

pub(in crate::admin::management) struct Partial {
    version: u64,
    fingerprint: Option<u64>,
    digest: [u8; 32],
    targets_digest: Option<[u8; 32]>,
    capacity: bool,
    total: usize,
    entries: Vec<Entry>,
    bytes: usize,
}

impl State {
    /// 业务作用：统一统计在途或已发布证书绑定的保留量，不能让分片绕过全接收槽限额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前所有者的已分配字节。
    pub(in crate::admin::management) fn bytes(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Partial(value) => value.bytes,
            Self::Complete(value) => value.bytes,
        }
    }

    /// 业务作用：只共享通过最终摘要验证的目录，保留半份不可见的不变量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整目录的Arc；未完成时无事实。
    pub(in crate::admin::management) fn complete(&self) -> Option<Arc<Directory>> {
        match self {
            Self::Complete(value) => Some(value.clone()),
            _ => None,
        }
    }

    /// 业务作用：在当前会话已复验的前提下有界装配证书绑定，重复ACK不追加或续期。
    ///
    /// 参数说明：
    /// - `request`：同一配置身份的有限分片。
    /// - `budget`：扣除其它节点后剩余的共享保留预算。
    ///
    /// 返回：确认偏移与完整标志；非法、乱序、矛盾或容量不足均拒绝。
    pub(in crate::admin::management) fn accept(
        &mut self,
        request: protocol::CertificatesRequest,
        budget: usize,
    ) -> Result<protocol::CatalogResponse, Status> {
        let total = request.total as usize;
        let offset = request.offset as usize;
        let expected: [u8; 32] = request
            .digest
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid certificate digest"))?;
        let targets: Option<[u8; 32]> = request
            .targets_digest
            .as_deref()
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| Status::invalid_argument("invalid certificate targets digest"))
            })
            .transpose()?;
        if total > MAX_ENTRIES
            || request.entries.len() > CHUNK
            || offset > total
            || request.entries.len() > total - offset
            || (total > 0 && request.entries.is_empty())
            || (request.capacity && total != 0)
        {
            return Err(Status::invalid_argument("invalid certificate bounds"));
        }
        let entries: Vec<_> = request
            .entries
            .into_iter()
            .map(decode)
            .collect::<Result<Vec<_>, _>>()?;
        if entries
            .iter()
            .any(|value| !value.valid() || (targets.is_none() && value.material_entry.is_some()))
            || entries
                .windows(2)
                .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(Status::invalid_argument("invalid certificate entries"));
        }
        if let Self::Complete(value) = self {
            if value.version != request.config_version
                || value.fingerprint != request.config_fingerprint
                || value.digest != expected
                || value.targets_digest != targets
                || value.capacity != request.capacity
                || value.entries.len() != total
                || value.entries.get(offset..offset + entries.len()) != Some(entries.as_slice())
            {
                // 已发布材料不能被另一份内容覆盖；只有当前会话的新摘要心跳才能撤销旧目录。
                return Err(Status::failed_precondition(
                    "certificate generation committed",
                ));
            }
            return Ok(protocol::CatalogResponse {
                next_offset: total as u32,
                complete: true,
            });
        }
        if matches!(self, Self::Empty) {
            if offset != 0 {
                return Err(Status::out_of_range("certificates must start at zero"));
            }
            let reserved = total * std::mem::size_of::<Entry>();
            if reserved > budget.min(MAX_BYTES) {
                return Err(Status::resource_exhausted("certificate memory exhausted"));
            }
            // 先保留结构体槽的总预算，再逐片累加文本，避免扩容逃逸容量门。
            *self = Self::Partial(Partial {
                version: request.config_version,
                fingerprint: request.config_fingerprint,
                digest: expected,
                targets_digest: targets,
                capacity: request.capacity,
                total,
                entries: Vec::with_capacity(total),
                bytes: reserved,
            });
        }
        let Self::Partial(partial) = self else {
            unreachable!("certificate state initialized");
        };
        if partial.version != request.config_version
            || partial.fingerprint != request.config_fingerprint
            || partial.digest != expected
            || partial.targets_digest != targets
            || partial.capacity != request.capacity
            || partial.total != total
        {
            return Err(Status::failed_precondition("certificate manifest changed"));
        }
        if offset < partial.entries.len() {
            if partial.entries.get(offset..offset + entries.len()) != Some(entries.as_slice()) {
                return Err(Status::failed_precondition("certificate replay changed"));
            }
            return Ok(protocol::CatalogResponse {
                next_offset: partial.entries.len() as u32,
                complete: false,
            });
        }
        if offset != partial.entries.len() {
            return Err(Status::out_of_range("certificate offset skipped"));
        }
        if partial
            .entries
            .last()
            .zip(entries.first())
            .is_some_and(|(a, b)| a.key() >= b.key())
        {
            return Err(Status::invalid_argument(
                "certificate identity repeated or unordered",
            ));
        }
        let added = entries
            .iter()
            .map(|entry| entry.bytes() - std::mem::size_of::<Entry>())
            .sum::<usize>();
        if added > budget.min(MAX_BYTES).saturating_sub(partial.bytes) {
            return Err(Status::resource_exhausted("certificate memory exhausted"));
        }
        partial.bytes += added;
        partial.entries.extend(entries);
        if partial.entries.len() < total {
            return Ok(protocol::CatalogResponse {
                next_offset: partial.entries.len() as u32,
                complete: false,
            });
        }
        if !valid_directory(&partial.entries)
            || digest(&partial.entries, partial.capacity) != expected
            || targets.is_some_and(|value| targets_digest(&expected, &partial.entries) != value)
        {
            // 完整内容不符时释放整份候选，摘要失败不能留下可读取的半成品。
            *self = Self::Empty;
            return Err(Status::data_loss("certificate digest mismatch"));
        }
        let Self::Partial(partial) = std::mem::take(self) else {
            unreachable!("verified certificate state");
        };
        *self = Self::Complete(Arc::new(Directory {
            version: partial.version,
            fingerprint: partial.fingerprint,
            digest: partial.digest,
            targets_digest: partial.targets_digest,
            capacity: partial.capacity,
            entries: partial.entries.into(),
            bytes: partial.bytes,
        }));
        Ok(protocol::CatalogResponse {
            next_offset: total as u32,
            complete: true,
        })
    }
}
