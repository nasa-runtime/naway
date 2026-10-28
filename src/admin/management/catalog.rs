//! 目录分片使用既有节点会话，半个目录与旧配置都不能成为集群对象存在性证据。

use super::protocol;
use crate::admin::catalog::{
    digest, scope_digest, Catalog, Entry, ScopeAuthority, MAX_BYTES, MAX_OBJECTS,
};
use nasa::grpc::Status;
use std::sync::Arc;

pub(super) const CHUNK: usize = 32;
pub(super) const STORE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub(super) enum State {
    #[default]
    Empty,
    Partial(Partial),
    Complete(Arc<Catalog>),
}

pub(super) struct Partial {
    digest: [u8; 32],
    capacity: bool,
    scope_supported: bool,
    scope_digest: [u8; 32],
    scopes: Arc<[ScopeAuthority]>,
    total: usize,
    entries: Vec<Entry>,
    bytes: usize,
}

impl State {
    /// 业务作用：在接收槽之间统一核算目录内存，完整目录和在途目录不同时占有一份节点预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前槽已分配的对象和字符串字节。
    pub(super) fn bytes(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Partial(partial) => partial.bytes,
            Self::Complete(catalog) => catalog.bytes,
        }
    }

    /// 业务作用：只共享通过完整摘要验证的目录，调用方仍须复验节点会话和事实新鲜度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整目录的Arc引用，在途目录保持不可见。
    pub(super) fn complete(&self) -> Option<Arc<Catalog>> {
        match self {
            Self::Complete(catalog) => Some(catalog.clone()),
            _ => None,
        }
    }

    /// 业务作用：按精确偏移装配有界目录，相同分片可重复确认，错误摘要不能发布半完成集合。
    ///
    /// 参数说明：
    /// - `request`：已经通过会话、配置代和传输身份复验的分片。
    /// - `budget`：扣除其它节点后本槽可占有的总字节。
    ///
    /// 返回：下一偏移和完整状态；拒绝不得刷新节点心跳。
    pub(super) fn accept(
        &mut self,
        request: protocol::CatalogRequest,
        budget: usize,
    ) -> Result<protocol::CatalogResponse, Status> {
        let total = request.total as usize;
        let offset = request.offset as usize;
        let expected: [u8; 32] = request
            .digest
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid catalog digest"))?;
        if total > MAX_OBJECTS
            || request.entries.len() > CHUNK
            || offset > total
            || request.entries.len() > total - offset
            || (total > 0 && request.entries.is_empty())
            || (request.capacity && total != 0)
            || (request.scope_supported && offset == 0 && request.entries.len() > 1)
        {
            return Err(Status::invalid_argument("invalid catalog bounds"));
        }
        let authority_digest = if request.scope_supported {
            request
                .scope_digest
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid scope digest"))?
        } else {
            if !request.scope_digest.is_empty() || !request.scopes.is_empty() {
                return Err(Status::invalid_argument("unsupported scope manifest"));
            }
            [0; 32]
        };
        let scopes = decode_scopes(request.scopes)?;
        if (offset != 0 || request.capacity) && !scopes.is_empty() {
            return Err(Status::invalid_argument("unexpected scope entries"));
        }
        if request.scope_supported && offset == 0 && scope_digest(&scopes) != authority_digest {
            // 权限集合未经完整验证不得占据接收槽，更不能与后续对象发布混用。
            return Err(Status::data_loss("scope digest mismatch"));
        }
        let entries: Vec<Entry> = request.entries.into_iter().map(decode).collect();
        if entries.iter().any(|entry| !entry.valid())
            || entries
                .windows(2)
                .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(Status::invalid_argument("invalid catalog entries"));
        }
        if let Self::Complete(catalog) = self {
            if catalog.digest != expected
                || catalog.capacity != request.capacity
                || catalog.entries.len() != total
                || catalog.scope_supported != request.scope_supported
                || catalog.scope_digest != authority_digest
                || (offset == 0 && catalog.scopes.as_ref() != scopes.as_slice())
                || catalog.entries.get(offset..offset + entries.len()) != Some(entries.as_slice())
            {
                // 一个配置代只有一个目录身份，迟到或不同内容不能借相同版本覆盖已经发布的集合。
                return Err(Status::failed_precondition(
                    "catalog generation already committed",
                ));
            }
            return Ok(protocol::CatalogResponse {
                next_offset: total as u32,
                complete: true,
            });
        }
        if matches!(self, Self::Empty) {
            if offset != 0 {
                return Err(Status::out_of_range("catalog must start at zero"));
            }
            let reserved = total * std::mem::size_of::<Entry>()
                + scopes.iter().map(ScopeAuthority::bytes).sum::<usize>();
            if reserved > budget.min(MAX_BYTES) {
                return Err(Status::resource_exhausted("catalog memory exhausted"));
            }
            // 先验证整份结构体槽预算再分配，后续字符串逐片核算，避免Vec扩容超过受管内存。
            *self = Self::Partial(Partial {
                digest: expected,
                capacity: request.capacity,
                scope_supported: request.scope_supported,
                scope_digest: authority_digest,
                scopes: scopes.into(),
                total,
                entries: Vec::with_capacity(total),
                bytes: reserved,
            });
        } else if offset == 0
            && matches!(self, Self::Partial(partial) if partial.scopes.as_ref() != scopes.as_slice())
        {
            return Err(Status::failed_precondition("scope replay content changed"));
        }
        let Self::Partial(partial) = self else {
            unreachable!("catalog state was initialized");
        };
        if partial.digest != expected
            || partial.total != total
            || partial.capacity != request.capacity
            || partial.scope_supported != request.scope_supported
            || partial.scope_digest != authority_digest
        {
            return Err(Status::failed_precondition("catalog manifest changed"));
        }
        if offset < partial.entries.len() {
            if partial.entries.get(offset..offset + entries.len()) != Some(entries.as_slice()) {
                return Err(Status::failed_precondition(
                    "catalog replay content changed",
                ));
            }
            return Ok(protocol::CatalogResponse {
                next_offset: partial.entries.len() as u32,
                complete: false,
            });
        }
        if offset != partial.entries.len() {
            return Err(Status::out_of_range("catalog offset skipped"));
        }
        if partial
            .entries
            .last()
            .zip(entries.first())
            .is_some_and(|(left, right)| left.key() >= right.key())
        {
            return Err(Status::invalid_argument(
                "catalog identities must be unique and ordered",
            ));
        }
        let added = entries
            .iter()
            .map(|entry| entry.bytes() - std::mem::size_of::<Entry>())
            .sum::<usize>();
        if added > budget.min(MAX_BYTES).saturating_sub(partial.bytes) {
            return Err(Status::resource_exhausted("catalog memory exhausted"));
        }
        partial.bytes += added;
        partial.entries.extend(entries);
        if partial.entries.len() < total {
            return Ok(protocol::CatalogResponse {
                next_offset: partial.entries.len() as u32,
                complete: false,
            });
        }
        if digest(&partial.entries, request.capacity) != expected {
            // 完整内容不能证明声明摘要时释放整个在途集合，任何部分都不能进入管理读面。
            *self = Self::Empty;
            return Err(Status::data_loss("catalog digest mismatch"));
        }
        let Self::Partial(partial) = std::mem::take(self) else {
            unreachable!("verified catalog is partial");
        };
        *self = Self::Complete(Arc::new(Catalog {
            version: request.config_version,
            fingerprint: request.config_fingerprint,
            capacity: request.capacity,
            digest: expected,
            entries: partial.entries.into(),
            scope_supported: partial.scope_supported,
            scope_digest: partial.scope_digest,
            scopes: partial.scopes,
            bytes: partial.bytes,
        }));
        Ok(protocol::CatalogResponse {
            next_offset: total as u32,
            complete: true,
        })
    }
}

/// 业务作用：在保存远端权限证明前校验固定字段、排序唯一性和容量，不接受模糊工作区身份。
///
/// 参数说明：
/// - `scopes`：本次首片携带的类型化权限证明。
///
/// 返回：转移字符串所有权的完整有界集合；未知身份形态、超额或摘要长度错误均拒绝。
fn decode_scopes(scopes: Vec<protocol::ScopeAuthority>) -> Result<Vec<ScopeAuthority>, Status> {
    if scopes.len() > 128 {
        return Err(Status::invalid_argument("scope capacity exceeded"));
    }
    let mut result = Vec::<ScopeAuthority>::with_capacity(scopes.len());
    for scope in scopes {
        let value = ScopeAuthority {
            workspace: scope.workspace,
            digest: scope
                .digest
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid scope authority"))?,
        };
        if !value.valid()
            || result
                .last()
                .is_some_and(|previous| previous.workspace >= value.workspace)
        {
            return Err(Status::invalid_argument("invalid scope identities"));
        }
        result.push(value);
    }
    Ok(result)
}

/// 业务作用：把固定字段转移到接收槽，不保留消息对象或复制已解码字符串。
///
/// 参数说明：
/// - `entry`：传输层有界但尚待业务字段验证的条目。
///
/// 返回：所有字符串所有权已转移的目录条目。
fn decode(entry: protocol::CatalogEntry) -> Entry {
    Entry {
        kind: entry.kind,
        id: entry.id,
        parent: entry.parent,
        workspace: entry.workspace,
        tenant: entry.tenant,
        environment: entry.environment,
        service: entry.service,
        order: entry.order,
        flags: entry.flags,
    }
}

/// 业务作用：仅对正在发送的一片对象构造类型化消息，心跳和未变化目录不复制全量集合。
///
/// 参数说明：
/// - `entry`：当前不可变目录中的条目。
///
/// 返回：有界协议对象，不包含配置正文或动态实例。
pub(super) fn encode(entry: &Entry) -> protocol::CatalogEntry {
    protocol::CatalogEntry {
        kind: entry.kind.clone(),
        id: entry.id.clone(),
        parent: entry.parent.clone(),
        workspace: entry.workspace.clone(),
        tenant: entry.tenant.clone(),
        environment: entry.environment.clone(),
        service: entry.service.clone(),
        order: entry.order,
        flags: entry.flags,
    }
}
