//! 当前材料身份由心跳授权；独立分片不能刷新节点年龄或恢复已撤销身份。

mod receive;
mod send;

pub(super) use receive::State;
pub(super) use send::Upload;

use super::protocol;
use crate::admin::certificates::Entry;
use crate::tls::material::CertificateLeaf;
use nasa::grpc::Status;
use std::sync::Arc;

pub(super) const STORE_BYTES: usize = 64 * 1024 * 1024;
const CHUNK: usize = 16;

/// 业务作用：把低敏协议字段移交目录所有者，固定摘要长度且不保留协议壳。
///
/// 参数说明：
/// - `value`：仍需通过状态、长度、排序和最终摘要验证的条目。
///
/// 返回：字段移交后的业务条目；非 SHA-256 长度拒绝，不复制 SAN 文本。
fn decode(value: protocol::CertificateEntry) -> Result<Entry, Status> {
    let leaf = value
        .leaf
        .map(|leaf| {
            let sha256 = leaf
                .sha256
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid certificate leaf digest"))?;
            Ok::<_, Status>(Arc::new(CertificateLeaf {
                sha256,
                not_before: leaf.not_before,
                not_after: leaf.not_after,
                names: leaf.names,
            }))
        })
        .transpose()?;
    Ok(Entry {
        listener: value.listener,
        protocol: value.protocol,
        binding: value.binding,
        selection_order: value.selection_order,
        state: value.state,
        source: value.source,
        leaf,
        ocsp_valid_until: value.ocsp_valid_until,
        ocsp_required: value.ocsp_required,
        workspace: value.workspace,
        tenant: value.tenant,
        environment: value.environment,
    })
}

/// 业务作用：只为当前有限分片复制公开字段，目录未变化时不重复编码完整集合。
///
/// 参数说明：
/// - `value`：当前已安装材料目录的一个条目。
///
/// 返回：不含证书材料、私钥、路径或内部会话凭据的消息。
fn encode(value: &Entry) -> protocol::CertificateEntry {
    protocol::CertificateEntry {
        listener: value.listener.clone(),
        protocol: value.protocol.clone(),
        binding: value.binding.clone(),
        selection_order: value.selection_order,
        state: value.state.clone(),
        source: value.source.clone(),
        leaf: value.leaf.as_ref().map(|leaf| protocol::CertificateLeaf {
            sha256: leaf.sha256.to_vec(),
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            names: leaf.names.clone(),
        }),
        ocsp_valid_until: value.ocsp_valid_until,
        ocsp_required: value.ocsp_required,
        workspace: value.workspace.clone(),
        tenant: value.tenant.clone(),
        environment: value.environment.clone(),
    }
}
