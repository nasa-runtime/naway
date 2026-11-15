//! HTTP入口守卫事实的类型化传输，只向已确认接收能力的管理目标增加字段和摘要。

use crate::admin::management::protocol;
use crate::observability::ingress_protection::{Reading, Snapshot};
use nasa::grpc::Status;
use sha2::{Digest, Sha256};

pub(super) const CHUNK: usize = 32;

/// 业务作用：给已协商入口域的完整事实建立独立摘要，原有域和缺席能力的摘要保持不变。
///
/// 参数说明：
/// - `snapshot`：本目标获准接收的同代完整入口事实。
/// - `base`：已经覆盖目标其它协商域的原摘要。
///
/// 返回：存在时覆盖容量、顺序、全部身份和计数；缺席时逐字返回原摘要。
pub(super) fn digest(snapshot: Option<&Snapshot>, base: [u8; 32]) -> [u8; 32] {
    let Some(snapshot) = snapshot else {
        return base;
    };
    let mut hash = Sha256::new();
    hash.update(b"naway-ingress-protection\0");
    hash.update(base);
    hash.update([u8::from(snapshot.capacity)]);
    hash.update((snapshot.rows.len() as u64).to_be_bytes());
    for row in &snapshot.rows {
        for field in [&row.listener, &row.workspace] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        for value in row.rejections {
            hash.update(value.to_be_bytes());
        }
    }
    hash.finalize().into()
}

/// 业务作用：在旧域之后附加本目标已协商的入口分片，不增加旧目标的字段或传输工作。
///
/// 参数说明：
/// - `part`：按原有域构造、仍受总消息上限保护的分片。
/// - `snapshot`：同一采样中获准发送的完整入口事实。
/// - `offset`：所有事实域共用的连续偏移。
/// - `start`：当前目标实际发送的其它事实域行数之和。
///
/// 返回：首片补充完整清单，每片最多32入口，不续期原采样或改变其它域。
pub(super) fn add(
    part: &mut protocol::SampleRequest,
    snapshot: Option<&Snapshot>,
    offset: usize,
    start: usize,
) {
    let Some(snapshot) = snapshot else {
        return;
    };
    if let Some(header) = &mut part.header {
        header.ingress_capacity = Some(snapshot.capacity);
        header.ingress_total = snapshot.rows.len() as u32;
    }
    if offset >= start {
        let index = (offset - start).min(snapshot.rows.len());
        part.ingress = snapshot.rows[index..(index + CHUNK).min(snapshot.rows.len())]
            .iter()
            .map(|row| protocol::IngressProtection {
                listener: row.listener.clone(),
                workspace: row.workspace.clone(),
                rejections: row.rejections.to_vec(),
            })
            .collect();
    }
}

/// 业务作用：严格还原入口身份及固定两类裁决，恶意行不能进入共享采样。
///
/// 参数说明：
/// - `row`：受消息预算保护的单行网络输入。
///
/// 返回：身份和形状合法时移动为原生行；非法字段拒绝整个上传，不截断或补零。
pub(super) fn decode(row: protocol::IngressProtection) -> Result<Reading, Status> {
    if [&row.listener, &row.workspace]
        .into_iter()
        .any(|value| value.is_empty() || value.len() > 128 || value.chars().any(char::is_control))
    {
        return Err(Status::invalid_argument("invalid ingress identity"));
    }
    Ok(Reading {
        listener: row.listener,
        workspace: row.workspace,
        rejections: row
            .rejections
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid ingress rejection classes"))?,
    })
}
