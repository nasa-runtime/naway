//! 路由事实只在传输边界转换为Protobuf，固定数组和目录身份共同进入完整性摘要。

use crate::admin::management::protocol;
use crate::observability::http_stream::routes::{Reading, Snapshot, Totals};
use nasa::grpc::Status;
use sha2::{Digest, Sha256};

pub(super) const CHUNK: usize = 32;

/// 业务作用：把路由字段纳入当前样本的原生摘要，旧样本缺席时保留原协议摘要语义。
///
/// 参数说明：
/// - `hash`：已写入固定指标的样本摘要。
/// - `snapshot`：本次类型化路由目录，None代表旧节点未提供能力。
///
/// 返回：存在时追加有长度边界的全部身份与事实，不生成中间编码或拷贝正文。
pub(super) fn digest(hash: &mut Sha256, snapshot: Option<&Snapshot>) {
    let Some(snapshot) = snapshot else {
        return;
    };
    hash.update(b"naway-route-traffic\0");
    hash.update([u8::from(snapshot.capacity)]);
    hash.update((snapshot.rows.len() as u64).to_be_bytes());
    for row in &snapshot.rows {
        for value in [&row.proxy, &row.route, &row.workspace] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        let totals = &row.totals;
        for value in [
            totals.requests,
            totals.active,
            totals.bytes,
            totals.duration_micros,
        ]
        .iter()
        .chain(totals.responses.iter())
        .chain(totals.outcomes.iter())
        .chain(totals.buckets.iter())
        {
            hash.update(value.to_be_bytes());
        }
    }
}

/// 业务作用：在网络边界编码单路由的有限事实，身份只在本次分片构造时复制。
///
/// 参数说明：
/// - `row`：已经通过目录字段与顺序校验的累计行。
///
/// 返回：固定形状消息，不携带请求内容、地址或其它配置。
pub(super) fn encode(row: &Reading) -> protocol::RouteTraffic {
    protocol::RouteTraffic {
        proxy: row.proxy.clone(),
        route: row.route.clone(),
        workspace: row.workspace.clone(),
        requests: row.totals.requests,
        active: row.totals.active,
        responses: row.totals.responses.to_vec(),
        bytes: row.totals.bytes,
        outcomes: row.totals.outcomes.to_vec(),
        duration_micros: row.totals.duration_micros,
        buckets: row.totals.buckets.to_vec(),
        sentinel_rejections: Vec::new(),
    }
}

/// 业务作用：移动已接收身份并严格还原固定形状数组，未知维度不能进入路由样本。
///
/// 参数说明：
/// - `row`：受消息字节上限保护的路由输入。
///
/// 返回：合法有限行；任一字段或数组长度错误拒绝整次上传。
pub(super) fn decode(row: protocol::RouteTraffic) -> Result<Reading, Status> {
    if [&row.proxy, &row.route, &row.workspace]
        .into_iter()
        .any(|value| value.is_empty() || value.len() > 128 || value.chars().any(char::is_control))
    {
        return Err(Status::invalid_argument("invalid route identity"));
    }
    Ok(Reading {
        proxy: row.proxy,
        route: row.route,
        workspace: row.workspace,
        totals: Totals {
            requests: row.requests,
            active: row.active,
            responses: row
                .responses
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid response classes"))?,
            bytes: row.bytes,
            outcomes: row
                .outcomes
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid response outcomes"))?,
            duration_micros: row.duration_micros,
            buckets: row
                .buckets
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid route duration buckets"))?,
            sentinel_rejections: if row.sentinel_rejections.is_empty() {
                None
            } else {
                Some(row.sentinel_rejections.try_into().map_err(|_| {
                    Status::invalid_argument("invalid route Sentinel rejection classes")
                })?)
            },
        },
    })
}

/// 业务作用：为明确支持路由 Sentinel 的目标扩展原样本摘要，缺席的新域保持旧摘要逐字一致。
///
/// 参数说明：
/// - `snapshot`：同一当前样本的完整路由目录。
/// - `base`：按该目标既有服务与监听器能力计算的原摘要。
///
/// 返回：存在明确裁决时返回覆盖全部可选计数的域隔离摘要；全部缺席时返回原摘要。
pub(super) fn sentinel_digest(snapshot: Option<&Snapshot>, base: [u8; 32]) -> [u8; 32] {
    let Some(snapshot) = snapshot.filter(|value| {
        value
            .rows
            .iter()
            .any(|row| row.totals.sentinel_rejections.is_some())
    }) else {
        return base;
    };
    let mut hash = Sha256::new();
    hash.update(b"naway-route-sentinel\0");
    hash.update(base);
    hash.update((snapshot.rows.len() as u64).to_be_bytes());
    for row in &snapshot.rows {
        hash.update([u8::from(row.totals.sentinel_rejections.is_some())]);
        if let Some(counts) = row.totals.sentinel_rejections {
            for value in counts {
                hash.update(value.to_be_bytes());
            }
        }
    }
    hash.finalize().into()
}

/// 业务作用：只向本轮心跳确认新能力的目标发送裁决计数，不能让旧接收器遇到无法验证的摘要。
///
/// 参数说明：
/// - `part`：已经按原有域和固定行数构造的路由分片。
/// - `snapshot`：与分片及摘要绑定的原生路由目录。
///
/// 返回：按已排序的完整对象身份填入最多五个计数，不改变原字段、偏移或分片大小。
pub(super) fn add_sentinel(part: &mut protocol::SampleRequest, snapshot: Option<&Snapshot>) {
    let Some(snapshot) = snapshot else {
        return;
    };
    for row in &mut part.routes {
        if let Ok(index) = snapshot
            .rows
            .binary_search_by(|value| (&value.proxy, &value.route).cmp(&(&row.proxy, &row.route)))
        {
            if let Some(counts) = snapshot.rows[index].totals.sentinel_rejections {
                row.sentinel_rejections = counts.to_vec();
            }
        }
    }
}
