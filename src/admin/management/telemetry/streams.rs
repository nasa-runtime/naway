//! 监听器事实的网络边界；固定形状与身份共同进入完整性摘要。

use crate::admin::management::protocol;
use crate::observability::stream_traffic::{Reading, Snapshot, Totals};
use nasa::grpc::Status;
use sha2::{Digest, Sha256};

pub(super) const CHUNK: usize = 32;

/// 业务作用：把完整监听器清单纳入当前样本摘要，缺少能力时不改变旧摘要合同。
///
/// 参数说明：
/// - `hash`：已经写入原固定指标和其它协商域的摘要状态。
/// - `snapshot`：该目标获准接收的完整监听器事实。
///
/// 返回：存在时追加固定标记、长度与全部累计，不建立 JSON 或动态客户标签。
pub(super) fn digest(hash: &mut Sha256, snapshot: Option<&Snapshot>) {
    let Some(snapshot) = snapshot else {
        return;
    };
    hash.update(b"naway-stream-traffic\0");
    hash.update([u8::from(snapshot.capacity)]);
    hash.update((snapshot.rows.len() as u64).to_be_bytes());
    for row in &snapshot.rows {
        for value in [&row.listener, &row.protocol, &row.workspace] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        let totals = &row.totals;
        for value in [
            totals.attempts,
            totals.admitted,
            totals.active,
            totals.dropped_datagrams,
            totals.duration_micros,
        ]
        .iter()
        .chain(totals.outcomes.iter())
        .chain(totals.bytes.iter())
        .chain(totals.datagrams.iter())
        .chain(totals.buckets.iter())
        {
            hash.update(value.to_be_bytes());
        }
    }
}

/// 业务作用：只在网络发送边界编码单监听器行，不携带地址、正文或当前会话身份。
///
/// 参数说明：
/// - `row`：已验证身份和固定维度的本次累计行。
///
/// 返回：固定形状 Protobuf 消息，字符串复制只属于当前有界分片。
pub(super) fn encode(row: &Reading) -> protocol::StreamTraffic {
    protocol::StreamTraffic {
        listener: row.listener.clone(),
        protocol: row.protocol.clone(),
        workspace: row.workspace.clone(),
        attempts: row.totals.attempts,
        admitted: row.totals.admitted,
        active: row.totals.active,
        outcomes: row.totals.outcomes.to_vec(),
        bytes: row.totals.bytes.to_vec(),
        datagrams: row.totals.datagrams.to_vec(),
        dropped_datagrams: row.totals.dropped_datagrams,
        duration_micros: row.totals.duration_micros,
        buckets: row.totals.buckets.to_vec(),
    }
}

/// 业务作用：移动网络输入并严格还原固定数组，未知协议或额外维度不能成为当前监听器事实。
///
/// 参数说明：
/// - `row`：受传输消息字节上限保护的单行输入。
///
/// 返回：完整合法行；非法身份或数组长度拒绝整次上传，不截断后发布。
pub(super) fn decode(row: protocol::StreamTraffic) -> Result<Reading, Status> {
    if [&row.listener, &row.workspace]
        .into_iter()
        .any(|value| value.is_empty() || value.len() > 128 || value.chars().any(char::is_control))
        || !matches!(row.protocol.as_str(), "tcp" | "udp")
    {
        return Err(Status::invalid_argument("invalid stream identity"));
    }
    Ok(Reading {
        listener: row.listener,
        protocol: row.protocol,
        workspace: row.workspace,
        totals: Totals {
            attempts: row.attempts,
            admitted: row.admitted,
            active: row.active,
            outcomes: row
                .outcomes
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid stream outcomes"))?,
            bytes: row
                .bytes
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid stream byte directions"))?,
            datagrams: row
                .datagrams
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid stream datagram directions"))?,
            dropped_datagrams: row.dropped_datagrams,
            duration_micros: row.duration_micros,
            buckets: row
                .buckets
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid stream duration buckets"))?,
        },
    })
}
