//! 每个目标只发送一份当前样本，按传输背压逐片构造协议字段。

use super::{frame, Upload, CHUNK};
use crate::admin::management::{protocol, reporter};
use nasa::grpc::{Channel, Status};
use std::sync::Arc;

/// 业务作用：复用管理通道逐片发送当前累计事实，不为慢Admin保留采样历史。
///
/// 参数说明：
/// - `client`：当前目标的共享通道句柄。
/// - `value`：与本轮事实同代的共享样本。
/// - `node`：当前本机管理身份。
/// - `session`：刚被心跳确认的目标会话。
/// - `deadline`：心跳、目录与指标共用的绝对期限。
///
/// 返回：只有完整样本ACK匹配才成功；失败由下一轮重新选择最新样本，不自动补发旧样本。
pub(in crate::admin::management) async fn upload(
    mut client: protocol::node_management_client::NodeManagementClient<Channel>,
    value: Arc<Upload>,
    node: String,
    session: Vec<u8>,
    deadline: tokio::time::Instant,
) -> Result<(), Status> {
    let sample_id = value.sample.sample_id;
    let series = value.sample.readings.len();
    let routes = value
        .sample
        .route_traffic
        .as_ref()
        .map_or(0, |value| value.rows.len());
    let offsets = (0..series)
        .step_by(CHUNK)
        .chain(
            (0..routes)
                .step_by(super::routes::CHUNK)
                .map(move |offset| series + offset),
        )
        .chain((series == 0 && routes == 0).then_some(0));
    let chunks = futures::stream::iter(offsets).map(move |offset| {
        frame(
            &value.sample,
            &node,
            &session,
            &value.digest,
            value.at,
            offset,
        )
    });
    let response = client
        .sample(reporter::timed_request(chunks, deadline)?)
        .await?
        .into_inner();
    if response.accepted_sample_id != sample_id {
        return Err(Status::data_loss("sample acknowledgement mismatch"));
    }
    Ok(())
}

use futures::StreamExt;
