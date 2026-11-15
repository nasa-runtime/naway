//! 每个目标只发送一份当前样本，按传输背压逐片构造协议字段。

use super::{frame, frame_with_streams, Upload, CHUNK};
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
/// - `features`：同一次目标心跳确认的服务、监听器、路由 Sentinel 与HTTP入口接收能力。
///
/// 返回：只有完整样本ACK匹配才成功；失败由下一轮重新选择最新样本，不自动补发旧样本。
pub(in crate::admin::management) async fn upload(
    mut client: protocol::node_management_client::NodeManagementClient<Channel>,
    value: Arc<Upload>,
    node: String,
    session: Vec<u8>,
    deadline: tokio::time::Instant,
    features: (bool, bool, bool, bool),
) -> Result<(), Status> {
    let (service_supported, stream_supported, sentinel_supported, ingress_supported) = features;
    let sample_id = value.sample.sample_id;
    let series = value.sample.readings.len();
    let routes = value
        .sample
        .route_traffic
        .as_ref()
        .map_or(0, |value| value.rows.len());
    let services = value
        .sample
        .service_state
        .as_ref()
        .filter(|_| service_supported)
        .map_or(0, |value| value.rows.len());
    let streams = value
        .sample
        .stream_traffic
        .as_ref()
        .filter(|_| stream_supported)
        .map_or(0, |value| value.rows.len());
    let ingress = value
        .sample
        .ingress_protection
        .as_ref()
        .filter(|_| ingress_supported)
        .map_or(0, |value| value.rows.len());
    let offsets = (0..series)
        .step_by(CHUNK)
        .chain(
            (0..routes)
                .step_by(super::routes::CHUNK)
                .map(move |offset| series + offset),
        )
        .chain(
            (0..services)
                .step_by(super::services::CHUNK)
                .map(move |offset| series + routes + offset),
        )
        .chain(
            (0..streams)
                .step_by(super::streams::CHUNK)
                .map(move |offset| series + routes + services + offset),
        )
        .chain(
            (0..ingress)
                .step_by(super::ingress::CHUNK)
                .map(move |offset| series + routes + services + streams + offset),
        )
        .chain(
            (series == 0 && routes == 0 && services == 0 && streams == 0 && ingress == 0)
                .then_some(0),
        );
    let base = match (service_supported, stream_supported) {
        (true, true) => value.stream_digest,
        (false, true) => value.stream_legacy_digest,
        (true, false) => value.digest,
        (false, false) => value.legacy_digest,
    };
    // 新计数只在当前目标明确接收时进入字段和摘要，异构 Admin 仍复用同一采样所有者。
    let digest = if sentinel_supported {
        super::routes::sentinel_digest(value.sample.route_traffic.as_ref(), base)
    } else {
        base
    };
    let digest = super::ingress::digest(
        value
            .sample
            .ingress_protection
            .as_ref()
            .filter(|_| ingress_supported),
        digest,
    );
    let chunks = futures::stream::iter(offsets).map(move |offset| {
        // 每目标能力独立决定字段与摘要；旧 Admin 不接收无法验证的新监听器域。
        let encode = if stream_supported {
            frame_with_streams
        } else {
            frame
        };
        let mut part = encode(
            &value.sample,
            &node,
            &session,
            &digest,
            value.at,
            offset,
            service_supported,
        );
        if sentinel_supported {
            super::routes::add_sentinel(&mut part, value.sample.route_traffic.as_ref());
        }
        if ingress_supported {
            super::ingress::add(
                &mut part,
                value.sample.ingress_protection.as_ref(),
                offset,
                series + routes + services + streams,
            );
        }
        part
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
