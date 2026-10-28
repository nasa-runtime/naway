//! 管理通信使用受管监听的真实会计，固定方法与结局目录不包含远端身份或凭据。

use super::Manager;
use crate::config::GatewaySnapshot;
use nametrics_core::{MetricSample, MetricValue};
use nasa::grpc::{Code, GrpcRpcOutcome, GrpcRpcRejectionReason, GrpcServerState};

/// 业务作用：把当前管理监听的连接与RPC事实加入实时采样，不反解析文本指标或保存历史。
///
/// 参数说明：
/// - `manager`：唯一受管监听owner。
/// - `snapshot`：本轮采样的配置权威。
///
/// 返回：固定低基数指标；接收未配置或已撤销时仅声明关闭或不可观测，不填造连接事实。
pub(in crate::admin) fn samples(
    manager: &Manager,
    snapshot: &GatewaySnapshot,
) -> Vec<MetricSample> {
    let enabled = snapshot
        .admin_management
        .as_ref()
        .is_some_and(|plan| plan.receiver.is_some());
    let observer = manager.observer(snapshot);
    let mut values = vec![
        gauge("gw_management_receiver_enabled", f64::from(enabled)),
        gauge(
            "gw_management_receiver_observed",
            f64::from(observer.is_some()),
        ),
    ];
    let Some(observer) = observer else {
        return values;
    };
    let current = observer.snapshot();
    values.extend([
        gauge(
            "gw_management_active_connections",
            current.active_connections as f64,
        ),
        counter(
            "gw_management_connections_accepted_total",
            current.accepted_total,
        ),
        counter(
            "gw_management_accept_failures_total",
            current.accept_failures_total,
        ),
        gauge(
            "gw_management_consecutive_accept_failures",
            current.consecutive_accept_failures as f64,
        ),
        gauge(
            "gw_management_accept_stall_milliseconds",
            current.accept_stall_millis as f64,
        ),
    ]);
    for (label, state) in [
        ("bound", GrpcServerState::Bound),
        ("running", GrpcServerState::Running),
        ("draining", GrpcServerState::Draining),
        ("closed", GrpcServerState::Closed),
        ("failed", GrpcServerState::Failed),
    ] {
        let mut sample = gauge(
            "gw_management_receiver_state",
            f64::from(current.state == state),
        );
        sample.labels.push(("state", label.into()));
        values.push(sample);
    }
    for method in observer.rpc_snapshot().into_iter().filter(|method| {
        method.service == "naway.management.v1.NodeManagement"
            && matches!(
                method.method,
                "Open" | "AuthenticateIssuer" | "Report" | "Catalog" | "Sample"
            )
    }) {
        for mut sample in [
            gauge("gw_management_rpc_active", method.active as f64),
            counter("gw_management_rpc_started_total", method.started_total),
            counter("gw_management_rpc_rejected_total", method.rejected_total),
        ] {
            sample.labels.push(("method", method.method.into()));
            values.push(sample);
        }
        for reason in [
            GrpcRpcRejectionReason::ConnectionConcurrency,
            GrpcRpcRejectionReason::ProcessConcurrency,
            GrpcRpcRejectionReason::MethodConcurrency,
            GrpcRpcRejectionReason::MethodRate,
            GrpcRpcRejectionReason::PeerIdentity,
        ] {
            let total = method
                .rejections
                .iter()
                .find(|(key, _)| *key == reason)
                .map_or(0, |(_, count)| *count);
            values.push(MetricSample {
                name: "gw_management_rpc_rejections_total",
                labels: vec![
                    ("method", method.method.into()),
                    ("reason", reason.label().into()),
                ],
                value: MetricValue::Counter(total),
            });
        }
        for outcome in outcomes() {
            let total = method
                .outcomes
                .iter()
                .find(|(key, _)| key.label() == outcome.label())
                .map_or(0, |(_, count)| *count);
            values.push(MetricSample {
                name: "gw_management_rpc_completed_total",
                labels: vec![
                    ("method", method.method.into()),
                    ("outcome", outcome.label().into()),
                ],
                value: MetricValue::Counter(total),
            });
        }
    }
    values
}

/// 业务作用：构造无动态标签的瞬时事实，保持当前资源与累计事件类型分离。
///
/// 参数说明：
/// - `name`：编译期固定指标名。
/// - `current`：受管owner的实际状态或数量。
///
/// 返回：可直接并入NASA指标目录的瞬时样本。
fn gauge(name: &'static str, current: f64) -> MetricSample {
    MetricSample {
        name,
        labels: vec![],
        value: MetricValue::Gauge(current),
    }
}

/// 业务作用：保留监听生命周期内的原始累计事件，由观察方按有效相邻区间计算速率。
///
/// 参数说明：
/// - `name`：编译期固定指标名。
/// - `total`：受管owner的累计会计。
///
/// 返回：不增加第二份计数状态的NASA计数样本。
fn counter(name: &'static str, total: u64) -> MetricSample {
    MetricSample {
        name,
        labels: vec![],
        value: MetricValue::Counter(total),
    }
}

/// 业务作用：预声明所有协议与框架结局，使第一次拒绝也能相对前一份零值样本计算增量。
///
/// 参数说明: 无。
///
/// 返回：唯一固定结局目录，不包含status文本或未知方法。
fn outcomes() -> impl Iterator<Item = GrpcRpcOutcome> {
    [
        Code::Ok,
        Code::Cancelled,
        Code::Unknown,
        Code::InvalidArgument,
        Code::DeadlineExceeded,
        Code::NotFound,
        Code::AlreadyExists,
        Code::PermissionDenied,
        Code::ResourceExhausted,
        Code::FailedPrecondition,
        Code::Aborted,
        Code::OutOfRange,
        Code::Unimplemented,
        Code::Internal,
        Code::Unavailable,
        Code::DataLoss,
        Code::Unauthenticated,
    ]
    .into_iter()
    .map(GrpcRpcOutcome::Code)
    .chain([
        GrpcRpcOutcome::Cancelled,
        GrpcRpcOutcome::ClientDeadlineExceeded,
        GrpcRpcOutcome::ServerTimeout,
        GrpcRpcOutcome::ServerStreamDuration,
        GrpcRpcOutcome::ServerStreamIdle,
        GrpcRpcOutcome::StreamReceivedMessages,
        GrpcRpcOutcome::StreamSentMessages,
        GrpcRpcOutcome::StreamReceivedBytes,
        GrpcRpcOutcome::StreamSentBytes,
        GrpcRpcOutcome::TransportLost,
    ])
}
