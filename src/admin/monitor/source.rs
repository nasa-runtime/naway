//! 将管理面已持有的当前运行态映射为低敏采样，不获取业务内容或跨节点网络。

use super::{model, process, Runtime};
use crate::admin::AdminState;
use nametrics_core::{MetricSample, MetricValue};
use std::sync::atomic::Ordering;

/// 业务作用：冻结本机真实累计样本与同代配置摘要，所有浏览器共享该采样。
///
/// 参数说明：
/// - `state`：管理面与数据面共享的事实源。
/// - `runtime`：采样器的进程身份与单调时钟。
/// - `sample_id`：本次递增采样序号。
/// - `snapshot`：本轮事实、服务归属和采样配置的唯一冻结来源。
///
/// 返回：完整固定目录；没有的数据不根据配置阈值推算。
pub(super) fn sample(
    state: &AdminState,
    runtime: &Runtime,
    sample_id: u64,
    snapshot: &crate::config::GatewaySnapshot,
) -> model::Sample {
    let summary = snapshot.summary();
    let mut values = crate::observability::metrics::realtime::samples(&state.metrics);
    values.extend(process::samples());
    let connections = state.conn_registry.stats(snapshot.version);
    for (name, count) in [
        ("gw_long_connections_current", connections.current as u64),
        ("gw_long_connections_stale", connections.stale as u64),
    ] {
        values.push(MetricSample {
            name,
            labels: vec![],
            value: MetricValue::Gauge(count as f64),
        });
    }
    #[cfg(feature = "grpc-edge")]
    edge(state, &mut values);
    #[cfg(feature = "admin-grpc")]
    values.extend(crate::admin::management::metrics::samples(
        &state.management,
        snapshot,
    ));
    let (bounds_ms, buckets, sum_micros) =
        crate::observability::metrics::realtime::duration(&state.metrics);
    model::Sample {
        schema_version: 1,
        boot_id: runtime.boot_id.clone(),
        sample_id,
        sampled_at_ms: super::unix_millis(),
        elapsed_ms: runtime.elapsed_ms(),
        sampling_period_ms: snapshot.admin_monitor.period.as_millis() as u64,
        state: model::NodeState {
            mode: crate::admin::admin_mode_name(state.mode).into(),
            ready: state.ready.load(Ordering::Acquire),
            config_version: snapshot.version,
            config_fingerprint: snapshot
                .config_fingerprint
                .map(|value| format!("{value:016x}")),
            discovery_enabled: snapshot.discovery.enabled,
            configuration_enabled: snapshot.config_source.enabled,
            proxies: summary.proxies,
            routes: summary.routes,
            services: summary.upstream_services,
        },
        readings: model::readings(values),
        latency: model::Histogram {
            bounds_ms,
            buckets,
            sum_micros,
        },
        route_traffic: Some(crate::observability::http_stream::routes::capture(snapshot)),
        service_state: Some(crate::upstream::observation::capture(
            snapshot,
            &state.active_health.unhealthy_set(),
        )),
        capabilities: [
            ("core", true),
            ("sentinel_queue", true),
            ("circuit_state", true),
            ("local_bucket_state", true),
            ("management_grpc", cfg!(feature = "admin-grpc")),
            ("process_cpu", cfg!(unix)),
            (
                "process_rss",
                cfg!(any(target_os = "linux", target_os = "macos")),
            ),
            ("rate_preallocation", cfg!(feature = "rate-preallocation")),
            ("upstream_outlier", cfg!(feature = "upstream-outlier")),
            ("config_providers", cfg!(feature = "config-providers")),
            ("telemetry", cfg!(feature = "telemetry-otlp")),
            ("lua", cfg!(feature = "lua-scripts")),
            ("webdav", cfg!(feature = "webdav")),
            ("media", cfg!(feature = "media-streaming")),
            (
                "cgi",
                cfg!(any(
                    feature = "fastcgi",
                    feature = "uwsgi",
                    feature = "scgi"
                )),
            ),
            ("xds_server", cfg!(feature = "xds-server")),
            ("route_traffic", true),
            ("service_state", true),
            ("sentinel_state", false),
            ("http_bytes", true),
            ("stream_completion_latency", true),
            ("compression_savings", true),
            ("response_codec", true),
        ]
        .into_iter()
        .map(|(key, enabled)| (key.into(), enabled))
        .collect(),
    }
}

/// 业务作用：读取内部gRPC当前运行代的低基数状态，避免把公网RPC代理与内部relay混为一谈。
///
/// 参数说明：
/// - `state`：已挂接的共享运行态。
/// - `values`：当前采样的有限指标列表。
///
/// 返回：仅追加已启用功能的真实状态，不枚举租户、group或payload。
#[cfg(feature = "grpc-edge")]
fn edge(state: &AdminState, values: &mut Vec<MetricSample>) {
    if let Some(hub) = state.edge_hub.get() {
        for (name, current) in [
            ("gw_edge_active_streams", hub.active_streams() as f64),
            ("gw_edge_groups", hub.group_count() as f64),
            ("gw_edge_payload_bytes", hub.payload_bytes() as f64),
            ("gw_edge_queue_refs", hub.queue_refs() as f64),
        ] {
            values.push(MetricSample {
                name,
                labels: vec![],
                value: MetricValue::Gauge(current),
            });
        }
        let (published, rejected, dropped, reassembled) = hub.publish_counters();
        for (name, total) in [
            ("gw_edge_publish_total", published),
            ("gw_edge_publish_rejected_total", rejected),
            ("gw_edge_dropped_frames_total", dropped),
            ("gw_edge_reassembly_bytes_total", reassembled),
        ] {
            values.push(MetricSample {
                name,
                labels: vec![],
                value: MetricValue::Counter(total),
            });
        }
    }
    if let Some(relay) = state.edge_relay.get().and_then(|slot| slot.load_full()) {
        let snapshot = relay.metrics();
        for (name, current) in [
            (
                "gw_edge_relay_peers_connected",
                snapshot.connected_peers as f64,
            ),
            ("gw_edge_relay_queue_depth", snapshot.queued_records as f64),
            (
                "gw_edge_relay_interest_ready_peers",
                snapshot.interest_ready_peers as f64,
            ),
        ] {
            values.push(MetricSample {
                name,
                labels: vec![],
                value: MetricValue::Gauge(current),
            });
        }
        for (name, total) in [
            ("gw_edge_relay_sent_total", snapshot.sent_total),
            (
                "gw_edge_relay_interest_filtered_total",
                snapshot.interest_filtered_total,
            ),
            ("gw_edge_relay_failed_total", snapshot.failed_total),
            ("gw_edge_relay_unknown_total", snapshot.unknown_total),
            ("gw_edge_relay_dedup_total", snapshot.dedup_total),
        ] {
            values.push(MetricSample {
                name,
                labels: vec![],
                value: MetricValue::Counter(total),
            });
        }
    }
}
