//! 管理实时采样的固定目录，直接读取原有事实，不复制业务实体或身份标签。

use super::{Metrics, REQUEST_DURATION_BUCKET_MS};
use nametrics_core::{MetricSample, MetricValue};
use std::sync::atomic::Ordering;

/// 业务作用：为实时监控读取固定核心与治理计数器，避免为每个浏览器另建记录器。
///
/// 参数说明：
/// - `metrics`：数据面共用的累计事实。
///
/// 返回：有界、无请求身份标签的结构化样本，未编译功能不生成假零样本。
pub(crate) fn samples(metrics: &Metrics) -> Vec<MetricSample> {
    let mut samples: Vec<_> = metrics
        .core_counters()
        .into_iter()
        .map(|(name, value)| MetricSample {
            name,
            labels: vec![],
            value: MetricValue::Counter(value),
        })
        .collect();
    for (name, counter) in [
        (
            "gw_access_log_dropped_total",
            &metrics.access_log_dropped_total,
        ),
        (
            "gw_llm_cache_exact_l1_hits_total",
            &metrics.llm_cache_exact_l1_hits_total,
        ),
        (
            "gw_llm_cache_exact_l2_hits_total",
            &metrics.llm_cache_exact_l2_hits_total,
        ),
        (
            "gw_llm_cache_semantic_l1_hits_total",
            &metrics.llm_cache_semantic_l1_hits_total,
        ),
        (
            "gw_llm_cache_semantic_l2_hits_total",
            &metrics.llm_cache_semantic_l2_hits_total,
        ),
        (
            "gw_llm_moderation_allowed_total",
            &metrics.llm_moderation_allowed_total,
        ),
        (
            "gw_llm_moderation_blocked_total",
            &metrics.llm_moderation_blocked_total,
        ),
        (
            "gw_llm_moderation_fail_open_total",
            &metrics.llm_moderation_fail_open_total,
        ),
        (
            "gw_llm_moderation_error_total",
            &metrics.llm_moderation_error_total,
        ),
        (
            "gw_usage_plan_allowed_total",
            &metrics.usage_plan_allowed_total,
        ),
        (
            "gw_usage_plan_limited_total",
            &metrics.usage_plan_limited_total,
        ),
        (
            "gw_usage_plan_unmapped_total",
            &metrics.usage_plan_unmapped_total,
        ),
        (
            "gw_request_schema_valid_total",
            &metrics.request_schema_valid_total,
        ),
        (
            "gw_request_schema_invalid_total",
            &metrics.request_schema_invalid_total,
        ),
        (
            "gw_request_schema_too_large_total",
            &metrics.request_schema_too_large_total,
        ),
        (
            "gw_request_schema_body_read_error_total",
            &metrics.request_schema_body_read_error_total,
        ),
        ("gw_graphql_allowed_total", &metrics.graphql_allowed_total),
        ("gw_graphql_invalid_total", &metrics.graphql_invalid_total),
        (
            "gw_graphql_too_large_total",
            &metrics.graphql_too_large_total,
        ),
        ("gw_graphql_too_deep_total", &metrics.graphql_too_deep_total),
        (
            "gw_graphql_too_complex_total",
            &metrics.graphql_too_complex_total,
        ),
        (
            "gw_graphql_introspection_denied_total",
            &metrics.graphql_introspection_denied_total,
        ),
        (
            "gw_graphql_body_read_error_total",
            &metrics.graphql_body_read_error_total,
        ),
        ("gw_waf_monitored_total", &metrics.waf_monitored_total),
        ("gw_waf_blocked_total", &metrics.waf_blocked_total),
        ("gw_waf_too_large_total", &metrics.waf_too_large_total),
        (
            "gw_waf_body_read_error_total",
            &metrics.waf_body_read_error_total,
        ),
        (
            "gw_opa_decision_allow_total",
            &metrics.opa_decision_allow_total,
        ),
        (
            "gw_opa_decision_deny_total",
            &metrics.opa_decision_deny_total,
        ),
        (
            "gw_opa_decision_fail_open_total",
            &metrics.opa_decision_fail_open_total,
        ),
        (
            "gw_opa_decision_unavailable_total",
            &metrics.opa_decision_unavailable_total,
        ),
        (
            "gw_opa_decision_invalid_input_total",
            &metrics.opa_decision_invalid_input_total,
        ),
        ("gw_opa_cache_hit_total", &metrics.opa_cache_hit_total),
        ("gw_opa_cache_miss_total", &metrics.opa_cache_miss_total),
        (
            "gw_opa_request_success_total",
            &metrics.opa_request_success_total,
        ),
        (
            "gw_opa_request_error_total",
            &metrics.opa_request_error_total,
        ),
        ("gw_casbin_allow_total", &metrics.casbin_allow_total),
        ("gw_casbin_deny_total", &metrics.casbin_deny_total),
        ("gw_casbin_fail_open_total", &metrics.casbin_fail_open_total),
        ("gw_casbin_error_total", &metrics.casbin_error_total),
        (
            "gw_casbin_invalid_input_total",
            &metrics.casbin_invalid_input_total,
        ),
        ("gw_wasm_continue_total", &metrics.wasm_continue_total),
        (
            "gw_wasm_local_response_total",
            &metrics.wasm_local_response_total,
        ),
        ("gw_wasm_fail_open_total", &metrics.wasm_fail_open_total),
        ("gw_wasm_error_total", &metrics.wasm_error_total),
        (
            "gw_external_plugin_continue_total",
            &metrics.external_plugin_continue_total,
        ),
        (
            "gw_external_plugin_local_response_total",
            &metrics.external_plugin_local_response_total,
        ),
        (
            "gw_external_plugin_fail_open_total",
            &metrics.external_plugin_fail_open_total,
        ),
        (
            "gw_external_plugin_error_total",
            &metrics.external_plugin_error_total,
        ),
        (
            "gw_external_plugin_invalid_input_total",
            &metrics.external_plugin_invalid_input_total,
        ),
        (
            "gw_upstream_prewarm_success_total",
            &metrics.upstream_prewarm_success_total,
        ),
        (
            "gw_upstream_prewarm_error_total",
            &metrics.upstream_prewarm_error_total,
        ),
        ("gw_compression_gzip_total", &metrics.compression_gzip_total),
        (
            "gw_compression_brotli_total",
            &metrics.compression_brotli_total,
        ),
        (
            "gw_decompression_gzip_total",
            &metrics.decompression_gzip_total,
        ),
        (
            "gw_decompression_brotli_total",
            &metrics.decompression_brotli_total,
        ),
        ("gw_http_cache_hits_total", &metrics.http_cache_hits_total),
        (
            "gw_http_cache_misses_total",
            &metrics.http_cache_misses_total,
        ),
        (
            "gw_http_cache_l2_hits_total",
            &metrics.http_cache_l2_hits_total,
        ),
        (
            "gw_http_cache_l2_misses_total",
            &metrics.http_cache_l2_misses_total,
        ),
        (
            "gw_http_cache_l2_errors_total",
            &metrics.http_cache_l2_errors_total,
        ),
        (
            "gw_http_cache_l2_store_ok_total",
            &metrics.http_cache_l2_store_ok_total,
        ),
        (
            "gw_http_cache_l2_store_errors_total",
            &metrics.http_cache_l2_store_errors_total,
        ),
        (
            "gw_http_cache_invalidation_ok_total",
            &metrics.http_cache_invalidation_ok_total,
        ),
        (
            "gw_http_cache_invalidation_errors_total",
            &metrics.http_cache_invalidation_errors_total,
        ),
        (
            "gw_http_cache_singleflight_leader_total",
            &metrics.http_cache_singleflight_leader_total,
        ),
        (
            "gw_http_cache_singleflight_follower_total",
            &metrics.http_cache_singleflight_follower_total,
        ),
        (
            "gw_http_cache_singleflight_wait_hit_total",
            &metrics.http_cache_singleflight_wait_hit_total,
        ),
        (
            "gw_http_cache_singleflight_timeout_total",
            &metrics.http_cache_singleflight_timeout_total,
        ),
        (
            "gw_http_cache_singleflight_bypass_total",
            &metrics.http_cache_singleflight_bypass_total,
        ),
        ("gw_http_cache_stale_total", &metrics.http_cache_stale_total),
        (
            "gw_http_cache_revalidation_ok_total",
            &metrics.http_cache_revalidation_ok_total,
        ),
        (
            "gw_http_cache_revalidation_errors_total",
            &metrics.http_cache_revalidation_errors_total,
        ),
        (
            "gw_http_cache_revalidation_skipped_total",
            &metrics.http_cache_revalidation_skipped_total,
        ),
        (
            "gw_stream_udp_downstream_datagrams_total",
            &metrics.stream_udp_downstream_datagrams_total,
        ),
        (
            "gw_stream_udp_upstream_datagrams_total",
            &metrics.stream_udp_upstream_datagrams_total,
        ),
        (
            "gw_stream_udp_dropped_datagrams_total",
            &metrics.stream_udp_dropped_datagrams_total,
        ),
    ] {
        samples.push(MetricSample {
            name,
            labels: vec![],
            value: MetricValue::Counter(counter.load(Ordering::Relaxed)),
        });
    }
    for (name, gauge) in [
        ("gw_active_connections", &metrics.active_connections),
        (
            "gw_stream_active_connections",
            &metrics.stream_active_connections,
        ),
        (
            "gw_active_health_unhealthy",
            &metrics.active_health_unhealthy,
        ),
        (
            "gw_upstream_identity_inflight_entries",
            &metrics.upstream_identity_inflight_entries,
        ),
        (
            "gw_upstream_identity_pending_entries",
            &metrics.upstream_identity_pending_entries,
        ),
        (
            "gw_upstream_identity_budget_entries",
            &metrics.upstream_identity_budget_entries,
        ),
    ] {
        samples.push(MetricSample {
            name,
            labels: vec![],
            value: MetricValue::Gauge(gauge.load(Ordering::Relaxed) as f64),
        });
    }
    samples.extend(crate::runtime::traffic_limit::metrics::samples());
    samples.extend(crate::runtime::sentinel::queue::metrics::samples());
    samples.extend(super::buckets::samples(metrics));
    samples.extend(crate::io::request_decompression::metrics::samples());
    samples.extend(metrics.http_stream.samples());
    samples.extend(metrics.circuits.samples());
    samples.extend(metrics.response_codec.samples());
    samples.extend(crate::upstream::load::metrics::samples());
    samples.extend(crate::routing::layers::metrics::samples());
    #[cfg(feature = "telemetry-otlp")]
    {
        samples.extend(metrics.ai.summary());
        samples.extend(super::governance::samples());
        samples.extend(crate::observability::telemetry::otlp::export_samples());
    }
    #[cfg(feature = "rate-preallocation")]
    samples.extend(crate::runtime::ratelimit::metrics::samples());
    #[cfg(feature = "upstream-outlier")]
    samples.extend(crate::upstream::passive::metrics::samples());
    #[cfg(feature = "config-providers")]
    samples.extend(crate::control::providers::metrics::samples());
    #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
    samples.extend(crate::protocols::cgi::metrics::samples());
    #[cfg(feature = "webdav")]
    samples.extend(crate::io::webdav::metrics::samples());
    #[cfg(feature = "media-streaming")]
    samples.extend(crate::io::media::metrics::samples());
    #[cfg(feature = "lua-scripts")]
    samples.extend(crate::extensions::scripts::metrics::samples());
    #[cfg(feature = "xds-server")]
    {
        samples.extend(crate::control::xds_server::metrics::samples());
    }
    samples
}

/// 业务作用：冻结响应头时延的非累计桶，供相邻采样求差而非累计分位展示。
///
/// 参数说明：
/// - `metrics`：现有请求时延事实。
///
/// 返回：毫秒边界、包含溢出桶的次数和累计微秒；并发读取的弱一致性由区间计算复验。
pub(crate) fn duration(metrics: &Metrics) -> (Vec<u64>, Vec<u64>, u64) {
    let mut buckets: Vec<_> = metrics
        .request_duration_buckets
        .iter()
        .map(|bucket| bucket.load())
        .collect();
    let finite = buckets.iter().copied().fold(0u64, u64::saturating_add);
    buckets.push(metrics.request_duration_count.load().saturating_sub(finite));
    (
        REQUEST_DURATION_BUCKET_MS.to_vec(),
        buckets,
        metrics.request_duration_sum_micros.load(),
    )
}
