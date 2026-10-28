//! 管理面借用路由执行计划比较参数，不复制请求头、响应体或安全凭据。

use super::Route;
mod authentication;
mod security;

impl Route {
    /// 业务作用：比较基础 HTTP 处理与流量预算的实际参数，识别同名过滤器的策略修改。
    ///
    /// 参数说明：
    /// - `candidate`：同代理、同路由身份下已完成构建的候选计划。
    ///
    /// 返回：头部、正文、接入、预算与超时策略一致时为真；复杂安全及扩展仍由各自摘要比较。
    pub(crate) fn same_basic_configuration(&self, candidate: &Self) -> bool {
        self.upstream_template == candidate.upstream_template
            && self.pass_request_headers == candidate.pass_request_headers
            && self.pass_request_body == candidate.pass_request_body
            && self.request_headers == candidate.request_headers
            && self.response_headers == candidate.response_headers
            && self.sub_filters == candidate.sub_filters
            && self.compression == candidate.compression
            && self.cors == candidate.cors
            && self.fallback_headers == candidate.fallback_headers
            && self.access_rules == candidate.access_rules
            && self.referer == candidate.referer
            && self.limit_except == candidate.limit_except
            && self.limit_req == candidate.limit_req
            && self.limit_conn == candidate.limit_conn
            && self.limit_rate == candidate.limit_rate
            && self.circuit_breakers == candidate.circuit_breakers
            && self.error_pages == candidate.error_pages
            && self.proxy_intercept_errors == candidate.proxy_intercept_errors
            && self.x_accel_redirect == candidate.x_accel_redirect
            && self.direct_response == candidate.direct_response
            && self.gateway_redirect == candidate.gateway_redirect
            && self.mirrors == candidate.mirrors
            && self.hedge == candidate.hedge
            && self.cache_invalidations == candidate.cache_invalidations
            && self.long_stream_idle_timeout_ms == candidate.long_stream_idle_timeout_ms
            && self.long_stream_max_lifetime_ms == candidate.long_stream_max_lifetime_ms
            && self.request_timeout_ms == candidate.request_timeout_ms
            && self.backend_request_timeout_ms == candidate.backend_request_timeout_ms
    }
}
