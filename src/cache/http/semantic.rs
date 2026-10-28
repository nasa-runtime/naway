//! 公共响应缓存比较只读声明，回填、失效和刷新状态不作为配置变化。

use super::HttpCachePolicy;

impl PartialEq for HttpCachePolicy {
    /// 业务作用：穷尽比较缓存期限、内容范围、L1/L2 与刷新预算，识别同名缓存策略调整。
    ///
    /// 参数说明：
    /// - `other`：已经完成路由缓存安全校验的候选计划。
    ///
    /// 返回：全部声明一致时为真；不读取缓存正文、generation 或 singleflight 锁。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            ttl,
            max_body_bytes,
            statuses,
            vary_headers,
            l2_enabled,
            store,
            singleflight_wait,
            singleflight_enabled,
            max_inflight,
            stale_while_revalidate,
            ttl_jitter_percent,
            // 工作区绑定、失效代际与正在回填的请求属于运行事实；store 仅提供冻结容量。
            workspace_budget: _,
            generation: _,
            generation_loaded: _,
            flights: _,
        } = self;
        ttl == &other.ttl
            && max_body_bytes == &other.max_body_bytes
            && statuses == &other.statuses
            && vary_headers == &other.vary_headers
            && l2_enabled == &other.l2_enabled
            && store.capacity() == other.store.capacity()
            && singleflight_wait == &other.singleflight_wait
            && singleflight_enabled == &other.singleflight_enabled
            && max_inflight == &other.max_inflight
            && stale_while_revalidate == &other.stale_while_revalidate
            && ttl_jitter_percent == &other.ttl_jitter_percent
    }
}

impl Eq for HttpCachePolicy {}
