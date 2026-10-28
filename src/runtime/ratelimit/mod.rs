//! 请求次数的两级令牌准入；最终成本结算始终留在精确共享账本。

mod cache;
mod ledger;
pub(crate) mod metrics;

use crate::config::model::RatePreallocationCfg as Policy;
use crate::runtime::state::{
    RateLimitFailMode, RateLimitFuture, RateLimitRequest, RateLimitReserveFuture, RateLimiter,
};
use std::sync::Arc;

pub(crate) struct Preallocated {
    inner: Arc<dyn RateLimiter>,
    cache: Arc<cache::Cache>,
}

impl Preallocated {
    /// 业务作用：为已准备的精确后端附加仅请求次数可用的批领层。
    ///
    /// 参数说明：
    /// - `inner`：原有共享限流与最终成本结算后端。
    /// - `client`：同一个 NASA Redis 连接。
    /// - `fail_mode`：依赖不可用策略。
    /// - `policy`：已校验的批领资源边界。
    ///
    /// 返回：创建有限后台回收器；代际容量不足时拒绝候选。
    pub(crate) fn new(
        inner: Arc<dyn RateLimiter>,
        client: Arc<nasa::redis::RedisClient>,
        fail_mode: RateLimitFailMode,
        policy: Policy,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            inner,
            cache: cache::Cache::new(client, policy, fail_mode)?,
        })
    }
}

impl RateLimiter for Preallocated {
    /// 业务作用：区分共享桶与本机批领缓存，不能把缓存项数当作 Redis 总桶数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：明确的批领后端边界；本机缓存仍由独立资源指标说明。
    fn bucket_observation(&self) -> crate::runtime::sentinel::buckets::Observation {
        crate::runtime::sentinel::buckets::Observation::Preallocated
    }
    /// 业务作用：匀速队列始终由精确后端授予时刻，批领余额不能提前放行等待请求。
    ///
    /// 参数说明：
    /// - `request`：当前冻结规则。
    /// - `policy`：匀速与容量合同。
    /// - `context`：不可续期的等待边界。
    ///
    /// 返回：原后端的调度结果，不领取或消费本地批次。
    fn queue<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        policy: crate::runtime::sentinel::queue::Policy,
        context: crate::runtime::sentinel::queue::Context,
    ) -> crate::runtime::sentinel::queue::AdmissionFuture<'a> {
        self.inner.queue(request, policy, context)
    }
    /// 业务作用：共享成本账本直接借用精确后端连接，不把多窗口配额兑换成本地批次。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层精确后端的已验证连接。
    fn redis_client(&self) -> Option<Arc<nasa::redis::RedisClient>> {
        self.inner.redis_client()
    }
    /// 业务作用：非请求次数调用保持原有共享精确扣减，不使用批领余额。
    ///
    /// 参数说明：
    /// - `request`：原有配额请求。
    ///
    /// 返回：原后端的精确判定。
    fn allow<'a>(&'a self, request: RateLimitRequest<'a>) -> RateLimitFuture<'a> {
        self.inner.allow(request)
    }

    /// 业务作用：只为有效的单请求次数规则启用本地预扣，零规则和非单位成本保留原合同。
    ///
    /// 参数说明：
    /// - `request`：冻结请求次数规则。
    /// - `generation`：请求配置版本。
    ///
    /// 返回：有效本地权威或共享领取结果；后端退休后明确拒绝新批领。
    fn allow_preallocated<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        generation: u64,
    ) -> RateLimitFuture<'a> {
        // 预热速率随共享时钟变化，批领的旧余额不能绕过当前曲线或空闲后的冷启动门。
        if request.warmup.is_some()
            || request.cost != 1
            || request.limit == 0
            || request.window.is_zero()
        {
            return self.inner.allow(request);
        }
        Box::pin(self.cache.allow(request, generation))
    }

    /// 业务作用：最终 provider 成本预留始终使用原后端及其幂等结算凭据。
    ///
    /// 参数说明：
    /// - `request`：需结算的配额请求。
    /// - `reservation_id`：全局幂等标识。
    /// - `max_actual`：最大允许负债。
    ///
    /// 返回：原共享账本的准入与结算句柄，不经过本地批次。
    fn reserve<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        reservation_id: &'a str,
        max_actual: u64,
    ) -> RateLimitReserveFuture<'a> {
        self.inner.reserve(request, reservation_id, max_actual)
    }

    /// 业务作用：在后端切换前同步撤销本地额度消费权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：后续与等待中的批领请求拒绝；已知余额由有界回收器尝试归还。
    fn retire(&self) {
        self.cache.retire();
        self.inner.retire();
    }

    /// 业务作用：正常停机时为已知未用余额提供有界归还机会，之后不再开放批领。
    ///
    /// 参数说明：
    /// - `timeout`：允许的清理墙钟预算。
    ///
    /// 返回：清理完成或预算耗尽后结束；未知余额保持保守预扣。
    fn shutdown_preallocation(
        &self,
        timeout: std::time::Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(self.cache.shutdown(timeout))
    }
}

impl Drop for Preallocated {
    /// 业务作用：未发布候选或最后一个在线句柄释放时停止后台常驻，不能遗留孤立回收器。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：标记退休，回收器完成有限清理后自行退出。
    fn drop(&mut self) {
        self.cache.retire();
    }
}
