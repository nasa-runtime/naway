//! 单 slot 共享预扣账本；传输和协议兼容由 nasa::redis 提供。

use super::{metrics, Policy};
use crate::runtime::state::{redis_scoped_rate_limit_keys, RateLimitRequest};
use sha2::{Digest, Sha256};
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;

pub(super) const GRANT: &str = include_str!("redis/grant.lua");
pub(super) const RETURN: &str = include_str!("redis/return.lua");

#[derive(Clone)]
pub(super) struct Ledger {
    pub key: String,
    active: String,
    owner: String,
    batches: String,
    pub fingerprint: String,
    args: Vec<String>,
    client: Arc<nasa::redis::RedisClient>,
    timeout: Duration,
}

impl Ledger {
    /// 业务作用：冻结一次规则的共享桶身份、精度边界与归属预算，避免异步领取中混入新参数。
    ///
    /// 参数说明：
    /// - `client`：已准备好的 NASA Redis 连接。
    /// - `request`：冻结路由的单请求规则。
    /// - `policy`：后端批领配置。
    ///
    /// 返回：只含哈希身份的同 slot 账本描述，不执行 Redis 操作。
    pub fn new(
        client: Arc<nasa::redis::RedisClient>,
        request: RateLimitRequest<'_>,
        policy: Policy,
    ) -> Self {
        let (key, active, _, owner) = redis_scoped_rate_limit_keys(
            request.scope,
            request.key,
            request.state_budget,
            &client.config().namespace,
        );
        let cap = request.limit.saturating_add(request.burst);
        let refill = request.limit as f64 / request.window.as_secs_f64();
        let owner_limit = request
            .state_budget
            .map_or(0, |budget| budget.remote_scope().1);
        let args = vec![
            cap.to_string(),
            format!("{refill:.12}"),
            request.max_active_keys.to_string(),
            u8::from(request.active_keys_fail_open).to_string(),
            request.key.to_string(),
            owner_limit.to_string(),
            policy.batch_size.to_string(),
            policy.lease_ms.to_string(),
            policy.max_outstanding_tokens.to_string(),
        ];
        let fingerprint = format!("{:x}", Sha256::digest(format!("{args:?}").as_bytes()));
        Self {
            batches: format!("{key}:preallocation"),
            key,
            active,
            owner,
            fingerprint,
            args,
            client,
            timeout: Duration::from_millis(policy.lease_ms),
        }
    }

    /// 业务作用：在共享桶原子预扣小批额度，超时不重试未知结果也不生成本地凭据。
    ///
    /// 参数说明：
    /// - `id`：本次领取唯一标识，用于 Redis 重复命令幂等。
    ///
    /// 返回：共享准入状态与批次令牌数；确定性拒绝是正常返回，只有基础设施不可用单独上报。
    pub async fn grant(&self, id: &str) -> anyhow::Result<(i64, u64)> {
        let mut args = self.args.iter().map(String::as_str).collect::<Vec<_>>();
        args.extend([self.fingerprint.as_str(), id]);
        metrics::GRANTS.fetch_add(1, Ordering::Relaxed);
        let result = tokio::time::timeout(
            self.timeout,
            self.client.eval::<Vec<i64>>(
                GRANT,
                &[&self.key, &self.active, &self.owner, &self.batches],
                &args,
            ),
        )
        .await?;
        // 只有 NASA 分类为基础设施不可用的错误可以交给 fail-open；权限、类型、slot 和解析错误闭合。
        let values = match result {
            Ok(values) => values,
            Err(error) if error.is_infra_retryable() => return Err(error.into()),
            Err(_) => return Ok((0, 0)),
        };
        if values.len() != 3 || !(0..=2).contains(&values[0]) || values[1] < 0 {
            return Ok((0, 0));
        }
        Ok((values[0], values[1] as u64))
    }

    /// 业务作用：幂等归还已经撤销的本地批次余额；依赖失败只保留原预扣，不猜测追加信用。
    ///
    /// 参数说明：
    /// - `id`：此前取得的唯一凭据。
    /// - `unused`：撤销时冻结的未使用额度。
    ///
    /// 返回：成功时记录真实退回令牌数；失败时保守消耗，账本仍有有限到期时间。
    pub async fn give_back(&self, id: &str, unused: u64) {
        let unused = unused.to_string();
        let result = tokio::time::timeout(
            self.timeout,
            self.client.eval::<i64>(
                RETURN,
                &[&self.key, &self.batches],
                &[id, &unused, &self.fingerprint],
            ),
        )
        .await;
        if let Ok(Ok(returned)) = result {
            metrics::RETURNED.fetch_add(returned.max(0) as u64, Ordering::Relaxed);
        } else {
            metrics::ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }
}
