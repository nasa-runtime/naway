//! 共享账本的冻结连接、同 slot 身份与单次有界脚本调用。

use super::Failure;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

pub(crate) struct Ledger {
    pub(super) client: Arc<nasa::redis::RedisClient>,
    pub(super) data: String,
    pub(super) index: String,
    pub(super) capacity: String,
}

impl Ledger {
    /// 业务作用：冻结已验证后端与归属身份，供同一流的多次调度复用，不逐帧编码状态键。
    ///
    /// 参数说明：
    /// - `client`：当前生效的共享后端连接。
    /// - `scope`：候选已验证的策略与方向身份。
    /// - `dimension`：已认证主体或已解析的维度。
    /// - `budget`：工作区状态容量；平台入口为空。
    ///
    /// 返回：同 slot 的数据键和容量索引，不包含原始凭据。
    pub(crate) fn new(
        client: Arc<nasa::redis::RedisClient>,
        scope: &str,
        dimension: &str,
        budget: Option<&crate::control::ownership::state::Budget>,
    ) -> Self {
        let mut identity = Sha256::new();
        identity.update((scope.len() as u64).to_be_bytes());
        identity.update(scope.as_bytes());
        identity.update(dimension.as_bytes());
        let identity = format!("{:x}", identity.finalize());
        let namespace = &client.config().namespace;
        let (data, index, capacity) = if let Some(budget) = budget {
            let (data, index) = budget.redis_keys(namespace, "traffic", &identity);
            (data, index, budget.remote_scope().1)
        } else {
            let slot = format!("{:x}", Sha256::digest(namespace.as_bytes()));
            let prefix = format!("gw:traffic:{{{slot}}}");
            (
                format!("{prefix}:{identity}"),
                format!("{prefix}:states"),
                crate::runtime::traffic_limit::MAX_ACTIVE_KEYS,
            )
        };
        Self {
            client,
            data,
            index,
            capacity: capacity.to_string(),
        }
    }

    /// 业务作用：执行一次有限时脚本，只有明确未执行的 NOSCRIPT 才携带正文重发。
    ///
    /// 参数说明：
    /// - `script`：产品内固定脚本。
    /// - `sha`：该脚本的预计算 SHA1。
    /// - `args`：有界整数协议参数。
    ///
    /// 返回：脚本整数协议或失败类别；未知提交结果不重试或退款。
    pub(super) async fn invoke(
        &self,
        script: &str,
        sha: &str,
        args: &[&str],
    ) -> Result<Vec<i64>, Failure> {
        let keys = [self.data.as_str(), self.index.as_str()];
        self.invoke_keys(script, sha, &keys, args).await
    }

    /// 业务作用：把排队权威与额度提交放进同一 slot 操作，避免队列过期后继续取得准入。
    ///
    /// 参数说明：
    /// - `script`：固定产品脚本。
    /// - `sha`：预计算脚本摘要。
    /// - `keys`：完整声明的同 slot 键。
    /// - `args`：有界整数与动作令牌参数。
    ///
    /// 返回：脚本结果；未知提交结果不重发。
    pub(super) async fn invoke_keys(
        &self,
        script: &str,
        sha: &str,
        keys: &[&str],
        args: &[&str],
    ) -> Result<Vec<i64>, Failure> {
        tokio::time::timeout(Duration::from_millis(500), async {
            match self.client.eval_sha::<Vec<i64>>(sha, keys, args).await {
                // 此响应证明没有执行写入；连接断开和超时不提供同等证据。
                Err(nasa::redis::NasaRedisError::Redis(error))
                    if error.code() == Some("NOSCRIPT") =>
                {
                    self.client.eval::<Vec<i64>>(script, keys, args).await
                }
                outcome => outcome,
            }
        })
        .await
        .map_err(|_| Failure::Unavailable)?
        .map_err(|error| {
            if error.is_infra_retryable() {
                Failure::Unavailable
            } else {
                Failure::Invalid
            }
        })
    }
}
