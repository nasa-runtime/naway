//! 共享匀速队列只接受明确脚本授权，未知提交不会降级成本地放行。

use super::{Context, Policy, Rejected};
use crate::runtime::state::{redis_scoped_rate_limit_keys, RateLimitRequest};
use crate::runtime::traffic_limit::resources::Retained;
use sha2::Digest;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

const SCRIPT: &str = include_str!("redis.lua");
static SHA: LazyLock<String> =
    LazyLock::new(|| format!("{:x}", sha1::Sha1::digest(SCRIPT.as_bytes())));

struct Ledger {
    client: Arc<nasa::redis::RedisClient>,
    keys: [String; 5],
    args: [String; 7],
}

struct Waiting {
    ledger: Arc<Ledger>,
    retained: Option<Retained>,
    released: bool,
    monitor: Option<super::metrics::Wait>,
}

/// 业务作用：在同 slot 共享账本上执行立即尝试或有界FIFO等待，所有等待复用原资源凭证。
///
/// 参数说明：
/// - `client`：已经选定并验证的 NASA Redis 连接。
/// - `retired`：原后端是否已失去发放资格。
/// - `request`：冻结规则与归属容量。
/// - `policy`：冻结间隔、队列容量和最大期限。
/// - `context`：原请求绝对期限与可保留实体上界。
///
/// 返回：明确取得调度授权时成功；不确定提交、容量、取消或失权均不开放业务转发。
pub(crate) async fn admit(
    client: Arc<nasa::redis::RedisClient>,
    retired: &AtomicBool,
    request: RateLimitRequest<'_>,
    policy: Policy,
    context: Context,
) -> Result<(), Rejected> {
    if request.cost != 1
        || request.warmup.is_some()
        || request.burst != 0
        || Policy::build(
            request.limit,
            request.window,
            policy.capacity,
            policy.max_wait.as_millis().min(u128::from(u64::MAX)) as u64,
        )
        .ok()
            != Some(policy)
    {
        return Err(Rejected::Unavailable);
    }
    check_authority(retired, context)?;
    let ledger = Arc::new(Ledger::new(client, request, policy)?);
    match ledger.invoke("probe", context.deadline).await {
        Ok(None) => {
            check_authority(retired, context)?;
            return Ok(());
        }
        Err(Rejected::UnknownBody) => {}
        Err(reason) => return Err(reason),
        Ok(Some(_)) => return Err(Rejected::Unavailable),
    }
    check_authority(retired, context)?;
    let bytes = context.retained_bound.ok_or(Rejected::UnknownBody)?;
    let retained = Retained::acquire(bytes).ok_or(Rejected::Capacity)?;
    // 在发送预约之前建立清理所有权；丢失 ACK 也不能让远端名额脱离有界清理责任。
    let mut waiting = Waiting {
        ledger,
        retained: Some(retained),
        released: false,
        monitor: Some(super::metrics::Wait::new()),
    };
    let mut delay = waiting.ledger.invoke("reserve", context.deadline).await?;
    loop {
        check_authority(retired, context)?;
        let Some(wait_us) = delay else {
            waiting.released = true;
            return Ok(());
        };
        let remaining = context.deadline.saturating_duration_since(Instant::now());
        tokio::time::sleep(Duration::from_micros(wait_us.clamp(1, 50_000)).min(remaining)).await;
        // 远端令牌不能替代本地请求期限或后端权威，唤醒后必须先复验再竞争放行。
        check_authority(retired, context)?;
        delay = waiting.ledger.invoke("claim", context.deadline).await?;
    }
}

/// 业务作用：阻止已超时或失去原后端权威的请求继续申请共享准入。
///
/// 参数说明：
/// - `retired`：当前冻结后端的退休标志。
/// - `context`：不可续期的原请求期限。
///
/// 返回：仍有效时成功，过期或退休均返回封闭拒绝。
fn check_authority(retired: &AtomicBool, context: Context) -> Result<(), Rejected> {
    if retired.load(Ordering::Acquire) {
        return Err(Rejected::Retired);
    }
    if Instant::now() >= context.deadline {
        return Err(Rejected::Deadline);
    }
    Ok(())
}

impl Ledger {
    /// 业务作用：一次编码同 slot 键和固定参数，后续轮询仅更新剩余期限。
    ///
    /// 参数说明：
    /// - `client`：本次准入固定的连接池。
    /// - `request`：规则、维度和工作区容量。
    /// - `policy`：已验证的整数调度合同。
    ///
    /// 返回：带唯一随机令牌的账本，随机源不可用时不创建预约。
    fn new(
        client: Arc<nasa::redis::RedisClient>,
        request: RateLimitRequest<'_>,
        policy: Policy,
    ) -> Result<Self, Rejected> {
        let (data, active, _, owner) = redis_scoped_rate_limit_keys(
            request.scope,
            request.key,
            request.state_budget,
            &client.config().namespace,
        );
        let data = format!("{data}:queue");
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| Rejected::Unavailable)?;
        Ok(Self {
            client,
            keys: [
                data.clone(),
                format!("{data}:tickets"),
                format!("{data}:deadlines"),
                format!("{active}:queue"),
                owner,
            ],
            args: [
                format!("{:032x}", u128::from_be_bytes(nonce)),
                policy.interval_us.to_string(),
                policy.capacity.to_string(),
                policy.max_wait.as_micros().to_string(),
                request.max_active_keys.min(1_000_000).to_string(),
                u8::from(request.active_keys_fail_open).to_string(),
                request
                    .state_budget
                    .map_or(0, |budget| budget.remote_scope().1)
                    .to_string(),
            ],
        })
    }

    /// 业务作用：在原期限内执行一次脚本，仅明确未执行的 NOSCRIPT 允许携带正文重发。
    ///
    /// 参数说明：
    /// - `operation`：固定 probe、reserve、claim 或 release 动作。
    /// - `deadline`：包含网络往返的绝对期限。
    ///
    /// 返回：无等待即准入，或下次复验延迟；未知结果一律拒绝，不猜测提交状态。
    async fn invoke(&self, operation: &str, deadline: Instant) -> Result<Option<u64>, Rejected> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Rejected::Deadline);
        }
        let remaining_us = remaining.as_micros().clamp(1, 60_000_000).to_string();
        let args = [
            operation,
            &self.args[0],
            &self.args[1],
            &self.args[2],
            &self.args[3],
            &remaining_us,
            &self.args[4],
            &self.args[5],
            &self.args[6],
        ];
        let keys = self.keys.each_ref().map(String::as_str);
        let outcome = tokio::time::timeout(remaining.min(Duration::from_millis(500)), async {
            match self.client.eval_sha::<Vec<i64>>(&SHA, &keys, &args).await {
                // NOSCRIPT 证明本次调用没有产生副作用；超时、断连与其它错误没有此证据。
                Err(nasa::redis::NasaRedisError::Redis(error))
                    if error.code() == Some("NOSCRIPT") =>
                {
                    self.client.eval::<Vec<i64>>(SCRIPT, &keys, &args).await
                }
                outcome => outcome,
            }
        })
        .await
        .map_err(|_| Rejected::Unavailable)?
        .map_err(|_| Rejected::Unavailable)?;
        match outcome.as_slice() {
            [1] => Ok(None),
            [3] => {
                super::metrics::state_open();
                Ok(None)
            }
            [2, delay] if *delay >= 0 && *delay <= 60_000_000 => Ok(Some(*delay as u64)),
            [-1] => Err(Rejected::Capacity),
            [-2] => Err(Rejected::Deadline),
            [-3] => Err(Rejected::UnknownBody),
            [-4] => Err(Rejected::StateCapacity),
            [-5] => Err(Rejected::Clock),
            _ => Err(Rejected::Unavailable),
        }
    }
}

impl Drop for Waiting {
    /// 业务作用：取消或未知提交时释放唯一预约，清理任务继续占用原进程资源名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最多执行一次500毫秒清理；无运行时或依赖不可用时由远端有限租期回收。
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let ledger = self.ledger.clone();
        let retained = self.retained.take();
        let monitor = self.monitor.take();
        // 原名额在清理结束前不归还，取消洪峰不能产生额外无界后台任务。
        runtime.spawn(async move {
            let _retained = retained;
            let _monitor = monitor;
            let _ = ledger
                .invoke("release", Instant::now() + Duration::from_millis(500))
                .await;
        });
    }
}
