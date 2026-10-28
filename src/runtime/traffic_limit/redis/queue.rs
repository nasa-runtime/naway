//! 集群排队名额以有限租期存在；取消清理也占用原等待名额，避免另建无界后台任务。

use super::{Failure, Ledger};
use crate::runtime::traffic_limit::resources::Retained;
use sha2::Digest;
use std::sync::{Arc, LazyLock};

const SCRIPT: &str = include_str!("queue.lua");
static SHA: LazyLock<String> =
    LazyLock::new(|| format!("{:x}", sha1::Sha1::digest(SCRIPT.as_bytes())));

pub(crate) struct Slot {
    pub(super) ledger: Arc<Ledger>,
    pub(super) token: String,
    retained: Option<Retained>,
    released: bool,
}

impl Slot {
    /// 业务作用：在保留请求前原子竞争集群队列名额，未知提交也保留清理责任。
    ///
    /// 参数说明：
    /// - `ledger`：同一准入账本的冻结身份。
    /// - `maximum`：全节点共享的队列容量。
    /// - `wait_ms`：本请求最大等待期限。
    /// - `retained`：已经取得的进程等待和实体容量。
    ///
    /// 返回：已取得的排队凭证；满队列返回 None，账本错误拒绝继续排队。
    pub(crate) async fn acquire(
        ledger: &Ledger,
        maximum: u64,
        wait_ms: u64,
        retained: Retained,
    ) -> Result<Option<Self>, Failure> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| Failure::Invalid)?;
        let token = format!("{:032x}", u128::from_be_bytes(nonce));
        let mut slot = Self {
            ledger: Arc::new(Ledger {
                client: ledger.client.clone(),
                data: format!("{}:waiting", ledger.data),
                index: ledger.index.clone(),
                capacity: ledger.capacity.clone(),
            }),
            token,
            retained: Some(retained),
            released: false,
        };
        let maximum = maximum.to_string();
        let lifetime = wait_ms.saturating_add(1000).to_string();
        let outcome = slot
            .ledger
            .invoke(
                SCRIPT,
                &SHA,
                &[&slot.ledger.capacity, "1", &slot.token, &maximum, &lifetime],
            )
            .await?;
        match outcome.as_slice() {
            [1] => Ok(Some(slot)),
            [0] => {
                slot.released = true;
                Ok(None)
            }
            [-1] => {
                slot.released = true;
                Err(Failure::StateCapacity)
            }
            _ => Err(Failure::Invalid),
        }
    }

    /// 业务作用：正常离队时释放精确令牌，清理失败依赖有限租期而不补发未知扣账。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已尝试一次清理；释放进程名额，不延长远端租期。
    pub(crate) async fn release(mut self) {
        let _ = self
            .ledger
            .invoke(
                SCRIPT,
                &SHA,
                &[&self.ledger.capacity, "0", &self.token, "1", "1"],
            )
            .await;
        self.released = true;
        self.retained.take();
    }
}

impl Drop for Slot {
    /// 业务作用：取消排队时回收远端令牌，清理任务仍受原进程等待预算约束。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有运行时时异步清理；运行时关闭时由 Redis 有限租期自然回收。
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let ledger = self.ledger.clone();
        let token = std::mem::take(&mut self.token);
        let retained = self.retained.take();
        // 保留原名额直至有限时清理结束，取消洪峰不能生成独立的无限后台队列。
        runtime.spawn(async move {
            let _retained = retained;
            let _ = ledger
                .invoke(SCRIPT, &SHA, &[&ledger.capacity, "0", &token, "1", "1"])
                .await;
        });
    }
}
