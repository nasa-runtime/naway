//! 把有限数据库往返转换成不可延长的签名预算，墙钟跳变只会撤销而不会续期。

use crate::admin::operations::model::Error;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(super) struct Stamp {
    wall: u64,
    monotonic: Instant,
}

pub(super) struct Proof {
    confirmed: Stamp,
    deadline: Instant,
    wall_limit: u64,
}

impl Stamp {
    /// 业务作用：同时观察签名使用的 Unix 时间和不可回拨时钟，无法表示的系统时间直接拒绝。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法当前观察；时间在 epoch 之前或超过协议整数域时不可签发。
    pub(super) fn now() -> Result<Self, Error> {
        let monotonic = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_millis();
        let wall = u64::try_from(wall)
            .ok()
            .filter(|value| *value > 0 && *value <= i64::MAX as u64)
            .ok_or(Error::Unavailable)?;
        Ok(Self {
            wall,
            monotonic,
        })
    }
}

impl Proof {
    /// 业务作用：仅在数据库时钟落入本机有限往返包络时承认已提交租约，并扣除固定安全余量。
    ///
    /// 参数说明：
    /// - `started`：进入共享事务前的本机观察。
    /// - `finished`：明确 COMMIT 返回后的本机观察。
    /// - `observed`：数据库在取得目标锁后读取的实际毫秒时刻。
    /// - `expires`：同一事务保存的三十秒租约绝对截止。
    ///
    /// 返回：原单调安全截止和墙钟上限；长往返、时钟分歧或期限不合约均拒绝。
    pub(super) fn confirmed(
        started: Stamp,
        finished: Stamp,
        observed: i64,
        expires: i64,
    ) -> Result<Self, Error> {
        let elapsed = finished
            .monotonic
            .checked_duration_since(started.monotonic)
            .ok_or(Error::Unavailable)?
            .as_millis();
        let observed = u64::try_from(observed).map_err(|_| Error::Unavailable)?;
        let expires = u64::try_from(expires).map_err(|_| Error::Unavailable)?;
        if elapsed > 1000
            || observed == 0
            || expires.checked_sub(observed) != Some(30_000)
            || finished
                .wall
                .abs_diff(started.wall.saturating_add(elapsed as u64))
                > 1000
            || observed < started.wall.saturating_sub(1000)
            || observed > finished.wall.saturating_add(1000)
        {
            return Err(Error::Unavailable);
        }
        let remaining = 30_000 - elapsed as u64 - 6000;
        let deadline = finished
            .monotonic
            .checked_add(Duration::from_millis(remaining))
            .ok_or(Error::Unavailable)?;
        let wall_limit = expires.checked_sub(6000).ok_or(Error::Unavailable)?;
        Ok(Self {
            confirmed: finished,
            deadline,
            wall_limit,
        })
    }

    /// 业务作用：从原证明消费一次当前签名窗口，调度暂停和后续时钟变动不得延长旧租约。
    ///
    /// 参数说明：
    /// - `now`：即将签名时的本机双时钟观察。
    ///
    /// 返回：最多二十秒且仍有至少两秒的窗口；漂移、倒退或预算不足拒绝。
    pub(super) fn window(self, now: Stamp) -> Result<(u64, u64), Error> {
        let elapsed = now
            .monotonic
            .checked_duration_since(self.confirmed.monotonic)
            .ok_or(Error::Unavailable)?
            .as_millis();
        if elapsed > u128::from(u64::MAX)
            || now
                .wall
                .abs_diff(self.confirmed.wall.saturating_add(elapsed as u64))
                > 1000
        {
            return Err(Error::Unavailable);
        }
        let remaining = self
            .deadline
            .checked_duration_since(now.monotonic)
            .ok_or(Error::Expired)?
            .as_millis()
            .min(20_000) as u64;
        let expires = now
            .wall
            .checked_add(remaining)
            .ok_or(Error::Unavailable)?
            .min(self.wall_limit);
        if expires > i64::MAX as u64 || expires.saturating_sub(now.wall) < 2000 {
            return Err(Error::Expired);
        }
        Ok((now.wall, expires))
    }
}
