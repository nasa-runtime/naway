//! 当前实体只使用各自有效期内的节点证据，聚合与网络等待不能延长原事实寿命。

use std::time::{Duration, Instant};

pub(super) struct Window {
    until: Instant,
}

impl Window {
    /// 业务作用：为一次当前读取绑定原聚合发布的有效期限，不以请求开始时刻续期。
    ///
    /// 参数说明：
    /// - `at`：原聚合结果的单调时钟发布时间。
    /// - `period`：已验证的本机采样周期。
    ///
    /// 返回：至多三个原采样周期的交付窗口，后续节点证据只能缩短该窗口。
    pub(super) fn new(at: Instant, period: Duration) -> Self {
        Self {
            until: at + period * 3,
        }
    }

    /// 业务作用：把实际参与事实或节点角色证明的原样本期限并入交付窗口。
    ///
    /// 参数说明：
    /// - `at`：该节点原样本的单调时钟采集时刻。
    /// - `period`：该样本自己声明且已经验证的采样周期。
    ///
    /// 返回：保留最早截止，不因节点重新上传相同样本或更慢的其它节点而延长期限。
    pub(super) fn include(&mut self, at: Instant, period: Duration) {
        self.until = self.until.min(at + period * 3);
    }

    /// 业务作用：在编码与授权复验后计算浏览器可使用的剩余寿命，亚毫秒余量也拒绝交付。
    ///
    /// 参数说明：
    /// - `now`：即将构造响应头时的当前单调时钟。
    ///
    /// 返回：仍有完整毫秒余量时的保守期限；已到期、余量不足或不能精确表示时为空。
    pub(super) fn remaining_ms(&self, now: Instant) -> Option<u64> {
        self.until
            .checked_duration_since(now)
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .filter(|millis| *millis > 0)
    }
}
