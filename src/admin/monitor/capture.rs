//! 定时采集与管理上报共用单一当前样本，配置换代不会等待旧周期才能建立事实。

use super::{model, source, Publication, Runtime, IDLE_MS};
use crate::admin::AdminState;
use crate::config::GatewaySnapshot;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

impl Runtime {
    /// 业务作用：确认本机或当前管理目标仍有有限观察需求，空闲节点不持续采集。
    ///
    /// 参数说明：
    /// - `snapshot`：本轮采用的监控开关与周期。
    ///
    /// 返回：启用且至少一种兴趣未到期时为真，不续期任何观察权。
    pub(super) fn interested(&self, snapshot: &GatewaySnapshot) -> bool {
        let plan = &snapshot.admin_monitor;
        let interest = self.last_interest.load(Ordering::Acquire);
        let now = self.elapsed_ms();
        let local = interest != 0
            && now.saturating_sub(interest) <= IDLE_MS.max(plan.period.as_millis() as u64 * 3);
        plan.enabled && (local || now < self.remote_until.load(Ordering::Acquire))
    }

    /// 业务作用：串行建立同代原生事实，周期内复用样本，配置换代立即建立新基线。
    ///
    /// 参数说明：
    /// - `state`：当前配置槽和运行事实，不通过外部网络采集。
    /// - `snapshot`：上报或聚合使用的完整已发布配置。
    ///
    /// 返回：当前样本与原采集时刻；失权、空闲或校验失败时为空，不能发布旧代结果。
    pub(super) fn capture(
        &self,
        state: &AdminState,
        snapshot: &Arc<GatewaySnapshot>,
    ) -> Option<Arc<Publication>> {
        let mut sequence = self.sampling.lock();
        // 采样锁只协调控制面事实，不能给旧快照补授当前配置的身份或观察需求。
        if !self.interested(snapshot) || !Arc::ptr_eq(&state.snap.load_full(), snapshot) {
            return None;
        }
        let previous = self.latest.load_full();
        if let Some(current) = &previous {
            if current.sample.state.config_version == snapshot.version
                && current.sample.state.config_fingerprint
                    == snapshot
                        .config_fingerprint
                        .map(|value| format!("{value:016x}"))
                && current.sample.sampling_period_ms
                    == snapshot.admin_monitor.period.as_millis() as u64
                && current.at.elapsed() < snapshot.admin_monitor.period
            {
                return Some(current.clone());
            }
        }
        *sequence = sequence.checked_add(1)?;
        let at = Instant::now();
        let mut sample = source::sample(state, self, *sequence, snapshot);
        // 配置发布可能发生在采集期间；失败只撤下输出，不用新身份标记旧服务或工作区事实。
        if !model::validate(&mut sample) || !Arc::ptr_eq(&state.snap.load_full(), snapshot) {
            self.latest.store(None);
            return None;
        }
        let publication = Arc::new(Publication::new(
            Arc::new(sample),
            previous.map(|value| value.sample.clone()),
            at,
        ));
        // 原生事实先发布，HTTP仅在读取时编码；跨配置基线由Publication拒绝，不产生虚假速率。
        self.latest.store(Some(publication.clone()));
        Some(publication)
    }
}
