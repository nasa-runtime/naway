//! 到期目录只驱动有限 future，进程级许可约束重叠轮次的实际网络并发。

use super::state::ProbeKey;
use super::{
    apply_probe_result, probe_instance, ActiveHealthChecker, ActiveHealthPolicy,
    HealthInstanceTarget,
};
use futures::{stream, StreamExt};
use std::sync::Arc;
use std::time::Instant;

pub(super) const MAX_CONCURRENT_PROBES: usize = 64;

pub(super) struct ProbeJob {
    pub key: ProbeKey,
    pub instance: HealthInstanceTarget,
    pub policy: ActiveHealthPolicy,
}

pub(super) struct ProbeResult {
    pub key: ProbeKey,
    pub ok: bool,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
}

impl ActiveHealthChecker {
    /// 业务作用：用固定宽度的异步窗口推进当前目录，取消整轮时同时撤下在途和待发探测。
    ///
    /// 参数说明：
    /// - `jobs`：本轮去重后的到期端点，尚未取得网络名额。
    /// - `owner`：本轮发布身份，实际发起前仍需复验。
    ///
    /// 返回：无；完成时仍获权的结果立即保留阈值，未执行项不作为失败，不创建独立等待任务。
    pub(super) async fn execute_probes(&self, jobs: Vec<ProbeJob>, owner: &Arc<()>) {
        let mut pending = stream::iter(jobs)
            .map(|job| self.execute_probe(job, owner))
            .buffer_unordered(MAX_CONCURRENT_PROBES);
        while let Some(result) = pending.next().await {
            if let Some(result) = result {
                // 完成的网络观测始终计数；失去发布权不会抹掉真实开销，也不会授予状态更新权。
                self.metrics.inc_active_health_probe(result.ok);
                let mut state = self.state.lock().expect("health state mutex poisoned");
                if !Arc::ptr_eq(&state.owner, owner) {
                    // 失权后只能报告实际开销，迟到结果不能更新新轮次已接管的连续阈值。
                    continue;
                }
                if let Some(entry) = state.instances.get_mut(&result.key) {
                    // 已确认结果先保留，避免其它请求取消时丢掉合法的连续成功或失败证据。
                    apply_probe_result(
                        entry,
                        result.ok,
                        result.healthy_threshold,
                        result.unhealthy_threshold,
                        &result.key.endpoint,
                    );
                }
            }
        }
    }

    /// 业务作用：在共享容量和当前轮次同时有效时启动一次探测，避免旧队列继续消耗上游资源。
    ///
    /// 参数说明：
    /// - `job`：已冻结的服务、端点和策略。
    /// - `owner`：拥有当前目录发布权的轮次身份。
    ///
    /// 返回：已执行探测的结果；许可关闭或轮次失权时返回空，许可由 future 生命周期释放。
    async fn execute_probe(&self, job: ProbeJob, owner: &Arc<()>) -> Option<ProbeResult> {
        let _permit = self.permits.acquire().await.ok()?;
        let client = {
            let mut state = self.state.lock().expect("health state mutex poisoned");
            if !Arc::ptr_eq(&state.owner, owner) {
                // 等待容量期间可能换代，旧轮次不能重新填入被新策略撤销的客户端或开始外呼。
                return None;
            }
            let entry = state.instances.get_mut(&job.key)?;
            // 排队不算探测，间隔和抖动序列只从真正获得启动权时推进。
            entry.last_probe = Some(Instant::now());
            entry.probe_sequence = entry.probe_sequence.wrapping_add(1);
            state.clients.for_target(&job.instance, &job.policy)
        };
        let ok = probe_instance(&client, &job.instance, &job.policy).await;
        Some(ProbeResult {
            key: job.key,
            ok,
            healthy_threshold: job.policy.healthy_threshold,
            unhealthy_threshold: job.policy.unhealthy_threshold,
        })
    }
}
