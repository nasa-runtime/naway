//! 带外订阅只投影唯一上游目录，不自行发现地址或创建第二份实例表。

use super::{subscription, LoadFeedbackPolicy};
use crate::upstream::{UpstreamDirectory, UpstreamInstance};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct Target {
    pub service: Arc<str>,
    pub instance: Arc<UpstreamInstance>,
    pub policy: LoadFeedbackPolicy,
}

impl Target {
    /// 业务作用：用服务、传输身份和实例入场代际标识订阅，防止同地址重建复用旧任务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只复制共享字符串引用的控制面键，不进入业务请求热路径。
    pub(crate) fn key(&self) -> (Arc<str>, Arc<str>, u64) {
        (
            self.service.clone(),
            self.instance.health_key.clone(),
            self.instance.feedback_generation,
        )
    }
}

impl UpstreamDirectory {
    /// 业务作用：从当前新鲜目录生成有界订阅目标，实例不足或被下线时不主动探测其它地址。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最多固定数量的共享实例引用；总体超限则拒绝整批反馈，业务调度仍回落基础算法。
    pub(crate) fn orca_targets(&self) -> anyhow::Result<Vec<Target>> {
        let mut targets = Vec::new();
        for (service, snapshot) in &self.services {
            let Some(subscription) = &snapshot.load_feedback.out_of_band else {
                continue;
            };
            let instances = self.instances_for(service, snapshot);
            for instance in instances
                .as_slice()
                .iter()
                .filter(|instance| instance.is_selectable())
            {
                anyhow::ensure!(
                    targets.len() < subscription::MAX_SUBSCRIPTIONS,
                    "ORCA subscription capacity exceeded"
                );
                subscription.validate_transport(
                    instance.protocol,
                    instance.uri.starts_with("http://"),
                    false,
                )?;
                targets.push(Target {
                    service: Arc::from(service.as_str()),
                    instance: instance.clone(),
                    policy: snapshot.load_feedback.clone(),
                });
            }
        }
        Ok(targets)
    }

    /// 业务作用：在记录报告前复验原实例仍属于当前目录，阻止撤销、过期和同地址重建后的迟到反馈。
    ///
    /// 参数说明：
    /// - `target`：订阅启动时固定的目录投影。
    ///
    /// 返回：身份、入场代际、策略及可用性仍一致时为 true，不修改健康或发现状态。
    pub(crate) fn orca_target_current(&self, target: &Target) -> bool {
        let Some(service) = self.services.get(target.service.as_ref()) else {
            return false;
        };
        if service.load_feedback.out_of_band != target.policy.out_of_band {
            return false;
        }
        self.instances_for(&target.service, service)
            .as_slice()
            .iter()
            .any(|instance| {
                instance.is_selectable()
                    && instance.health_key == target.instance.health_key
                    && instance.feedback_generation == target.instance.feedback_generation
                    && instance.protocol == target.instance.protocol
                    && instance
                        .tls_profile
                        .as_ref()
                        .is_none_or(|profile| profile.allows_new_requests())
            })
    }
}
