//! 节点基线与文件决定共用一次有界观察，取消等待不能提前归还磁盘工作的许可。

use super::Journal;
use crate::{
    config::GatewaySnapshot,
    control::{
        baseline::NodeBaseline,
        publication_status::{PublicationStatus, Storage},
    },
};
use std::{sync::Arc, time::Duration};

pub(crate) struct Observation {
    pub baseline: Option<NodeBaseline>,
    pub publication: PublicationStatus,
}

impl Observation {
    /// 业务作用：同时撤下动作基线与提交字段，避免读取失败后拼接不同轮次的证据。
    ///
    /// 参数说明：
    /// - `state`：无提交证据的固定原因。
    ///
    /// 返回：仅携带低敏状态且没有发布基线的当前观察。
    pub(crate) fn empty(state: &'static str) -> Self {
        Self {
            baseline: None,
            publication: PublicationStatus::empty(state),
        }
    }
}

impl Journal {
    /// 业务作用：同次复验永久目录、文件决定与活动配置，保护异常不能被旧的启动状态掩盖。
    ///
    /// 参数说明：
    /// - `snapshot`：与报告或本机概览绑定的活动配置快照。
    ///
    /// 返回：一秒内确认的文件决定，空闲且原文身份完整时附带基线；未知状态不携带旧提交字段。
    pub(crate) async fn observe(self: &Arc<Self>, snapshot: Arc<GatewaySnapshot>) -> Observation {
        let Ok(permit) = self.observation.clone().try_acquire_owned() else {
            return Observation::empty("unavailable");
        };
        let owner = self.clone();
        // 许可进入真实阻塞工作，外层超时或任务取消不得允许下一轮再积累一个磁盘读取任务。
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let Some(storage) = owner.storage.try_lock() else {
                return Observation::empty("unavailable");
            };
            // 待完成决定可与仍服务的旧快照并存；这里验证永久管理绑定，不能误用候选完成门。
            if owner.verify_expected(storage.as_ref()).is_err()
                || !snapshot.admin_management.as_ref().is_some_and(|plan| {
                    plan.matches_journal(&owner.identity.node_id, &owner.identity.cluster_id)
                })
            {
                return Observation::empty("protected");
            }
            let Some(storage) = storage.as_ref() else {
                return Observation::empty("uninitialized");
            };
            #[cfg(feature = "node-actions")]
            if storage.action().is_some() {
                // 现有文件状态协议不能表达远程效果；撤下新提案基线，不能把仍占用动作槽的节点报为空闲。
                return Observation::empty("protected");
            }
            let plan = storage.local();
            let state = match plan.map(|plan| plan.direction) {
                None => "idle",
                Some(super::local::Direction::Preparing) => "preparing",
                Some(super::local::Direction::Forward) => "forward",
                Some(super::local::Direction::Backward) => "backward",
            };
            let publication = PublicationStatus {
                schema: 1,
                state,
                storage: Some(Storage {
                    cluster_id: owner.identity.cluster_id.clone(),
                    store_id: owner.identity.store_id.clone(),
                    node_admission_epoch: storage.admission_epoch().to_string(),
                    revision: storage.revision().to_string(),
                    operation_id: plan.map(|plan| plan.operation.clone()),
                }),
            };
            // 文件决定未结束就不为新提案提供受理基线；只读状态本身不解除写入保护。
            let baseline = if plan.is_none() && snapshot.config_fingerprint.is_some() {
                snapshot.document_identity.as_ref().map(|identity| {
                    NodeBaseline::from_parts(
                        owner.identity.cluster_id.clone(),
                        owner.identity.store_id.clone(),
                        storage.admission_epoch(),
                        identity.digest(),
                    )
                })
            } else {
                None
            };
            Observation {
                baseline,
                publication,
            }
        });
        tokio::time::timeout(Duration::from_secs(1), work)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_else(|| Observation::empty("unavailable"))
    }
}
