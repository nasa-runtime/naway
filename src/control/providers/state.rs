//! 来源目录和合并视图随同一 GatewaySnapshot 发布；不存在可提前提交水位的第二事实源。

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{ensure, Result};

use super::{
    compile,
    model::Declaration,
    plan::Plan,
    registry::{Registry, View},
};
use crate::config::model::GatewayConfig;

pub(crate) struct Observation {
    pub(super) signature: [u8; 32],
    pub(super) incarnation: u64,
    pub(super) source: String,
    pub(super) document: Declaration,
    pub(super) workload: Option<super::workload::State>,
    pub(super) observed: Instant,
}

#[derive(Default)]
pub(crate) struct Input {
    pub previous: Option<Arc<Snapshot>>,
    pub observation: Option<Observation>,
}

pub(crate) struct Snapshot {
    pub(super) plan: Arc<Plan>,
    pub(super) registry: Registry,
    pub(super) view: View,
    pub(super) report: compile::Report,
    pub(super) workloads: BTreeMap<String, super::workload::State>,
    valid_until: Option<Instant>,
}

impl Input {
    /// 业务作用：在本地候选内更新来源证据并物化完整声明，任何失败均不改变活动快照的水位或租期。
    ///
    /// 参数说明：
    /// - `cfg`：为一次独立加载的本地候选
    /// - `directory`：是本地凭据路径根。
    ///
    /// 返回：与本候选绑定的不可变来源快照；关闭时为 None，旧来源观测或非法语义拒绝整个候选。
    pub(crate) fn prepare(
        self,
        cfg: &mut GatewayConfig,
        directory: &Path,
    ) -> Result<Option<Arc<Snapshot>>> {
        let plan = Plan::build(
            cfg,
            directory,
            self.previous.as_ref().map(|snapshot| &snapshot.plan),
        )?;
        let Some(plan) = plan else {
            // 旧 worker 不能借迟到响应重新开启已被本地权威关闭的来源。
            ensure!(
                self.observation.is_none(),
                "configuration providers were disabled"
            );
            return Ok(None);
        };
        let mut workloads = self
            .previous
            .as_ref()
            .filter(|snapshot| snapshot.plan.signature == plan.signature)
            .map(|snapshot| snapshot.workloads.clone())
            .unwrap_or_default();
        let mut registry = match self
            .previous
            .filter(|snapshot| snapshot.plan.signature == plan.signature)
        {
            Some(previous) => previous.registry.clone(),
            None => Registry::new(
                plan.sources
                    .values()
                    .map(|source| source.authority.clone())
                    .collect(),
            )?,
        };
        let now = Instant::now();
        let candidate = if let Some(observation) = self.observation {
            ensure!(
                observation.signature == plan.signature
                    && observation.incarnation == plan.incarnation
                    && observation.observed <= now,
                "provider observation authority changed"
            );
            let source = plan
                .sources
                .get(&observation.source)
                .ok_or_else(|| anyhow::anyhow!("provider observation source missing"))?;
            if let Some(workload) = observation.workload {
                ensure!(
                    matches!(
                        source.transport,
                        super::plan::Transport::Docker(_)
                            | super::plan::Transport::Nomad(_)
                            | super::plan::Transport::Ecs(_)
                    ),
                    "unexpected workload projection"
                );
                // 标签水位属于完整候选，编译或资源准备失败时随候选丢弃，不能提前污染下一次重读。
                workloads.insert(observation.source.clone(), workload);
            }
            // 合并前单独验证来源的类型和能力，低优先级或冲突状态不能掩盖非法安全字段与越权声明。
            let isolated = Registry::new(vec![source.authority.clone()])?.stage(
                &observation.source,
                observation.document.clone(),
                now,
            )?;
            compile::validate(cfg, &isolated.view, &plan.policies).map_err(|_| {
                anyhow::anyhow!("provider declaration violates schema or authority")
            })?;
            registry.stage(
                &observation.source,
                observation.document,
                observation.observed,
            )?
        } else {
            registry.expire(now)?
        };
        // 远端非法值不进入 reload 审计或错误正文，避免解析器把任意载荷反射到管理面与日志。
        let report = compile::apply(cfg, &candidate.view, &plan.policies)
            .map_err(|_| anyhow::anyhow!("provider graph rejected"))?;
        let view = candidate.view.clone();
        let valid_until = candidate.valid_until;
        // 此处只提交私有候选目录；只有外层完整构建和资源准备成功后的 ArcSwap 才让水位生效。
        registry.authorize(candidate)?.commit();
        Ok(Some(Arc::new(Snapshot {
            plan,
            registry,
            view,
            report,
            workloads,
            valid_until,
        })))
    }
}

impl Snapshot {
    /// 业务作用：在完整资源准备结束后复验来源时间权威，阻止构建跨过租期后迟到开放旧图。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：全部活动证据仍有效时为 true；到期必须重新生成撤回候选，不得直接发布。
    pub(crate) fn is_fresh(&self) -> bool {
        self.valid_until
            .is_none_or(|deadline| Instant::now() < deadline)
    }

    /// 业务作用：判断远端动态配置是否试图更换本地来源权威，而不是只改变业务声明。
    ///
    /// 参数说明：
    /// - `other`：是待发布候选的来源计划。
    ///
    /// 返回：来源端点、权限、归属、凭据和资源预算的摘要一致时为 true。
    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        self.plan.signature == other.plan.signature
    }
}
