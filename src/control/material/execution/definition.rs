//! 材料工作流以原节点为步骤单位，所有节点准备确认之后才进入任何节点文件决定。

use crate::config::operations::MAX_TARGETS;
use anyhow::{ensure, Result};
use nasa::saga::{
    CancelMode, Compensation, DefinitionVersion, ResolutionMode, ResolutionSpec, ServiceIdentity,
    StepDefinition, StepName, TimeoutPolicy, WorkflowDefinition, WorkflowName,
};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

/// 业务作用：从原节点数构造独立材料工作流，重复逻辑目标不能重复占用准备步骤或备份容量。
///
/// 参数说明：
/// - `nodes`：已批准完整目标集合去重后的冻结节点数，不取当前在线数量。
///
/// 返回：全部prepare先于全部apply的可补偿定义；节点数越界或NASA合同非法时拒绝。
pub(crate) fn definition(nodes: usize) -> Result<WorkflowDefinition> {
    ensure!(
        (1..=MAX_TARGETS).contains(&nodes),
        "material workflow node count exceeds bounds"
    );
    let owner = ServiceIdentity::new("naway-data")?;
    let mut steps = Vec::with_capacity(nodes * 2);
    // 全节点准备是文件方向的前置屏障；不能将在线子集或某一来源的成功当成全批准备。
    for phase in ["prepare", "apply"] {
        for index in 0..nodes {
            steps.push(StepDefinition::new(
                StepName::new(format!("{phase}-{index:03}"))?,
                owner.clone(),
                Compensation::Compensable,
                CancelMode::ResolveOnly,
                ResolutionSpec::allowed(ResolutionMode::Poll, Duration::from_secs(300)),
                Duration::from_secs(30),
                TimeoutPolicy::CompensateLateSuccess,
            ));
        }
    }
    Ok(WorkflowDefinition::new(
        WorkflowName::new(format!("naway-material-nodes-{nodes}"))?,
        DefinitionVersion::new(1)?,
        steps,
    )?)
}

/// 业务作用：复用固定数量的材料定义，节点恢复和重复查询不重建整份工作流步骤。
///
/// 参数说明：
/// - `nodes`：原任务冻结的节点数量。
///
/// 返回：最多一百二十八份不可变共享定义；非法数量不取得缓存槽，也不改变配置动作定义。
pub(crate) fn cached(nodes: usize) -> Result<Arc<WorkflowDefinition>> {
    static DEFINITIONS: OnceLock<[OnceLock<Arc<WorkflowDefinition>>; MAX_TARGETS]> =
        OnceLock::new();
    ensure!(
        (1..=MAX_TARGETS).contains(&nodes),
        "material workflow node count exceeds bounds"
    );
    let slots = DEFINITIONS.get_or_init(|| std::array::from_fn(|_| OnceLock::new()));
    let slot = &slots[nodes - 1];
    if let Some(definition) = slot.get() {
        return Ok(definition.clone());
    }
    let _ = slot.set(Arc::new(definition(nodes)?));
    Ok(slot
        .get()
        .expect("fixed material definition initialized")
        .clone())
}
