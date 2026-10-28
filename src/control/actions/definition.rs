//! 目标数量决定固定工作流，预检屏障由步骤顺序直接约束。

use crate::config::operations::MAX_TARGETS;
use nasa::saga::{
    CancelMode, Compensation, DefinitionVersion, ResolutionMode, ResolutionSpec, ServiceIdentity,
    StepDefinition, StepName, TimeoutPolicy, WorkflowDefinition, WorkflowName,
};
use std::time::Duration;

/// 业务作用：把冻结目标集合映射为先全部预检、后逐目标应用的唯一 Saga，失败由同一引擎逆序补偿。
///
/// 参数说明：
/// - `targets`：按稳定节点身份排序后冻结的目标数量，不随在线成员改变。
///
/// 返回：每目标两个可补偿步骤；数量越界或任何步骤合同非法时拒绝构造。
pub(crate) fn definition(targets: usize) -> anyhow::Result<WorkflowDefinition> {
    anyhow::ensure!(
        (1..=MAX_TARGETS).contains(&targets),
        "workflow target count outside bounds"
    );
    let owner = ServiceIdentity::new("naway-data")?;
    let mut steps = Vec::with_capacity(targets * 2);
    // 正向顺序本身形成全目标屏障；不能交错 prepare/apply，让一个节点提前发布。
    for phase in ["prepare", "apply"] {
        for index in 0..targets {
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
        WorkflowName::new(format!("naway-config-targets-{targets}"))?,
        DefinitionVersion::new(1)?,
        steps,
    )?)
}

/// 业务作用：让节点反复读取持久事实时复用有限固定定义，不在每次磁盘校验重建全部步骤。
///
/// 参数说明：
/// - `targets`：原动作冻结的目标总数。
///
/// 返回：该数量对应的不可变共享定义；最多缓存一百二十八种，非法数量不创建缓存槽。
#[cfg(feature = "node-actions")]
pub(crate) fn cached(targets: usize) -> anyhow::Result<std::sync::Arc<WorkflowDefinition>> {
    use std::sync::{Arc, OnceLock};
    static DEFINITIONS: OnceLock<[OnceLock<Arc<WorkflowDefinition>>; MAX_TARGETS]> =
        OnceLock::new();
    anyhow::ensure!(
        (1..=MAX_TARGETS).contains(&targets),
        "workflow target count outside bounds"
    );
    let slots = DEFINITIONS.get_or_init(|| std::array::from_fn(|_| OnceLock::new()));
    let slot = &slots[targets - 1];
    if let Some(definition) = slot.get() {
        return Ok(definition.clone());
    }
    let candidate = Arc::new(definition(targets)?);
    let _ = slot.set(candidate);
    Ok(slot.get().expect("fixed definition initialized").clone())
}
