//! 冻结全目标预检先于应用的流程顺序，避免独立目标过早开放发布。

use crate::config::operations::MAX_TARGETS;
use crate::control::actions::definition::definition;
use nasa::saga::pgsql::DefinitionRegistry;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
pub(in crate::admin::operations) struct Summary {
    pub definitions: usize,
    pub max_targets: usize,
    pub sha256: String,
}

/// 业务作用：一次构建全部受支持目标数量的不可变定义和整体摘要，供各 Admin 复验同一编排合同。
///
/// 参数说明: 无。
///
/// 返回：最多一百二十八份固定定义；构造或 NASA 合同校验不成立时拒绝工作流就绪。
pub(super) fn registry() -> anyhow::Result<(DefinitionRegistry, Summary)> {
    let mut registry = DefinitionRegistry::new();
    let mut digest = Sha256::new();
    digest.update(b"naway-workflow-registry\0");
    digest.update((MAX_TARGETS as u32).to_be_bytes());
    for targets in 1..=MAX_TARGETS {
        let workflow = definition(targets)?;
        let name = workflow.name().as_str();
        digest.update((name.len() as u32).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(workflow.version().get().to_be_bytes());
        digest.update(workflow.digest().as_bytes());
        registry.register(workflow)?;
    }
    let summary = Summary {
        definitions: registry.len(),
        max_targets: MAX_TARGETS,
        sha256: crate::admin::operations::model::hex(&digest.finalize()),
    };
    Ok((registry, summary))
}
