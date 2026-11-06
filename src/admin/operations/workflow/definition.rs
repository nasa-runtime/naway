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
/// 返回：配置与材料各自最多一百二十八份独立定义；不具备节点动作时只登记配置定义，未知历史定义拒绝就绪。
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
    #[cfg(feature = "node-actions")]
    {
        // 材料与配置共享同一个引擎和配额，但必须保留独立定义；开关关闭也不能把历史材料实例解释为配置动作。
        digest.update(b"naway-material-workflows\0");
        digest.update((MAX_TARGETS as u32).to_be_bytes());
        for nodes in 1..=MAX_TARGETS {
            let workflow = crate::control::material::execution::definition::definition(nodes)?;
            let name = workflow.name().as_str();
            digest.update((name.len() as u32).to_be_bytes());
            digest.update(name.as_bytes());
            digest.update(workflow.version().get().to_be_bytes());
            digest.update(workflow.digest().as_bytes());
            registry.register(workflow)?;
        }
    }
    let summary = Summary {
        definitions: registry.len(),
        max_targets: MAX_TARGETS,
        sha256: crate::admin::operations::model::hex(&digest.finalize()),
    };
    Ok((registry, summary))
}
