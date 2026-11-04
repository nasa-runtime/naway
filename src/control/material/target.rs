//! 原目标声明冻结启动、配置与材料代，不能由当前节点状态补齐旧意图。

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub node_id: String,
    pub boot_id: String,
    pub base_version: u64,
    pub base_fingerprint: String,
    pub node_baseline: crate::control::baseline::NodeBaseline,
    pub target: crate::tls::targets::Target,
    pub certificate_etag: String,
    pub material_generation: String,
}
