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

impl Target {
    /// 业务作用：在受理和原记录读取边界采用同一规范顺序，重复身份不能在批次分组时被覆盖。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用原节点与逻辑目标组成的稳定排序键，不分配副本。
    pub(crate) fn identity(&self) -> (&str, u8, &str, &str) {
        (
            &self.node_id,
            self.target.kind as u8,
            &self.target.listener,
            &self.target.entry,
        )
    }

    /// 业务作用：复验原提案的完整目标合同，存储读取和节点传输不能放宽首次受理的基线要求。
    ///
    /// 参数说明：
    /// - `targets`：已经排序且不可由当前成员补齐的全部原目标。
    /// - `cluster`：原持久提案所属的唯一发行集群。
    ///
    /// 返回：数量、字段、唯一顺序及同节点基线全部一致时为真；缺少材料代或异常记录拒绝。
    pub(crate) fn valid_set(targets: &[Self], cluster: &str) -> bool {
        if targets.is_empty() || targets.len() > crate::config::operations::MAX_TARGETS {
            return false;
        }
        targets.iter().enumerate().all(|(index, target)| {
            crate::config::operations::token(&target.node_id, 128)
                && crate::config::operations::token(&target.boot_id, 128)
                && target.base_version > 0
                && target.base_fingerprint.len() == 16
                && target
                    .base_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && target.node_baseline.valid()
                && target.node_baseline.cluster_id == cluster
                && target.target.valid()
                && crate::tls::keypair::valid_material_generation(&target.material_generation)
                && target
                    .certificate_etag
                    .strip_prefix("\"sha256-")
                    .and_then(|value| value.strip_suffix('"'))
                    .is_some_and(crate::tls::keypair::valid_material_generation)
                && (index == 0
                    || (targets[index - 1].identity() < target.identity()
                        && (targets[index - 1].node_id != target.node_id
                            || (targets[index - 1].boot_id == target.boot_id
                                && targets[index - 1].base_version == target.base_version
                                && targets[index - 1].base_fingerprint
                                    == target.base_fingerprint
                                && targets[index - 1].node_baseline == target.node_baseline))))
        })
    }
}
