//! 配置动作的有限领域与管理权限映射。

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Domain {
    Gateway,
    Sentinel,
    InterfaceGuard,
}

impl Domain {
    /// 业务作用：把提案和节点命令映射到同一固定持久键与权限资源，不接受任意操作名。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：稳定领域键及对应现有管理权限。
    pub(crate) fn identity(self) -> (&'static str, crate::config::model::AdminResource) {
        use crate::config::model::AdminResource;
        match self {
            Self::Gateway => ("gateway", AdminResource::Config),
            Self::Sentinel => ("sentinel", AdminResource::Sentinel),
            Self::InterfaceGuard => ("interface-guard", AdminResource::InterfaceGuard),
        }
    }
}
