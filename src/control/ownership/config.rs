//! 控制面归属、显式引用授权与委派容量声明。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OwnershipCfg {
    pub enabled: bool,
    pub workspaces: BTreeMap<String, WorkspaceCfg>,
    /// 使用种类和稳定对象 id 定位，不能通过用户可改的显示名改变归属。
    pub objects: BTreeMap<String, ObjectCfg>,
    /// 只有平台配置可声明跨域授权；工作区编辑入口不能修改这张表。
    pub grants: Vec<GrantCfg>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCfg {
    pub tenant: String,
    pub environment: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// 主体 id 必须存在于管理面认证目录，HTTP header 不能新增主体或工作区。
    pub members: BTreeMap<String, Role>,
    /// 平台授权的集群读取节点身份；空列表不提供工作区集群视图，不能由委派动作扩大。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cluster_nodes: Vec<String>,
    pub quota: QuotaCfg,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaCfg {
    pub max_objects: usize,
    pub max_inflight: usize,
    pub max_pending_changes: usize,
    pub max_state_entries: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectCfg {
    pub workspace: String,
    /// 同种类名称只在本工作区唯一；底层稳定 id 保留原有路由/服务引用语义。
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCfg {
    pub source_workspace: String,
    /// 精确对象身份，不接受通配符或整个租户的隐式授权。
    pub target: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Operator,
    Administrator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Review,
    Delegate,
    Rollback,
}

impl Role {
    /// 业务作用：把工作区角色转换为固定能力，避免角色序数被误当作全平台权限。
    ///
    /// 参数说明：
    /// - `action`：是工作区入口执行的动作。
    ///
    /// 返回：viewer 只读、operator 可提交，administrator 可复核、回滚和委派。
    pub fn allows(self, action: Action) -> bool {
        match action {
            Action::Read => true,
            Action::Write => self >= Self::Operator,
            Action::Review | Action::Delegate | Action::Rollback => self == Self::Administrator,
        }
    }
}
