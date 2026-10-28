//! 集群配置动作的共同业务合同，编排与目标节点使用同一冻结定义。

#[cfg(feature = "node-actions")]
pub(crate) mod absence;
pub(crate) mod authorization;
#[cfg(feature = "node-actions")]
pub(crate) mod command;
#[cfg(any(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
pub(crate) mod definition;
pub(crate) mod domain;
#[cfg(feature = "node-actions")]
pub(crate) mod effect;
#[cfg(feature = "node-actions")]
pub(crate) mod receipt;
#[cfg(feature = "node-actions")]
pub(crate) mod release;
