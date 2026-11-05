//! 原目标材料条件独立查询，不读取候选私钥、不创建提案或持久执行动作。

mod client;
pub(in crate::admin) mod command;
mod delivery;
mod node;
mod run;
mod session;
pub(in crate::admin::management) mod wire;

pub(in crate::admin) use super::actions::window::Window as RequestWindow;
pub(in crate::admin::management) use client::Channel;
pub(in crate::admin::management) use delivery::Offer;
pub(in crate::admin) use run::{Completed, inspect, recheck};

pub(in crate::admin) struct Inspection {
    pub batch: crate::tls::keypair::conditions::Batch,
    pub installations: Option<crate::control::material::installation::Batch>,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::admin) enum Reason {
    Unsupported,
    Disabled,
    Unavailable,
    Capacity,
    Expired,
    Denied,
    BaselineChanged,
    TargetAbsent,
    ExternalSource,
    Storage,
    ImpactUnproven,
}

impl From<crate::tls::keypair::conditions::Unavailable> for Reason {
    /// 业务作用：跨节点只传递固定材料失败类别，不把本机路径或底层错误作为响应。
    ///
    /// 参数说明：
    /// - `reason`：完整材料观察明确拒绝的原因。
    ///
    /// 返回：对应低敏类别，失败不会被改写为无影响或未受管成功。
    fn from(reason: crate::tls::keypair::conditions::Unavailable) -> Self {
        use crate::tls::keypair::conditions::Unavailable;
        match reason {
            Unavailable::TargetAbsent => Self::TargetAbsent,
            Unavailable::ExternalSource => Self::ExternalSource,
            Unavailable::Capacity => Self::Capacity,
            Unavailable::Storage => Self::Storage,
            Unavailable::ImpactUnproven => Self::ImpactUnproven,
        }
    }
}
