//! 原材料候选沿独立短期签名通道预检，不改变批准、材料文件或活动监听。

mod body;
mod client;
pub(in crate::admin) mod command;
mod content;
#[cfg(feature = "admin-operations-pgsql")]
mod delivery;
mod node;
#[cfg(feature = "admin-operations-pgsql")]
mod run;
mod session;
mod wire;

pub(in crate::admin::management) use client::Channel;
pub(in crate::admin) use content::Content;
#[cfg(feature = "admin-operations-pgsql")]
pub(in crate::admin::management) use delivery::Offer;
#[cfg(feature = "admin-operations-pgsql")]
pub(in crate::admin) use run::{inspect, recheck, Completed};

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
    MaterialChanged,
    CandidateInvalid,
}

impl From<super::material::Reason> for Reason {
    /// 业务作用：共享公开条件的失败分类，独立预检不将来源观察失败降格为可构建成功。
    ///
    /// 参数说明：
    /// - `reason`：通用原目标与公开条件门的明确拒绝原因。
    ///
    /// 返回：同语义低敏类别，不包含本机路径或秘密。
    fn from(reason: super::material::Reason) -> Self {
        use super::material::Reason as Source;
        match reason {
            Source::Unsupported => Self::Unsupported,
            Source::Disabled => Self::Disabled,
            Source::Unavailable => Self::Unavailable,
            Source::Capacity => Self::Capacity,
            Source::Expired => Self::Expired,
            Source::Denied => Self::Denied,
            Source::BaselineChanged => Self::BaselineChanged,
            Source::TargetAbsent => Self::TargetAbsent,
            Source::ExternalSource => Self::ExternalSource,
            Source::Storage => Self::Storage,
            Source::ImpactUnproven => Self::ImpactUnproven,
        }
    }
}

impl From<crate::tls::keypair::preview::Rejected> for Reason {
    /// 业务作用：隔离完整 TLS 构建和文件读取诊断，跨节点仅交付可供操作决策的固定原因。
    ///
    /// 参数说明：
    /// - `reason`：同一材料锁内拒绝原条件或候选策略的原因。
    ///
    /// 返回：公开失败类别，不输出私钥摘要、路径或底层错误链。
    fn from(reason: crate::tls::keypair::preview::Rejected) -> Self {
        use crate::tls::keypair::preview::Rejected;
        match reason {
            Rejected::Conditions(reason) => super::material::Reason::from(reason).into(),
            Rejected::Changed => Self::MaterialChanged,
            Rejected::Denied => Self::Denied,
            Rejected::Invalid => Self::CandidateInvalid,
        }
    }
}
