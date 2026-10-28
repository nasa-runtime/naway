//! 候选容量、业务拒绝与内部工作失败的明确响应边界。

use crate::admin::{json, plain, BoxBody};
use hyper::{Response, StatusCode};

/// 尚未产生配置副作用的候选构建结论。
pub(in crate::admin) enum BuildError {
    Busy,
    Invalid(String),
    Exhausted,
    Baseline,
    Worker,
    Workspace,
}

impl BuildError {
    /// 业务作用：保留受限领域的低敏策略错误，同时让容量不足与内部失败保持准确类别。
    ///
    /// 参数说明：
    /// - `reason`：该领域允许公开的固定策略拒绝说明。
    ///
    /// 返回：候选非法时返回固定400文案，其余情况沿用明确的构建错误响应。
    pub(in crate::admin) fn policy_response(self, reason: &str) -> Response<BoxBody> {
        match self {
            Self::Invalid(_) => plain(StatusCode::BAD_REQUEST, reason),
            other => other.response(),
        }
    }

    /// 业务作用：将临时容量拒绝与候选非法区分，调用方不能把过载解释为配置已经失败或发布。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：忙碌503、候选非法400、版本耗尽或归档不可用409、工作任务异常500。
    pub(in crate::admin) fn status(&self) -> StatusCode {
        match self {
            Self::Busy => StatusCode::SERVICE_UNAVAILABLE,
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::Exhausted | Self::Baseline => StatusCode::CONFLICT,
            Self::Worker | Self::Workspace => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 业务作用：向管理调用者返回明确的构建失败，不包含临时原文或尚未成立的发布结论。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有错误类别对应状态的JSON响应，真实文件及快照保持原状。
    pub(in crate::admin) fn response(self) -> Response<BoxBody> {
        let reason = match &self {
            Self::Busy => "candidate build capacity unavailable",
            Self::Invalid(reason) => reason,
            Self::Exhausted => "config version space exhausted",
            Self::Baseline => "active configuration archive unavailable",
            Self::Worker => "candidate worker did not complete",
            Self::Workspace => "candidate workspace unavailable",
        };
        json(
            self.status(),
            serde_json::json!({
                "ok": false,
                "error": reason,
            }),
        )
    }
}
