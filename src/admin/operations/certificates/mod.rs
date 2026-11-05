//! 独立加密材料受理与双人审阅；保存、批准与目标安装具有不同权威。

mod api;
mod authorization;
mod capacity;
mod crypto;
pub(super) mod impact;
mod model;
#[cfg(feature = "node-actions")]
mod preview;
mod reading;
mod response;
mod retention;
mod review;
mod storage;

use super::{Store, model::Error};
pub(in crate::admin) use api::handle;
pub(super) use capacity::register;
pub(super) use retention::collect;

/// 业务作用：为材料原请求创建独立幂等域，不能重放三文档提案的既有收据。
///
/// 参数说明：
/// - `scope`：已校验的精确平台或工作区域。
/// - `epoch`：原请求取得的正受理代际。
///
/// 返回：满足 NASA route 上界且与配置提案不相交的稳定身份。
fn route(scope: &str, epoch: i64) -> String {
    format!("certificate:{scope}:{epoch}")
}

/// 业务作用：把存储异常归入封闭材料合同，不向客户端输出 SQL、连接信息或输入内容。
///
/// 参数说明：
/// - `error`：数据库操作的失败事实。
///
/// 返回：容量、冲突、过期或不可用的固定分类。
fn database_error(error: sqlx::Error) -> Error {
    match error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
    {
        Some("PN001") => Error::Capacity,
        Some("23505") => Error::Conflict,
        Some("23514") => Error::Expired,
        _ => Error::Unavailable,
    }
}
