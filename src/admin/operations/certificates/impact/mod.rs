//! 完整来源影响独立登记和审阅，不改变原材料审批的含义。

#[cfg(feature = "node-actions")]
mod api;
mod capacity;
#[cfg(feature = "node-actions")]
mod encoding;
#[cfg(feature = "node-actions")]
mod model;
#[cfg(feature = "node-actions")]
mod reading;
mod retention;
#[cfg(feature = "node-actions")]
mod review;
#[cfg(feature = "node-actions")]
mod storage;

#[cfg(feature = "node-actions")]
pub(super) use api::{dispatch, matches};

use super::{Error, Store};
pub(in crate::admin::operations) use capacity::register;
pub(super) use retention::{collect, lock_retention};

/// 业务作用：为完整影响登记隔离幂等收据，不能与原材料上传或配置提案相互重放。
///
/// 参数说明：
/// - `scope`：规范的平台或工作区域。
/// - `epoch`：影响登记取得的共享受理代。
///
/// 返回：有界且稳定的 NASA route 身份，回收时必须使用同一身份。
fn route(scope: &str, epoch: i64) -> String {
    format!("material-impact:{scope}:{epoch}")
}
