//! 工作区预算拒绝保持固定语义，不向调用方泄露其它归属或容量使用明细。

/// 归属已失效或工作区/进程容量不足；调用方不得降级到其它归属继续预留。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservationDenied;

impl std::fmt::Display for ReservationDenied {
    /// 业务作用：提供稳定的预算拒绝原因，避免通过错误文本探测其它工作区状态。
    ///
    /// 参数说明：
    /// - `out`：错误格式化目标。
    ///
    /// 返回：写入固定拒绝说明，不携带身份或计数。
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("workspace reservation unavailable")
    }
}

impl std::error::Error for ReservationDenied {}
