//! 令牌桶观测使用固定状态和容量边界，不携带请求维度或修改额度。

/// 单次只读扫描同时约束保留项和 HashMap 槽容量。
pub(crate) const SCAN_LIMIT: usize = 16_384;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub total: usize,
    pub steady: usize,
    pub cold: usize,
    pub warming: usize,
    pub warm: usize,
    pub expired: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    Local(Counts),
    Shared,
    Preallocated,
    Unsupported,
    Busy,
    Capacity,
    Unavailable,
}
