//! 路由选择、改写与分层授权上下文直接比较冻结结构，不通过展示 JSON 建立身份。

use super::Route;

impl Route {
    /// 业务作用：比较决定路由可达性、优先级和分层决策的全部固定入口字段。
    ///
    /// 参数说明：
    /// - `candidate`：同代理中已完成路由和层级图校验的候选计划。
    ///
    /// 返回：身份、顺序、目标、断言、路径改写及完整层级声明一致时为真；变量内容由快照域统一比较。
    pub(crate) fn same_selection_configuration(&self, candidate: &Self) -> bool {
        self.id == candidate.id
            && self.order == candidate.order
            && self.upstream == candidate.upstream
            && self.internal == candidate.internal
            && self.predicates == candidate.predicates
            && self.strip_prefix == candidate.strip_prefix
            && self.rewrite_prefix == candidate.rewrite_prefix
            && self.gateway_rewrite_full_path == candidate.gateway_rewrite_full_path
            && self.preserve_host == candidate.preserve_host
            && self.layer == candidate.layer
    }
}
