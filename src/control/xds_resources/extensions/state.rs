use super::super::*;

impl XdsPolicyCache {
    /// 业务作用：替换命名扩展证明并重新闭合依赖；撤回证明不允许沿用仍含该终结器的活动 listener。
    ///
    /// 参数说明：
    /// - `names`：整份 ECDS 接受集，仅包含已校验的空 Router。
    /// - `now`：依赖等待的单调时间锚点。
    ///
    /// 返回：闭包完整时给出活动候选，否则给出等待状态及必要的保护发布。
    pub(crate) fn accept_extensions(
        &mut self,
        names: BTreeSet<String>,
        now: Instant,
    ) -> XdsPolicyOutcome {
        self.accepted_extensions = names;
        self.reconcile(now)
    }
}
