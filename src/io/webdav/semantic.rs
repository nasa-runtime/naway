//! DAV 比较已验证声明与资源归属，不遍历目录、锁表或活动会话。

use super::Plan;

impl PartialEq for Plan {
    /// 业务作用：比较本地或代理 DAV 的完整资源边界，不把当前文件锁与并发占用当成配置变更。
    ///
    /// 参数说明：
    /// - `other`：冻结方法、挂载点和容量限制的候选计划。
    ///
    /// 返回：完整声明和资源归属一致时为真，不重新获取目录能力或重算材料摘要。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            cfg,
            resource_fingerprint,
            root: _,
            inflight: _,
            methods: _,
        } = self;
        cfg == &other.cfg && resource_fingerprint == &other.resource_fingerprint
    }
}

impl Eq for Plan {}
