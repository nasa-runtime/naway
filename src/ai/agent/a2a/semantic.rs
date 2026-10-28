//! A2A 比较冻结目标、公开协议与权限，任务目录和活动流不属于配置身份。

use super::{A2aCfg, Acl, LimitsCfg, Plan, SecurityCfg, Target};

#[derive(PartialEq, Eq)]
struct Identity<'a> {
    security: &'a SecurityCfg,
    limits: &'a LimitsCfg,
    cfg: &'a A2aCfg,
    target: &'a Target,
    card_target: &'a Target,
    base: &'a str,
    private_authority: &'a str,
    discovery: &'a Acl,
    invocation: &'a Acl,
}

impl Plan {
    /// 业务作用：穷尽保留 A2A 固定参数，区分目录发现授权与业务任务授权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用实际目标材料、规范地址和全部声明；不读取任务、会话或信号量。
    fn semantic_identity(&self) -> Identity<'_> {
        let Self {
            security,
            limits,
            cfg,
            target,
            card_target,
            base,
            private_authority,
            discovery,
            invocation,
            inflight: _,
            control: _,
            catalog: _,
        } = self;
        Identity {
            security,
            limits,
            cfg,
            target,
            card_target,
            base,
            private_authority,
            discovery,
            invocation,
        }
    }
}

impl PartialEq for Plan {
    /// 业务作用：识别 A2A 协议入口、身份和实际后端凭据的变化，避免沿用同名路由摘要。
    ///
    /// 参数说明：
    /// - `other`：通过 card、安全和预算验证的候选计划。
    ///
    /// 返回：固定合同相同时为真；不把在线任务状态或已消耗预算当作配置变更。
    fn eq(&self, other: &Self) -> bool {
        self.semantic_identity() == other.semantic_identity()
    }
}

impl Eq for Plan {}
