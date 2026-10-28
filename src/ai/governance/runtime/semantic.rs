//! 检索来源比较完整声明与实际目标凭据；编译 ACL 由同次冻结的 invocation 唯一决定。

use super::Source;

impl PartialEq for Source {
    /// 业务作用：比较检索权限、来源预算与解析后的固定外呼身份，识别同路径凭据轮换。
    ///
    /// 参数说明：
    /// - `other`：已完成来源白名单和 ACL 校验的候选来源。
    ///
    /// 返回：完整声明及实际外呼目标相同时为真，不执行检索或读取请求期引用目录。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            cfg,
            target,
            acl: _,
        } = self;
        cfg == &other.cfg && target == &other.target
    }
}

impl Eq for Source {}
