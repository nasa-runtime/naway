//! 媒体声明与冻结资源身份参与比较，解析任务和共享配额不参与。

use super::Plan;

impl PartialEq for Plan {
    /// 业务作用：比较实际容器解析边界和静态根身份，不读取文件实体或申请解析名额。
    ///
    /// 参数说明：
    /// - `other`：已验证预算并绑定静态根的候选媒体计划。
    ///
    /// 返回：完整声明与资源身份都一致时为真；不重新序列化配置或等待活动解析任务。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            cfg,
            fingerprint,
            quota: _,
        } = self;
        cfg == &other.cfg && fingerprint == &other.fingerprint
    }
}

impl Eq for Plan {}
