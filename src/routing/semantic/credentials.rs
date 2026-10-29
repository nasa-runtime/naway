//! 路由只比较自己绑定的凭据，不把无关 provider 的变化扩散到所有路由。

use super::Route;

impl Route {
    /// 业务作用：把普通上游凭据的实际注入内容与授权策略纳入该路由的候选审查。
    ///
    /// 参数说明：
    /// - `candidate`：同一路由的已验证候选。
    ///
    /// 返回：双方都无凭据或完整计划一致时为真；不读取续租和缓存运行状态。
    pub(crate) fn same_credential_configuration(&self, candidate: &Self) -> bool {
        match (&self.upstream_credentials, &candidate.upstream_credentials) {
            (None, None) => true,
            (Some(current), Some(next)) => current.configuration_eq(next),
            _ => false,
        }
    }
}
