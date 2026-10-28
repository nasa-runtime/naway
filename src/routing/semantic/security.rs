//! 本地安全计划按实际编译声明比较，比较过程不读取业务正文或运行时计数。

use super::Route;

impl Route {
    /// 业务作用：识别内容防护、机器人治理、本地授权和请求解码的同名策略变化。
    ///
    /// 参数说明：
    /// - `candidate`：同代理、同路由身份下完成安全校验的候选计划。
    ///
    /// 返回：受支持的安全声明相同时为真；材料与凭据只比较，不输出或序列化。
    pub(crate) fn same_local_security_configuration(&self, candidate: &Self) -> bool {
        self.waf == candidate.waf
            && self.dlp == candidate.dlp
            && self.csrf == candidate.csrf
            && self.bot == candidate.bot
            && self.casbin_authorization == candidate.casbin_authorization
            && self.request_decompression == candidate.request_decompression
            && self.conditional_returns == candidate.conditional_returns
    }
}
