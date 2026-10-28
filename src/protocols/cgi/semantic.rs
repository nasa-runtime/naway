//! CGI 只比较冻结脚本与协议声明，不读取连接池或消耗并发许可。

use super::Plan;

impl PartialEq for Plan {
    /// 业务作用：识别脚本、协议收尾、复用及资源预算变化，不把请求执行事实带入配置审查。
    ///
    /// 参数说明：
    /// - `other`：已通过固定脚本和协议能力校验的候选计划。
    ///
    /// 返回：完整声明一致时为真；比较不编码 JSON、不锁池、不建立连接。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            config,
            inflight: _,
            idle: _,
        } = self;
        config == &other.config
    }
}

impl Eq for Plan {}
