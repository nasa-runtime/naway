//! 脚本配置审查复用冻结源码与能力，不重新编码配置或接触熔断运行态。

use super::Plugin;

impl PartialEq for Plugin {
    /// 业务作用：识别脚本源码、完整声明、已编译头权限及熔断归属的变化。
    ///
    /// 参数说明：
    /// - `other`：经过沙箱编译与预算校验的候选脚本。
    ///
    /// 返回：冻结计划一致时为真；派生展示指纹和当前熔断状态不影响比较。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            cfg,
            source,
            fingerprint: _,
            include,
            mutation,
            circuit_key,
            circuit: _,
        } = self;
        cfg == &other.cfg
            && source == &other.source
            && include == &other.include
            && mutation == &other.mutation
            && circuit_key == &other.circuit_key
    }
}

impl Eq for Plugin {}
