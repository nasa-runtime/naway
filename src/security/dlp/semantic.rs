//! 固定 DLP 检测器比较实际模式与规则集合，不执行扫描或重新编译。

use super::Detector;

impl PartialEq for Detector {
    /// 业务作用：比较敏感信息检测范围，保持正则执行状态与配置声明独立。
    ///
    /// 参数说明：
    /// - `other`：构建期使用相同固定选项编译的候选检测器。
    ///
    /// 返回：启用集合及全部固定正则模式相同时为真，不复制表达式或读取请求实体。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            enabled,
            email,
            phone,
            national_id,
            jwt,
            api_key,
            secret,
        } = self;
        enabled == &other.enabled
            && email.as_str() == other.email.as_str()
            && phone.as_str() == other.phone.as_str()
            && national_id.as_str() == other.national_id.as_str()
            && jwt.as_str() == other.jwt.as_str()
            && api_key.as_str() == other.api_key.as_str()
            && secret.as_str() == other.secret.as_str()
    }
}

impl Eq for Detector {}
