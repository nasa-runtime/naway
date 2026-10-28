//! 机器人 glob 保留构建时固定身份，配置比较不重新解析匹配表达式。

use globset::GlobSet;

pub(super) struct GlobPlan {
    pub(super) matcher: GlobSet,
    pub(super) identity: [u8; 32],
}

impl GlobPlan {
    /// 业务作用：执行已冻结的 User-Agent 匹配，保持身份摘要仅用于控制面比较。
    ///
    /// 参数说明：
    /// - `user_agent`：经过长度与文本格式校验的请求 User-Agent。
    ///
    /// 返回：任一已编译 pattern 命中时为真，不重新解析表达式或计算摘要。
    pub(super) fn is_match(&self, user_agent: &str) -> bool {
        self.matcher.is_match(user_agent)
    }
}

impl PartialEq for GlobPlan {
    /// 业务作用：按规范 pattern 集合比较机器人匹配规则，忽略输入次序和 ASCII 大小写差异。
    ///
    /// 参数说明：
    /// - `other`：固定编译选项相同的候选匹配计划。
    ///
    /// 返回：构建时分帧材料身份一致时为真，不读取或复制 matcher 的运行状态。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            identity,
            matcher: _,
        } = self;
        identity == &other.identity
    }
}

impl Eq for GlobPlan {}
