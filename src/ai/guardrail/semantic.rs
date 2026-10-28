//! 内容护栏比较实际编译表达式与方向，保留分类和流式前瞻边界。

use super::Rule;

impl PartialEq for Rule {
    /// 业务作用：识别内容裁决规则的变化，不重新编译正则或扫描请求与响应文本。
    ///
    /// 参数说明：
    /// - `other`：使用相同有界编译选项构建的候选规则。
    ///
    /// 返回：分类、方向、表达式和最大匹配长度相同；正则内部执行状态不参与比较。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            category,
            directions,
            matcher,
            maximum_bytes,
        } = self;
        *category == other.category
            && *directions == other.directions
            && matcher.as_str() == other.matcher.as_str()
            && *maximum_bytes == other.maximum_bytes
    }
}

impl Eq for Rule {}
