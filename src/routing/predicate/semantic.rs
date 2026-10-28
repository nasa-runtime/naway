//! 断言投影只借用构建时规范化的内容，正则与 glob 匹配器不需要重新编译或生成字符串签名。

use super::{HeaderName, HeaderOp, HostPattern, Method, PathTemplateSegment, Predicate, ValueOp};

#[derive(PartialEq, Eq)]
enum Identity<'a> {
    Prefix(&'a str),
    ElementPrefix(&'a str),
    Exact(&'a str),
    #[cfg(feature = "scg-compat")]
    Regex(&'a str),
    Glob(&'a str),
    Template(&'a str, &'a [PathTemplateSegment]),
    Method(&'a [Method]),
    Host(&'a [HostPattern]),
    Header(&'a HeaderName, &'a HeaderOp),
    Query(&'a str, &'a ValueOp),
    Weight(&'a str, u32),
}

#[derive(PartialEq, Eq)]
enum ValueIdentity<'a> {
    Exact(&'a str),
    Prefix(&'a str),
    Regex(&'a str),
    Present,
    Absent,
}

impl Predicate {
    /// 业务作用：把每类断言穷尽映射为无分配的冻结身份，区分相同文本下不同匹配语义。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用实际参数的类型身份；匹配器由同次构建的规范表达式代表，OR 列表已在解析期排序。
    fn semantic_identity(&self) -> Identity<'_> {
        match self {
            Self::PathPrefix(value) => Identity::Prefix(value),
            Self::PathElementPrefix(value) => Identity::ElementPrefix(value),
            Self::PathExact(value) => Identity::Exact(value),
            #[cfg(feature = "scg-compat")]
            Self::PathRegex {
                raw,
                matcher: _,
            } => Identity::Regex(raw),
            Self::PathGlob {
                raw,
                matcher: _,
            } => Identity::Glob(raw),
            Self::PathTemplate {
                signature,
                segments,
            } => Identity::Template(signature, segments),
            Self::Method(values) => Identity::Method(values),
            Self::Host(values) => Identity::Host(values),
            Self::Header {
                name,
                op,
            } => Identity::Header(name, op),
            Self::Query {
                name,
                op,
            } => Identity::Query(name, op),
            Self::Weight {
                group,
                weight,
            } => Identity::Weight(group, *weight),
        }
    }
}

impl PartialEq for Predicate {
    /// 业务作用：比较已编译路由条件，避免管理面通过序列化展示签名判断路由是否变化。
    ///
    /// 参数说明：
    /// - `other`：由相同 DSL 构建器验证和规范化的候选断言。
    ///
    /// 返回：断言类型与全部冻结参数一致时为真，不读取请求、不分配签名字符串。
    fn eq(&self, other: &Self) -> bool {
        self.semantic_identity() == other.semantic_identity()
    }
}

impl Eq for Predicate {}

impl HeaderOp {
    /// 业务作用：区分头部条件的值、正则和存在性语义，比较不接触运行期请求头。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与实际 matcher 同次构建的借用身份。
    fn semantic_identity(&self) -> ValueIdentity<'_> {
        match self {
            Self::Exact(value) => ValueIdentity::Exact(value),
            Self::Prefix(value) => ValueIdentity::Prefix(value),
            Self::Regex {
                raw,
                matcher: _,
            } => ValueIdentity::Regex(raw),
            Self::Present => ValueIdentity::Present,
            Self::Absent => ValueIdentity::Absent,
        }
    }
}

impl PartialEq for HeaderOp {
    /// 业务作用：比较头部断言的操作符与固定输入，防止同名头的权限范围变化被遗漏。
    ///
    /// 参数说明：
    /// - `other`：已编译的候选头部操作符。
    ///
    /// 返回：操作符与匹配输入相同时为真，不构造中间字符串。
    fn eq(&self, other: &Self) -> bool {
        self.semantic_identity() == other.semantic_identity()
    }
}

impl Eq for HeaderOp {}

impl ValueOp {
    /// 业务作用：保留 query 值的精确或正则匹配边界，避免比较时重新构建表达式。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用实际匹配输入的类型身份。
    fn semantic_identity(&self) -> ValueIdentity<'_> {
        match self {
            Self::Exact(value) => ValueIdentity::Exact(value),
            Self::Regex {
                raw,
                matcher: _,
            } => ValueIdentity::Regex(raw),
        }
    }
}

impl PartialEq for ValueOp {
    /// 业务作用：比较 query 匹配策略，保留操作符差异而不解析业务请求。
    ///
    /// 参数说明：
    /// - `other`：已编译的候选 query 操作符。
    ///
    /// 返回：操作符和输入完全一致时为真。
    fn eq(&self, other: &Self) -> bool {
        self.semantic_identity() == other.semantic_identity()
    }
}

impl Eq for ValueOp {}
