//! 输出 XML 比较保留 QName；输入匹配仍沿用 namespace URI 与 local name 的等价语义。

use super::{XmlEmitFieldPlan, XmlEmitPlan};

impl PartialEq for XmlEmitPlan {
    /// 业务作用：比较响应 XML 的根元素和字段生成计划，识别输出前缀变化。
    ///
    /// 参数说明：
    /// - `other`：已通过命名空间与输出路径校验的候选计划。
    ///
    /// 返回：根元素完整 QName、expanded name 和字段计划一致时为真，不生成正文。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            root,
            fields,
        } = self;
        root == &other.root && root.qname == other.root.qname && fields == &other.fields
    }
}

impl Eq for XmlEmitPlan {}

impl PartialEq for XmlEmitFieldPlan {
    /// 业务作用：比较 JSON 字段到 XML 输出路径的映射，避免仅按元素身份漏报前缀调整。
    ///
    /// 参数说明：
    /// - `other`：同一候选输出中的字段计划。
    ///
    /// 返回：输入、必填约束及输出路径每一级的完整名称一致时为真。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            from,
            path,
            required,
        } = self;
        from == &other.from
            && required == &other.required
            && path.len() == other.path.len()
            && path.iter().zip(&other.path).all(|(current, candidate)| {
                current == candidate && current.qname == candidate.qname
            })
    }
}

impl Eq for XmlEmitFieldPlan {}
