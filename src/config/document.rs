//! 不执行配置求值的 YAML 文档适配，统一复用 naml 的解析与编码预算。

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde_json::Value;

/// 配置编辑与候选文档沿用文件加载的单文档上限。
pub(crate) const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;

/// 业务作用：固定协议文档读写预算，避免别名展开和输出转义突破正文上限。
///
/// 参数说明：
/// - `max_bytes`：是所属入口已有的正文预算。
///
/// 返回：同时限制输入、展开文本、结构深度和编码输出的 naml 预算。
fn limits(max_bytes: usize) -> naml::yaml::Limits {
    naml::yaml::Limits {
        input_bytes: max_bytes,
        output_bytes: max_bytes,
        string_bytes: max_bytes.min(1024 * 1024),
        ..Default::default()
    }
}

/// 业务作用：读取 Console、snippet 或外部 schema 原文，保持占位符和字符串键原样。
///
/// 参数说明：
/// - `bytes`：是已取得的正文
/// - `max_bytes`：为入口允许的最大输入与展开文本。
///
/// 返回：唯一完整的 YAML 值；重复键、非法类型、畸形文档或超限均拒绝且不回显正文。
pub(crate) fn parse(bytes: &[u8], max_bytes: usize) -> Result<Value> {
    // 文档编辑不能执行环境覆盖、imports 或占位符，否则管理写操作会把本机秘密固化进配置。
    naml::yaml::from_slice_with_limits(bytes, &limits(max_bytes)).context("invalid YAML document")
}

/// 业务作用：将原始 YAML 文档绑定到严格业务模型，不引入文件读取或环境求值。
///
/// 参数说明：
/// - `bytes`：是正文
/// - `max_bytes`：是所属入口预算；目标类型决定字段约束。
///
/// 返回：解析与字段类型均满足要求时返回模型；绑定失败只返回低敏结构错误。
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8], max_bytes: usize) -> Result<T> {
    serde_json::from_value(parse(bytes, max_bytes)?)
        .map_err(|_| anyhow::anyhow!("YAML document does not match the required schema"))
}

/// 业务作用：把局部编辑后的完整候选编码为 YAML，交由统一配置构建器验证后发布。
///
/// 参数说明：
/// - `document`：是候选树
/// - `max_bytes`：限制结构文本和最终输出。
///
/// 返回：预算内的完整 YAML；失败不返回部分正文，也不写入配置事实源。
pub(crate) fn encode(document: &Value, max_bytes: usize) -> Result<String> {
    naml::yaml::to_string_with_limits(document, &limits(max_bytes))
        .context("cannot encode YAML document")
}
