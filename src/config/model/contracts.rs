//! 请求校验、响应合同及实体转换声明。

use super::*;

/// 路由级 OpenAPI / JSON Schema 请求校验配置。
///
/// `head_schema` 校验一个稳定 envelope：`method`/`path`/`query`/`headers`/
/// `path_params`。query/header 的每个值都是字符串数组，既保留重复值，也避免静默选择
/// 第一个值造成参数污染。`body_schema` 只校验 JSON body。两者都在 build-then-swap
/// 阶段编译；请求热路径不会重新解析 schema。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RequestValidationCfg {
    /// 内联 head JSON Schema；与 `head_schema_file` 二选一。
    #[serde(default)]
    pub head_schema: Option<serde_json::Value>,
    /// head JSON/YAML Schema 文件；相对路径按 `gateway.yml` 所在目录解析。
    #[serde(default)]
    pub head_schema_file: Option<String>,
    /// 内联 JSON body Schema；与 `body_schema_file` 二选一。
    #[serde(default)]
    pub body_schema: Option<serde_json::Value>,
    /// body JSON/YAML Schema 文件；相对路径按 `gateway.yml` 所在目录解析。
    #[serde(default)]
    pub body_schema_file: Option<String>,
    /// OpenAPI 3 JSON/YAML 文件。设置时由 `operation_id` 定位 operation，并与显式 schema 互斥。
    #[serde(default)]
    pub openapi_file: Option<String>,
    /// OpenAPI operationId；使用 `openapi_file` 时必填。
    #[serde(default)]
    pub operation_id: Option<String>,
    /// OpenAPI path template；与 `operation_method` 成对，用于没有 operationId 的门户导入。
    #[serde(default)]
    pub operation_path: Option<String>,
    /// OpenAPI method；与 `operation_path` 成对，和 `operation_id` 二选一。
    #[serde(default)]
    pub operation_method: Option<String>,
    /// body 收集硬上限。存在 body schema 时必须在 1..=16MiB 内显式设置。
    #[serde(default)]
    pub max_body_bytes: u64,
    /// 显式 body schema 的空 body 语义；缺省为 required。OpenAPI 来源默认服从 requestBody.required。
    #[serde(default)]
    pub body_required: Option<bool>,
}

/// 路由级 OpenAPI 响应契约配置。
///
/// schema 在候选快照构建期按 operation、status 和 media type 全部编译。`observe`
/// 以透传包装体记录结果；`block` 与 `replace_error` 才会在写下游前有界收集实体。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ResponseContractCfg {
    /// OpenAPI 3 JSON/YAML 文件；路径相对主配置目录解析。
    pub openapi_file: String,
    /// OpenAPI operationId；与 `operation_path` + `operation_method` 二选一。
    #[serde(default)]
    pub operation_id: Option<String>,
    /// OpenAPI path template；与 `operation_method` 成对。
    #[serde(default)]
    pub operation_path: Option<String>,
    /// OpenAPI method；与 `operation_path` 成对。
    #[serde(default)]
    pub operation_method: Option<String>,
    /// 响应不符合契约时的动作；缺省只观察。
    #[serde(default)]
    pub mode: ResponseContractModeCfg,
    /// 可检查的实体字节上限，必须在 1..=16MiB 内显式设置。
    pub max_body_bytes: u64,
    /// `replace_error` 使用的固定状态码。
    #[serde(default = "default_response_contract_replacement_status")]
    pub replacement_status: u16,
    /// `replace_error` 使用的固定低敏响应文本。
    #[serde(default = "default_response_contract_replacement_body")]
    pub replacement_body: String,
    /// 显式受信本地 schema catalog；只有列出的文档才允许被外部 `$ref` 引用。
    #[serde(default)]
    pub catalog_files: Vec<String>,
    /// 显式 HTTPS schema registry 文档；URL、摘要和 detached 签名共同冻结内容身份。
    #[serde(default)]
    pub registry_documents: Vec<SchemaRegistryDocumentCfg>,
}

/// 一个可进入响应契约 catalog 的签名 HTTPS schema 文档。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SchemaRegistryDocumentCfg {
    /// 固定 HTTPS URL，不允许 redirect 或运行期派生 authority。
    pub url: String,
    /// 原始响应字节的 SHA-256 十六进制摘要。
    pub sha256: String,
    /// detached Ed25519 signature SecretSource，内容为 Base64。
    pub signature: String,
    /// Ed25519 public key SecretSource，内容为 32-byte Base64。
    pub public_key: String,
    /// 可选自定义 CA PEM 文件，路径相对主配置目录解析。
    #[serde(default)]
    pub ca_file: Option<String>,
    /// 单文档响应硬上限。
    #[serde(default = "default_schema_registry_max_bytes")]
    pub max_bytes: usize,
    /// 单次 HTTPS 请求总 deadline。
    #[serde(default = "default_schema_registry_timeout_ms")]
    pub timeout_ms: u64,
    /// 已验签进程内缓存的最长复用时间。
    #[serde(default = "default_schema_registry_cache_ttl_ms")]
    pub cache_ttl_ms: u64,
}

/// 响应契约不符合时的数据面动作。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseContractModeCfg {
    /// 原响应立即透传，在流结束后记录校验结论。
    #[default]
    Observe,
    /// 写下游前完成有界校验，不符合契约时返回固定 502。
    Block,
    /// 写下游前完成有界校验，不符合契约时返回配置的低敏错误响应。
    ReplaceError,
}

/// 声明式实体转换配置。
///
/// JSON 操作只接受精确 JSON Pointer，不支持 wildcard 或脚本。XML/SOAP 输入先按
/// namespace-aware 路径提取为 JSON，输出则从 JSON Pointer 映射到固定 XML 元素路径。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BodyTransformCfg {
    /// 输入实体格式。
    #[serde(default)]
    pub input: BodyFormatCfg,
    /// 输出实体格式。
    #[serde(default)]
    pub output: BodyFormatCfg,
    /// 输入实体的聚合硬上限，必须在 1..=16MiB 内。
    pub max_body_bytes: u64,
    /// 序列化后实体的硬上限，必须在 1..=16MiB 内。
    pub max_output_bytes: u64,
    /// 对中间 JSON 值按声明顺序执行的确定性字段操作。
    #[serde(default)]
    pub operations: Vec<JsonTransformOperationCfg>,
    /// XML prefix 到 namespace URI 的固定映射。
    #[serde(default)]
    pub namespaces: std::collections::BTreeMap<String, String>,
    /// XML/SOAP 输入到中间 JSON 的精确字段映射。
    #[serde(default)]
    pub xml_extract: Vec<XmlFieldMappingCfg>,
    /// 中间 JSON 到 XML/SOAP 输出的固定结构。
    #[serde(default)]
    pub xml_emit: Option<XmlEmitCfg>,
    /// SOAP 输入必须匹配或 SOAP 输出需要设置的固定 SOAPAction。
    #[serde(default)]
    pub soap_action: Option<String>,
    /// SOAP Fault 命中时修改 HTTP status 的固定映射，仅响应转换可用。
    #[serde(default)]
    pub soap_fault: Option<SoapFaultMappingCfg>,
    /// XML 最大元素深度。
    #[serde(default = "default_transform_xml_depth")]
    pub max_xml_depth: usize,
    /// XML 最大节点事件数。
    #[serde(default = "default_transform_xml_nodes")]
    pub max_xml_nodes: usize,
    /// 单元素最大属性数。
    #[serde(default = "default_transform_xml_attributes")]
    pub max_xml_attributes: usize,
    /// XML 文本总字节上限。
    #[serde(default = "default_transform_xml_text_bytes")]
    pub max_xml_text_bytes: usize,
}

/// 实体转换支持的受限格式。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BodyFormatCfg {
    /// JSON 或 `application/*+json`。
    #[default]
    Json,
    /// 普通 XML。
    Xml,
    /// SOAP 1.1/1.2 envelope。
    Soap,
}

/// 中间 JSON 值上的确定性字段操作。
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum JsonTransformOperationCfg {
    /// 把现有字段移动到新位置；目标必须尚不存在。
    Rename {
        from: String,
        to: String,
    },
    /// 在尚不存在的位置增加固定值。
    Add {
        path: String,
        value: serde_json::Value,
    },
    /// 删除现有字段；字段不存在时保持幂等。
    Remove {
        path: String,
    },
    /// 只在字段不存在时写入固定默认值。
    Default {
        path: String,
        value: serde_json::Value,
    },
    /// 要求字段存在且属于指定 JSON 类型。
    TypeCheck {
        path: String,
        expected: JsonValueTypeCfg,
    },
}

/// JSON 字段类型约束。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JsonValueTypeCfg {
    Null,
    Boolean,
    Number,
    Integer,
    String,
    Array,
    Object,
}

/// XML/SOAP 输入字段到中间 JSON Pointer 的映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct XmlFieldMappingCfg {
    /// namespace-aware 元素路径，例如 `/soap:Envelope/soap:Body/m:Get/m:id`。
    pub from: String,
    /// 中间 JSON 的精确 JSON Pointer。
    pub to: String,
    /// 路径未命中时是否拒绝本次转换。
    #[serde(default)]
    pub required: bool,
    /// 提取文本需要转换成的 JSON 类型；缺省为 string。
    #[serde(default)]
    pub value_type: XmlValueTypeCfg,
}

/// XML 文本到 JSON 值的受限转换类型。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum XmlValueTypeCfg {
    #[default]
    String,
    Integer,
    Number,
    Boolean,
}

/// XML/SOAP 输出的固定根和字段映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct XmlEmitCfg {
    /// 输出根元素的 QName；SOAP 输出时这是 Body 内的业务根元素。
    pub root: String,
    /// 中间 JSON Pointer 到输出元素路径的映射。
    #[serde(default)]
    pub fields: Vec<XmlEmitFieldCfg>,
}

/// 中间 JSON 字段到固定 XML 元素路径的映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct XmlEmitFieldCfg {
    /// 中间 JSON 的精确 JSON Pointer。
    pub from: String,
    /// 相对 `xml_emit.root` 的 QName 路径，使用 `/` 分隔。
    pub to: String,
    /// 输入字段不存在时是否拒绝转换。
    #[serde(default)]
    pub required: bool,
}

/// SOAP Fault 到 HTTP 状态的固定映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SoapFaultMappingCfg {
    /// namespace-aware Fault 元素路径。
    pub path: String,
    /// Fault 命中后写入的 HTTP 状态码。
    pub status: u16,
}

/// 业务作用：提供响应契约替换错误的安全默认状态，避免无配置时伪装成上游成功。
///
/// 参数说明: 无。
///
/// 返回：返回 502。
pub(super) const fn default_response_contract_replacement_status() -> u16 {
    502
}

/// 业务作用：为远端 schema 文档设置单次读取上限，限制控制面候选内存。
///
/// 参数说明: 无。
///
/// 返回：返回 1 MiB 默认上限。
pub(super) const fn default_schema_registry_max_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：为显式 HTTPS schema registry 设置有限请求 deadline。
///
/// 参数说明: 无。
///
/// 返回：返回 3000 毫秒默认值。
pub(super) const fn default_schema_registry_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：限制已验签 schema 缓存复用时间，使远端撤换在下一次候选构建时可重新取证。
///
/// 参数说明: 无。
///
/// 返回：返回 60000 毫秒默认值。
pub(super) const fn default_schema_registry_cache_ttl_ms() -> u64 {
    60_000
}

/// 业务作用：提供不暴露 schema、字段名或上游实体的固定替换错误文本。
///
/// 参数说明: 无。
///
/// 返回：返回稳定的低敏错误消息。
pub(super) fn default_response_contract_replacement_body() -> String {
    "upstream response does not satisfy contract".to_string()
}

/// 业务作用：限制 XML 转换的默认嵌套层级，避免深层文档放大解析栈和路径状态。
///
/// 参数说明: 无。
///
/// 返回：返回 64 层默认上限。
pub(super) const fn default_transform_xml_depth() -> usize {
    64
}

/// 业务作用：限制单次 XML 转换处理的节点事件总量。
///
/// 参数说明: 无。
///
/// 返回：返回 100000 个事件默认上限。
pub(super) const fn default_transform_xml_nodes() -> usize {
    100_000
}

/// 业务作用：限制单元素属性数量，避免属性洪泛消耗解析资源。
///
/// 参数说明: 无。
///
/// 返回：返回 128 个属性默认上限。
pub(super) const fn default_transform_xml_attributes() -> usize {
    128
}

/// 业务作用：限制 XML 文本累计字节，避免小结构携带超大文本绕过节点预算。
///
/// 参数说明: 无。
///
/// 返回：返回 16 MiB 默认上限。
pub(super) const fn default_transform_xml_text_bytes() -> usize {
    16 * 1024 * 1024
}
