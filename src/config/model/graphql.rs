//! GraphQL 预算与固定 REST 映射声明。

use super::*;

/// route 级 GraphQL 查询深度/复杂度守卫。
///
/// 支持 GraphQL-over-HTTP GET/JSON/raw query、multipart upload，以及显式放行的
/// `graphql-transport-ws`/legacy `graphql-ws` 透明升级。degraphql 是独立的固定查询映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GraphqlGuardCfg {
    /// POST envelope/raw query 的最大实体字节数。读取严格有界，超过返回 413。
    #[serde(default = "default_graphql_max_body_bytes")]
    pub max_body_bytes: u64,
    /// 解码后 GraphQL query 文本的最大 UTF-8 字节数，GET/POST 使用同一上限。
    #[serde(default = "default_graphql_max_query_bytes")]
    pub max_query_bytes: usize,
    /// lexer 最多产生的 token 数，用独立 CPU/AST 预算防止短 token 洪泛。
    #[serde(default = "default_graphql_max_tokens")]
    pub max_tokens: usize,
    /// 根字段深度计为 1；任一可达选择路径超过该值即在上游前拒绝。
    #[serde(default = "default_graphql_max_depth")]
    pub max_depth: usize,
    /// 每个字段成本为 1，fragment 每次 spread 都重新计费；超过即拒绝。
    #[serde(default = "default_graphql_max_complexity")]
    pub max_complexity: usize,
    /// 是否允许 `__schema`/`__type`/`__typename` 等 introspection 字段。
    #[serde(default)]
    pub allow_introspection: bool,
    /// 是否允许 GraphQL WebSocket subscription transport 透明转发。
    ///
    /// WebSocket 消息不会被本 HTTP query guard 重写或拆包；开启表示上游 GraphQL server
    /// 负责每条 subscription 的解析/复杂度门，网关仍执行握手前 auth/rate/连接预算。
    #[serde(default)]
    pub allow_websocket_subscriptions: bool,
}

/// REST→GraphQL 声明式映射。GraphQL 文档固定在配置中，客户端只能提供有界 variables，
/// 不能把任意 query 注入受信上游。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DegraphqlCfg {
    /// 固定 GraphQL query/mutation 文档。
    pub query: String,
    /// 多 operation 文档的选择名；单 operation 可留空。
    #[serde(default)]
    pub operation_name: Option<String>,
    /// GraphQL 上游 path，不带 query/fragment。
    #[serde(default = "default_degraphql_upstream_path")]
    pub upstream_path: String,
    /// REST path 模板；存在 path variable 时必填，并应与 route `PathTemplate` 一致。
    #[serde(default)]
    pub rest_path_template: String,
    /// GraphQL variables 名到不可信 REST 输入的显式映射。
    #[serde(default)]
    pub variables: HashMap<String, DegraphqlVariableCfg>,
    /// 生成 JSON envelope 的硬上限。
    #[serde(default = "default_degraphql_max_body_bytes")]
    pub max_body_bytes: usize,
}

/// 一个 degraphql variable 的来源和 JSON 标量类型。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DegraphqlVariableCfg {
    /// REST 输入来源。
    pub source: DegraphqlVariableSourceCfg,
    /// path/query/header 字段名；literal 来源必须为空。
    #[serde(default)]
    pub name: String,
    /// literal 来源的固定 JSON 值。
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    /// 不可信文本到 GraphQL variable JSON 的转换类型。
    #[serde(default)]
    pub kind: DegraphqlVariableKindCfg,
    /// 缺失时是否 400；false 时省略该 variable。
    #[serde(default = "default_true")]
    pub required: bool,
    /// 单值输入的 UTF-8 字节上限。
    #[serde(default = "default_degraphql_max_value_bytes")]
    pub max_value_bytes: usize,
}

/// degraphql variable 从 REST 请求的哪个位置取值。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DegraphqlVariableSourceCfg {
    /// 从已匹配 REST path template 的参数取值。
    Path,
    /// 从 query 参数取第一个值。
    Query,
    /// 从显式命名的 HTTP header 取值。
    Header,
    /// 使用配置中的固定 JSON 值。
    Literal,
}

/// 将不可信 REST 文本转换为 GraphQL variable JSON 时使用的标量类型。
#[derive(Debug, Deserialize, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum DegraphqlVariableKindCfg {
    /// 保持为 JSON string。
    #[default]
    String,
    /// 严格解析为有符号整数。
    Integer,
    /// 严格解析为有限浮点数。
    Number,
    /// 严格解析为布尔值。
    Boolean,
}

/// 业务作用：为未显式声明的 `upstream_path` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_degraphql_upstream_path() -> String {
    "/graphql".to_owned()
}

/// 业务作用：为未显式声明的 `max_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_degraphql_max_body_bytes() -> usize {
    256 * 1024
}

/// 业务作用：为未显式声明的 `max_value_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_degraphql_max_value_bytes() -> usize {
    16 * 1024
}

impl Default for GraphqlGuardCfg {
    /// 业务作用：构造 `GraphqlGuardCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            max_body_bytes: default_graphql_max_body_bytes(),
            max_query_bytes: default_graphql_max_query_bytes(),
            max_tokens: default_graphql_max_tokens(),
            max_depth: default_graphql_max_depth(),
            max_complexity: default_graphql_max_complexity(),
            allow_introspection: false,
            allow_websocket_subscriptions: false,
        }
    }
}

/// 业务作用：为未显式声明的 `max_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_graphql_max_body_bytes() -> u64 {
    256 * 1024
}

/// 业务作用：为未显式声明的 `max_query_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_graphql_max_query_bytes() -> usize {
    128 * 1024
}

/// 业务作用：为未显式声明的 `max_tokens` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_graphql_max_tokens() -> usize {
    32 * 1024
}

/// 业务作用：为未显式声明的 `max_depth` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_graphql_max_depth() -> usize {
    16
}

/// 业务作用：为未显式声明的 `max_complexity` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_graphql_max_complexity() -> usize {
    1_000
}
