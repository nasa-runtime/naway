//! Agent 入口的显式协议、身份边界与固定工具目录。

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// 一个路由只能选择一个 Agent 协议入口。
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentCfg {
    Mcp(Box<McpCfg>),
    A2a(Box<A2aCfg>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCfg {
    pub protocol_version: String,
    pub security: SecurityCfg,
    #[serde(default)]
    pub limits: LimitsCfg,
    #[serde(default)]
    pub servers: Vec<ServerCfg>,
    #[serde(default)]
    pub tools: Vec<ToolCfg>,
    #[serde(default)]
    pub openapi: Vec<OpenApiCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aCfg {
    pub protocol_version: String,
    pub security: SecurityCfg,
    #[serde(default)]
    pub limits: LimitsCfg,
    pub target: TargetCfg,
    /// 对外可见的网关绝对 URL，不从客户端 Host 或上游 card 推导。
    pub public_url: String,
    pub binding: A2aBinding,
    /// 固定的上游发现路径，独立于 JSON-RPC 或 REST 业务入口。
    pub card_path: String,
    /// 对外认证描述必须与当前网关路由一致，不复制上游 agent 的私有认证端点。
    pub card_security_schemes: BTreeMap<String, Value>,
    pub card_security: Vec<BTreeMap<String, Vec<String>>>,
    pub discovery: AclCfg,
    pub invocation: AclCfg,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum A2aBinding {
    Jsonrpc,
    Rest,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityCfg {
    /// 路由所属租户；相同后端也不会跨此命名空间共用状态。
    pub tenant: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// 只读取验签后的 claim；配置后必须与固定 tenant 相等。
    #[serde(default)]
    pub tenant_claim: Option<String>,
    #[serde(default)]
    pub groups_claim: Option<String>,
    #[serde(default)]
    pub scopes_claim: Option<String>,
    /// 固定 consumer 到 group 的映射，只应用于已经通过路由认证的 consumer。
    #[serde(default)]
    pub consumer_groups: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AclCfg {
    /// 只有显式为 true 才允许不附加任何维度约束的已认证访问。
    #[serde(default)]
    pub allow_authenticated: bool,
    #[serde(default)]
    pub consumers: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsCfg {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_frame_bytes: usize,
    pub max_sessions: usize,
    pub max_sessions_per_identity: usize,
    pub session_ttl_ms: u64,
    pub deadline_ms: u64,
    pub max_inflight: usize,
    pub max_calls_per_session: u64,
    pub max_bytes_per_session: u64,
}

impl Default for LimitsCfg {
    /// 业务作用：为显式 Agent 入口提供保守的会话、调用、字节和时长预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有硬边界的默认配额；配置构建还会复验数值关系与绝对上限。
    fn default() -> Self {
        Self {
            max_request_bytes: 256 * 1024,
            max_response_bytes: 1024 * 1024,
            max_frame_bytes: 64 * 1024,
            max_sessions: 1024,
            max_sessions_per_identity: 16,
            session_ttl_ms: 300_000,
            deadline_ms: 30_000,
            max_inflight: 128,
            max_calls_per_session: 1000,
            max_bytes_per_session: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetCfg {
    /// 仅固定 origin 或 lb://service，不接受请求变量、用户名、query 或 fragment。
    pub uri: String,
    pub path: String,
    /// 只在固定目标上使用的 Bearer SecretSource；客户端凭据不向工具服务传播。
    #[serde(default)]
    pub api_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerCfg {
    pub id: String,
    pub target: TargetCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCfg {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    #[serde(default)]
    pub output_schema: Option<Value>,
    pub discovery: AclCfg,
    pub invocation: AclCfg,
    pub side_effect: SideEffect,
    pub deadline_ms: u64,
    pub max_calls_per_session: u64,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub backend: ToolBackendCfg,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    ReadOnly,
    Idempotent,
    Destructive,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolBackendCfg {
    Rest {
        target: TargetCfg,
        method: String,
    },
    Mcp {
        server: String,
        tool: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenApiCfg {
    /// 本地 OpenAPI 文档，只转换显式声明的 operationId，忽略文档中的 server URL。
    pub file: String,
    pub target: TargetCfg,
    pub operations: Vec<OpenApiOperationCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenApiOperationCfg {
    pub operation_id: String,
    pub name: String,
    pub discovery: AclCfg,
    pub invocation: AclCfg,
    pub side_effect: SideEffect,
    pub deadline_ms: u64,
    pub max_calls_per_session: u64,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}
