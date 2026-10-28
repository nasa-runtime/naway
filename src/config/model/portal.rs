//! 开发者门户、API 目录与用量套餐声明。

use super::*;

/// 全局 usage-plan 目录与 consumer→plan 稳定绑定。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct UsagePlansCfg {
    /// 可选外部持久事实源；端点、信任与容量属于需要重启的进程级边界。
    #[serde(default)]
    pub meter: Option<crate::portal::meter::MeterCfg>,
    /// 套餐名到固定窗口配额的映射。
    #[serde(default)]
    pub plans: HashMap<String, UsagePlanCfg>,
    /// 已认证 consumer id 到套餐名的稳定绑定。
    #[serde(default)]
    pub consumers: HashMap<String, String>,
    /// 成员仅匹配认证链已验证的 consumer；套餐映射在构建期展开，同层不同套餐拒绝歧义。
    #[serde(default)]
    pub groups: std::collections::BTreeMap<String, crate::security::scopes::ConsumerGroupCfg>,
    /// 认证前的静态作用域与认证后的身份作用域共用固定层级和失败闭合规则。
    #[serde(default)]
    pub policies: Vec<crate::security::scopes::PolicyCfg>,
}

/// 一个固定窗口请求配额套餐。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UsagePlanCfg {
    /// 每个固定窗口内允许的基础请求数。
    pub requests: u64,
    /// 固定窗口长度，单位毫秒。
    pub window_ms: u64,
    /// 在基础额度之外允许的突发请求数。
    #[serde(default)]
    pub burst: u64,
    /// 本节点为该套餐维护的最大活动 consumer 维度数。
    #[serde(default = "default_usage_plan_max_active_keys")]
    pub max_active_keys: usize,
    /// 维度表达到上限时是否放行；默认 false，配额安全优先。
    #[serde(default)]
    pub active_keys_fail_open: bool,
}

/// 开发者门户、API 产品目录和 OpenAPI 自动路由配置。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct DeveloperPortalCfg {
    /// 总开关；关闭时仍声明 catalog/key application 会被构建期拒绝，避免误以为已发布。
    #[serde(default)]
    pub enabled: bool,
    /// 允许未携带 admin 凭据读取门户页面、catalog 和 OpenAPI 文档。
    #[serde(default)]
    pub public_catalog: bool,
    /// 每份 OpenAPI 原始文件的硬上限。
    #[serde(default = "default_portal_max_document_bytes")]
    pub max_document_bytes: usize,
    /// 导入的 API catalog；每个 operation 物化为普通 gateway route。
    #[serde(default)]
    pub catalogs: Vec<DeveloperCatalogCfg>,
    /// 与路由部署身份分离的产品、版本与文档目录。
    #[serde(default)]
    pub products: Vec<crate::portal::products::ProductCfg>,
    /// 已验证 SSO、团队与应用合同；启用后应用变更始终经过双人审批。
    #[serde(default)]
    pub management: Option<crate::portal::management::ManagementCfg>,
    /// 只创建待审批申请，不在公网请求链直接签发 secret。
    #[serde(default)]
    pub key_applications: DeveloperKeyApplicationsCfg,
}

/// 一份 OpenAPI 文档到一个 HTTP proxy/upstream 的声明式映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeveloperCatalogCfg {
    /// 稳定目录 id，用于 URL 与生成 route id。
    pub id: String,
    /// 门户展示标题；空时读取 OpenAPI `info.title`。
    #[serde(default)]
    pub title: String,
    /// 门户展示描述；空时读取 OpenAPI `info.description`。
    #[serde(default)]
    pub description: String,
    /// OpenAPI 3 JSON/YAML 文件，相对 gateway.yml 解析。
    pub openapi_file: String,
    /// 目标 proxy id；多 proxy 时必填，旧单入口可写 `default`。
    #[serde(default = "default_portal_proxy_id")]
    pub proxy_id: String,
    /// 所有生成 route 的上游 origin (`http(s)://` 或 `lb://`)。
    pub upstream: String,
    /// 附加到每条生成 route 的原生 filter；认证/改写仍走统一 DSL 与构建校验。
    #[serde(default)]
    pub filters: Vec<String>,
    /// 每条生成 route 的 usage-plan 绑定。
    #[serde(default)]
    pub usage_plan: Option<UsagePlanRouteCfg>,
    /// OpenAPI requestBody 校验聚合上限；没有 requestBody 的 operation 保持 head-only。
    #[serde(default = "default_portal_max_validation_body_bytes")]
    pub max_validation_body_bytes: u64,
    /// 生成 route 的顺序。
    #[serde(default)]
    pub order: i32,
}

/// 门户 key 申请入口。它只写一条 pending 申请，真正的 key 签发必须由独立审批面完成。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeveloperKeyApplicationsCfg {
    /// 是否开放开发者 key 申请入口。
    #[serde(default)]
    pub enabled: bool,
    /// 门户专用 Bearer token SecretSource；与 admin/API key 凭据隔离。
    #[serde(default)]
    pub authorization_token: String,
    /// DynamicStore collection，支持 local/file/Redis 后端。
    #[serde(default = "default_portal_key_application_collection")]
    pub collection: String,
    /// 单次 JSON 申请 body 上限。
    #[serde(default = "default_portal_key_application_body_bytes")]
    pub max_body_bytes: usize,
    /// pending key 数量上限；达到上限后拒绝新 applicant，已有 applicant 仍可幂等覆盖。
    #[serde(default = "default_portal_max_pending_applications")]
    pub max_pending: usize,
}

impl Default for DeveloperKeyApplicationsCfg {
    /// 业务作用：构造 `DeveloperKeyApplicationsCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            authorization_token: String::new(),
            collection: default_portal_key_application_collection(),
            max_body_bytes: default_portal_key_application_body_bytes(),
            max_pending: default_portal_max_pending_applications(),
        }
    }
}

/// 业务作用：为未显式声明的 `max_document_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_portal_max_document_bytes() -> usize {
    8 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `proxy_id` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_portal_proxy_id() -> String {
    "default".to_owned()
}

/// 业务作用：为未显式声明的 `max_validation_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_portal_max_validation_body_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `collection` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_portal_key_application_collection() -> String {
    "developer-key-applications".to_owned()
}

/// 业务作用：为未显式声明的 `max_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_portal_key_application_body_bytes() -> usize {
    16 * 1024
}

/// 业务作用：为未显式声明的 `max_pending` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_portal_max_pending_applications() -> usize {
    10_000
}

/// 业务作用：为未显式声明的 `max_active_keys` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_usage_plan_max_active_keys() -> usize {
    100_000
}

/// route 对全局 usage-plan 目录的绑定。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UsagePlanRouteCfg {
    /// 未出现在 `usage_plans.consumers` 的身份所用套餐；空表示不允许未映射 consumer。
    #[serde(default)]
    pub default_plan: Option<String>,
    /// true 时没有可信 consumer 直接 401；false 时匿名身份可使用 default_plan。
    #[serde(default = "default_true")]
    pub require_consumer: bool,
}
