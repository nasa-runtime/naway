//! 管理面认证、审批、发布与审计声明。

use super::*;

/// 管理/观测面配置(与数据面端口隔离,默认只绑内网回环,绝不暴露到数据面端口)。
#[derive(Debug, Deserialize, Clone)]
pub struct AdminCfg {
    /// 管理面监听地址；默认 `127.0.0.1:18080`，热更先绑定候选端口再换代监听器。
    #[serde(default = "default_admin_listen")]
    pub listen: String,
    /// 是否在管理面暴露 `/metrics`(Prometheus)，默认true，仍受管理认证与权限约束。
    #[serde(default = "default_true")]
    pub expose_metrics: bool,
    /// 内置实时监控，与Prometheus独立，不保留历史采样。
    #[serde(default)]
    pub monitor: AdminMonitorCfg,
    /// 独立节点管理连接；不依赖注册中心、配置中心或实时指标采样开关。
    #[serde(default)]
    pub management: crate::config::management::Config,
    /// 跨管理节点共享的候选与审批权威，默认关闭且不依赖配置中心。
    #[serde(default)]
    pub operations: crate::config::operations::Config,
    /// 管理面自身认证:保护 `/readyz`、`/metrics` 与 `/admin/**`;`/healthz` 默认可匿名给容器 liveness。
    #[serde(default)]
    pub auth: AdminAuthCfg,
    /// 控制面细粒度授权；关闭时保持 “已认证即管理员”兼容语义。
    #[serde(default)]
    pub rbac: AdminRbacCfg,
    /// 管理操作持久、防篡改审计。
    #[serde(default)]
    pub audit: AdminAuditCfg,
    /// 集群配置渐进发布策略；关闭时保持一次 CAS 全量发布的兼容行为。
    #[serde(default)]
    pub rollout: AdminRolloutCfg,
    /// 高危管理变更的 maker-checker 策略；关闭时保持直接执行兼容行为。
    #[serde(default)]
    pub approval: AdminApprovalCfg,
    /// UI/API 候选配置 dry-run 的请求体上限；只影响控制面，不改变数据面 body 策略。
    #[serde(default = "default_admin_max_config_body_bytes")]
    pub max_config_body_bytes: usize,
}

impl Default for AdminCfg {
    /// 业务作用：构造 `AdminCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            listen: default_admin_listen(),
            expose_metrics: true,
            monitor: AdminMonitorCfg::default(),
            management: crate::config::management::Config::default(),
            operations: crate::config::operations::Config::default(),
            auth: AdminAuthCfg::default(),
            rbac: AdminRbacCfg::default(),
            audit: AdminAuditCfg::default(),
            rollout: AdminRolloutCfg::default(),
            approval: AdminApprovalCfg::default(),
            max_config_body_bytes: default_admin_max_config_body_bytes(),
        }
    }
}

/// 内置实时监控与静态集群成员；仅管理读面使用，不进入业务转发热路径。
#[derive(Debug, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct AdminMonitorCfg {
    pub enabled: bool,
    pub sample_interval_ms: u64,
    pub use_discovery: bool,
    pub peers: Vec<AdminMonitorPeerCfg>,
}

impl Default for AdminMonitorCfg {
    /// 业务作用：提供独立本机实时监控，只有实际观察时才启动采样。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：两秒周期和空静态成员；自动发现仍受各自中心开关与跨节点授权限制。
    fn default() -> Self {
        Self {
            enabled: true,
            sample_interval_ms: 2000,
            use_discovery: true,
            peers: Vec::new(),
        }
    }
}

/// 无注册中心部署下明确声明的管理节点，禁止由浏览器输入任意地址。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminMonitorPeerCfg {
    pub id: String,
    pub address: String,
}

/// 高危管理变更的双人复核策略。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminApprovalCfg {
    /// 是否把指定资源的写操作先登记为待审批候选。
    #[serde(default)]
    pub enabled: bool,
    /// 需要复核的资源域；仅允许 Sentinel、Consumers 与 Certs。
    #[serde(default = "default_admin_approval_resources")]
    pub resources: Vec<AdminResource>,
    /// 待审批候选有效期，过期候选永不执行。
    #[serde(default = "default_admin_approval_ttl_seconds")]
    pub ttl_seconds: u64,
    /// 单进程待审批候选上限；达到上限时拒绝新提交。
    #[serde(default = "default_admin_approval_max_pending")]
    pub max_pending: usize,
}

impl Default for AdminApprovalCfg {
    /// 业务作用：构造 `AdminApprovalCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            resources: default_admin_approval_resources(),
            ttl_seconds: default_admin_approval_ttl_seconds(),
            max_pending: default_admin_approval_max_pending(),
        }
    }
}

/// 集群配置金丝雀发布与健康门控策略。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminRolloutCfg {
    /// 是否把 Nacos 配置发布改为先 canary、再全量的状态机。
    #[serde(default)]
    pub enabled: bool,
    /// 从符合 selector 的启用成员中选取的节点数。
    #[serde(default = "default_admin_rollout_canary_count")]
    pub canary_count: usize,
    /// 可选成员 metadata 键；空值表示按稳定 node_id 选择所有启用成员中的前 N 个。
    #[serde(default)]
    pub selector_key: String,
    /// selector_key 非空时要求 metadata 精确等于该值。
    #[serde(default)]
    pub selector_value: String,
    /// canary 换版并取得首个健康样本后的观察窗口。
    #[serde(default = "default_admin_rollout_observation_seconds")]
    pub observation_seconds: u64,
    /// 观察窗内 canary 请求 5xx 比例绝对上限。
    #[serde(default = "default_admin_rollout_max_5xx_ratio")]
    pub max_5xx_ratio: f64,
    /// canary p99 相对基线的最大倍率；没有基线流量时只使用绝对上限。
    #[serde(default = "default_admin_rollout_max_p99_regression_ratio")]
    pub max_p99_regression_ratio: f64,
    /// canary 请求端到端 p99 绝对上限。
    #[serde(default = "default_admin_rollout_max_p99_ms")]
    pub max_p99_ms: u64,
    /// 是否要求另一名具备 Config/Write 权限的主体确认后才从 canary 放量。
    #[serde(default)]
    pub require_approval: bool,
}

impl Default for AdminRolloutCfg {
    /// 业务作用：构造 `AdminRolloutCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            canary_count: default_admin_rollout_canary_count(),
            selector_key: String::new(),
            selector_value: String::new(),
            observation_seconds: default_admin_rollout_observation_seconds(),
            max_5xx_ratio: default_admin_rollout_max_5xx_ratio(),
            max_p99_regression_ratio: default_admin_rollout_max_p99_regression_ratio(),
            max_p99_ms: default_admin_rollout_max_p99_ms(),
            require_approval: false,
        }
    }
}

/// 管理面认证配置。
#[derive(Debug, Deserialize, Clone)]
pub struct AdminAuthCfg {
    /// 是否启用管理面认证。默认 false，仅适用于受信本机或隔离内网；对外开放 admin/UI 前必须开启。
    #[serde(default)]
    pub enabled: bool,
    /// Bearer token。非空时接受 `Authorization: Bearer <token>`。
    #[serde(default)]
    pub bearer_token: String,
    /// Basic 用户名。与 `basic_password` 同时非空时接受 `Authorization: Basic ...`。
    #[serde(default)]
    pub basic_user: String,
    /// Basic 密码。与 `basic_user` 同时非空时启用 Basic。
    #[serde(default)]
    pub basic_password: String,
    /// Basic challenge realm。
    #[serde(default = "default_admin_auth_realm")]
    pub realm: String,
    /// 是否允许 `/healthz` 匿名访问。默认 true,避免容器 liveness 被凭据轮换误伤。
    #[serde(default = "default_true")]
    pub allow_healthz_unauthenticated: bool,
    /// 允许发起管理面状态变更请求的浏览器 Origin。空列表表示拒绝所有带 Origin/Referer 的写请求；
    /// CLI/服务间请求通常不带这两个浏览器来源头，不受影响。
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// 是否允许本节点用**自己这份 admin 凭据**去抓取同集群其它节点的 `/metrics`。
    ///
    /// 默认 **false**,必须显式开启。为什么不默认开:
    /// - 它让 admin 从"只被访问"变成"会主动外连",是**攻击面的实质变化**——被打穿的
    ///   admin 可以借它探测内网,必须由运维明示接受;
    /// - 它假设集群各节点**同构配置**(同一份凭据)。该假设在自动化部署下通常成立,
    ///   但不成立时抓取只会 401、不会静默串权,失败如实计入响应而不是伪造零值。
    ///
    /// 凭据只从进程内已解析的配置取,**不接受请求携带的任何凭证**——否则控制面就成了
    /// 一个可被借用的跳板(调用方带什么凭据,网关就拿什么去连内网别的机器)。
    /// 开启时必须同时启用 `admin.auth`；RBAC 模式还必须至少有一个 Cluster/Read principal。
    #[serde(default)]
    pub allow_cluster_metrics_scrape: bool,
}

impl Default for AdminAuthCfg {
    /// 业务作用：构造 `AdminAuthCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            bearer_token: String::new(),
            basic_user: String::new(),
            basic_password: String::new(),
            realm: default_admin_auth_realm(),
            allow_healthz_unauthenticated: true,
            allowed_origins: Vec::new(),
            allow_cluster_metrics_scrape: false,
        }
    }
}

/// 管理面 RBAC bootstrap 配置。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct AdminRbacCfg {
    /// 是否启用 principal 级授权；启用后旧 `admin.auth` 单凭据不能旁路 principal 绑定。
    #[serde(default)]
    pub enabled: bool,
    /// 静态 principal 列表；凭据支持 SecretSource，角色/授权变更随快照热更。
    #[serde(default)]
    pub principals: Vec<AdminPrincipalCfg>,
}

/// 一个可认证的管理端主体及其角色/附加授权。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminPrincipalCfg {
    /// 审计稳定主体 id；不能从请求头直接指定。
    pub id: String,
    /// 此 principal 的 Bearer token SecretSource。
    #[serde(default)]
    pub bearer_token: String,
    /// 此 principal 的 Basic 用户名。
    #[serde(default)]
    pub basic_user: String,
    /// 此 principal 的 Basic 密码 SecretSource。
    #[serde(default)]
    pub basic_password: String,
    /// 内置角色，可组合取权限并集。
    #[serde(default)]
    pub roles: Vec<AdminRole>,
    /// 面向自定义运维分工的附加授权，不会撤销内置角色权限。
    #[serde(default)]
    pub grants: Vec<AdminGrantCfg>,
}

/// 一条自定义 RBAC 授权，表达固定资源域上的动作集合。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminGrantCfg {
    /// 受控资源域。
    pub resource: AdminResource,
    /// 允许动作；空列表在构建期拒绝，防止看似配置但实际无效。
    pub actions: Vec<AdminAction>,
}

/// 架构内置角色；角色只提供权限模板，认证仍绑定到具体 principal。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AdminRole {
    /// 只通过显式工作区成员关系授权，不具备任何平台级管理权限。
    Workspace,
    /// 普通运维资源只读；流量诊断仍需显式 grant。
    Viewer,
    /// 路由/流控配置的 read、dry-run 与 write。
    Operator,
    /// 接口守卫/ACL/黑名单及 emergency-kill。
    SecuritySre,
    /// 全部资源与动作。
    Admin,
}

/// 管理面资源域；值固定，因此可在快照构建期编译为低成本权限位图。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AdminResource {
    /// 完整配置 bundle、历史与发布状态。
    Config,
    /// HTTP 路由。
    Routes,
    /// 接口守卫与动态 disable。
    InterfaceGuard,
    /// Sentinel 限流/熔断规则。
    Sentinel,
    /// ACL 与黑白名单。
    Acl,
    /// Secret 引用与轮换。
    Secrets,
    /// 消费者与 API key。
    Consumers,
    /// TLS/ACME 证书。
    Certs,
    /// 集群成员、节点操作与指标。
    Cluster,
    /// HTTP response cache。
    Cache,
    /// 长连接 drain/关闭。
    Connections,
    /// 上游服务发现视图。
    Upstreams,
    /// 防篡改操作审计。
    Audit,
    /// 限时流量诊断的申请、复核和有界下载。
    Diagnostics,
}

impl AdminResource {
    /// 固定资源域全集；用于内置角色构建，不依赖用户输入产生动态 label。
    pub const ALL: [Self; 14] = [
        Self::Config,
        Self::Routes,
        Self::InterfaceGuard,
        Self::Sentinel,
        Self::Acl,
        Self::Secrets,
        Self::Consumers,
        Self::Certs,
        Self::Cluster,
        Self::Cache,
        Self::Connections,
        Self::Upstreams,
        Self::Audit,
        Self::Diagnostics,
    ];

    /// 业务作用：转换为权限位图中的稳定资源序号。
    pub const fn index(self) -> u32 {
        self as u32
    }
}

/// 管理动作按风险递增；emergency-kill 与普通 write 始终分开授权。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AdminAction {
    /// 读取状态或配置。
    Read,
    /// build-only 校验、diff 或 explain。
    DryRun,
    /// 常规配置/运行态写入。
    Write,
    /// 秒级封杀接口、IP 或主动关闭连接。
    EmergencyKill,
    /// 配置回滚。
    Rollback,
}

impl AdminAction {
    /// 每个资源域预留的动作槽数。
    pub const COUNT: u32 = 5;

    /// 业务作用：转换为权限位图中的稳定动作序号。
    pub const fn index(self) -> u32 {
        self as u32
    }
}

/// 管理操作审计的持久化/外部确认配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminAuditCfg {
    /// 是否启用审计；RBAC 启用时必须同时启用。
    #[serde(default)]
    pub enabled: bool,
    /// 本地 append-only hash-chain spool；相对路径以 gateway.yml 目录为基准。
    #[serde(default = "default_admin_audit_file")]
    pub file: String,
    /// HMAC-SHA256 SecretSource；至少 32 bytes，用于检测离线修改/重排。
    #[serde(default)]
    pub signing_key: String,
    /// 可选外部持久审计 HTTP endpoint；每个写动作在副作用前等待 2xx 确认。
    #[serde(default)]
    pub endpoint: String,
    /// 外部 endpoint 的 Authorization header SecretSource。
    #[serde(default)]
    pub authorization: String,
    /// 外部确认超时。
    #[serde(default = "default_admin_audit_timeout_ms")]
    pub timeout_ms: u64,
    /// 是否每条本地记录 `sync_data`；生产默认 true，避免 OS page cache 丢审计。
    #[serde(default = "default_true")]
    pub fsync: bool,
    /// 单条 canonical JSON 上限。
    #[serde(default = "default_admin_audit_max_record_bytes")]
    pub max_record_bytes: usize,
    /// `/api/audit` 内存保留条数；完整历史仍在持久 spool/外部 sink。
    #[serde(default = "default_admin_audit_history_limit")]
    pub history_limit: usize,
    /// 仅用于开发/单机：显式允许没有外部持久 sink；生产不应开启。
    #[serde(default)]
    pub allow_local_only: bool,
}

impl Default for AdminAuditCfg {
    /// 业务作用：构造 `AdminAuditCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            file: default_admin_audit_file(),
            signing_key: String::new(),
            endpoint: String::new(),
            authorization: String::new(),
            timeout_ms: default_admin_audit_timeout_ms(),
            fsync: true,
            max_record_bytes: default_admin_audit_max_record_bytes(),
            history_limit: default_admin_audit_history_limit(),
            allow_local_only: false,
        }
    }
}

/// 业务作用：为未显式声明的 `listen` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_admin_listen() -> String {
    "127.0.0.1:18080".to_string()
}

/// 业务作用：为未显式声明的 `realm` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_admin_auth_realm() -> String {
    "gateway-admin".to_string()
}

/// 业务作用：为未显式声明的 `file` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_admin_audit_file() -> String {
    ".gateway-audit/audit.jsonl".to_string()
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_admin_audit_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：为未显式声明的 `max_record_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_admin_audit_max_record_bytes() -> usize {
    64 * 1024
}

/// 业务作用：为未显式声明的 `history_limit` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_admin_audit_history_limit() -> usize {
    1_024
}

/// 业务作用：为未显式声明的 `max_config_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_admin_max_config_body_bytes() -> usize {
    2 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `canary_count` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_admin_rollout_canary_count() -> usize {
    1
}

/// 业务作用：为未显式声明的 `observation_seconds` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_admin_rollout_observation_seconds() -> u64 {
    60
}

/// 业务作用：为未显式声明的 `max_5xx_ratio` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_admin_rollout_max_5xx_ratio() -> f64 {
    0.01
}

/// 业务作用：为未显式声明的 `max_p99_regression_ratio` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_admin_rollout_max_p99_regression_ratio() -> f64 {
    1.5
}

/// 业务作用：为未显式声明的 `max_p99_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_admin_rollout_max_p99_ms() -> u64 {
    2_000
}

/// 业务作用：提供 maker-checker 默认覆盖的高危资源集合。
///
/// 参数说明: 无。
///
/// 返回：返回流量防护、消费者凭据和证书三个资源域。
pub(super) fn default_admin_approval_resources() -> Vec<AdminResource> {
    vec![
        AdminResource::Sentinel,
        AdminResource::Consumers,
        AdminResource::Certs,
    ]
}

/// 业务作用：提供待审批候选的默认有效期。
///
/// 参数说明: 无。
///
/// 返回：返回 900 秒。
pub(super) const fn default_admin_approval_ttl_seconds() -> u64 {
    900
}

/// 业务作用：提供待审批队列的默认硬上限。
///
/// 参数说明: 无。
///
/// 返回：返回 64 条。
pub(super) const fn default_admin_approval_max_pending() -> usize {
    64
}
