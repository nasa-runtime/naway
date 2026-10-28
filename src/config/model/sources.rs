//! 配置来源、重载与 xDS 权威声明。

use super::*;

/// 进程级控制面模式与 xDS bootstrap 配置。
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneCfg {
    /// 配置事实源模式；默认 native，不启动任何 xDS task。
    #[serde(default)]
    pub mode: ControlPlaneModeCfg,
    /// 可选 xDS v3 client 配置。
    #[serde(default)]
    pub xds: XdsCfg,
}

/// 配置事实源的进程级所有权模式。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneModeCfg {
    /// file/Nacos/admin 继续拥有全部资源。
    #[default]
    Native,
    /// xDS 拥有声明为 xDS 的完整资源域。
    Xds,
    /// native 与 xDS 按资源域整块分权，禁止同域 merge。
    Hybrid,
}

/// xDS v3 client bootstrap 配置；所有字段只允许本地配置修改。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsCfg {
    /// 显式总开关；未编 `xds-client` 时 true 必须在构建期失败。
    #[serde(default)]
    pub enabled: bool,
    /// ADS 传输 variant。
    #[serde(default)]
    pub transport: XdsTransportCfg,
    /// management server URI；生产非 loopback 必须为 HTTPS+mTLS。
    #[serde(default)]
    pub server: String,
    /// 稳定 Node identity 与固定 allowlist metadata。
    #[serde(default)]
    pub node: XdsNodeCfg,
    /// xDS 自身 TLS/mTLS 信任与身份；远端资源永远不能修改。
    #[serde(default)]
    pub tls: XdsTlsCfg,
    /// 启动时 xDS 不可达的策略。
    #[serde(default)]
    pub startup_policy: XdsStartupPolicyCfg,
    /// 断线重连退避。
    #[serde(default)]
    pub reconnect: XdsReconnectCfg,
    /// HTTP/2 keepalive 参数。
    #[serde(default)]
    pub keepalive: XdsKeepaliveCfg,
    /// decode/translate/warming/apply 的硬预算。
    #[serde(default)]
    pub limits: XdsLimitsCfg,
    /// listeners/routes/clusters/endpoints/secrets 的整域 owner。
    #[serde(default)]
    pub ownership: XdsOwnershipCfg,
}

impl Default for XdsCfg {
    /// 业务作用：提供完全关闭、无 transport task 的 xDS 安全默认值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：native owner、ADS SotW 与规范硬预算；`enabled=false`。
    fn default() -> Self {
        Self {
            enabled: false,
            transport: XdsTransportCfg::default(),
            server: String::new(),
            node: XdsNodeCfg::default(),
            tls: XdsTlsCfg::default(),
            startup_policy: XdsStartupPolicyCfg::default(),
            reconnect: XdsReconnectCfg::default(),
            keepalive: XdsKeepaliveCfg::default(),
            limits: XdsLimitsCfg::default(),
            ownership: XdsOwnershipCfg::default(),
        }
    }
}

/// xDS ADS 传输 variant。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum XdsTransportCfg {
    /// v3 AggregatedDiscoveryService SotW bidi stream。
    #[default]
    AdsSotwV3,
    /// v3 Delta ADS；按资源 version/removed/TTL 做增量缓存。
    AdsDeltaV3,
}

/// xDS 启动不可达时的唯一降级策略。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum XdsStartupPolicyCfg {
    /// xDS-owned 资源未取得有效版本时 readiness 保持 503。
    #[default]
    RequireXds,
    /// 仅允许经过签名、有效期和完整校验的磁盘 LKG；该策略尚未启用，配置校验会拒绝。
    SignedLastGood,
}

/// xDS Node identity；metadata 只能使用构建期固定 allowlist key。
#[derive(Debug, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsNodeCfg {
    /// 节点稳定唯一 id。
    #[serde(default)]
    pub id: String,
    /// 节点所属逻辑 gateway cluster。
    #[serde(default)]
    pub cluster: String,
    /// 允许发给 management server 的低敏、低基数 metadata。
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// 一个文件型 xDS SecretSource；不接受远端覆盖或明文内联私钥。
#[derive(Debug, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsSecretFileCfg {
    /// PEM 文件路径；相对 gateway.yml 目录解析。
    #[serde(default)]
    pub file: String,
}

/// xDS management server 的 TLS/mTLS bootstrap 身份。
#[derive(Debug, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsTlsCfg {
    /// 服务端 CA PEM。
    #[serde(default)]
    pub ca: XdsSecretFileCfg,
    /// 客户端证书链 PEM。
    #[serde(default)]
    pub cert: XdsSecretFileCfg,
    /// 客户端私钥 PEM。
    #[serde(default)]
    pub key: XdsSecretFileCfg,
    /// TLS SNI 与证书校验名。
    #[serde(default)]
    pub server_name: String,
}

/// xDS 断线重连的指数退避参数。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsReconnectCfg {
    /// 初始退避；使用 `200ms`/`2s` 形式。
    #[serde(default = "default_xds_initial_backoff")]
    pub initial_backoff: String,
    /// 最大退避。
    #[serde(default = "default_xds_max_backoff")]
    pub max_backoff: String,
    /// 对称 jitter 比例，范围 0..=1。
    #[serde(default = "default_xds_jitter")]
    pub jitter: f64,
}

impl Default for XdsReconnectCfg {
    /// 业务作用：提供避免 management server 重连风暴的保守退避默认值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：200ms 初始、30s 上限与 20% jitter。
    fn default() -> Self {
        Self {
            initial_backoff: default_xds_initial_backoff(),
            max_backoff: default_xds_max_backoff(),
            jitter: default_xds_jitter(),
        }
    }
}

/// ADS HTTP/2 keepalive 参数。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsKeepaliveCfg {
    /// 空闲 PING 周期。
    #[serde(default = "default_xds_keepalive_interval")]
    pub interval: String,
    /// PING ACK deadline。
    #[serde(default = "default_xds_keepalive_timeout")]
    pub timeout: String,
}

impl Default for XdsKeepaliveCfg {
    /// 业务作用：提供低频保活且能有界发现半开连接的默认值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：30s interval 与 5s timeout。
    fn default() -> Self {
        Self {
            interval: default_xds_keepalive_interval(),
            timeout: default_xds_keepalive_timeout(),
        }
    }
}

/// xDS decode、缓存、warming 与 apply channel 的资源硬上限。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsLimitsCfg {
    /// 单个 DiscoveryResponse 解码上限。
    #[serde(default = "default_xds_max_response_bytes")]
    pub max_response_bytes: usize,
    /// 单 type SotW 资源数或 Delta 单次变更数上限。
    #[serde(default = "default_xds_max_resources_per_type")]
    pub max_resources_per_type: usize,
    /// 单个 Any payload 上限。
    #[serde(default = "default_xds_max_resource_bytes")]
    pub max_resource_bytes: usize,
    /// 单 type accepted/warming cache 资源与 named tombstone 上限。
    #[serde(default = "default_xds_max_warming_resources")]
    pub max_warming_resources: usize,
    /// transport→apply 有界 channel 容量。
    #[serde(default = "default_xds_max_apply_queue")]
    pub max_apply_queue: usize,
    /// 依赖 warming deadline。
    #[serde(default = "default_xds_warming_timeout")]
    pub warming_timeout: String,
}

impl Default for XdsLimitsCfg {
    /// 业务作用：固定 xDS 敌意/异常控制面输入的默认内存和队列边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与  bootstrap 示例一致的硬上限。
    fn default() -> Self {
        Self {
            max_response_bytes: default_xds_max_response_bytes(),
            max_resources_per_type: default_xds_max_resources_per_type(),
            max_resource_bytes: default_xds_max_resource_bytes(),
            max_warming_resources: default_xds_max_warming_resources(),
            max_apply_queue: default_xds_max_apply_queue(),
            warming_timeout: default_xds_warming_timeout(),
        }
    }
}

/// 一个 xDS 资源域的唯一 owner。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum XdsResourceOwnerCfg {
    /// file/Nacos/admin owner。
    #[default]
    Native,
    /// xDS owner；native 控制面不得写同域影子配置。
    Xds,
}

/// 五个资源域的整块所有权声明。
#[derive(Debug, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsOwnershipCfg {
    /// listener topology owner。
    #[serde(default)]
    pub listeners: XdsResourceOwnerCfg,
    /// route owner。
    #[serde(default)]
    pub routes: XdsResourceOwnerCfg,
    /// cluster policy owner。
    #[serde(default)]
    pub clusters: XdsResourceOwnerCfg,
    /// endpoint table owner。
    #[serde(default)]
    pub endpoints: XdsResourceOwnerCfg,
    /// TLS secret owner。
    #[serde(default)]
    pub secrets: XdsResourceOwnerCfg,
}

/// 业务作用：提供 xDS 首次重连退避默认值。
///
/// 参数说明: 无。
///
/// 返回：`200ms` duration 字符串。
pub(super) fn default_xds_initial_backoff() -> String {
    "200ms".to_owned()
}

/// 业务作用：限制 xDS 指数退避上界，避免断线后永久沉默。
///
/// 参数说明: 无。
///
/// 返回：`30s` duration 字符串。
pub(super) fn default_xds_max_backoff() -> String {
    "30s".to_owned()
}

/// 业务作用：提供抑制 xDS 客户端同步重连风暴的默认 jitter。
///
/// 参数说明: 无。
///
/// 返回：20% 对称 jitter 比例。
pub(super) const fn default_xds_jitter() -> f64 {
    0.2
}

/// 业务作用：提供 ADS HTTP/2 空闲保活周期。
///
/// 参数说明: 无。
///
/// 返回：`30s` duration 字符串。
pub(super) fn default_xds_keepalive_interval() -> String {
    "30s".to_owned()
}

/// 业务作用：限定 ADS keepalive ACK 等待时间。
///
/// 参数说明: 无。
///
/// 返回：`5s` duration 字符串。
pub(super) fn default_xds_keepalive_timeout() -> String {
    "5s".to_owned()
}

/// 业务作用：限制单个 xDS response 的解码内存。
///
/// 参数说明: 无。
///
/// 返回：16 MiB 默认上限。
pub(super) const fn default_xds_max_response_bytes() -> usize {
    16 * 1024 * 1024
}

/// 业务作用：限制单 type SotW 资源或 Delta 单次变更数量。
///
/// 参数说明: 无。
///
/// 返回：100000 条默认上限。
pub(super) const fn default_xds_max_resources_per_type() -> usize {
    100_000
}

/// 业务作用：限制单个 xDS Any payload 的内存占用。
///
/// 参数说明: 无。
///
/// 返回：1 MiB 默认上限。
pub(super) const fn default_xds_max_resource_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制 accepted/warming cache 与 named deletion evidence 的驻留规模。
///
/// 参数说明: 无。
///
/// 返回：100000 条默认上限。
pub(super) const fn default_xds_max_warming_resources() -> usize {
    100_000
}

/// 业务作用：限制 transport 到 apply single-writer 的在途候选数。
///
/// 参数说明: 无。
///
/// 返回：64 个候选的默认上限。
pub(super) const fn default_xds_max_apply_queue() -> usize {
    64
}

/// 业务作用：限定 xDS 依赖 warming 的最长等待时间。
///
/// 参数说明: 无。
///
/// 返回：`30s` duration 字符串。
pub(super) fn default_xds_warming_timeout() -> String {
    "30s".to_owned()
}

/// 热重载 worker 的有界队列与去抖参数。
///
/// 这是 bootstrap 执行配置：修改后需要重启进程才能重建 channel，避免热更时同时存在
/// 新旧两个 reload worker。
#[derive(Debug, Deserialize, Clone)]
pub struct ReloadCfg {
    /// naml watcher、SIGHUP 与 Nacos 共用事件队列容量。0 按 1 处理，始终保持有界。
    #[serde(default = "default_reload_channel_capacity")]
    pub channel_capacity: usize,
    /// 收到首个变更事件后的聚合窗口(ms)。0 表示不等待，仍会排空已入队的重复事件。
    #[serde(default = "default_reload_debounce_ms")]
    pub debounce_ms: u64,
}

impl Default for ReloadCfg {
    /// 业务作用：构造 `ReloadCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            channel_capacity: default_reload_channel_capacity(),
            debounce_ms: default_reload_debounce_ms(),
        }
    }
}

/// 控制面配置文档来源。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigSourceCfg {
    /// 远端配置输入总开关；false 屏蔽 Nacos、配置 provider、xDS client 与 Kubernetes 路由输入。
    /// 不关闭本地文件热更或 Admin；缺省 true 仅允许后端开关生效，切换总开关需要重启。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Nacos 配置中心统一配置来源。启用后由 reload worker watch 远端三份配置并 build-then-swap。
    #[serde(default)]
    pub nacos: NacosConfigSourceCfg,
}

impl Default for ConfigSourceCfg {
    /// 业务作用：保留配置后端的显式启用语义，默认不订阅任何配置中心。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：总开关允许后端声明生效，Nacos 配置订阅默认关闭。
    fn default() -> Self {
        Self {
            enabled: true,
            nacos: NacosConfigSourceCfg::default(),
        }
    }
}

/// Nacos 配置中心三文档或原子 bundle 的 bootstrap 配置。
#[derive(Debug, Deserialize, Clone)]
pub struct NacosConfigSourceCfg {
    /// 是否启用 Nacos 配置中心 watch；还需总开关允许。默认 false，本地配置模式也可多节点部署。
    #[serde(default)]
    pub enabled: bool,
    /// Nacos server 地址,如 `"127.0.0.1:8848"` 或逗号分隔多地址。
    #[serde(default)]
    pub server_addr: String,
    /// Nacos namespace ID;public 空间留空。
    #[serde(default)]
    pub namespace: String,
    /// Nacos group。
    #[serde(default = "default_nacos_group")]
    pub group: String,
    /// Nacos 端来源标识。
    #[serde(default = "default_nacos_app_name")]
    pub app_name: String,
    /// Nacos 鉴权用户名。
    #[serde(default)]
    pub username: String,
    /// Nacos 鉴权密码。
    #[serde(default)]
    pub password: String,
    /// 主配置 dataId。内容应是完整 `gateway.yml`。
    #[serde(default = "default_nacos_gateway_data_id")]
    pub gateway_data_id: String,
    /// 接口守卫 dataId。内容应是完整 `interface-guard.yml`。
    #[serde(default = "default_nacos_interface_guard_data_id")]
    pub interface_guard_data_id: String,
    /// Sentinel 规则 dataId。内容应是完整 `sentinel-rules.yml`。
    #[serde(default = "default_nacos_sentinel_rules_data_id")]
    pub sentinel_rules_data_id: String,
    /// 可选单 dataId 原子 bundle：JSON 同时携带 gateway/interface-guard/sentinel 三份
    /// 完整文档与 bundle_version。非空时 watcher/回滚只 CAS 该 dataId，不再消费三个
    /// 独立 dataId；空字符串保留旧兼容模式。
    #[serde(default)]
    pub bundle_data_id: String,
    /// 远端配置私有物化目录。相对本地 bootstrap gateway.yml 所在目录;不会覆盖 operator 手写文件。
    #[serde(default = "default_nacos_materialized_dir")]
    pub materialized_dir: String,
    /// watch/connect 失败后的重连退避。
    #[serde(default = "default_nacos_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
}

impl Default for NacosConfigSourceCfg {
    /// 业务作用：构造 `NacosConfigSourceCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            server_addr: String::new(),
            namespace: String::new(),
            group: default_nacos_group(),
            app_name: default_nacos_app_name(),
            username: String::new(),
            password: String::new(),
            gateway_data_id: default_nacos_gateway_data_id(),
            interface_guard_data_id: default_nacos_interface_guard_data_id(),
            sentinel_rules_data_id: default_nacos_sentinel_rules_data_id(),
            bundle_data_id: String::new(),
            materialized_dir: default_nacos_materialized_dir(),
            reconnect_backoff_ms: default_nacos_reconnect_backoff_ms(),
        }
    }
}

/// 业务作用：为未显式声明的 `gateway_data_id` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_nacos_gateway_data_id() -> String {
    "gateway.yml".to_string()
}

/// 业务作用：为未显式声明的 `interface_guard_data_id` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_nacos_interface_guard_data_id() -> String {
    "interface-guard.yml".to_string()
}

/// 业务作用：为未显式声明的 `sentinel_rules_data_id` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_nacos_sentinel_rules_data_id() -> String {
    "sentinel-rules.yml".to_string()
}

/// 业务作用：为未显式声明的 `materialized_dir` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_nacos_materialized_dir() -> String {
    ".gateway-nacos-config".to_string()
}

/// 业务作用：为未显式声明的 `channel_capacity` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_reload_channel_capacity() -> usize {
    16
}

/// 业务作用：为未显式声明的 `debounce_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_reload_debounce_ms() -> u64 {
    300
}
