//! WAF、身份授权、内容防护与地域策略声明。

use super::*;

/// route 级内置 API WAF 配置。
///
/// 未配置时请求保持流式快路径；仅 `inspect_body: true` 会为 JSON/XML 请求启用有界聚合。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WafCfg {
    /// 处置模式：`enforce` 拦截，`monitor` 只记录低基数命中结果后继续转发。
    #[serde(default = "default_waf_mode")]
    pub mode: String,
    /// 是否检查 JSON/XML 请求体；false 时只检查 method、URI 与 headers。
    #[serde(default)]
    pub inspect_body: bool,
    /// 请求体聚合上限；超过后故障关闭，不允许绕过检查进入上游。
    #[serde(default = "default_waf_body_bytes")]
    pub max_body_bytes: u64,
    /// 单个 URI/header/结构化字符串允许扫描的最大字节数；超过后按异常输入处理。
    #[serde(default = "default_waf_value_bytes")]
    pub max_value_bytes: usize,
    /// 启用的固定规则 id；空数组表示启用全部内置规则。
    #[serde(default)]
    pub enabled_rules: Vec<String>,
    /// 按规则与精确 target 配置的例外；不支持通配符，避免例外范围无意扩大。
    #[serde(default)]
    pub exclusions: Vec<WafExclusionCfg>,
    /// 可选外部 literal 规则包；候选发布前必须同时通过摘要、签名、格式和资源预算校验。
    #[serde(default)]
    pub rule_pack: Option<WafRulePackCfg>,
    /// JSON 最大嵌套深度。
    #[serde(default = "default_waf_structured_depth")]
    pub max_json_depth: usize,
    /// 单个 JSON document 最大 value 节点数。
    #[serde(default = "default_waf_structured_nodes")]
    pub max_json_nodes: usize,
    /// XML 最大元素嵌套深度。
    #[serde(default = "default_waf_structured_depth")]
    pub max_xml_depth: usize,
    /// 单个 XML document 最大事件节点数。
    #[serde(default = "default_waf_structured_nodes")]
    pub max_xml_nodes: usize,
    /// 单个 XML document 最大属性总数。
    #[serde(default = "default_waf_xml_attributes")]
    pub max_xml_attributes: usize,
}

/// 一条 WAF 精确例外。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WafExclusionCfg {
    /// 被豁免的固定规则 id。
    pub rule: String,
    /// 精确 target：`path`、`query`、`body` 或 `header:<lowercase-name>`。
    pub target: String,
}

/// 外部 WAF literal 规则包的真实性与资源边界。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WafRulePackCfg {
    /// 本地 JSON 规则包；相对主配置目录解析并纳入统一 dependency watcher。
    pub source: String,
    /// 原始 JSON 字节的 SHA-256 十六进制摘要。
    pub sha256: String,
    /// 原始 JSON 字节的 detached Ed25519 signature，使用 Base64 SecretSource。
    pub signature: String,
    /// 32 字节 Ed25519 public key，使用 Base64 SecretSource。
    pub public_key: String,
    /// 规则包原始字节硬上限。
    #[serde(default = "default_waf_rule_pack_bytes")]
    pub max_pack_bytes: usize,
    /// 规则条目硬上限。
    #[serde(default = "default_waf_rule_pack_rules")]
    pub max_rules: usize,
    /// 全部规则 literal 数量硬上限。
    #[serde(default = "default_waf_rule_pack_patterns")]
    pub max_patterns: usize,
    /// 同步候选构建允许消耗的最长 wall time。
    #[serde(default = "default_waf_rule_pack_compile_ms")]
    pub max_compile_ms: u64,
}

/// route 级 Bot 识别、行为评分与挑战策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BotCfg {
    /// 处置模式：`enforce|monitor`。
    #[serde(default = "default_waf_mode")]
    pub mode: String,
    /// User-Agent allowlist glob；非空时不匹配的请求进入挑战。
    #[serde(default)]
    pub allowed_user_agents: Vec<String>,
    /// User-Agent denylist glob。
    #[serde(default)]
    pub denied_user_agents: Vec<String>,
    /// 必须存在且只有一个合法值的 header 名。
    #[serde(default)]
    pub required_headers: Vec<String>,
    /// 出现即计为自动化信号的 header 名。
    #[serde(default = "default_bot_automation_headers")]
    pub automation_headers: Vec<String>,
    /// 参与稳定客户端指纹的 header 名；User-Agent 始终参与且原值不会进入日志或限流 key。
    #[serde(default = "default_bot_fingerprint_headers")]
    pub fingerprint_headers: Vec<String>,
    /// 明确拒绝的 SHA-256 指纹，使用 64 位小写十六进制字符串。
    #[serde(default)]
    pub denied_fingerprints: Vec<String>,
    /// 缺少或非法 User-Agent 的行为分数。
    #[serde(default = "default_bot_signal_score")]
    pub missing_user_agent_score: u32,
    /// 浏览器 User-Agent 与基础浏览器 header 不一致时的行为分数。
    #[serde(default = "default_bot_browser_mismatch_score")]
    pub browser_header_mismatch_score: u32,
    /// 每个已出现 automation header 的行为分数。
    #[serde(default = "default_bot_signal_score")]
    pub automation_header_score: u32,
    /// 累积分数达到该阈值时进入挑战。
    #[serde(default = "default_bot_score_threshold")]
    pub score_threshold: u32,
    /// 通过 HMAC 请求签名复验后才可信的搜索机器人声明。
    #[serde(default)]
    pub trusted_search_bots: Vec<TrustedSearchBotCfg>,
    /// 可选的客户端指纹速率信号，复用进程级有界 RateLimiter。
    #[serde(default)]
    pub rate: Option<BotRateCfg>,
    /// 挑战响应状态码，必须是 4xx；速率拒绝固定使用 429。
    #[serde(default = "default_bot_challenge_status")]
    pub challenge_status: u16,
    /// `WWW-Authenticate` 的安全 realm，只允许短 ASCII token。
    #[serde(default = "default_bot_challenge_realm")]
    pub challenge_realm: String,
}

/// 一个需要逐请求签名复验的可信搜索机器人声明。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrustedSearchBotCfg {
    /// 稳定、低基数的声明名称，仅用于配置错误定位。
    pub name: String,
    /// 声称该身份的 User-Agent glob；匹配后签名失败会故障关闭。
    pub user_agents: Vec<String>,
    /// HMAC-SHA256 SecretSource，构建期解析且至少 32 bytes。
    pub signature_secret: String,
    /// Base64URL 无填充签名 header。
    #[serde(default = "default_bot_signature_header")]
    pub signature_header: String,
    /// Unix 秒时间戳 header。
    #[serde(default = "default_bot_timestamp_header")]
    pub timestamp_header: String,
    /// 签名时间戳允许的最大绝对偏差。
    #[serde(default = "default_bot_signature_skew_secs")]
    pub max_clock_skew_secs: u64,
}

/// Bot 客户端指纹速率信号。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BotRateCfg {
    /// 窗口内允许的请求数。
    pub limit: u64,
    /// 统计窗口毫秒数。
    pub window_ms: u64,
    /// 基础额度外允许的突发请求数。
    #[serde(default)]
    pub burst: u64,
    /// 单规则最多维护的活动客户端指纹数。
    #[serde(default = "default_bot_max_active_keys")]
    pub max_active_keys: usize,
    /// 活动指纹表耗尽时是否放行新指纹；默认故障关闭。
    #[serde(default)]
    pub active_keys_fail_open: bool,
}

/// route 级浏览器 CSRF 来源与 token 策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CsrfCfg {
    /// 处置模式：`enforce|monitor`。
    #[serde(default = "default_waf_mode")]
    pub mode: String,
    /// 需要 CSRF 门禁的 HTTP 方法；默认覆盖常见状态变更方法。
    #[serde(default = "default_csrf_methods")]
    pub methods: Vec<String>,
    /// 允许的精确 `scheme://authority`；`same-origin` 表示与当前请求一致。
    #[serde(default = "default_csrf_allowed_origins")]
    pub allowed_origins: Vec<String>,
    /// Origin 缺失时是否允许用 Referer 的 origin 复验。
    #[serde(default = "default_true")]
    pub allow_referer_fallback: bool,
    /// Origin 与 Referer 均缺失时是否显式放行；默认故障关闭。
    #[serde(default)]
    pub allow_missing_origin: bool,
    /// token 模式：`double_submit|signed`。
    #[serde(default = "default_csrf_token_mode")]
    pub token_mode: String,
    /// 必须使用 `__Host-` 前缀的 CSRF cookie 名。
    #[serde(default = "default_csrf_cookie_name")]
    pub cookie_name: String,
    /// 客户端回传 CSRF token 的单值 header 名。
    #[serde(default = "default_csrf_header_name")]
    pub header_name: String,
    /// `signed` 模式的 HMAC-SHA256 SecretSource；double-submit 模式必须为空。
    #[serde(default)]
    pub token_secret: String,
    /// signed token 最大年龄。
    #[serde(default = "default_csrf_token_ttl_secs")]
    pub token_ttl_secs: u64,
    /// 是否在未受保护方法的响应中签发新 token header 与 cookie。
    #[serde(default = "default_true")]
    pub issue_on_safe_methods: bool,
}

/// route 级 PII、凭据与 secret 检测、遮蔽和阻断策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DlpCfg {
    /// 命中动作：`block|redact|monitor`。
    #[serde(default = "default_dlp_action")]
    pub action: String,
    /// 启用的固定规则名；空数组表示启用全部内置规则。
    #[serde(default)]
    pub enabled_rules: Vec<String>,
    /// 要检查的请求 header 精确名称。
    #[serde(default)]
    pub request_headers: Vec<String>,
    /// 要检查的响应 header 精确名称。
    #[serde(default)]
    pub response_headers: Vec<String>,
    /// 是否解码并检查 query 参数名和值。
    #[serde(default = "default_true")]
    pub inspect_query: bool,
    /// 是否检查 access log 会记录的 path，并在命中时用固定路径替代。
    #[serde(default = "default_true")]
    pub protect_log_path: bool,
    /// 是否有界聚合并检查请求 body。
    #[serde(default)]
    pub inspect_request_body: bool,
    /// 是否有界聚合并检查响应 body。
    #[serde(default)]
    pub inspect_response_body: bool,
    /// body 检查允许的 media type 精确值或 `application/*+json`。
    #[serde(default = "default_dlp_body_media_types")]
    pub body_media_types: Vec<String>,
    /// 单方向 body 聚合硬上限。
    #[serde(default = "default_dlp_body_bytes")]
    pub max_body_bytes: u64,
    /// redact 动作写入字段或值的固定替代文本。
    #[serde(default = "default_dlp_replacement")]
    pub replacement: String,
    /// 按固定 rule 与精确 target 配置的例外。
    #[serde(default)]
    pub exclusions: Vec<DlpExclusionCfg>,
}

/// 一条 DLP 精确例外。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DlpExclusionCfg {
    /// 被豁免的固定规则名。
    pub rule: String,
    /// 精确 target：header/query 带名称，body 与 path_log 使用固定名。
    pub target: String,
}

/// 业务作用：为敏感数据策略提供故障关闭的默认处置。
///
/// 参数说明: 无。
///
/// 返回：返回 `block`。
pub(super) fn default_dlp_action() -> String {
    "block".to_owned()
}

/// 业务作用：限制默认 DLP body 慢路径只处理结构明确、可安全重放的 media type。
///
/// 参数说明: 无。
///
/// 返回：返回 JSON 与 URL encoded form 的固定 media type 列表。
pub(super) fn default_dlp_body_media_types() -> Vec<String> {
    vec![
        "application/json".to_owned(),
        "application/*+json".to_owned(),
        "application/x-www-form-urlencoded".to_owned(),
    ]
}

/// 业务作用：约束显式 DLP body 慢路径的默认并发内存占用。
///
/// 参数说明: 无。
///
/// 返回：返回一 MiB。
pub(super) const fn default_dlp_body_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：提供不包含命中原值的默认遮蔽文本。
///
/// 参数说明: 无。
///
/// 返回：返回固定 `[REDACTED]`。
pub(super) fn default_dlp_replacement() -> String {
    "[REDACTED]".to_owned()
}

/// 业务作用：提供默认 CSRF 状态变更方法集合。
///
/// 参数说明: 无。
///
/// 返回：返回 POST、PUT、PATCH 与 DELETE。
pub(super) fn default_csrf_methods() -> Vec<String> {
    ["POST", "PUT", "PATCH", "DELETE"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// 业务作用：默认只信任与当前请求 scheme 和 authority 相同的浏览器来源。
///
/// 参数说明: 无。
///
/// 返回：返回 `same-origin` 唯一规则。
pub(super) fn default_csrf_allowed_origins() -> Vec<String> {
    vec!["same-origin".to_owned()]
}

/// 业务作用：提供不依赖服务端状态的默认 CSRF token 模式。
///
/// 参数说明: 无。
///
/// 返回：返回 `double_submit`。
pub(super) fn default_csrf_token_mode() -> String {
    "double_submit".to_owned()
}

/// 业务作用：提供符合浏览器 host-only 安全约束的默认 CSRF cookie 名。
///
/// 参数说明: 无。
///
/// 返回：返回带 `__Host-` 前缀的固定名称。
pub(super) fn default_csrf_cookie_name() -> String {
    "__Host-naway-csrf".to_owned()
}

/// 业务作用：提供 CSRF token 回传的默认 header 名。
///
/// 参数说明: 无。
///
/// 返回：返回 `x-csrf-token`。
pub(super) fn default_csrf_header_name() -> String {
    "x-csrf-token".to_owned()
}

/// 业务作用：限制服务端签名 CSRF token 的默认有效期。
///
/// 参数说明: 无。
///
/// 返回：返回两小时对应的秒数。
pub(super) const fn default_csrf_token_ttl_secs() -> u64 {
    2 * 60 * 60
}

/// 业务作用：提供默认的常见自动化声明 header，只把其出现作为可组合信号而非单独身份事实。
///
/// 参数说明: 无。
///
/// 返回：返回 Playwright、Puppeteer 与 WebDriver 常用的固定 header 名。
pub(super) fn default_bot_automation_headers() -> Vec<String> {
    vec![
        "x-playwright".to_owned(),
        "x-puppeteer".to_owned(),
        "webdriver".to_owned(),
    ]
}

/// 业务作用：选择不含凭据且跨请求稳定的默认浏览器指纹字段。
///
/// 参数说明: 无。
///
/// 返回：返回 Accept、语言和 Client Hints 的固定 header 名。
pub(super) fn default_bot_fingerprint_headers() -> Vec<String> {
    vec![
        "accept".to_owned(),
        "accept-language".to_owned(),
        "sec-ch-ua".to_owned(),
        "sec-ch-ua-platform".to_owned(),
    ]
}

/// 业务作用：为单个确定自动化信号设置默认风险分值。
///
/// 参数说明: 无。
///
/// 返回：返回 4，使一个强信号默认达到挑战阈值。
pub(super) const fn default_bot_signal_score() -> u32 {
    4
}

/// 业务作用：为浏览器声明与 header 形态不一致设置较低的组合分值。
///
/// 参数说明: 无。
///
/// 返回：返回 2，避免单个弱信号直接阻断。
pub(super) const fn default_bot_browser_mismatch_score() -> u32 {
    2
}

/// 业务作用：提供 Bot 行为评分的默认挑战门槛。
///
/// 参数说明: 无。
///
/// 返回：返回 4。
pub(super) const fn default_bot_score_threshold() -> u32 {
    4
}

/// 业务作用：提供 Bot 挑战的默认 HTTP 状态。
///
/// 参数说明: 无。
///
/// 返回：返回 403。
pub(super) const fn default_bot_challenge_status() -> u16 {
    403
}

/// 业务作用：提供不暴露 route 或策略细节的默认挑战 realm。
///
/// 参数说明: 无。
///
/// 返回：返回固定 realm。
pub(super) fn default_bot_challenge_realm() -> String {
    "verification-required".to_owned()
}

/// 业务作用：提供可信机器人签名 header 的默认名称。
///
/// 参数说明: 无。
///
/// 返回：返回固定小写 header 名。
pub(super) fn default_bot_signature_header() -> String {
    "x-naway-bot-signature".to_owned()
}

/// 业务作用：提供可信机器人签名时间戳 header 的默认名称。
///
/// 参数说明: 无。
///
/// 返回：返回固定小写 header 名。
pub(super) fn default_bot_timestamp_header() -> String {
    "x-naway-bot-timestamp".to_owned()
}

/// 业务作用：限制可信机器人签名的默认重放时间窗口。
///
/// 参数说明: 无。
///
/// 返回：返回 60 秒。
pub(super) const fn default_bot_signature_skew_secs() -> u64 {
    60
}

/// 业务作用：限制本地或共享限流器为单条 Bot 规则维护的默认客户端基数。
///
/// 参数说明: 无。
///
/// 返回：返回十万个活动指纹。
pub(super) const fn default_bot_max_active_keys() -> usize {
    100_000
}

/// route 级 GeoIP、ASN 与匿名网络策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GeoIpCfg {
    /// GeoIP2/GeoLite2 Country、City 或 Enterprise MMDB；配置国家规则时必填。
    #[serde(default)]
    pub country_database_file: Option<String>,
    /// GeoIP2/GeoLite2 ASN MMDB；配置 ASN 规则时必填。
    #[serde(default)]
    pub asn_database_file: Option<String>,
    /// GeoIP2 Anonymous-IP MMDB；配置匿名网络规则时必填。
    #[serde(default)]
    pub anonymous_database_file: Option<String>,
    /// 允许的 ISO 3166-1 alpha-2 国家代码；非空时形成 allowlist。
    #[serde(default)]
    pub allowed_countries: Vec<String>,
    /// 拒绝的 ISO 3166-1 alpha-2 国家代码。
    #[serde(default)]
    pub denied_countries: Vec<String>,
    /// 允许的 Autonomous System Number；非空时形成 allowlist。
    #[serde(default)]
    pub allowed_asns: Vec<u32>,
    /// 拒绝的 Autonomous System Number。
    #[serde(default)]
    pub denied_asns: Vec<u32>,
    /// 要拒绝的匿名网络 trait 固定名。
    #[serde(default)]
    pub denied_anonymous_traits: Vec<String>,
    /// 规则需要字段但数据库没有该地址记录时的动作：`allow|deny`。
    #[serde(default = "default_geoip_missing_action")]
    pub on_not_found: String,
    /// MMDB 查询或 record 解码失败时的动作：`allow|deny`。
    #[serde(default = "default_geoip_error_action")]
    pub on_lookup_error: String,
    /// 数据库 build epoch 超过允许年龄时的动作：`reject|allow|deny`。
    #[serde(default = "default_geoip_stale_action")]
    pub on_stale: String,
    /// MMDB build epoch 的最大允许年龄；每次候选构建都会重新核对。
    #[serde(default = "default_geoip_database_age_secs")]
    pub max_database_age_secs: u64,
}

/// 业务作用：为 GeoIP 无记录提供故障关闭的默认动作。
///
/// 参数说明: 无。
///
/// 返回：返回 `deny`，避免未知地址被伪装成允许国家或 ASN。
pub(super) fn default_geoip_missing_action() -> String {
    "deny".to_owned()
}

/// 业务作用：为 MMDB 查询或 record 解码失败提供故障关闭的默认动作。
///
/// 参数说明: 无。
///
/// 返回：返回 `deny`，使损坏或类型漂移的 record 不会绕过策略。
pub(super) fn default_geoip_error_action() -> String {
    "deny".to_owned()
}

/// 业务作用：为过期 GeoIP 数据库提供 last-known-good 安全默认。
///
/// 参数说明: 无。
///
/// 返回：返回 `reject`，候选换版失败并继续使用上一份有效快照。
pub(super) fn default_geoip_stale_action() -> String {
    "reject".to_owned()
}

/// 业务作用：为 GeoIP 数据 freshness 设置覆盖常见月度更新周期的默认窗口。
///
/// 参数说明: 无。
///
/// 返回：返回 45 天对应的秒数。
pub(super) const fn default_geoip_database_age_secs() -> u64 {
    45 * 24 * 60 * 60
}

/// 业务作用：为 WAF 提供故障关闭的默认处置模式。
///
/// 参数说明: 无。
///
/// 返回：返回 `enforce`，使新增策略默认拦截确定命中的攻击输入。
pub(super) fn default_waf_mode() -> String {
    "enforce".to_owned()
}

/// 业务作用：约束显式 WAF 请求体慢路径的默认并发内存占用。
///
/// 参数说明: 无。
///
/// 返回：返回 1 MiB 请求体聚合上限。
pub(super) const fn default_waf_body_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：约束单个 URI、header 或结构化字符串的扫描成本。
///
/// 参数说明: 无。
///
/// 返回：返回 64 KiB 单值扫描上限。
pub(super) const fn default_waf_value_bytes() -> usize {
    64 * 1024
}

/// 业务作用：限制 JSON/XML 解析的默认嵌套深度，避免深层输入耗尽栈或解析预算。
///
/// 参数说明: 无。
///
/// 返回：返回 64 层结构化数据深度上限。
pub(super) const fn default_waf_structured_depth() -> usize {
    64
}

/// 业务作用：限制单个 JSON/XML document 的默认结构规模。
///
/// 参数说明: 无。
///
/// 返回：返回十万个结构节点上限。
pub(super) const fn default_waf_structured_nodes() -> usize {
    100_000
}

/// 业务作用：限制 XML 属性解析总量，防止宽元素制造无界 CPU 消耗。
///
/// 参数说明: 无。
///
/// 返回：返回一万个 XML 属性上限。
pub(super) const fn default_waf_xml_attributes() -> usize {
    10_000
}

/// 业务作用：限制外部 WAF 规则包在候选构建阶段的单文件内存占用。
///
/// 参数说明: 无。
///
/// 返回：返回 4 MiB 原始 JSON 上限。
pub(super) const fn default_waf_rule_pack_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：限制外部 WAF 规则包可增加的规则扫描规模。
///
/// 参数说明: 无。
///
/// 返回：返回 1024 条规则上限。
pub(super) const fn default_waf_rule_pack_rules() -> usize {
    1024
}

/// 业务作用：限制外部 WAF 规则包可增加的 literal 总量。
///
/// 参数说明: 无。
///
/// 返回：返回 16384 个 literal 上限。
pub(super) const fn default_waf_rule_pack_patterns() -> usize {
    16_384
}

/// 业务作用：为有界 JSON 解析和 literal 索引构建提供确定的默认时间门。
///
/// 参数说明: 无。
///
/// 返回：返回 2000 毫秒候选构建上限。
pub(super) const fn default_waf_rule_pack_compile_ms() -> u64 {
    2_000
}

/// route 级内嵌 Casbin 决策配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CasbinAuthorizationCfg {
    /// Casbin PERM model CONF，相对于 gateway.yml 所在目录。
    pub model_file: String,
    /// Casbin CSV policy，相对于 gateway.yml 所在目录。
    pub policy_file: String,
    /// 按 model `[request_definition] r = ...` 顺序组装的参数。默认
    /// `[consumer, path, method]`；可用 route_id/client_ip/scheme/header:X-Resource 支持域与 ABAC。
    #[serde(default = "default_casbin_arguments")]
    pub arguments: Vec<String>,
    /// 是否强制已认证 consumer。false 时缺失主体统一传 `anonymous`。
    #[serde(default = "default_true")]
    pub require_identity: bool,
    /// 单个动态参数的 UTF-8 字节上限，防止超大 header/path 放大策略引擎。
    #[serde(default = "default_casbin_max_argument_bytes")]
    pub max_argument_bytes: usize,
    /// 一次 enforce 所有参数的合计字节上限。
    #[serde(default = "default_casbin_max_input_bytes")]
    pub max_input_bytes: usize,
    /// 只在 Casbin 内部执行异常时放行；明确 deny、缺主体或 input 超限永不 fail-open。
    #[serde(default)]
    pub fail_open: bool,
}

/// 业务作用：为未显式声明的 `arguments` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_casbin_arguments() -> Vec<String> {
    vec![
        "consumer".to_owned(),
        "path".to_owned(),
        "method".to_owned(),
    ]
}

/// 业务作用：为未显式声明的 `max_argument_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_casbin_max_argument_bytes() -> usize {
    4096
}

/// 业务作用：为未显式声明的 `max_input_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_casbin_max_input_bytes() -> usize {
    16 * 1024
}

/// Route 级 OPA decision 配置。
///
/// 默认调用 OPA Data API；`engine=embedded` 时从签名 bundle 构建本地 Rego 引擎。
/// request body 与完整 JWT claims 都必须在 `input` 中显式开启，未开启时保持 head-only 流式路径。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaAuthorizationCfg {
    /// 求值引擎；默认 external。
    #[serde(default)]
    pub engine: OpaEngineCfg,
    /// OPA 上游 base：`http(s)://host[:port]` 或 `lb://service`。
    #[serde(default)]
    pub target: String,
    /// OPA Data API 路径，例如 `/v1/data/gateway/authz`；必须显式填写。
    #[serde(default)]
    pub path: String,
    /// response head + body 的总决策 deadline，毫秒。
    #[serde(default = "default_opa_timeout_ms")]
    pub timeout_ms: u64,
    /// OPA transport/5xx/畸形响应时是否放行；默认 fail-closed。
    #[serde(default)]
    pub fail_open: bool,
    /// OPA 服务凭据的完整 Authorization header 值；支持 SecretSource，空表示不发送。
    #[serde(default)]
    pub authorization: String,
    /// 作为不可信请求属性加入 input 的 header allowlist；敏感凭据类 header 永远拒绝。
    #[serde(default)]
    pub include_headers: Vec<String>,
    /// 单个 allowlist header value 的最大字节数。
    #[serde(default = "default_opa_max_header_value_bytes")]
    pub max_header_value_bytes: usize,
    /// 序列化后 OPA JSON input 的严格最大字节数。
    #[serde(default = "default_opa_max_input_bytes")]
    pub max_input_bytes: usize,
    /// OPA response body 的严格最大字节数。
    #[serde(default = "default_opa_max_response_bytes")]
    pub max_response_bytes: usize,
    /// 为 true 时必须能从已通过认证链得到稳定 consumer，否则本地 403，不外呼 OPA。
    #[serde(default)]
    pub require_identity: bool,
    /// 可选本节点 decision L1。存在即启用；错误和 unavailable 永不缓存。
    #[serde(default)]
    pub cache: Option<OpaDecisionCacheCfg>,
    /// 可选签名标准 OPA bundle；embedded 引擎必须配置。
    #[serde(default)]
    pub bundle: Option<OpaBundleCfg>,
    /// 输入扩展；默认不读取 body、不暴露完整 claims。
    #[serde(default)]
    pub input: OpaInputCfg,
    /// OPA allow 结果可携带的受控副作用。
    #[serde(default)]
    pub obligations: OpaObligationsCfg,
    /// 外部依赖首次失败后的退避，毫秒。
    #[serde(default = "default_opa_backoff_initial_ms")]
    pub backoff_initial_ms: u64,
    /// 外部依赖连续失败的最大退避，毫秒。
    #[serde(default = "default_opa_backoff_max_ms")]
    pub backoff_max_ms: u64,
}

/// OPA 求值引擎。
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpaEngineCfg {
    /// 通过 HTTP 调用独立 OPA。
    #[default]
    External,
    /// 在进程内执行签名 bundle 中的 Rego。
    Embedded,
}

/// 签名 OPA bundle 配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaBundleCfg {
    /// 本地 `.tar.gz` bundle；相对主配置目录解析并纳入 dependency watcher。
    pub source: String,
    /// detached Ed25519 signature 的 Base64 SecretSource，签名覆盖压缩 bundle 原始字节。
    pub signature: String,
    /// 32 字节 Ed25519 public key 的 Base64 SecretSource。
    pub public_key: String,
    /// Rego query，例如 `data.gateway.authz`。
    #[serde(default = "default_opa_bundle_query")]
    pub query: String,
    /// 压缩 bundle 最大字节数。
    #[serde(default = "default_opa_bundle_max_bytes")]
    pub max_bundle_bytes: usize,
    /// 所有 archive regular file 解压后累计最大字节数。
    #[serde(default = "default_opa_bundle_max_expanded_bytes")]
    pub max_expanded_bytes: usize,
    /// archive regular file 数量硬上限。
    #[serde(default = "default_opa_bundle_max_files")]
    pub max_files: usize,
}

/// OPA request input 显式扩展。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaInputCfg {
    /// 是否把完整请求 body 加入 input 并原样重放给后续管线。
    #[serde(default)]
    pub include_body: bool,
    /// body 聚合硬上限。
    #[serde(default = "default_opa_input_max_body_bytes")]
    pub max_body_bytes: usize,
    /// 可聚合的 Content-Type allowlist；按去参数 media type 精确匹配。
    #[serde(default = "default_opa_input_content_types")]
    pub content_types: Vec<String>,
    /// 是否加入网关已经验签、时效与 issuer/audience 均通过的完整 JWT claims。
    #[serde(default)]
    pub include_jwt_claims: bool,
}

impl Default for OpaInputCfg {
    /// 业务作用：提供不读取 body/claims 的安全输入基线，并保留显式启用时的有限默认预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回 head-only 输入配置；body 上限与 media type 仅在 `include_body=true` 时生效。
    fn default() -> Self {
        Self {
            include_body: false,
            max_body_bytes: default_opa_input_max_body_bytes(),
            content_types: default_opa_input_content_types(),
            include_jwt_claims: false,
        }
    }
}

/// OPA obligations 白名单与资源门。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaObligationsCfg {
    /// OPA 可设置/删除的 request header 名称。
    #[serde(default)]
    pub request_headers: Vec<String>,
    /// OPA 可设置/删除的 response header 名称。
    #[serde(default)]
    pub response_headers: Vec<String>,
    /// 可接受的审计 metadata key。
    #[serde(default)]
    pub audit_metadata: Vec<String>,
    /// 单次 decision obligation 条目硬上限。
    #[serde(default = "default_opa_obligation_max_entries")]
    pub max_entries: usize,
    /// 单个 header/audit value 最大字节数。
    #[serde(default = "default_opa_obligation_max_value_bytes")]
    pub max_value_bytes: usize,
    /// 全部 obligation 名称和值累计最大字节数。
    #[serde(default = "default_opa_obligation_max_bytes")]
    pub max_bytes: usize,
}

impl Default for OpaObligationsCfg {
    /// 业务作用：默认不给 OPA 任何 header/audit 副作用权限，同时建立非零资源硬门。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回空 allowlist；即使策略返回 obligation 也会整体拒绝。
    fn default() -> Self {
        Self {
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            audit_metadata: Vec::new(),
            max_entries: default_opa_obligation_max_entries(),
            max_value_bytes: default_opa_obligation_max_value_bytes(),
            max_bytes: default_opa_obligation_max_bytes(),
        }
    }
}

/// OPA decision L1 配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaDecisionCacheCfg {
    /// allow decision TTL，毫秒。
    #[serde(default = "default_opa_cache_ttl_ms")]
    pub ttl_ms: u64,
    /// deny decision TTL，毫秒；通常短于 allow。
    #[serde(default = "default_opa_cache_deny_ttl_ms")]
    pub deny_ttl_ms: u64,
    /// 每 route 最大 decision entry 数，TinyLFU 到顶淘汰。
    #[serde(default = "default_opa_cache_max_entries")]
    pub max_entries: u64,
    /// 外部 Rego/data 的运维版本；签名 bundle 模式自动使用 manifest revision/digest。
    #[serde(default)]
    pub policy_revision: String,
    /// 是否合并本节点同 key 并发 miss。
    #[serde(default = "default_true")]
    pub singleflight: bool,
    /// follower 最长等待时间，毫秒。
    #[serde(default = "default_opa_singleflight_wait_ms")]
    pub singleflight_wait_ms: u64,
    /// 每 route 同时活跃的不同 miss key 硬上限。
    #[serde(default = "default_opa_singleflight_max_keys")]
    pub singleflight_max_keys: usize,
    /// 是否把已验证 decision 写入 DynamicStore 供节点间复用。
    #[serde(default)]
    pub distributed: bool,
    /// 跨节点 decision collection。
    #[serde(default = "default_opa_distributed_collection")]
    pub distributed_collection: String,
    /// 跨节点 collection 最大 entry 数。
    #[serde(default = "default_opa_distributed_max_entries")]
    pub distributed_max_entries: usize,
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_timeout_ms() -> u64 {
    500
}

/// 业务作用：为未显式声明的 `max_header_value_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_max_header_value_bytes() -> usize {
    4 * 1024
}

/// 业务作用：为未显式声明的 `max_input_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_max_input_bytes() -> usize {
    64 * 1024
}

/// 业务作用：为未显式声明的 `max_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_max_response_bytes() -> usize {
    64 * 1024
}

/// 业务作用：为未显式声明的 `ttl_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_cache_ttl_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `deny_ttl_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_cache_deny_ttl_ms() -> u64 {
    250
}

/// 业务作用：为未显式声明的 `singleflight_wait_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_singleflight_wait_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `singleflight_max_keys` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_singleflight_max_keys() -> usize {
    1_024
}

/// 业务作用：为未显式声明的 `distributed_collection` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_distributed_collection() -> String {
    "opa_decisions".to_string()
}

/// 业务作用：为未显式声明的 `distributed_max_entries` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_distributed_max_entries() -> usize {
    100_000
}

/// 业务作用：为未显式声明的 `query` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_bundle_query() -> String {
    "data.gateway.authz".to_string()
}

/// 业务作用：为未显式声明的 `max_bundle_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_bundle_max_bytes() -> usize {
    8 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `max_expanded_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_bundle_max_expanded_bytes() -> usize {
    32 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `max_files` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_bundle_max_files() -> usize {
    256
}

/// 业务作用：为未显式声明的 `max_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_input_max_body_bytes() -> usize {
    64 * 1024
}

/// 业务作用：为未显式声明的 `content_types` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_input_content_types() -> Vec<String> {
    vec!["application/json".to_string()]
}

/// 业务作用：为未显式声明的 `max_entries` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_obligation_max_entries() -> usize {
    32
}

/// 业务作用：为未显式声明的 `max_value_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_obligation_max_value_bytes() -> usize {
    4 * 1024
}

/// 业务作用：为未显式声明的 `max_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_obligation_max_bytes() -> usize {
    32 * 1024
}

/// 业务作用：为未显式声明的 `backoff_initial_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_backoff_initial_ms() -> u64 {
    100
}

/// 业务作用：为未显式声明的 `backoff_max_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_backoff_max_ms() -> u64 {
    5_000
}

/// 业务作用：为未显式声明的 `max_entries` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_opa_cache_max_entries() -> u64 {
    10_000
}
