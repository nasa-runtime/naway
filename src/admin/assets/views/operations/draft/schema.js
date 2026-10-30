const definitions = {
  usage_plan: [
    ["requests", "窗口内基础请求数", "number"],
    ["window_ms", "固定窗口（毫秒）", "number"],
    ["burst", "额外突发请求数", "number"],
    ["max_active_keys", "本节点活跃消费者上限", "number"],
    ["active_keys_fail_open", "维度满额时放行", "boolean"],
  ],

  consumer_group: [
    ["consumers", "已认证消费者成员（每行一项）", "lines"],
    ["plan", "组套餐", "string"],
  ],

  scope_policy: [
    ["authentication", "静态作用域认证链（每行一项）", "lines"],
    ["require_authentication", "必须有已验证身份", "boolean"],
    ["deny", "拒绝该作用域", "boolean"],
    ["quota_plan", "附加额度套餐", "string"],
    ["quota_per_consumer", "按消费者独立计额", "boolean"],
    ["products", "允许产品交集（每行一项）", "lines"],
    ["request_headers", "网关上下文请求头映射", "json"],
    ["inherit_headers", "继承上层上下文请求头", "boolean"],
  ],

  credential: [
    ["kind", "凭据类型", "string"],
    ["value", "凭据值的 SecretSource 引用", "string"],
    ["username", "Basic 用户名", "string"],
    ["target", "注入的 header 或 query 名称", "string"],
    ["overwrite", "允许覆盖路由生成的同名值", "boolean"],
    ["allowed_backends", "允许接收凭据的后端（每行一项）", "lines"],
    ["client_certificate", "客户端证书 SecretSource 引用", "string"],
    ["client_private_key", "客户端私钥 SecretSource 引用", "string"],
  ],

  secret_provider: [
    ["endpoint", "固定 HTTPS API 前缀", "string"],
    ["authorization", "认证值 SecretSource 引用", "string"],
    ["authorization_header", "认证 header 名称", "string"],
    ["authorization_prefix", "认证值前缀", "string"],
    ["ca_certificate", "信任根 SecretSource 引用", "string"],
    ["client_certificate", "客户端证书 SecretSource 引用", "string"],
    ["client_private_key", "客户端私钥 SecretSource 引用", "string"],
    ["value_pointer", "秘密值 JSON Pointer", "string"],
    ["version_pointer", "版本 JSON Pointer", "string"],
    ["lease_seconds_pointer", "租约秒数 JSON Pointer", "string"],
    ["refresh_interval_ms", "刷新周期（毫秒）", "number"],
    ["max_stale_ms", "最大陈旧期（毫秒）", "number"],
    ["connect_timeout_ms", "建连期限（毫秒）", "number"],
    ["request_timeout_ms", "请求期限（毫秒）", "number"],
    ["max_response_bytes", "响应字节上限", "number"],
    ["retry_base_ms", "首次退避（毫秒）", "number"],
    ["retry_max_ms", "退避上限（毫秒）", "number"],
  ],

  instance: [
    ["uri", "实例 URI", "string"],
    ["weight", "调度权重", "number"],
    ["healthy", "静态健康标记", "boolean"],
    ["down", "手工下线", "boolean"],
    ["backup", "备用实例", "boolean"],
    ["slow_start_ms", "慢启动周期（毫秒）", "number"],
    ["region", "地域", "string"],
    ["zone", "可用区", "string"],
    ["subzone", "子可用区", "string"],
  ],

  route: [
    ["uri", "上游 URI", "string"],
    ["order", "匹配顺序", "number"],
    ["predicates", "路由断言（每行一项）", "lines"],
    ["filters", "处理链（每行一项，顺序保留）", "lines"],
    ["preserve_host", "保留客户端 Host", "boolean"],
    ["upstream_credentials", "上游凭据引用（每行一项）", "lines"],
  ],

  proxy: [
    ["listen", "明文监听地址", "string"],
    ["plain_enabled", "启用明文监听", "boolean"],
    ["server_names", "主机名称（每行一项）", "lines"],
    ["trusted_proxies", "可信前置代理 CIDR（每行一项）", "lines"],
    ["redirect_https", "跳转 HTTPS", "boolean"],
    ["redirect_https_status", "HTTPS 跳转状态码", "number"],
    ["hsts_max_age", "HSTS 有效秒数", "number"],
  ],

  service: [
    ["source", "实例来源", "string"],
    ["critical", "参与全局就绪判断", "boolean"],
    ["registry_service", "注册服务名称", "string"],
    ["registry_namespace", "注册命名空间", "string"],
    ["registry_port", "注册服务端口", "number"],
    ["nacos_service", "Nacos 服务名称", "string"],
    ["lb_policy", "负载均衡策略", "string"],
    ["hash_on", "一致性哈希来源", "string"],
    ["upstream_credentials", "上游凭据引用（每行一项）", "lines"],
  ],

  stream: [
    ["listen", "监听地址", "string"],
    ["protocol", "传输协议", "string"],
    ["upstream", "上游地址", "string"],
    ["reject_all", "拒绝全部连接", "boolean"],
    ["connect_timeout_ms", "连接超时（毫秒）", "number"],
    ["timeout_ms", "会话期限（毫秒）", "number"],
  ],

  flow: [
    ["enabled", "启用规则", "boolean"],
    ["route", "绑定路由", "string"],
    ["key", "限流维度", "string"],
    ["rate", "速率", "string"],
    ["burst", "突发容量", "number"],
    ["behavior", "控制行为", "string"],
    ["warmup_ms", "预热周期（毫秒）", "number"],
    ["cold_factor", "冷态速率除数", "number"],
    ["cold_after_ms", "重新预热间隔（毫秒）", "number"],
    ["max_queue", "最大排队数", "number"],
    ["max_wait_ms", "排队期限（毫秒）", "number"],
    ["max_active_keys", "最大活跃维度数", "number"],
    ["active_keys_fail", "维度满额动作", "string"],
    ["limit", "并发上限", "number"],
  ],

  degrade: [
    ["enabled", "启用规则", "boolean"],
    ["route", "绑定路由", "string"],
    ["strategy", "统计依据", "string"],
    ["failure_threshold", "失败次数阈值", "number"],
    ["ratio_bps", "比例阈值（万分比）", "number"],
    ["slow_ms", "慢调用阈值（毫秒）", "number"],
    ["window_ms", "统计窗口（毫秒）", "number"],
    ["min_requests", "最少请求数", "number"],
    ["break_ms", "保护持续时间（毫秒）", "number"],
    ["fallback_status", "降级状态码", "number"],
    ["fallback_body", "降级正文", "string"],
  ],

  interface_rule: [["enabled", "启用规则", "boolean"]],
};

export const objectKinds = {
  gateway: [
    ["proxy", "HTTP 入口"],
    ["route", "HTTP 路由"],
    ["service", "上游服务"],
    ["credential", "上游凭据"],
    ["secret_provider", "远程秘密源"],
    ["usage_plan", "用量套餐"],
    ["consumer_group", "消费者组"],
    ["scope_policy", "身份作用域策略"],
    ["stream", "流协议监听"],
  ],

  sentinel: [
    ["flow", "流控规则"],
    ["degrade", "降级规则"],
  ],

  "interface-guard": [["interface_rule", "接口守卫规则"]],
};

/**
 * 业务作用：为原始对象提供常用字段控件，不注入任何运行默认值。
 * 参数说明：
 * - `kind`：服务端返回的对象类别。
 * 返回：已知字段描述；其它字段继续按原声明类型编辑。
 */
export function draftFields(kind) {
  return definitions[kind] ?? [];
}

/**
 * 业务作用：识别以独立 name 选择的具名对象，创建时不混用数组 id 与映射键。
 * 参数说明：
 * - `kind`：服务端支持的对象类别。
 * 返回：服务、套餐、组、上游凭据与远程秘密源为 true；其它对象使用 id。
 */
export function namedObject(kind) {
  return [
    "service",
    "credential",
    "secret_provider",
    "usage_plan",
    "consumer_group",
  ].includes(kind);
}

/**
 * 业务作用：用完整独立身份展示对象，斜线和点仅作为普通名称字符。
 * 参数说明：
 * - `object`：带类别及独立父对象身份的选择器。
 * 返回：可作为纯文本显示的名称，不用于解析或还原对象身份。
 */
export function objectLabel(object) {
  const name = object.name ?? object.id;
  return object.kind === "route"
    ? `route · ${object.proxy} → ${name}`
    : `${object.kind} · ${name}`;
}
