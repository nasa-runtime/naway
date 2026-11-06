const accountFields = [
  ["bootstrap_without_seed", "允许无种子证书启动", "boolean"],
  ["bootstrap_http01_only", "兼容 HTTP-01 无种子启动声明", "boolean"],
  ["directory_url", "ACME directory URL", "string"],
  ["directory_ca_file", "ACME directory 自定义 CA 路径", "string"],
  ["domains", "签发 DNS 名称（每行一项）", "lines"],
  ["contacts", "账户联系地址（每行一项）", "lines"],
  ["challenge", "验证方式：http-01 / dns-01", "string"],
  ["account_credentials_file", "账户凭据文件路径", "string"],
  ["renew_before_days", "到期前续期窗口（天）", "number"],
  ["check_interval_ms", "证书检查间隔（毫秒）", "number"],
  ["retry_backoff_ms", "签发失败退避（毫秒）", "number"],
  ["order_timeout_ms", "订单轮询期限（毫秒）", "number"],
  ["activation_poll_ms", "无种子 TLS 激活检查间隔（毫秒）", "number"],
  ["lock_backend", "续期锁：local / redis", "string"],
  ["lock_key", "续期锁业务身份", "string"],
  ["storage_mode", "存储方式：local-file / shared-file", "string"],
  ["keypair_retention_generations", "保留的完整证书对代数", "number"],
];

const dnsFields = [
  [
    "provider",
    "DNS provider：command / cloudflare / rfc2136 / vault",
    "string",
  ],
  ["command", "DNS provider 可执行文件路径", "string"],
  ["args", "固定非秘密参数（每行一项）", "lines"],
  ["propagation_delay_ms", "DNS 传播等待（毫秒）", "number"],
  ["timeout_ms", "单次 DNS 操作期限（毫秒）", "number"],
  ["retry_attempts", "网络 provider 最大尝试次数", "number"],
  ["retry_backoff_ms", "网络 provider 重试退避（毫秒）", "number"],
  ["max_response_bytes", "HTTP provider 响应字节上限", "number"],
  ["ttl_seconds", "TXT TTL（秒）", "number"],
];

const cloudflareFields = [
  ["cloudflare_zone_id", "Cloudflare zone id", "string"],
  ["cloudflare_api_token", "Cloudflare token SecretSource 引用", "string"],
  ["cloudflare_api_base", "Cloudflare API 根地址", "string"],
];

const rfc2136Fields = [
  ["rfc2136_server", "权威 DNS TCP 地址", "string"],
  ["rfc2136_zone", "DNS UPDATE zone", "string"],
  ["rfc2136_tsig_key_name", "TSIG key name", "string"],
  ["rfc2136_tsig_secret", "TSIG SecretSource 引用", "string"],
];

const vaultFields = [
  ["vault_endpoint", "Vault HTTPS 根地址", "string"],
  ["vault_token", "Vault token SecretSource 引用", "string"],
  ["vault_present_path", "Vault present 相对 API path", "string"],
  ["vault_cleanup_path", "Vault cleanup 相对 API path", "string"],
  ["vault_namespace", "Vault namespace", "string"],
];

/**
 * 业务作用：只为 HTTP 默认身份提供原生 ACME 声明控件，保持签发与 DNS provider 的配置边界。
 * 参数说明：
 * - `kind`：当前候选的配置对象类型。
 * 返回：精确字段分组；不读取账户或 DNS 凭据，不创建订单，也不自动删除其它 provider 字段。
 */
export function acmeFieldGroups(kind) {
  if (kind !== "proxy") {
    return [];
  }
  const dns = ["tls", "acme", "dns01"];
  return [
    [["tls", "acme"], "ACME 账户、签发与续期", accountFields],
    [dns, "ACME DNS-01 provider 与预算", dnsFields],
    [dns, "ACME DNS-01 Cloudflare", cloudflareFields],
    [dns, "ACME DNS-01 RFC2136", rfc2136Fields],
    [dns, "ACME DNS-01 Vault", vaultFields],
  ];
}
