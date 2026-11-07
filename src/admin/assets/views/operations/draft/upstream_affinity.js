/**
 * 业务作用：为具名服务提供会话亲和载体与期限的独立字段，保留未编辑的配置声明。
 * 参数说明：
 * - `kind`：候选对象类型。
 * 返回：仅服务提供会话保持分组，不自动创建策略或降低 Cookie 默认保护属性。
 */
export function upstreamAffinityFieldGroups(kind) {
  if (kind !== "service") {
    return [];
  }
  return [
    [
      ["session_affinity"],
      "服务会话保持",
      [
        ["mode", "亲和载体：cookie / header", "string"],
        ["name", "Cookie 或 Header 名称", "string"],
        ["ttl_seconds", "滚动 Cookie Max-Age（秒，0 不设滚动期限）", "number"],
        [
          "absolute_timeout_seconds",
          "绝对有效期（秒，0 不校验，最多 31536000）",
          "number",
        ],
        [
          "idle_timeout_seconds",
          "空闲有效期（秒，0 不校验，最多 31536000）",
          "number",
        ],
        ["permanent_cookie", "持久 Cookie（须声明绝对有效期）", "boolean"],
        ["path", "Cookie Path", "string"],
        ["omit_path", "省略 Cookie Path（与 path 互斥）", "boolean"],
        ["domain", "Cookie Domain（缺省仅当前主机）", "string"],
        ["same_site", "Cookie SameSite：Lax / Strict / None", "string"],
        ["secure", "Cookie Secure（缺省 true）", "boolean"],
        ["http_only", "Cookie HttpOnly（缺省 true）", "boolean"],
      ],
    ],
  ];
}
