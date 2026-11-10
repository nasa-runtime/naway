/**
 * 业务作用：显式编辑浏览器来源与 CSRF token 双门禁，保持密钥引用与未编辑的安全开关。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十一项原生声明；不读取密钥、不签发 token 或物化默认策略。
 */
export function routeCsrfFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["csrf"],
      "浏览器来源与 CSRF",
      [
        ["mode", "处置模式：enforce / monitor", "string"],
        [
          "methods",
          "受保护方法（每行一项，1–16 个大写方法，排除 GET / HEAD / OPTIONS / TRACE）",
          "lines",
        ],
        [
          "allowed_origins",
          "允许来源（每行一项：精确 HTTP(S) origin 或 same-origin，最多 64 项）",
          "lines",
        ],
        ["allow_referer_fallback", "Origin 缺失时复验 Referer 来源", "boolean"],
        ["allow_missing_origin", "来源缺失时明确放行来源门", "boolean"],
        ["token_mode", "Token 模式：double_submit / signed", "string"],
        ["cookie_name", "__Host- 前缀的 Cookie 名（最多 64 字节）", "string"],
        ["header_name", "客户端回传 Token 的单值头名称", "string"],
        [
          "token_secret",
          "signed 模式 HMAC SecretSource（至少 32 字节）",
          "string",
        ],
        ["token_ttl_secs", "Token 最大年龄（1–604800 秒）", "number"],
        [
          "issue_on_safe_methods",
          "未受保护方法成功或重定向时签发 Token",
          "boolean",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：按原位置维护受保护方法和允许来源，避免整表重写扩大浏览器请求的放行范围。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的两个字符串列表；其它对象不增加 CSRF 声明。
 */
export function routeCsrfDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["csrf", "methods"],
      title: "CSRF 受保护方法",
      type: "string",
    },
    {
      path: ["csrf", "allowed_origins"],
      title: "CSRF 允许来源",
      type: "string",
    },
  ];
}
