/**
 * 业务作用：编辑路由签名规则包的原生声明与构建预算，秘密引用保持文本且不在页面求值。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的完整包声明与八个独立字段；未编辑时不填充默认值或回传原子树。
 */
export function routeWafPackFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["waf"],
      "WAF 外部规则包声明",
      [["rule_pack", "完整签名包声明（移除时保留内置 WAF）", "json"]],
    ],
    [
      ["waf", "rule_pack"],
      "WAF 签名规则包字段",
      [
        ["source", "本地 JSON 文件路径（相对主配置目录）", "string"],
        ["sha256", "原始 JSON 的 SHA-256 十六进制摘要", "string"],
        ["signature", "Ed25519 签名的 Base64 SecretSource", "string"],
        ["public_key", "32 字节公钥的 Base64 SecretSource", "string"],
        ["max_pack_bytes", "规则包容量（1–4194304 字节）", "number"],
        ["max_rules", "规则数量上限（1–1024）", "number"],
        ["max_patterns", "全部 literal 数量上限（1–16384）", "number"],
        ["max_compile_ms", "候选构建期限（1–5000 毫秒）", "number"],
      ],
    ],
  ];
}
