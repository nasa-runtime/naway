/**
 * 业务作用：按原生授权合同编辑 OPA 目标、签名材料、输入权限、受控义务与缓存边界。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十七主声明与四个子组，不读取秘密、策略文件或填充默认值。
 */
export function routeOpaFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["opa_authorization"],
      "OPA 授权目标与失败策略",
      [
        ["engine", "求值引擎：external / embedded", "string"],
        ["target", "external 目标：HTTP(S) origin 或 lb://service", "string"],
        ["path", "external 绝对路径（最多2048字节，无 query）", "string"],
        ["timeout_ms", "决策总期限（1–60000 毫秒，含响应正文）", "number"],
        ["fail_open", "依赖求值或协议失败时放行，不执行失败义务", "boolean"],
        [
          "authorization",
          "external 完整 Authorization 值 SecretSource",
          "string",
        ],
        ["include_headers", "不可信输入头名单（每行一项，最多32项）", "lines"],
        ["max_header_value_bytes", "单输入头值上限（1–65536 字节）", "number"],
        ["max_input_bytes", "完整编码输入上限（256–1048576 字节）", "number"],
        ["max_response_bytes", "决策响应上限（16–1048576 字节）", "number"],
        ["require_identity", "要求已通过认证链的稳定 consumer", "boolean"],
        ["cache", "完整决策缓存声明（移除仅关闭缓存）", "json"],
        ["bundle", "完整签名 bundle 声明（embedded 必需）", "json"],
        ["input", "完整输入扩展声明（移除恢复 head-only）", "json"],
        ["obligations", "完整义务权限声明（移除恢复空名单）", "json"],
        ["backoff_initial_ms", "首次失败退避（1–60000 毫秒）", "number"],
        ["backoff_max_ms", "退避上限（不低于首次，最多300000 毫秒）", "number"],
      ],
    ],
    [
      ["opa_authorization", "bundle"],
      "OPA 本地签名 bundle",
      [
        ["source", "本地 tar.gz 路径（相对主配置目录）", "string"],
        [
          "signature",
          "原压缩字节的64字节 Ed25519 签名 Base64 SecretSource",
          "string",
        ],
        ["public_key", "32字节 Ed25519 公钥 Base64 SecretSource", "string"],
        ["query", "静态规则路径：data.<package>.<rule>", "string"],
        ["max_bundle_bytes", "压缩字节上限（1–67108864）", "number"],
        [
          "max_expanded_bytes",
          "regular file 展开总字节上限（1–268435456）",
          "number",
        ],
        ["max_files", "regular file 数量上限（1–4096）", "number"],
      ],
    ],
    [
      ["opa_authorization", "input"],
      "OPA 显式正文与已验证 claims",
      [
        ["include_body", "有界读取 JSON 正文并原样重放", "boolean"],
        ["max_body_bytes", "正文上限（1–1048576 字节）", "number"],
        ["content_types", "去参数精确 media type（每行一项，1–32项）", "lines"],
        [
          "include_jwt_claims",
          "附带网关已验签且验证通过的 JWT claims",
          "boolean",
        ],
      ],
    ],
    [
      ["opa_authorization", "obligations"],
      "OPA 受控义务与原子应用预算",
      [
        [
          "request_headers",
          "允许设置或删除的请求头（每行一项，最多256项）",
          "lines",
        ],
        [
          "response_headers",
          "允许设置或删除的响应头（每行一项，最多256项）",
          "lines",
        ],
        ["audit_metadata", "允许的审计 key（每行一项，最多256项）", "lines"],
        ["max_entries", "单次全部义务条目上限（1–256）", "number"],
        ["max_value_bytes", "单个义务值上限（1–65536 字节）", "number"],
        ["max_bytes", "全部义务名称和值总字节上限（1–1048576）", "number"],
      ],
    ],
    [
      ["opa_authorization", "cache"],
      "OPA 决策缓存与同键请求合并",
      [
        ["ttl_ms", "allow 缓存寿命（1–300000 毫秒）", "number"],
        ["deny_ttl_ms", "deny 缓存寿命（1–300000 毫秒）", "number"],
        ["max_entries", "本节点条目容量（1–1000000）", "number"],
        [
          "policy_revision",
          "external 策略修订（1–128 可见ASCII字节）",
          "string",
        ],
        ["singleflight", "合并本节点同键并发 miss", "boolean"],
        ["singleflight_wait_ms", "follower 等待上限（1–30000 毫秒）", "number"],
        [
          "singleflight_max_keys",
          "同时活跃 miss key 上限（1–65536）",
          "number",
        ],
        ["distributed", "经 DynamicStore 复用已验证决策", "boolean"],
        ["distributed_collection", "跨节点决策 collection 名称", "string"],
        [
          "distributed_max_entries",
          "共享 collection 容量（启用时1–1000000）",
          "number",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：逐项维护 OPA 输入和义务名单，让增删仅作用于明确选择的位置。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的五个字符串列表；次序保持原声明，不自行规范化、去重或扩大权限。
 */
export function routeOpaDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["opa_authorization", "include_headers"],
      title: "OPA 不可信输入头",
      type: "string",
    },
    {
      path: ["opa_authorization", "input", "content_types"],
      title: "OPA JSON 正文 media type",
      type: "string",
    },
    {
      path: ["opa_authorization", "obligations", "request_headers"],
      title: "OPA 请求头义务名单",
      type: "string",
    },
    {
      path: ["opa_authorization", "obligations", "response_headers"],
      title: "OPA 响应头义务名单",
      type: "string",
    },
    {
      path: ["opa_authorization", "obligations", "audit_metadata"],
      title: "OPA 审计元数据名单",
      type: "string",
    },
  ];
}
