export const schemaRegistryDocumentFields = [
  ["url", "固定 HTTPS 文档 URL（无凭据或 fragment）", "string"],
  ["sha256", "原始文档 SHA-256（64 位十六进制）", "string"],
  ["signature", "Base64 Ed25519 签名的 SecretSource 引用", "string"],
  ["public_key", "Base64 Ed25519 公钥的 SecretSource 引用", "string"],
  ["ca_file", "可选信任 CA 本地 PEM 路径", "string"],
  ["max_bytes", "单文档容量（1–4194304 字节）", "number"],
  ["timeout_ms", "HTTPS 总期限（100–30000 毫秒）", "number"],
  ["cache_ttl_ms", "已验签字节最长复用时间（1–86400000 毫秒）", "number"],
];

/**
 * 业务作用：显式编辑响应合同来源与失败动作，保持未编辑的信任声明和正文预算。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十项原生响应合同字段；本地路径、URL 和 SecretSource 不在页面求值。
 */
export function routeResponseContractFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["response_contract"],
      "OpenAPI 响应合同与 Schema 来源",
      [
        ["openapi_file", "OpenAPI 本地 JSON / YAML 路径", "string"],
        ["operation_id", "OpenAPI operationId（与路径和方法二选一）", "string"],
        ["operation_path", "OpenAPI 路径模板（须同时填写方法）", "string"],
        [
          "operation_method",
          "OpenAPI HTTP 方法（须同时填写路径模板）",
          "string",
        ],
        ["mode", "合同动作：observe / block / replace_error", "string"],
        ["max_body_bytes", "响应检查容量（1–16777216 字节）", "number"],
        [
          "replacement_status",
          "替代 HTTP 状态（replace_error 不得为成功状态）",
          "number",
        ],
        [
          "replacement_body",
          "固定替代文本（至多 4096 UTF-8 字节，多行文本）",
          "multiline",
        ],
        ["catalog_files", "受信本地 Schema catalog（每行一项）", "lines"],
        ["registry_documents", "完整签名 HTTPS Schema 文档列表", "json"],
      ],
    ],
  ];
}

/**
 * 业务作用：按原位置维护受信 Schema 来源，显式撤销时保留其它合同与独立安全策略。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的本地 catalog 字符串列表和八字段签名 HTTPS 文档列表；不生成默认来源。
 */
export function routeResponseContractDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["response_contract", "catalog_files"],
      title: "响应合同本地 catalog",
      type: "string",
    },
    {
      path: ["response_contract", "registry_documents"],
      title: "响应合同签名 HTTPS 文档",
      type: "schema_registry_document",
    },
  ];
}
