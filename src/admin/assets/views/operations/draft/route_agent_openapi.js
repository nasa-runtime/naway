import {
  agentTargetFields,
  agentAclFields,
  mcpToolFields,
} from "./route_agent_tools.js";

export const openApiCatalogFields = [
  [
    "file",
    "本地 OpenAPI 3.0/3.1 文档引用（最多2MiB；这里只编辑引用，不读取文件）",
    "string",
  ],
  ["target", "完整固定目标前缀（文档 servers 不产生目标或凭据权威）", "json"],
  [
    "operations",
    "完整显式操作名单（1–256项；可在目录操作列表逐项编辑）",
    "json",
  ],
];

export const openApiOperationFields = [
  [
    "operation_id",
    "文档中的精确 operationId（不选择未显式声明的操作）",
    "string",
  ],
  ["name", "网关工具稳定名称（1–64字节；字母、数字、_、-、.）", "string"],
  ...mcpToolFields.filter(([name]) =>
    [
      "discovery",
      "invocation",
      "side_effect",
      "deadline_ms",
      "max_calls_per_session",
      "max_request_bytes",
      "max_response_bytes",
    ].includes(name),
  ),
];

/**
 * 业务作用：分别维护本地转换文档、固定目标及操作 ACL，不从文档服务器或认证描述生成授权。
 * 参数说明：
 * - `kind`：当前路由、转换目录或操作元素的草稿类别。
 * 返回：原生目录目标与操作权限控件；文档解析、引用、预算和工具目录关系仍由原目标预检复验。
 */
export function routeAgentOpenApiFieldGroups(kind) {
  if (kind === "route") {
    return [
      [
        ["agent"],
        "MCP OpenAPI 完整转换目录",
        [
          [
            "openapi",
            "完整本地转换目录（最多16项；只转换显式 operations）",
            "json",
          ],
        ],
      ],
    ];
  }
  if (kind === "mcp_openapi_catalog") {
    return [[["target"], "OpenAPI 固定目标前缀", agentTargetFields]];
  }
  if (["mcp_openapi_operation", "mcp_openapi_operation_new"].includes(kind)) {
    return [
      [["discovery"], "OpenAPI 工具独立发现 ACL", agentAclFields],
      [["invocation"], "OpenAPI 工具独立调用 ACL", agentAclFields],
    ];
  }
  return [];
}

/**
 * 业务作用：以当前原文目录下标选择内层操作名单，不复制或重建其它目录和操作。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * - `values`：只用于显示目录文件名和选择原始下标的字段投影。
 * 返回：完整目录及最多16个明确目录的内层列表位置，类型不符或超量时只保留完整目录入口。
 */
export function routeAgentOpenApiDraftLists(kind, values) {
  if (kind !== "route") {
    return [];
  }
  const result = [
    {
      path: ["agent", "openapi"],
      title: "MCP OpenAPI 转换目录",
      type: "mcp_openapi_catalog",
    },
  ];
  const catalogs = values?.agent?.openapi;
  if (!Array.isArray(catalogs) || catalogs.length > 16) {
    return result;
  }
  for (const [index, catalog] of catalogs.entries()) {
    if (!catalog || Array.isArray(catalog) || typeof catalog !== "object") {
      continue;
    }
    const file =
      typeof catalog.file === "string"
        ? catalog.file.slice(0, 120)
        : "未声明文件";
    result.push({
      path: ["agent", "openapi"],
      parents: [{ index, path: ["operations"] }],
      title: `OpenAPI 操作 · 目录 ${index} · ${file}`,
      type: "mcp_openapi_operation",
    });
  }
  return result;
}
