export const agentTargetFields = [
  ["uri", "固定后端 origin 或 lb://service（不读取客户端目标）", "string"],
  ["path", "固定后端路径（REST 工具可显式声明路径参数模板）", "string"],
  ["api_key", "此固定目标的 Bearer SecretSource 引用（不读取秘密）", "string"],
];

export const agentAclFields = [
  [
    "allow_authenticated",
    "显式允许已认证身份（其它已配置维度仍须同时满足）",
    "boolean",
  ],
  ["consumers", "完整已认证 consumer 名单（每行一项，最多64项）", "lines"],
  ["groups", "完整已验证组名单（每行一项，最多64项，至少一组匹配）", "lines"],
  ["scopes", "完整已验签 scope 名单（每行一项，最多64项，全部满足）", "lines"],
];

export const mcpToolFields = [
  ["name", "工具稳定名称（1–64字节；字母、数字、_、-、.）", "string"],
  ["description", "工具用途说明（最多4096字节）", "string"],
  ["input_schema", "完整输入 JSON Schema（必须描述 object）", "json"],
  [
    "output_schema",
    "可选完整输出 JSON Schema（移除停止该 schema 检查）",
    "json",
  ],
  [
    "discovery",
    "完整发现 ACL（独立于调用，空策略须显式放行已认证身份）",
    "json",
  ],
  ["invocation", "完整调用 ACL（每次重新验证，不继承发现权限）", "json"],
  [
    "side_effect",
    "副作用声明（read_only、idempotent、destructive；不保证远端事务）",
    "string",
  ],
  [
    "deadline_ms",
    "单次工具动作期限（毫秒；1–300000，仍受路由及会话期限限制）",
    "number",
  ],
  [
    "max_calls_per_session",
    "本工具每会话调用上限（1–100000，失败或取消不退款）",
    "number",
  ],
  [
    "max_request_bytes",
    "工具请求字节上限（1–4194304；不超过路由预算）",
    "number",
  ],
  [
    "max_response_bytes",
    "工具响应字节上限（1–16777216；不超过路由预算）",
    "number",
  ],
  [
    "backend",
    "完整固定后端（显式选择 rest 或 mcp，替换移除旧类型的其它字段）",
    "json",
  ],
];

/**
 * 业务作用：独立维护 MCP 工具合同、发现与调用权限及固定后端，不从目录展示生成调用授权。
 * 参数说明：
 * - `kind`：当前路由或工具元素的草稿类别。
 * 返回：原生字段控件；严格后端类型、schema、ACL、目录和预算关系由原目标预检复验。
 */
export function routeAgentToolFieldGroups(kind) {
  if (kind === "route") {
    return [
      [
        ["agent"],
        "MCP 完整工具目录",
        [
          [
            "tools",
            "完整手工工具目录（最多256项，可按原位置逐项编辑；至少保留一个可执行工具）",
            "json",
          ],
        ],
      ],
    ];
  }
  if (!["mcp_tool", "mcp_tool_new"].includes(kind)) {
    return [];
  }
  return [
    [["discovery"], "MCP 独立发现 ACL", agentAclFields],
    [["invocation"], "MCP 独立调用 ACL", agentAclFields],
    [
      ["backend"],
      "MCP 工具后端选择",
      [
        [
          "type",
          "显式后端类型（rest 或 mcp；切换须移除另一类型字段）",
          "string",
        ],
        [
          "method",
          "REST 固定方法（GET、POST、PUT、PATCH、DELETE；read_only 仅 GET）",
          "string",
        ],
        [
          "target",
          "完整 REST 固定目标（替换整个地址、路径与独立凭据）",
          "json",
        ],
        [
          "server",
          "MCP 固定 server 的稳定 id（必须已在 servers 声明）",
          "string",
        ],
        ["tool", "MCP 后端工具名（不从客户端请求推导）", "string"],
      ],
    ],
    [["backend", "target"], "MCP 工具 REST 固定目标", agentTargetFields],
  ];
}

/**
 * 业务作用：以原始下标编辑 MCP 工具目录，稳定名称只在新增或完整替换时开放。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供工具列表，不初始化工具、会话、ACL 或独立凭据。
 */
export function routeAgentToolDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    { path: ["agent", "tools"], title: "MCP 固定工具", type: "mcp_tool" },
  ];
}
