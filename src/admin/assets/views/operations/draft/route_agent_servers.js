import { agentTargetFields } from "./route_agent_tools.js";

export const mcpServerFields = [
  ["id", "服务器稳定身份（1–64字节；字母、数字、_、-、.）", "string"],
  [
    "target",
    "完整 MCP 固定目标（地址、路径和独立 SecretSource；不继承其它服务器凭据）",
    "json",
  ],
];

/**
 * 业务作用：独立维护 MCP 固定服务器目标，不把工具引用或客户端地址变为服务器发现权威。
 * 参数说明：
 * - `kind`：当前路由或服务器元素的草稿类别。
 * 返回：完整目录或目标子字段控件；被引用服务器删除、非法目标和数量仍由原目标预检拒绝。
 */
export function routeAgentServerFieldGroups(kind) {
  if (kind === "route") {
    return [
      [
        ["agent"],
        "MCP 完整服务器目录",
        [
          [
            "servers",
            "完整固定服务器目录（最多16项；删除不自动移除引用它的工具）",
            "json",
          ],
        ],
      ],
    ];
  }
  if (!["mcp_server", "mcp_server_new"].includes(kind)) {
    return [];
  }
  return [[["target"], "MCP 固定服务器目标", agentTargetFields]];
}

/**
 * 业务作用：按原始下标增改固定服务器，已有稳定 id 与工具引用保持独立。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供服务器列表，新增和完整替换须明确身份和完整目标，不创建远端会话。
 */
export function routeAgentServerDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    { path: ["agent", "servers"], title: "MCP 固定服务器", type: "mcp_server" },
  ];
}
