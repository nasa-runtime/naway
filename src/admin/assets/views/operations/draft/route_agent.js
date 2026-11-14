import {
  identitySecurityFields,
  identityConsumerGroupEditor,
} from "./identity_security.js";

export const agentLimitFields = [
  ["max_request_bytes", "单次请求字节上限（1–4194304）", "number"],
  ["max_response_bytes", "单次响应字节上限（1–16777216）", "number"],
  [
    "max_frame_bytes",
    "单个流事件字节上限（1–1048576；不超过响应预算）",
    "number",
  ],
  ["max_sessions", "MCP 会话或 A2A task 状态总量（1–16384）", "number"],
  [
    "max_sessions_per_identity",
    "每个已验证主体的状态数量（1–总量上限）",
    "number",
  ],
  [
    "session_ttl_ms",
    "会话或 task 状态保留期限（毫秒；1000–3600000）",
    "number",
  ],
  ["deadline_ms", "单次动作期限（毫秒；1–300000）", "number"],
  ["max_inflight", "在途动作总量（1–4096）", "number"],
  ["max_calls_per_session", "每会话或 task 状态调用总数（1–100000）", "number"],
  [
    "max_bytes_per_session",
    "每会话或 task 状态总字节（1–1073741824；至少容纳最大请求加响应）",
    "number",
  ],
];

/**
 * 业务作用：独立编辑 Agent 协议、可信身份和有界状态预算，不隐式切换协议或扩大权限。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供原生字段；缺失声明保持缺失，协议与预算关系仍须原目标完整预检。
 */
export function routeAgentFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["agent"],
      "Agent 协议与完整身份预算（需 agent-protocols）",
      [
        [
          "protocol",
          "显式协议（mcp 或 a2a；切换须完整声明该协议必需字段）",
          "string",
        ],
        [
          "protocol_version",
          "显式兼容协议版本（MCP 2025-11-25；A2A 0.3.0）",
          "string",
        ],
        ["security", "完整可信身份（替换全部；Agent 存在时不可缺失）", "json"],
        ["limits", "完整状态预算（替换全部；移除采用原生默认预算）", "json"],
      ],
    ],
    [["agent", "security"], "Agent 可信租户与身份来源", identitySecurityFields],
    [["agent", "limits"], "Agent 会话与任务预算", agentLimitFields],
  ];
}

/**
 * 业务作用：按原位置维护 Agent 允许来源，不把客户端 Origin 当作认证证据。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供独立 Origin 列表，不添加默认来源或改写 AI 治理身份。
 */
export function routeAgentDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["agent", "security", "allowed_origins"],
      title: "Agent 允许 Origin",
      type: "string",
    },
  ];
}

/**
 * 业务作用：逐键维护 Agent 已认证 consumer 的固定组名单，保留其它身份域的授权声明。
 * 参数说明：
 * - `object`：当前已读取的完整路由身份。
 * - `values`：原始路由字段的展示投影。
 * - `capacity`：单候选输入字节容量。
 * - `submit`：沿原选择代和权限门提交动作的回调。
 * - `changed`：输入变化时撤销旧在途结果的回调。
 * 返回：有界映射面板，新增须显式设置，删除须确认，不创建或认证 consumer。
 */
export function agentConsumerGroupEditor(
  object,
  values,
  capacity,
  submit,
  changed,
) {
  return identityConsumerGroupEditor(
    "agent",
    object,
    values,
    capacity,
    submit,
    changed,
  );
}
