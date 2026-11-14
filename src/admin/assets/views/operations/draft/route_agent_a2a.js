import { agentTargetFields, agentAclFields } from "./route_agent_tools.js";

export const a2aFields = [
  ["target", "完整固定 A2A 后端（独立 Bearer SecretSource）", "json"],
  [
    "public_url",
    "显式网关公开 HTTP(S) URL（最多2048字节；path 决定协议入口）",
    "string",
  ],
  ["binding", "单一协议绑定（jsonrpc 或 rest；协议版本为0.3.0）", "string"],
  ["card_path", "独立固定上游发现路径（不从业务路径或客户端推导）", "string"],
  [
    "card_security_schemes",
    "完整网关认证描述映射（1–8项；apiKey/header、http bearer/basic 或 HTTPS openIdConnect）",
    "json",
  ],
  [
    "card_security",
    "完整有序认证需求（1–8项非空映射；只引用已声明认证名称）",
    "json",
  ],
  ["discovery", "完整独立发现 ACL（不授予任务调用权限）", "json"],
  ["invocation", "完整独立任务调用 ACL（不授予发现权限）", "json"],
];

/**
 * 业务作用：显式配置 A2A 固定后端、公开发现合同及独立权限，不信任客户端或上游卡片选择地址。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供 A2A 字段与目标、ACL 子项；协议互斥、认证引用和预算由原目标预检复验。
 */
export function routeAgentA2aFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [["agent"], "A2A 公开发现与固定目标（需 agent-protocols）", a2aFields],
    [["agent", "target"], "A2A 独立后端目标与凭据", agentTargetFields],
    [["agent", "discovery"], "A2A 独立发现权限", agentAclFields],
    [["agent", "invocation"], "A2A 独立任务权限", agentAclFields],
  ];
}

/**
 * 业务作用：按原始顺序维护公开认证需求，不从认证描述创建实际路由认证或扩大调用权限。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供认证需求的单项 JSON 动作，新增需求仍须引用完整认证描述中的名称。
 */
export function routeAgentA2aDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["agent", "card_security"],
      title: "A2A 公开认证需求",
      type: "json",
    },
  ];
}
