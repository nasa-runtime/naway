export const localityTargetFields = [
  ["region", "目标地域", "string"],
  ["zone", "目标可用区", "string"],
  ["subzone", "目标子可用区（缺省覆盖整个可用区）", "string"],
  ["priority", "目标优先级（0–65535，越小越优先）", "number"],
  ["weight", "同层相对权重（1–10000）", "number"],
  ["degraded", "降低同层份额", "boolean"],
];

/**
 * 业务作用：提供可信地域的精确子字段编辑，保留未编辑拓扑及显式跨区边界。
 * 参数说明：
 * - `kind`：候选对象类型。
 * 返回：仅服务提供地域分组；不自动声明目标、权重或允许未列实例。
 */
export function upstreamLocalityFieldGroups(kind) {
  if (kind !== "service") {
    return [];
  }
  return [
    [
      ["locality"],
      "服务地域选择",
      [
        ["local_zone", "本地可用区", "string"],
        ["local_region", "本地地域（声明后使用分层目标）", "string"],
        ["local_subzone", "本地子可用区（须声明地域）", "string"],
        ["mode", "选择模式：failover / weighted", "string"],
        ["failover_zones", "单层备用可用区（按顺序，每行一项）", "lines"],
        ["allow_unlisted", "允许未列拓扑最终兜底（缺省 false）", "boolean"],
        ["zone_weights", "单层可用区权重映射（仅 weighted）", "json"],
        ["degraded_zones", "单层劣化可用区（每行一项）", "lines"],
        ["degraded_weight_percent", "劣化份额比例（1–100，缺省 20）", "number"],
      ],
    ],
  ];
}

/**
 * 业务作用：将地域目标和单层列表按原位置编辑，避免提交未改动的完整拓扑数组。
 * 参数说明：
 * - `kind`：候选对象类型。
 * 返回：服务的类型化目标及两个字符串列表；每次动作仍绑定当前候选摘要。
 */
export function upstreamLocalityDraftLists(kind) {
  if (kind !== "service") {
    return [];
  }
  return [
    {
      path: ["locality", "targets"],
      title: "分层地域目标",
      type: "locality_target",
    },
    {
      path: ["locality", "failover_zones"],
      title: "单层备用可用区",
      type: "string",
    },
    {
      path: ["locality", "degraded_zones"],
      title: "单层劣化可用区",
      type: "string",
    },
  ];
}
