export const trafficLimitFields = [
  [
    "events",
    "输出独立计量事实（须 quota 与 traffic_meter；切换不清空现有账本）",
    "boolean",
  ],
  [
    "backend",
    "显式账本后端（local 或 redis；Redis 需 redis-runtime）",
    "string",
  ],
  [
    "scope",
    "共享边界（route、service、global 或 shared:名称；始终隔离工作区）",
    "string",
  ],
  [
    "key",
    "额度维度（global/ip/route/header:名称/query:名称，或可信 consumer/api_key）",
    "string",
  ],
  [
    "request_bandwidth",
    "完整请求方向带宽（替换全部；移除只关闭此方向）",
    "json",
  ],
  [
    "response_bandwidth",
    "完整响应方向带宽（替换全部；移除只关闭此方向）",
    "json",
  ],
  ["quota", "完整多窗口额度与成本来源（全部窗口同时满足）", "json"],
  ["fail_mode", "账本依赖不可用动作（fail_open 或 fail_closed）", "string"],
];

export const trafficBandwidthFields = [
  ["bytes_per_second", "稳态字节/秒（必须大于0）", "number"],
  ["burst_bytes", "突发字节容量（可显式0）", "number"],
  ["after_bytes", "前置不整形字节数（可显式0）", "number"],
  ["max_wait_ms", "每帧最长等待（毫秒；1–60000；超期终止该方向）", "number"],
];

/**
 * 业务作用：独立维护流量账本权威与两个方向的带宽声明，不从页面显示值重建共享额度或另一方向。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供完整策略、八项原生字段和两组带宽子项；共享范围及依赖仍由原目标预检。
 */
export function routeTrafficLimitFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [["traffic_limit"], "流量账本、共享范围与完整额度", trafficLimitFields],
    [
      ["traffic_limit", "request_bandwidth"],
      "请求方向带宽",
      trafficBandwidthFields,
    ],
    [
      ["traffic_limit", "response_bandwidth"],
      "响应方向带宽",
      trafficBandwidthFields,
    ],
  ];
}
