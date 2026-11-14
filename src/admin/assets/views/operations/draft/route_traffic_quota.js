export const trafficQuotaFields = [
  [
    "algorithm",
    "额度算法（fixed_window/sliding_window/leaky_bucket）",
    "string",
  ],
  ["windows", "完整并行窗口（1–16项，全部满足；可逐项编辑）", "json"],
  ["overflow", "超额动作（reject 或 delay）", "string"],
  ["max_queue", "delay 的排队容量（1–4096；reject 不使用）", "number"],
  ["max_wait_ms", "delay 的单请求最长等待（毫秒；1–60000）", "number"],
  [
    "cost_source",
    "明确成本来源（per_request/response_bytes/grpc_messages/graphql_cost/trusted_usage）",
    "string",
  ],
  ["reserve", "准入预留成本（per_request 的显式0按1计费）", "number"],
  ["bytes_per_unit", "response_bytes 的计费字节单位（显式0按1计算）", "number"],
  [
    "max_actual",
    "可信用量或 Redis 响应结算成本上限（1–4294967296，预留不得超过它）",
    "number",
  ],
  [
    "settlement_idle_ms",
    "Redis 响应回执最长无进展（毫秒；1000–600000；本地账本不使用）",
    "number",
  ],
  [
    "usage",
    "完整可信来源（仅 trusted_usage；切换来源须明确处理旧 header）",
    "json",
  ],
];

export const trafficQuotaWindowFields = [
  ["limit", "窗口额度（必须大于0）", "number"],
  ["window_ms", "窗口长度（毫秒；大于0，Redis 至多31天）", "number"],
  ["burst", "突发额度（可显式0；leaky_bucket 不使用）", "number"],
];

export const trafficUsageFields = [
  ["source", "固定来源（provider_tokens 或 response_header）", "string"],
  [
    "header",
    "唯一上游计费头（1–128字节；provider_tokens 须空；不能是敏感或协议控制头）",
    "string",
  ],
];

/**
 * 业务作用：把并行额度、排队与可信成本来源分开编辑，缺失或非法证据不能被页面转换成零用量。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供额度与可信来源子项；算法、数值和依赖组合仍由原目标完整预检。
 */
export function routeTrafficQuotaFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [["traffic_limit", "quota"], "多窗口额度与成本结算", trafficQuotaFields],
    [
      ["traffic_limit", "quota", "usage"],
      "可信上游用量来源",
      trafficUsageFields,
    ],
  ];
}

/**
 * 业务作用：按原始下标维护并行窗口，单个窗口动作不能重建其它窗口或可信成本来源。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供窗口列表位置，不生成默认额度或自动改变超额动作。
 */
export function routeTrafficQuotaDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["traffic_limit", "quota", "windows"],
      title: "流量额度并行窗口",
      type: "traffic_quota_window",
    },
  ];
}
