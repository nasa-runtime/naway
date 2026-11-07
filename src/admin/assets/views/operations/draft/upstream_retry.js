export const upstreamRetryFields = [
  ["protocol", "上游协议：auto / h1 / h2 / h2c / h3", "string"],
  ["next_upstream", "换实例触发条件（每行一项，空列表禁用）", "lines"],
  ["next_upstream_tries", "总尝试次数（含首次；0 到候选耗尽）", "number"],
  ["next_upstream_backoff_ms", "换实例前退避（毫秒）", "number"],
  ["max_fails", "被动摘除失败阈值（0 关闭）", "number"],
  ["fail_timeout_ms", "被动失败窗口与摘除时长（毫秒）", "number"],
];

/**
 * 业务作用：提供服务重试预算与连接预热的精确子字段，保留未编辑声明和缺省状态。
 * 参数说明：
 * - `kind`：候选对象类型。
 * 返回：仅服务提供预算与预热分组；不凭编辑动作开启预算或生成预热配置。
 */
export function upstreamRetryFieldGroups(kind) {
  if (kind !== "service") {
    return [];
  }
  return [
    [
      ["retry_budget"],
      "服务重试预算",
      [
        ["enabled", "启用额外重试预算", "boolean"],
        ["budget_percent", "窗口请求量允许重试比例（0–100）", "number"],
        ["min_retry_concurrency", "最低重试额度（1–100000）", "number"],
        ["min_retries_per_window", "每窗口最低重试额度（1–1000000）", "number"],
        ["window_ms", "统计窗口（100–3600000 毫秒）", "number"],
      ],
    ],
    [
      ["prewarm"],
      "上游连接预热",
      [
        ["connections", "期望预热连接数（1–32）", "number"],
        ["path", "HEAD 预热绝对路径", "string"],
        ["timeout_ms", "预热请求期限（10–60000 毫秒）", "number"],
      ],
    ],
  ];
}
