/**
 * 业务作用：提供服务并发准入和窗口摘除的独立子字段，保持未编辑策略及原始缺省状态。
 * 参数说明：
 * - `kind`：候选对象类型。
 * 返回：服务对象的两组原生字段；其它对象无分组，不注入运行默认值或自动启用策略。
 */
export function upstreamCapacityFieldGroups(kind) {
  if (kind !== "service") {
    return [];
  }
  return [
    [
      ["adaptive_concurrency"],
      "服务并发准入",
      [
        ["enabled", "启用自适应并发", "boolean"],
        ["min_concurrency", "在途并发下界（至少 1）", "number"],
        ["max_concurrency", "在途并发上界（不小于下界）", "number"],
        ["sample_window_ms", "延迟采样窗口（50–60000 毫秒）", "number"],
        [
          "min_rtt_window_ms",
          "最低 RTT 重标定周期（1000–3600000 毫秒）",
          "number",
        ],
        ["jitter_bp", "标定周期抖动（0–10000 万分比）", "number"],
        ["queue_limit", "排队上限（0 直接拒绝，最多 1000000）", "number"],
        ["queue_deadline_ms", "排队期限（1–60000 毫秒）", "number"],
      ],
    ],
    [
      ["outlier"],
      "服务窗口摘除",
      [
        ["window_ms", "统计窗口（160–300000 毫秒）", "number"],
        ["min_samples", "开始判定的最少样本（1–1000000）", "number"],
        ["failure_percent", "失败比例阈值（0 不使用，最多 100）", "number"],
        ["slow_percent", "慢调用比例阈值（0 不使用，最多 100）", "number"],
        ["slow_ms", "慢调用耗时阈值（1–300000 毫秒）", "number"],
        ["max_ejection_percent", "同时摘除比例上限（1–99）", "number"],
        ["base_ejection_ms", "首次摘除冷却（1–300000 毫秒）", "number"],
        [
          "max_ejection_ms",
          "恢复失败冷却上限（不小于首次，最多 300000 毫秒）",
          "number",
        ],
        ["probe_timeout_ms", "恢复探测期限（1–60000 毫秒）", "number"],
      ],
    ],
  ];
}
