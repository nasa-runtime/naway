/**
 * 业务作用：提供服务负载反馈与带外订阅的精确字段，保持未编辑的采样和传输信任声明。
 * 参数说明：
 * - `kind`：候选对象类型。
 * 返回：仅服务提供两组原生控件；不自动启用反馈、建立订阅或允许明文传输。
 */
export function upstreamFeedbackFieldGroups(kind) {
  if (kind !== "service") {
    return [];
  }
  return [
    [
      ["load_feedback"],
      "服务负载反馈",
      [
        ["mode", "反馈口径：none / latency_ewma / utilization", "string"],
        ["freshness_ms", "反馈有效期（100–3600000 毫秒）", "number"],
        ["min_samples", "参与比较的最少样本（1–10000）", "number"],
        ["smoothing_bp", "平滑系数（1–10000 万分比）", "number"],
        ["panic_threshold_bp", "新鲜反馈覆盖下限（0–10000 万分比）", "number"],
        ["orca_header", "ORCA 文本报告响应头名", "string"],
      ],
    ],
    [
      ["load_feedback", "out_of_band"],
      "ORCA 带外订阅",
      [
        ["report_interval_ms", "请求报告周期（100–60000 毫秒）", "number"],
        ["connect_timeout_ms", "连接期限（100–60000 毫秒）", "number"],
        ["idle_timeout_ms", "空闲期限（大于周期，最多 300000 毫秒）", "number"],
        ["reconnect_backoff_ms", "重连退避（100–60000 毫秒）", "number"],
        ["max_report_bytes", "单报告容量（1–4096 字节）", "number"],
        [
          "allow_plaintext",
          "明确允许受控网络的明文订阅（缺省 false）",
          "boolean",
        ],
      ],
    ],
  ];
}
