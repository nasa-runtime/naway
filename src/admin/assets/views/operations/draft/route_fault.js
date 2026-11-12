/**
 * 业务作用：显式维护路由故障采样、延迟和固定错误，不隐式开启注入或改变原后端。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供四项原生故障字段；未编辑声明保持原值，关闭须移除整段策略。
 */
export function routeFaultFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["fault_injection"],
      "路由故障注入（移除整段声明才关闭）",
      [
        [
          "percentage_bps",
          "命中比例（1–10000 basis points；10000 表示全部命中）",
          "number",
        ],
        ["delay_ms", "命中后的异步延迟（0–60000 毫秒）", "number"],
        [
          "abort_status",
          "延迟后的固定错误状态（仅4xx/5xx；移除可仅延迟）",
          "number",
        ],
        [
          "abort_body",
          "固定错误 UTF-8 正文（最多64KiB，保留换行和空串）",
          "multiline",
        ],
      ],
    ],
  ];
}
