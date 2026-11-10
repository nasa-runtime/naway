export const routeDeadlineFields = [
  [
    "request_timeout_ms",
    "上游转发至完整响应的总时限（毫秒，0 不增加截止点）",
    "number",
  ],
  [
    "backend_request_timeout_ms",
    "每次上游尝试的完整时限（毫秒，0 不增加截止点）",
    "number",
  ],
  [
    "long_stream_idle_timeout_ms",
    "响应帧间空闲期限（毫秒，未声明继承入口，0 关闭）",
    "number",
  ],
  [
    "long_stream_max_lifetime_ms",
    "SSE / gRPC 与原生边缘桥接最长寿命（毫秒，0 不限制）",
    "number",
  ],
];

/**
 * 业务作用：提供路由并行副本的精确子字段，不隐式确认业务幂等性或创建策略。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供副本策略控件；其它类别保持原有字段集合。
 */
export function routeDeadlineFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["hedge"],
      "并行副本（须明确确认业务允许重复执行）",
      [
        ["idempotent", "明确确认业务幂等（必须为 true）", "boolean"],
        ["delay_ms", "副本启动延迟（1–60000 毫秒）", "number"],
        ["max_attempts", "主请求与副本总次数（固定为 2）", "number"],
      ],
    ],
  ];
}
