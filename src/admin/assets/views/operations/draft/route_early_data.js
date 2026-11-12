/**
 * 业务作用：显式维护路由 0-RTT 授权与重放窗口，使禁用声明和监听器能力保持独立。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供两项声明，不修改方法、上游、认证、请求体转发或监听器恢复策略。
 */
export function routeEarlyDataFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["early_data"],
      "路由 0-RTT 授权与重放保护",
      [
        [
          "enabled",
          "明确允许本路由 0-RTT（仍需监听器与重放保护门）",
          "boolean",
        ],
        [
          "replay_window_ms",
          "一次性 nonce 保留窗口（毫秒；启用时1000–600000）",
          "number",
        ],
      ],
    ],
  ];
}
