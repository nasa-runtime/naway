/**
 * 业务作用：编辑 Bot 速率信号的令牌与状态容量边界，显式区分新指纹溢出放行和已有指纹额度。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的完整速率声明与五个原生字段；未编辑时不填充默认值或改变其它 Bot 信号。
 */
export function routeBotRateFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["bot"],
      "Bot 速率信号声明",
      [["rate", "完整速率声明（移除时保留其它 Bot 信号）", "json"]],
    ],
    [
      ["bot", "rate"],
      "Bot 速率与指纹容量",
      [
        ["limit", "基础令牌量（新建必填，1–10000000）", "number"],
        ["window_ms", "补充窗口（新建必填，1–86400000 毫秒）", "number"],
        ["burst", "附加突发容量（0–10000000）", "number"],
        ["max_active_keys", "最多保留的活动指纹数（1–1000000）", "number"],
        ["active_keys_fail_open", "指纹表满时放行未记账的新指纹", "boolean"],
      ],
    ],
  ];
}
