export const trustedBotFields = [
  ["name", "声明名称（唯一的 1–64 字节 ASCII token）", "string"],
  ["user_agents", "声称身份的 User-Agent glob（至少一项，每行一项）", "lines"],
  [
    "signature_secret",
    "签名密钥的 SecretSource 引用（至少 32 字节）",
    "string",
  ],
  ["signature_header", "Base64URL 无填充签名的头名称", "string"],
  ["timestamp_header", "Unix 秒时间戳的头名称（须与签名头不同）", "string"],
  ["max_clock_skew_secs", "时间戳最大绝对偏差（1–900 秒）", "number"],
];

/**
 * 业务作用：显式编辑完整可信声明，撤销豁免时保留其它 Bot 匹配与速率保护。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供完整列表控件；未编辑时不回传原始声明或求值密钥引用。
 */
export function routeBotTrustedFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["bot"],
      "可信搜索机器人声明",
      [
        [
          "trusted_search_bots",
          "完整可信列表（清空或移除时保留普通 Bot 信号）",
          "json",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：按原位置维护需逐请求验签的机器人声明，不以声明名称授予业务认证身份。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的六字段类型化列表；其它对象不增加信任声明或隐式默认值。
 */
export function routeBotTrustedDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["bot", "trusted_search_bots"],
      title: "可信搜索机器人",
      type: "bot_trusted",
    },
  ];
}
