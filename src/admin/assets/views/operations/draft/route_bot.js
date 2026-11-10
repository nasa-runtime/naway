/**
 * 业务作用：编辑路由 Bot 的匹配、行为和挑战声明，保留未编辑的速率与签名信任策略。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十三个常用字段；读取不会隐式启用策略或填充默认信号。
 */
export function routeBotFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["bot"],
      "Bot 匹配与行为信号",
      [
        ["mode", "处置模式：enforce / monitor", "string"],
        ["allowed_user_agents", "允许的 User-Agent glob（每行一项）", "lines"],
        ["denied_user_agents", "拒绝的 User-Agent glob（每行一项）", "lines"],
        ["required_headers", "必须为单个非空值的头名称（每行一项）", "lines"],
        ["automation_headers", "自动化信号头名称（每行一项）", "lines"],
        [
          "fingerprint_headers",
          "参与指纹的头名称（每行一项，保留顺序）",
          "lines",
        ],
        ["denied_fingerprints", "拒绝的 SHA-256 小写指纹（每行一项）", "lines"],
        ["missing_user_agent_score", "缺少或非法 User-Agent 的分数", "number"],
        [
          "browser_header_mismatch_score",
          "浏览器声明缺少基础头的分数",
          "number",
        ],
        ["automation_header_score", "每个自动化信号头的分数", "number"],
        ["score_threshold", "挑战分数阈值（大于 0）", "number"],
        ["challenge_status", "挑战状态码（400–499，不能为 429）", "number"],
        ["challenge_realm", "挑战 realm（1–64 字节 ASCII token）", "string"],
      ],
    ],
  ];
}

/**
 * 业务作用：按原位置编辑 Bot 匹配与指纹列表，顺序变更只影响用户明确选择的列表。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的六个字符串列表；其它对象不增加列表或改变原声明。
 */
export function routeBotDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["bot", "allowed_user_agents"],
      title: "Bot 允许 User-Agent",
      type: "string",
    },
    {
      path: ["bot", "denied_user_agents"],
      title: "Bot 拒绝 User-Agent",
      type: "string",
    },
    { path: ["bot", "required_headers"], title: "Bot 必需头", type: "string" },
    {
      path: ["bot", "automation_headers"],
      title: "Bot 自动化信号头",
      type: "string",
    },
    {
      path: ["bot", "fingerprint_headers"],
      title: "Bot 指纹头",
      type: "string",
    },
    {
      path: ["bot", "denied_fingerprints"],
      title: "Bot 拒绝指纹",
      type: "string",
    },
  ];
}
