export const dlpExclusionFields = [
  ["rule", "已启用的固定 DLP 规则名", "string"],
  [
    "target",
    "精确位置：request_header:<名称> / response_header:<名称> / query:<名称> / request_body / response_body / path_log",
    "string",
  ],
];

/**
 * 业务作用：显式选择敏感数据检查位置与处置方式，避免未编辑的正文方向被隐式开启。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供 DLP 原生字段；保持原声明时不回传配置或物化默认值。
 */
export function routeDlpFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["dlp"],
      "敏感数据保护",
      [
        ["action", "命中动作：block / redact / monitor", "string"],
        ["enabled_rules", "启用规则（每行一项，空列表启用全部）", "lines"],
        ["request_headers", "检查请求头（精确名称，每行一项）", "lines"],
        ["response_headers", "检查响应头（精确名称，每行一项）", "lines"],
        ["inspect_query", "解码检查 query 名称和值", "boolean"],
        ["protect_log_path", "检查日志路径并遮蔽命中值", "boolean"],
        ["inspect_request_body", "有界聚合并检查请求正文", "boolean"],
        ["inspect_response_body", "有界聚合并检查响应正文", "boolean"],
        ["body_media_types", "正文 media type（每行一项）", "lines"],
        ["max_body_bytes", "单方向正文容量（1–16777216 字节）", "number"],
        ["replacement", "遮蔽替代文本（1–128 字节可打印 ASCII）", "string"],
        ["exclusions", "完整精确例外列表（空列表撤销全部例外）", "json"],
      ],
    ],
  ];
}

/**
 * 业务作用：按原位置维护 DLP 规则、检查目标与精确例外，避免例外扩散到其它方向。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的四个字符串列表和两字段例外列表；其它对象不新增敏感数据策略。
 */
export function routeDlpDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["dlp", "enabled_rules"],
      title: "DLP 启用规则",
      type: "string",
    },
    {
      path: ["dlp", "request_headers"],
      title: "DLP 请求头",
      type: "string",
    },
    {
      path: ["dlp", "response_headers"],
      title: "DLP 响应头",
      type: "string",
    },
    {
      path: ["dlp", "body_media_types"],
      title: "DLP 正文类型",
      type: "string",
    },
    {
      path: ["dlp", "exclusions"],
      title: "DLP 精确例外",
      type: "dlp_exclusion",
    },
  ];
}
