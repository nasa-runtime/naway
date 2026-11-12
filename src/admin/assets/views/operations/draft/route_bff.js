export const bffTargetFields = [
  [
    "id",
    "聚合结果稳定 key（1–64字节，字母、数字、-、_、.，不得为 _errors）",
    "string",
  ],
  ["uri", "固定 HTTP(S) origin 或 lb://service；路径另行声明", "string"],
  [
    "path",
    "固定 origin path（最多2048字节，无 query/fragment，保持原始编码）",
    "string",
  ],
  [
    "timeout_ms",
    "单目标共同转发与读取期限（10–60000毫秒，且不超过总期限）",
    "number",
  ],
  ["max_response_bytes", "单目标 JSON 响应体上限（1–4194304 字节）", "number"],
  [
    "required",
    "此目标失败使整个聚合失败；false 时为 null 并记录固定 _errors 原因",
    "boolean",
  ],
  [
    "forward_headers",
    "从已治理下游 head 复制的完整名单（每行一项，最多32项）",
    "lines",
  ],
];

/**
 * 业务作用：显式维护只读聚合的共享期限、输出预算与完整目标声明，不自动选择终端后端。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供三项原生聚合字段；未编辑预算和目标保持原声明。
 */
export function routeBffFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["bff_aggregation"],
      "BFF 只读聚合",
      [
        ["targets", "完整固定目标列表（1–16项；也可逐项编辑）", "json"],
        [
          "max_total_response_bytes",
          "完整聚合 JSON 编码上限（1024–16777216 字节）",
          "number",
        ],
        [
          "total_timeout_ms",
          "全部子请求的共同总期限（10–60000毫秒）",
          "number",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：按原始位置编辑固定聚合目标，避免浏览器重建其它目标或改变已有结果键。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供类型化目标列表，新增与替换要求显式稳定 id。
 */
export function routeBffDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["bff_aggregation", "targets"],
      title: "BFF 聚合子请求",
      type: "bff_target",
    },
  ];
}
