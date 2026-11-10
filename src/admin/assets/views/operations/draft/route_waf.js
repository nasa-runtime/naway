export const wafExclusionFields = [
  ["rule", "已启用的规则 id", "string"],
  ["target", "精确检查位置：path / query / body / header:<小写名称>", "string"],
];

/**
 * 业务作用：提供路由内置 WAF 的独立检查与预算控件，保留未编辑的规则包和其它原始声明。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供 WAF 字段；不替用户填写模式、规则或正文检查开关。
 */
export function routeWafFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["waf"],
      "WAF 请求检查",
      [
        ["mode", "处置模式：enforce / monitor", "string"],
        ["inspect_body", "明确检查 JSON / XML 请求正文", "boolean"],
        ["max_body_bytes", "结构化正文容量（1–16777216 字节）", "number"],
        ["max_value_bytes", "单个检查值的扫描预算（1–262144 字节）", "number"],
        ["enabled_rules", "启用内置规则（每行一项，空列表启用全部）", "lines"],
        ["max_json_depth", "JSON 最大嵌套深度（1–128）", "number"],
        ["max_json_nodes", "JSON 最大值节点数（1–1000000）", "number"],
        ["max_xml_depth", "XML 最大元素深度（1–128）", "number"],
        ["max_xml_nodes", "XML 最大事件节点数（1–1000000）", "number"],
        ["max_xml_attributes", "XML 最大属性总数（1–100000）", "number"],
      ],
    ],
  ];
}

/**
 * 业务作用：为 WAF 规则选择与精确例外提供逐项编辑，位置始终绑定当前候选原文。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的规则字符串列表与类型化例外列表；其它对象不新增列表。
 */
export function routeWafDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["waf", "enabled_rules"],
      title: "WAF 启用内置规则",
      type: "string",
    },
    {
      path: ["waf", "exclusions"],
      title: "WAF 精确例外",
      type: "waf_exclusion",
    },
  ];
}
