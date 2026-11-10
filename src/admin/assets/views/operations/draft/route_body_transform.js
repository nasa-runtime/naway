export const bodyTransformOperationFields = [
  ["action", "操作：rename / add / remove / default / type_check", "string"],
  ["from", "rename：源 JSON Pointer（移动现有值）", "string"],
  ["to", "rename：目标 JSON Pointer（须尚不存在）", "string"],
  ["path", "add / remove / default / type_check：JSON Pointer", "string"],
  ["value", "add / default：固定 JSON 值（包括 null）", "json"],
  [
    "expected",
    "type_check：null / boolean / number / integer / string / array / object",
    "string",
  ],
];

export const bodyTransformExtractFields = [
  ["from", "输入绝对 QName 路径（按 namespace URI 匹配）", "string"],
  ["to", "中间 JSON 的非根 JSON Pointer", "string"],
  ["required", "输入路径未命中时拒绝转换", "boolean"],
  ["value_type", "提取文本类型：string / integer / number / boolean", "string"],
];

export const bodyTransformEmitFields = [
  ["from", "中间 JSON 的非根 JSON Pointer", "string"],
  ["to", "相对输出根的 QName 路径（使用 / 分隔）", "string"],
  ["required", "JSON 字段不存在时拒绝转换", "boolean"],
];

const directions = [
  ["request_transform", "请求实体转换"],
  ["response_transform", "响应实体转换"],
];

const transformFields = [
  ["input", "输入格式：json / xml / soap", "string"],
  ["output", "输出格式：json / xml / soap", "string"],
  ["max_body_bytes", "输入聚合上限（1–16777216 字节）", "number"],
  ["max_output_bytes", "新实体上限（1–16777216 字节）", "number"],
  ["operations", "完整 JSON 操作列表（按声明顺序执行）", "json"],
  ["namespaces", "固定 prefix 到 namespace URI 的字符串映射", "json"],
  ["xml_extract", "完整 XML / SOAP 输入提取列表", "json"],
  ["xml_emit", "完整 XML / SOAP 输出结构（root 和 fields）", "json"],
  [
    "soap_action",
    "请求侧匹配或设置的 SOAPAction（响应侧仅校验声明）",
    "string",
  ],
  ["soap_fault", "完整 SOAP Fault 状态映射（仅响应方向）", "json"],
  ["max_xml_depth", "XML 最大元素深度（1–256）", "number"],
  ["max_xml_nodes", "XML 最大节点事件数（1–1000000）", "number"],
  ["max_xml_attributes", "XML 单元素属性上限（1–4096）", "number"],
  ["max_xml_text_bytes", "XML 文本总上限（1–16777216 字节）", "number"],
];

/**
 * 业务作用：分别编辑请求与响应的有界实体转换，避免声明一个方向时隐式激活另一个方向。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的格式、映射、输出结构和资源字段；SOAP Fault 只提供响应方向，默认值不写入候选。
 */
export function routeBodyTransformFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  const groups = directions.flatMap(([key, title]) => [
    [
      [key],
      title,
      transformFields.filter(
        ([field]) => key === "response_transform" || field !== "soap_fault",
      ),
    ],
    [
      [key, "xml_emit"],
      title + "：XML / SOAP 输出结构",
      [
        ["root", "输出根 QName（SOAP 中为 Body 内的业务根）", "string"],
        ["fields", "完整输出字段列表", "json"],
      ],
    ],
  ]);
  groups.push([
    ["response_transform", "soap_fault"],
    "响应实体转换：SOAP Fault 状态",
    [
      ["path", "标准 Envelope / Body 下的 Fault QName 路径", "string"],
      ["status", "命中 Fault 后的非成功 HTTP 状态", "number"],
    ],
  ]);
  return groups;
}

/**
 * 业务作用：按原位置维护两个方向的操作与映射顺序，单项修改不替换其它元素或未编辑字段。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：每个方向的 JSON 操作、XML 提取和 XML 输出三类列表，不创建空转换策略。
 */
export function routeBodyTransformDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return directions.flatMap(([key, title]) => [
    {
      path: [key, "operations"],
      title: title + " JSON 操作",
      type: "body_transform_operation",
    },
    {
      path: [key, "xml_extract"],
      title: title + " XML 提取",
      type: "body_transform_extract",
    },
    {
      path: [key, "xml_emit", "fields"],
      title: title + " XML 输出字段",
      type: "body_transform_emit",
    },
  ]);
}

/**
 * 业务作用：用操作名与源目标路径识别转换列表元素，帮助确认正在移动或删除的声明。
 * 参数说明：
 * - `entry`：当前元素的只读展示投影。
 * 返回：仅含已有字符串字段的可读名称；异常类型不参与业务值转换。
 */
export function bodyTransformEntryLabel(entry) {
  const action = typeof entry?.action === "string" ? entry.action + " · " : "";
  const from = typeof entry?.from === "string" ? entry.from : "";
  const to = typeof entry?.to === "string" ? entry.to : "";
  const path = typeof entry?.path === "string" ? entry.path : "";
  return action + (path || [from, to].filter(Boolean).join(" → ") || "元素");
}
