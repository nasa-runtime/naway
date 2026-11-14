export const layerFields = [
  ["parent_ref", "同一入口的固定父分支身份（根须移除声明）", "string"],
  ["branch", "声明为无终端后端的分支（须有可达子层）", "boolean"],
  ["matches", "完整可信条件（最多16项，全部满足）", "json"],
  ["context", "完整只写一次的可信上下文映射（最多16项）", "json"],
];

export const layerMatchFields = [
  [
    "type",
    "明确条件类型（authenticated/consumer/claim/claim_contains/risk/variable）",
    "string",
  ],
  ["name", "claim 或 variable 的固定名称", "string"],
  ["equals", "consumer/claim/risk/variable 的精确比较值", "string"],
  [
    "value",
    "authenticated 使用 JSON 布尔值；claim_contains 使用 JSON 字符串",
    "json",
  ],
];

export const layerContextFields = [
  ["type", "明确来源（literal 或 claim）", "string"],
  ["value", "literal 的固定文本（1–256字节，无控制字符）", "string"],
  ["name", "claim 的已验签字段名称（1–128字节安全 ASCII）", "string"],
];

/**
 * 业务作用：分别编辑层级拓扑与父层策略产生的可信事实，不用客户端字段或默认声明扩大子层可达性。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供四个原生字段；根、分支、变量相位与授权仍由原目标完整预检。
 */
export function routeLayerFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [[["layer"], "分层路由与可信上下文", layerFields]];
}

/**
 * 业务作用：按原始位置维护可信条件，避免编辑单项时重建父引用或上下文映射。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供明确类型的条件列表，插入与替换不继承相邻条件。
 */
export function routeLayerDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    { path: ["layer", "matches"], title: "分层可信条件", type: "layer_match" },
  ];
}

/**
 * 业务作用：要求新条件完整声明所选变体的字段，不能从相邻项或另一变体继承匹配权。
 * 参数说明：
 * - `value`：本次明确输入的新条件。
 * 返回：六种完整且类型准确的声明通过；缺失、额外或矛盾字段抛出错误，候选保持原样。
 */
export function validateLayerMatchDeclaration(value) {
  const variants = {
    authenticated: { value: "boolean" },
    consumer: { equals: "string" },
    claim: { name: "string", equals: "string" },
    claim_contains: { name: "string", value: "string" },
    risk: { equals: "string" },
    variable: { name: "string", equals: "string" },
  };
  const fields = Object.hasOwn(variants, value.type)
    ? variants[value.type]
    : null;
  if (
    !fields ||
    Object.keys(value).some(
      (key) => key !== "type" && !Object.hasOwn(fields, key),
    ) ||
    Object.entries(fields).some(([key, type]) => typeof value[key] !== type)
  ) {
    throw new Error(
      "新增或替换条件须明确六种 type 之一及其完整字段，不得携带另一变体的字段。",
    );
  }
}

/**
 * 业务作用：要求新上下文只选择常量或已验签 claim，阻止完整替换继承旧来源字段。
 * 参数说明：
 * - `value`：本次明确输入的上下文来源。
 * 返回：完整 literal/claim 声明通过，缺失或额外字段抛出错误；实际值与父链约束仍须原目标校验。
 */
export function validateLayerContextDeclaration(value) {
  const field =
    value.type === "literal" ? "value" : value.type === "claim" ? "name" : null;
  if (
    !field ||
    typeof value[field] !== "string" ||
    Object.keys(value).some((key) => key !== "type" && key !== field)
  ) {
    throw new Error(
      "新增或替换上下文须明确 literal/value 或 claim/name，不能继承旧来源字段。",
    );
  }
}
