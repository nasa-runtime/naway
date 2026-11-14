export const productVersionFields = [
  ["id", "产品内稳定版本身份（1–64字节字母、数字、_、-、.）", "string"],
  [
    "lifecycle",
    "明确生命周期：draft / active / deprecated / retired",
    "string",
  ],
  ["visibility", "明确可见性：public / private", "string"],
  ["deprecated_at", "仅 deprecated 必须声明的 RFC3339 弃用时刻", "string"],
  [
    "subscription_teams",
    "显式订阅团队（每行一项；空名单不授予任何团队）",
    "lines",
  ],
  ["compare_to", "同产品内其它版本的兼容比较基线", "string"],
  ["documents", "完整文档声明（1–16项；替换全部文件与操作选择）", "json"],
];

export const productDocumentFields = [
  ["id", "版本内稳定文档身份（1–64字节字母、数字、_、-、.）", "string"],
  ["format", "明确文档格式：openapi / asyncapi / markdown", "string"],
  ["file", "原目标配置根内文档引用（这里只编辑原文，不读取文件）", "string"],
  ["operations", "显式发布操作（每行一项；Markdown 必须为空）", "lines"],
];

/**
 * 业务作用：为产品的原文版本、文档与授权名单提供有界父位置，不能从错型声明推断另一份目录。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * - `values`：只用于列出原始下标和稳定身份的字段投影。
 * 返回：产品版本、每个版本的团队与文档、每份文档的操作列表；超量或错型时不展开内层位置。
 */
export function productDraftLists(kind, values) {
  if (kind !== "product") {
    return [];
  }
  const result = [
    {
      path: ["versions"],
      title: "API 产品版本",
      type: "product_version",
      maxItems: 32,
    },
  ];
  if (!Array.isArray(values?.versions) || values.versions.length > 32) {
    return result;
  }
  for (const [index, version] of values.versions.entries()) {
    if (!version || Array.isArray(version) || typeof version !== "object") {
      continue;
    }
    const name =
      typeof version.id === "string" ? version.id.slice(0, 64) : "未声明身份";
    const parent = [{ index, path: ["documents"] }];
    result.push(
      {
        path: ["versions"],
        parents: [{ index, path: ["subscription_teams"] }],
        title: `API 产品订阅团队 · 版本 ${index} · ${name}`,
        type: "string",
        maxItems: 128,
      },
      {
        path: ["versions"],
        parents: parent,
        title: `API 产品文档 · 版本 ${index} · ${name}`,
        type: "product_document",
        maxItems: 16,
      },
    );
    if (!Array.isArray(version.documents) || version.documents.length > 16) {
      continue;
    }
    for (const [documentIndex, document] of version.documents.entries()) {
      if (
        !document ||
        Array.isArray(document) ||
        typeof document !== "object"
      ) {
        continue;
      }
      const id =
        typeof document.id === "string"
          ? document.id.slice(0, 64)
          : "未声明身份";
      result.push({
        path: ["versions"],
        parents: [...parent, { index: documentIndex, path: ["operations"] }],
        title: `API 产品文档操作 · 版本 ${index} · ${name} · 文档 ${documentIndex} · ${id}`,
        type: "string",
        maxItems: 4096,
      });
    }
  }
  return result;
}

/**
 * 业务作用：让新增和整值替换显式声明产品合同与权限，不从相邻版本或文档继承公开性、团队和操作。
 * 参数说明：
 * - `kind`：版本或文档的列表元素类别。
 * - `fields`：本次明确设置的新元素全部字段。
 * 返回：原生必需身份、枚举和有界名单完整时允许提交；文件解析和跨版本关系仍由原目标完整预检。
 */
export function validateProductElement(kind, fields) {
  if (!["product_version", "product_document"].includes(kind)) {
    return;
  }
  if (
    typeof fields?.id !== "string" ||
    !/^[A-Za-z0-9_.-]{1,64}$/.test(fields.id)
  ) {
    throw new Error("新增或替换产品版本和文档必须明确填写1–64字节的稳定 id。");
  }
  if (kind === "product_version") {
    // 新合同没有可继承的可见性或订阅权，缺少显式名单不能被当作另一版本的授权。
    if (
      !["draft", "active", "deprecated", "retired"].includes(
        fields.lifecycle,
      ) ||
      !["public", "private"].includes(fields.visibility) ||
      !Array.isArray(fields.subscription_teams) ||
      fields.subscription_teams.length > 128 ||
      fields.subscription_teams.some(
        (team) =>
          typeof team !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(team),
      ) ||
      !Array.isArray(fields.documents) ||
      fields.documents.length < 1 ||
      fields.documents.length > 16
    ) {
      throw new Error(
        "新增或替换版本必须明确有效的 lifecycle、visibility、subscription_teams 和1–16项 documents。",
      );
    }
    if (
      (fields.lifecycle === "deprecated") !==
        Object.hasOwn(fields, "deprecated_at") ||
      (Object.hasOwn(fields, "deprecated_at") &&
        (typeof fields.deprecated_at !== "string" ||
          !fields.deprecated_at.length))
    ) {
      throw new Error(
        "deprecated 版本必须明确填写 deprecated_at，其它生命周期必须不声明此字段。",
      );
    }
  } else if (
    !["openapi", "asyncapi", "markdown"].includes(fields.format) ||
    typeof fields.file !== "string" ||
    !fields.file.length ||
    !Array.isArray(fields.operations) ||
    fields.operations.length > 4096 ||
    fields.operations.some(
      (operation) =>
        typeof operation !== "string" ||
        !operation.length ||
        new TextEncoder().encode(operation).length > 256 ||
        /[\x00-\x1f\x7f]/.test(operation),
    ) ||
    (fields.format === "markdown"
      ? fields.operations.length !== 0
      : fields.operations.length === 0)
  ) {
    throw new Error(
      "新增或替换文档必须明确有效的 format、非空 file 和 operations；Markdown 名单须为空，API 文档须显式选择操作。",
    );
  }
}
