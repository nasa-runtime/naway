export const portalSubscriptionFields = [
  ["product", "明确订阅的产品身份", "string"],
  ["version", "明确订阅的产品版本身份", "string"],
];

export const portalCredentialFields = [
  ["id", "应用内稳定凭据身份（1–64字节安全 ASCII）", "string"],
  ["sha256", "明确凭据摘要（64位小写十六进制，不填明文 key）", "string"],
  ["revoked", "明确撤销状态（true 撤销 / false 可用）", "boolean"],
];

/**
 * 业务作用：为独立门户应用列出固定回调、订阅和凭据位置，不从缺失字段或其它对象推断授权。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：应用的三个原生有界列表；其它对象无此目录，是否可编辑仍取决于原始字段类型。
 */
export function portalApplicationDraftLists(kind) {
  if (kind !== "portal_application") {
    return [];
  }
  return [
    {
      path: ["redirect_uris"],
      title: "门户应用回调地址",
      type: "string",
      validate: "portal_redirect",
      maxItems: 16,
    },
    {
      path: ["subscriptions"],
      title: "门户应用产品订阅",
      type: "portal_subscription",
      maxItems: 128,
    },
    {
      path: ["credentials"],
      title: "门户应用凭据摘要",
      type: "portal_credential",
      maxItems: 16,
    },
  ];
}

/**
 * 业务作用：让新增或整值替换明确声明回调、订阅和凭据权限，不继承相邻项或生成明文密钥。
 * 参数说明：
 * - `kind`：固定门户列表元素或回调的校验类别。
 * - `value`：本次显式提交的新元素原文。
 * 返回：完整且符合原生标识、HTTPS 回调或摘要格式时成功；其它类别不处理，跨对象授权仍须完整预检。
 */
export function validatePortalApplicationElement(kind, value) {
  if (kind === "portal_redirect") {
    let uri;
    try {
      uri = typeof value === "string" ? new URL(value) : null;
    } catch {
      uri = null;
    }
    if (
      !uri ||
      new TextEncoder().encode(value).length > 2048 ||
      /[\x00-\x1f\x7f-\x9f*]/.test(value) ||
      uri.protocol !== "https:" ||
      !uri.hostname ||
      uri.username ||
      uri.password ||
      value.includes("#")
    ) {
      throw new Error(
        "应用回调必须明确填写最多2048字节的精确 HTTPS URL，不含凭据、控制字符、片段或通配符。",
      );
    }
    return;
  }
  if (!["portal_subscription", "portal_credential"].includes(kind)) {
    return;
  }
  const identity = /^[A-Za-z0-9_.-]{1,64}$/;
  // 产品、版本与凭据不能从其它元素恢复；未明确选择 revoked 时不能默认为可用凭据。
  if (
    kind === "portal_subscription"
      ? typeof value?.product !== "string" ||
        !identity.test(value.product) ||
        typeof value?.version !== "string" ||
        !identity.test(value.version)
      : typeof value?.id !== "string" ||
        !identity.test(value.id) ||
        typeof value?.sha256 !== "string" ||
        !/^[a-f0-9]{64}$/.test(value.sha256) ||
        typeof value?.revoked !== "boolean"
  ) {
    throw new Error(
      "订阅须明确填写有效 product 与 version；凭据须明确填写有效 id、64位小写 sha256 和 revoked，不能填写明文 key。",
    );
  }
}
