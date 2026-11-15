import { element } from "../../../core/dom.js";
import { fieldRow } from "./controls.js";

const portalSamlDefinitions = [
  ["metadata", "已签名 IdP metadata 文件源原文"],
  ["metadata_signing_cert", "metadata 签名证书 SecretSource 原文"],
  ["idp_entity_id", "固定 IdP entity 身份"],
  ["sp_entity_id", "固定 SP entity 身份"],
  ["acs", "已批准 HTTPS origin 的门户 ACS"],
  ["max_assertion_bytes", "断言字节上限（1024–1048576）"],
  ["clock_skew_secs", "双向时钟容差（秒，0–3600）"],
  ["replay_ttl_secs", "已消费断言保留期限（秒，1–86400）"],
  ["identity_headers", "已签名属性到业务头的映射 attribute:Header"],
];

/**
 * 业务作用：定位唯一 SAML 声明的原始 token，任何重复参数均保持原生拒绝语义。
 * 参数说明：
 * - `source`：既有 SAML filter 原文，不展开引用或访问身份服务。
 * 返回：唯一 token 的原文区间；协议不符、残缺 token 或重复参数时返回 null，须整值编辑。
 */
function parsePortalSamlSource(source) {
  if (typeof source !== "string" || !source.startsWith("saml_auth ")) {
    return null;
  }
  const result = new Map();
  const seen = new Set();
  for (const token of [...source.matchAll(/[^\p{White_Space}]+/gu)].slice(1)) {
    const separator = token[0].indexOf("=");
    if (separator <= 0) {
      return null;
    }
    const key = token[0].slice(0, separator);
    const raw = token[0].slice(separator + 1);
    // 原生 SAML 拒绝任何重复键或空值；子项不能在非法原文中选取信任来源或补入默认值。
    if (seen.has(key) || !raw.replace(/^['"]+|['"]+$/g, "")) {
      return null;
    }
    seen.add(key);
    const definition = portalSamlDefinitions.find(([name]) => name === key);
    if (!definition) {
      continue;
    }
    result.set(definition[0], {
      start: token.index,
      end: token.index + token[0].length,
      key,
      raw: token[0].slice(separator + 1),
    });
  }
  return result;
}

/**
 * 业务作用：拒绝单 token 注入、无界断言预算和敏感身份头，保持文件源与信任身份原文供原目标验证。
 * 参数说明：
 * - `key`：SAML 声明的规范业务键。
 * - `value`：明确填写的原文，不读取 metadata 或签名材料。
 * 返回：符合原文与本地选项边界的值；非法输入抛错，不生成部分候选。
 */
function validatePortalSamlValue(key, value) {
  if (!value || /[\p{White_Space}\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(
      "SAML 声明需要非空单个原生 token，不能包含空白或控制字符。",
    );
  }
  const literal = value.replace(/^['"]+|['"]+$/g, "");
  if (!literal) {
    throw new Error("SAML 声明需要明确的非空值。");
  }
  const bounds = {
    max_assertion_bytes: [1024, 1048576],
    clock_skew_secs: [0, 3600],
    replay_ttl_secs: [1, 86400],
  };
  if (Object.hasOwn(bounds, key)) {
    const [minimum, maximum] = bounds[key];
    const number = Number(literal);
    if (
      !/^[0-9]+$/.test(literal) ||
      !Number.isSafeInteger(number) ||
      number < minimum ||
      number > maximum
    ) {
      throw new Error(
        "SAML " +
          key +
          " 需要 " +
          minimum +
          "–" +
          maximum +
          " 范围内的十进制整数。",
      );
    }
  }
  if (
    key === "metadata" &&
    !["file://", "k8s-file://", "vault-agent://"].some(
      (prefix) => literal.startsWith(prefix) && literal.length > prefix.length,
    )
  ) {
    throw new Error(
      "SAML metadata 须为 file / k8s-file / vault-agent 文件源原文。",
    );
  }
  if (key === "identity_headers") {
    const mappings = literal.split(",");
    const headers = new Set();
    if (mappings.length > 16) {
      throw new Error("SAML 身份头映射最多16项。");
    }
    for (const mapping of mappings) {
      const [attribute, header, extra] = mapping.split(":");
      const normalized = header?.toLowerCase();
      if (
        !attribute ||
        new TextEncoder().encode(attribute).length > 128 ||
        !header ||
        !/^[!#$%&'*+.^_`|~A-Za-z0-9-]+$/.test(header) ||
        extra !== undefined ||
        headers.has(normalized) ||
        [
          "authorization",
          "proxy-authorization",
          "cookie",
          "host",
          "connection",
          "keep-alive",
          "proxy-connection",
          "transfer-encoding",
          "te",
          "trailer",
          "upgrade",
          "content-length",
        ].includes(normalized)
      ) {
        throw new Error(
          "SAML 身份头需要有界属性名和唯一普通业务头，不能覆盖凭据、路由或 framing 头。",
        );
      }
      headers.add(normalized);
    }
  }
  return value;
}

/**
 * 业务作用：对所选声明实施精确 token 编辑，保持固定门户输入与未选中的所有原文。
 * 参数说明：
 * - `source`：冻结的 filter 原文。
 * - `tokens`：同一原文的唯一声明区间。
 * - `actions`：明确选择的设置或移除动作。
 * - `capacity`：候选字节容量。
 * 返回：完整新 filter；非法动作或超容量抛错，未选中的 token 与分隔空白保持原样。
 */
function applyPortalSamlActions(source, tokens, actions, capacity) {
  const replacements = [];
  const additions = [];
  for (const action of actions) {
    const existing = tokens.get(action.key);
    if (action.remove) {
      if (existing) {
        replacements.push({
          ...existing,
          value: "",
        });
      }
      continue;
    }
    const value = `${existing?.key ?? action.key}=${validatePortalSamlValue(action.key, action.value)}`;
    if (existing) {
      replacements.push({
        ...existing,
        value,
      });
    } else {
      additions.push(value);
    }
  }
  if (additions.length) {
    const trailing = source.match(/\p{White_Space}*$/u)[0];
    const end = source.length - trailing.length;
    replacements.push({
      start: end,
      end,
      value: " " + additions.join(" "),
    });
  }
  let result = source;
  for (const replacement of replacements.sort(
    (left, right) => right.start - left.start,
  )) {
    result =
      result.slice(0, replacement.start) +
      replacement.value +
      result.slice(replacement.end);
  }
  if (new TextEncoder().encode(result).length > capacity) {
    throw new Error("SAML 身份声明超过当前候选容量。");
  }
  return result;
}

/**
 * 业务作用：为既有门户 SAML 策略提供独立身份与断言声明入口，不自动生成默认值或联动信任配置。
 * 参数说明：
 * - `kind`：冻结对象类别，只接受门户管理声明。
 * - `values`：服务端无求值返回的展示投影。
 * - `capacity`：候选字节上限。
 * 返回：九类声明的控件和单个 filter 动作读取器；其它协议无控件，歧义原文仅提示整值编辑。
 */
export function portalSamlFields(kind, values, capacity) {
  if (kind !== "portal_management" || values.sso?.type !== "saml") {
    return null;
  }
  const source = values.sso.filter;
  const tokens = parsePortalSamlSource(source);
  const node = element("details", "", "draft-saml");
  node.append(element("summary", "SAML 身份与断言声明"));
  node.append(
    element(
      "p",
      tokens
        ? "只改变明确选择的原文 token，不读取 metadata、证书或秘密，不补默认参数。metadata 须为 file / k8s-file / vault-agent 文件源；签名、entity 身份、ACS、预算及已签名属性合同仍须原目标完整预检与审批执行。移除必需信任或组映射会被拒绝，不能同次编辑整段 SSO 或 filter。"
        : "当前 filter 不是可定位的显式 saml_auth 声明，或含残缺、空值与重复参数。请明确编辑整段 filter；子项不会选取重复来源。",
      "subtle",
    ),
  );
  node.append(
    element(
      "p",
      "门户固定使用 HTTP-POST 输入：header 必须缺失，ACS 为 /api/developer/account/callback 且 HTTPS origin 已获批准。groups_header 必须由已签名属性映射拥有；这里不提供任意 header 输入切换，不自动补值或授予角色。",
      "subtle",
    ),
  );
  const rows = new Map();
  if (tokens) {
    for (const [name, title] of portalSamlDefinitions) {
      const row = fieldRow(
        `SAML声明 → ${name}`,
        title,
        "string",
        tokens.get(name)?.raw,
        capacity,
      );
      rows.set(name, row);
      node.append(row.node);
    }
  }

  /**
   * 业务作用：仅将明确选择的身份与断言参数转成同一条 filter 动作，让祖先和同路径冲突统一拒绝。
   * 参数说明: 无。
   * 返回：无选择时为空；合法选择只设置 sso.filter，非法值或容量不足时抛错。
   */
  function read() {
    const actions = [];
    for (const [key, row] of rows) {
      const action = row.read();
      if (action) {
        actions.push({
          key,
          ...action,
        });
      }
    }
    if (!actions.length) {
      return [];
    }
    return [
      {
        op: "set",
        path: ["sso", "filter"],
        value: applyPortalSamlActions(source, tokens, actions, capacity),
      },
    ];
  }
  return {
    node,
    read,
  };
}
