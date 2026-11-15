import { element } from "../../../core/dom.js";
import { fieldRow } from "./controls.js";

const portalOidcEndpointDefinitions = [
  ["issuer", "固定 HTTPS 身份签发者", ["issuer"]],
  [
    "discovery_url",
    "固定 HTTPS discovery 地址",
    ["discovery_url", "oidc_discovery"],
  ],
  [
    "authorization_endpoint",
    "固定 HTTPS 授权地址",
    ["authorization_endpoint", "authorize_url"],
  ],
  ["token_endpoint", "固定 HTTPS token 地址", ["token_endpoint", "token_url"]],
  [
    "userinfo_endpoint",
    "可选 HTTPS userinfo 地址",
    ["userinfo_endpoint", "userinfo_url"],
  ],
  [
    "introspection_endpoint",
    "可选 HTTPS introspection 地址",
    ["introspection_endpoint", "introspection_url"],
  ],
  ["redirect_uri", "已批准 HTTPS origin 的门户回调 URI", ["redirect_uri"]],
  ["post_logout_uri", "退出后的有界本地 URI", ["post_logout_uri"]],
  ["scope", "包含 openid 的逗号分隔 scope", ["scope", "scopes"]],
  ["algorithm", "固定 ID token 算法 RS256 / ES256", ["algorithm", "alg"]],
  [
    "identity_headers",
    "已验证 claim 到业务头的映射 claim:Header",
    ["identity_headers", "claim_headers"],
  ],
];

/**
 * 业务作用：定位唯一端点声明的原始 token，并将同义参数归于同一业务键而不决定重复来源的优先级。
 * 参数说明：
 * - `source`：既有 OIDC filter 原文，不展开引用或访问身份服务。
 * 返回：唯一 token 的原文区间；协议不符、残缺 token 或同义重复时返回 null，须整值编辑。
 */
function parsePortalOidcEndpointSource(source) {
  if (typeof source !== "string" || !source.startsWith("oidc_rp ")) {
    return null;
  }
  const result = new Map();
  for (const token of [...source.matchAll(/[^\p{White_Space}]+/gu)].slice(1)) {
    const separator = token[0].indexOf("=");
    if (separator <= 0) {
      return null;
    }
    const key = token[0].slice(0, separator);
    const definition = portalOidcEndpointDefinitions.find(([, , aliases]) =>
      aliases.includes(key),
    );
    if (!definition) {
      continue;
    }
    // 子项不能替使用者选择重复的信任锚点，否则展示值与原生解析结果可能属于不同来源。
    if (result.has(definition[0])) {
      return null;
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
 * 业务作用：拒绝声明分隔符注入和已知不安全的登录选项，保持输入原文供原目标执行完整 URI 与信任校验。
 * 参数说明：
 * - `key`：规范业务键。
 * - `value`：明确填写的单个原生 token，不读取引用。
 * 返回：符合单 token 与本地选项边界的原文；非法输入抛错，不生成部分候选。
 */
function validatePortalOidcEndpointValue(key, value) {
  if (!value || /[\p{White_Space}\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(
      "OIDC 端点声明需要非空的单个原生 token，不能包含空白或控制字符。",
    );
  }
  const literal =
    value.length >= 2 &&
    ["'", '"'].includes(value[0]) &&
    value.at(-1) === value[0]
      ? value.slice(1, -1)
      : value;
  if (!literal) {
    throw new Error("OIDC 端点声明需要明确的非空值。");
  }
  if (
    key === "algorithm" &&
    !["RS256", "ES256"].includes(literal.toUpperCase())
  ) {
    throw new Error("OIDC ID token 算法仅支持 RS256 / ES256。");
  }
  if (key === "scope") {
    const scope = literal.replaceAll(",", " ");
    const scopes = new Set(scope.split(/\p{White_Space}+/u).filter(Boolean));
    if (
      !scopes.has("openid") ||
      scopes.size > 32 ||
      new TextEncoder().encode(scope).length > 1024
    ) {
      throw new Error("OIDC scope 须包含 openid，最多32项且不超过1024字节。");
    }
  }
  // 浏览器会重新解释反斜线；保持编码的路径只交给原生 URI 校验，不能先解码再拼接跳转。
  if (
    key === "post_logout_uri" &&
    (!literal.startsWith("/") ||
      literal.startsWith("//") ||
      literal.includes("\\") ||
      new TextEncoder().encode(literal).length > 8192)
  ) {
    throw new Error("OIDC 退出返回值须为不含原始反斜线的有界本地 URI。");
  }
  if (key === "identity_headers") {
    const mappings = literal.split(",");
    const headers = new Set();
    if (mappings.length > 16) {
      throw new Error("OIDC 身份头映射须为1至16项。");
    }
    for (const mapping of mappings) {
      const [claim, header, extra] = mapping.split(":");
      const normalized = header?.toLowerCase();
      if (
        !/^[A-Za-z0-9_.-]{1,64}$/.test(claim) ||
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
          "OIDC 身份头需要唯一的普通业务头及合法 claim，不能覆盖凭据、路由或 framing 头。",
        );
      }
      headers.add(normalized);
    }
  }
  return value;
}

/**
 * 业务作用：对所选声明实施精确 token 编辑，保持既有别名、固定门户身份和所有其它原文。
 * 参数说明：
 * - `source`：冻结的 filter 原文。
 * - `tokens`：同一原文的唯一声明区间。
 * - `actions`：明确选择的设置或移除动作。
 * - `capacity`：候选字节容量。
 * 返回：完整新 filter；非法动作或超容量抛错，未选中的 token 与分隔空白保持原样。
 */
function applyPortalOidcEndpointActions(source, tokens, actions, capacity) {
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
    const value = `${existing?.key ?? action.key}=${validatePortalOidcEndpointValue(action.key, action.value)}`;
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
    throw new Error("OIDC 端点声明超过当前候选容量。");
  }
  return result;
}

/**
 * 业务作用：为既有门户 OIDC 策略提供独立端点与登录声明入口，不自动生成默认值或联动信任配置。
 * 参数说明：
 * - `kind`：冻结对象类别，只接受门户管理声明。
 * - `values`：服务端无求值返回的展示投影。
 * - `capacity`：候选字节上限。
 * 返回：十一类声明的控件和单个 filter 动作读取器；其它协议无控件，歧义原文仅提示整值编辑。
 */
export function portalOidcEndpointFields(kind, values, capacity) {
  if (kind !== "portal_management" || values.sso?.type !== "oidc") {
    return null;
  }
  const source = values.sso.filter;
  const tokens = parsePortalOidcEndpointSource(source);
  const node = element("details", "", "draft-oidc-endpoints");
  node.append(element("summary", "OIDC 端点与登录声明"));
  node.append(
    element(
      "p",
      tokens
        ? "只改变明确选择的原文 token，保持已有别名，不连接 IdP、不读取秘密、不补默认值。HTTPS URI、全部 IdP 端点与 issuer 同 authority、批准的 redirect origin 等合同仍由原目标完整预检与审批执行校验。移除必需参数会被拒绝；不能同次编辑整段 SSO、filter 或另一组 filter 参数。"
        : "当前 filter 不是可定位的显式 oidc_rp 声明，或含残缺 token、重复端点或同义参数。请明确编辑整段 filter；子项不会选取重复来源。",
      "subtle",
    ),
  );
  node.append(
    element(
      "p",
      "门户固定 callback_path=/api/developer/account/callback、logout_path=/api/developer/account/logout、cookie_name=naway_portal_oidc。redirect_uri 须使用该 callback 和已批准的 HTTPS origin；这里不提供改变这三个固定身份的子项，也不自动补入缺失声明。",
      "subtle",
    ),
  );
  const rows = new Map();
  if (tokens) {
    for (const [name, title] of portalOidcEndpointDefinitions) {
      const row = fieldRow(
        `OIDC端点 → ${name}`,
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
   * 业务作用：仅将明确选择的端点与登录参数转成同一条 filter 动作，让祖先和同路径冲突统一拒绝。
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
        value: applyPortalOidcEndpointActions(
          source,
          tokens,
          actions,
          capacity,
        ),
      },
    ];
  }
  return {
    node,
    read,
  };
}
