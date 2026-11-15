import { element } from "../../../core/dom.js";
import { fieldRow } from "./controls.js";

const portalOidcClientDefinitions = [
  ["client_id", "客户端身份（不超过512字节）", ["client_id"]],
  ["client_secret", "客户端凭据 SecretSource 原文", ["client_secret"]],
  ["client_auth", "客户端认证方式（basic / post 及原生别名）", ["client_auth"]],
  [
    "ca_certificate",
    "身份服务 CA 的 SecretSource 原文",
    ["ca_certificate", "ca_pem", "ca_file"],
  ],
];

/**
 * 业务作用：定位客户端参数的唯一原始 token，将 CA 别名视为同一声明而不选择重复来源。
 * 参数说明：
 * - `source`：既有 OIDC filter 原文，不读取其中的材料或秘密引用。
 * 返回：可精确定位的客户端参数；协议不符、token 残缺或同义参数重复时返回 null，须整值编辑。
 */
function parsePortalOidcClientSource(source) {
  if (typeof source !== "string" || !source.startsWith("oidc_rp ")) {
    return null;
  }
  const tokens = [...source.matchAll(/[^\p{White_Space}]+/gu)];
  const clients = new Map();
  for (const token of tokens.slice(1)) {
    const separator = token[0].indexOf("=");
    if (separator <= 0) {
      return null;
    }
    const key = token[0].slice(0, separator);
    const definition = portalOidcClientDefinitions.find(([, , aliases]) =>
      aliases.includes(key),
    );
    if (!definition) {
      continue;
    }
    // 原生解析具有顺序含义；重复或同义来源必须由使用者明确处理，不能由子项选取权威。
    if (clients.has(definition[0])) {
      return null;
    }
    clients.set(definition[0], {
      start: token.index,
      end: token.index + token[0].length,
      key,
      raw: token[0].slice(separator + 1),
    });
  }
  return clients;
}

/**
 * 业务作用：约束显式客户端参数为单个原生 token，避免空白注入其它选项或无效认证方式。
 * 参数说明：
 * - `key`：客户端参数的规范业务键。
 * - `value`：使用者明确填写的原文字面值，秘密和 CA 引用不求值。
 * 返回：可写入的原文；空值、分隔符注入、超长身份或不受支持的认证方式抛错，不生成部分候选。
 */
function validatePortalOidcClientValue(key, value) {
  if (!value || /[\p{White_Space}\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(
      `OIDC 客户端 ${key} 需要非空的单个原生 token，不能包含空白或控制字符。`,
    );
  }
  const literal =
    value.length >= 2 &&
    ["'", '"'].includes(value[0]) &&
    value.at(-1) === value[0]
      ? value.slice(1, -1)
      : value;
  if (
    !literal ||
    (key === "client_id" && new TextEncoder().encode(literal).length > 512)
  ) {
    throw new Error(
      "OIDC 客户端身份必须非空且不超过512字节；其它参数也须有明确值。",
    );
  }
  if (
    key === "client_auth" &&
    ![
      "basic",
      "secret_basic",
      "client_secret_basic",
      "post",
      "secret_post",
      "client_secret_post",
    ].includes(literal.toLowerCase())
  ) {
    throw new Error("OIDC 客户端认证方式需要 basic / post 或对应的原生别名。");
  }
  return value;
}

/**
 * 业务作用：仅替换、移除或明确追加所选客户端参数，保持 CA 别名、其它 token 与原空白。
 * 参数说明：
 * - `source`：冻结的原始 filter。
 * - `tokens`：同一原文中定位的唯一客户端参数。
 * - `actions`：明确选择的设置或移除动作。
 * - `capacity`：当前候选字节容量，用于拒绝超长声明。
 * 返回：只包含本次客户端参数动作的新 filter；非法输入或超容量时抛错，不发布部分结果。
 */
function applyPortalOidcClientActions(source, tokens, actions, capacity) {
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
    const value = `${existing?.key ?? action.key}=${validatePortalOidcClientValue(action.key, action.value)}`;
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
    // 以原始尾空白定位新增区间，删除末 token 也不能改变其它分隔空白的相对位置。
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
    throw new Error("OIDC 客户端声明超过当前候选容量。");
  }
  return result;
}

/**
 * 业务作用：为既有门户 OIDC 策略提供客户端声明控件，不读取秘密或改变未选中的认证参数。
 * 参数说明：
 * - `kind`：冻结对象类别，只接受门户管理声明。
 * - `values`：服务端无求值返回的原始对象，只用于展示和定位。
 * - `capacity`：候选字节上限。
 * 返回：四个客户端控件及单个 filter 动作读取器；其它协议不提供控件，歧义原文只展示说明。
 */
export function portalOidcClientFields(kind, values, capacity) {
  if (kind !== "portal_management" || values.sso?.type !== "oidc") {
    return null;
  }
  const source = values.sso.filter;
  const tokens = parsePortalOidcClientSource(source);
  const node = element("details", "", "draft-oidc-client");
  node.append(element("summary", "OIDC 客户端与 CA 声明"));
  node.append(
    element(
      "p",
      tokens
        ? "只编辑明确选择的客户端身份、凭据、认证方式与 CA 来源，不读取材料、不连接身份服务、不补默认值。已有 CA 别名保持原名；移除 CA 会使用原生系统信任，移除必需身份或凭据将使原目标预检拒绝。不能同次编辑整段 SSO、filter 或另一组 filter 参数，全部声明仍须原目标完整预检与审批执行。"
        : "当前 filter 不是可定位的显式 oidc_rp 声明，或含残缺 token、重复客户端参数或 CA 别名。请明确编辑整段 filter；子项不会选取重复来源。",
      "subtle",
    ),
  );
  const rows = new Map();
  if (tokens) {
    for (const [name, title] of portalOidcClientDefinitions) {
      const row = fieldRow(
        `OIDC客户端 → ${name}`,
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
   * 业务作用：从明确选择构造单个客户端 filter 动作，使未选中的展示原文保持原样。
   * 参数说明: 无。
   * 返回：无选择时为空；合法选择仅设置 sso.filter，非法 token 或容量不足时拒绝整次动作。
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
        value: applyPortalOidcClientActions(source, tokens, actions, capacity),
      },
    ];
  }
  return {
    node,
    read,
  };
}
