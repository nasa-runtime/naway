import { element } from "../../../core/dom.js";
import { fieldRow } from "./controls.js";

const portalOidcBudgetDefinitions = [
  ["timeout_ms", "身份服务请求期限（毫秒，1–60000）", 1, 60000],
  ["session_ttl_secs", "OIDC 会话最长寿命（秒，60–86400）", 60, 86400],
  ["pending_ttl_secs", "登录事务最长寿命（秒，30–900）", 30, 900],
  ["max_pending", "待完成登录事务容量（1–10000）", 1, 10000],
  ["max_sessions", "OIDC 会话容量（1–1000000）", 1, 1000000],
];

/**
 * 业务作用：在不求值的原始 OIDC 声明中定位预算参数，保留其它 token 和原空白。
 * 参数说明：
 * - `source`：既有 filter 字符串，不读取其中的秘密或变量引用。
 * 返回：唯一预算参数的原始区间；非显式 OIDC、残缺 token 或重复预算返回 null，须使用整值编辑。
 */
function parsePortalOidcBudgetSource(source) {
  if (typeof source !== "string" || !source.startsWith("oidc_rp ")) {
    return null;
  }
  const tokens = [...source.matchAll(/[^\p{White_Space}]+/gu)];
  if (tokens[0]?.[0] !== "oidc_rp") {
    return null;
  }
  const budgets = new Map();
  for (const token of tokens.slice(1)) {
    const separator = token[0].indexOf("=");
    if (separator <= 0) {
      return null;
    }
    const key = token[0].slice(0, separator);
    if (!portalOidcBudgetDefinitions.some(([name]) => name === key)) {
      continue;
    }
    // 同名预算在原生解析中具有顺序含义，子项编辑不能擅自合并或选择其中一次声明。
    if (budgets.has(key)) {
      return null;
    }
    budgets.set(key, {
      start: token.index,
      end: token.index + token[0].length,
      raw: token[0].slice(separator + 1),
    });
  }
  return budgets;
}

/**
 * 业务作用：只替换明确选择的预算 token，保持端点、凭据引用、未知参数及其原文不变。
 * 参数说明：
 * - `source`：冻结的既有 filter 原文。
 * - `tokens`：从同一原文定位的唯一预算区间。
 * - `actions`：控件明确设置或移除的预算动作。
 * - `capacity`：当前候选容量上限，用于拒绝过长的新声明。
 * 返回：只含本次预算变更的新 filter；非法整数、越界或容量不足时拒绝，不返回部分结果。
 */
function applyPortalOidcBudgetActions(source, tokens, actions, capacity) {
  const replacements = [];
  const additions = [];
  for (const action of actions) {
    const definition = portalOidcBudgetDefinitions.find(
      ([name]) => name === action.key,
    );
    if (!definition) {
      throw new Error("OIDC 预算参数不受支持。");
    }
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
    const literal = action.value.trim();
    const number = Number(literal);
    if (
      !/^[0-9]+$/.test(literal) ||
      !Number.isSafeInteger(number) ||
      number < definition[2] ||
      number > definition[3]
    ) {
      throw new Error(
        `OIDC 预算 ${action.key} 需要 ${definition[2]}–${definition[3]} 范围内的十进制整数。`,
      );
    }
    const value = `${action.key}=${number}`;
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
    // 新参数插在原始尾空白之前，移除末尾 token 不应改变其它分隔空白与新增参数的相对位置。
    const trailing = source.match(/\p{White_Space}*$/u)[0];
    const end = source.length - trailing.length;
    replacements.push({
      start: end,
      end,
      value: " " + additions.join(" "),
    });
  }
  let result = source;
  // 从原文尾部替换区间，前面 token 的位置不受其它显式修改影响。
  for (const replacement of replacements.sort(
    (left, right) => right.start - left.start,
  )) {
    result =
      result.slice(0, replacement.start) +
      replacement.value +
      result.slice(replacement.end);
  }
  if (new TextEncoder().encode(result).length > capacity) {
    throw new Error("OIDC 预算声明超过当前候选容量。");
  }
  return result;
}

/**
 * 业务作用：为既有门户 OIDC 策略提供独立预算控件，避免为调整容量重写整段认证声明。
 * 参数说明：
 * - `kind`：冻结的草稿对象类别，仅接受门户管理设置。
 * - `values`：服务端无求值返回的原始对象，不作为完整子树输出。
 * - `capacity`：当前候选字节上限。
 * 返回：预算控件及单个 sso.filter 路径动作读取器；其它对象或协议返回 null，无法定位的原文只展示说明。
 */
export function portalOidcBudgetFields(kind, values, capacity) {
  if (kind !== "portal_management" || values.sso?.type !== "oidc") {
    return null;
  }
  const source = values.sso.filter;
  const tokens = parsePortalOidcBudgetSource(source);
  const node = element("details", "", "draft-oidc-budget");
  node.append(element("summary", "OIDC 登录预算参数"));
  if (!tokens) {
    node.append(
      element(
        "p",
        "当前 filter 不是可定位的显式 oidc_rp 声明，或含残缺 token、重复预算参数。请明确编辑整段 filter；预算子项不会猜测协议或参数优先级。",
        "subtle",
      ),
    );
  } else {
    node.append(
      element(
        "p",
        "只改变明确选择的五个预算参数，未编辑的端点、秘密引用、其它 token 和原空白保持原文。这里不读取材料、不连接身份服务、不补默认值。设置须使用十进制整数；移除参数恢复原生缺省语义。不能同次编辑整段 SSO 或 filter；有效会话预算仍受门户管理预算和 token 剩余有效期约束，全部声明须原目标完整预检。",
        "subtle",
      ),
    );
  }
  const rows = new Map();
  if (tokens) {
    for (const [name, title] of portalOidcBudgetDefinitions) {
      const row = fieldRow(
        `OIDC预算 → ${name}`,
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
   * 业务作用：从本次显式选择构造唯一 filter 字符串动作，不让展示值重写未选参数。
   * 参数说明: 无。
   * 返回：无选择时为空；有选择时仅设置 sso.filter，非法预算在构造动作前拒绝。
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
        value: applyPortalOidcBudgetActions(source, tokens, actions, capacity),
      },
    ];
  }
  return {
    node,
    read,
  };
}
