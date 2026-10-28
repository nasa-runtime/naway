"use strict";

const catalogsNode = document.getElementById("catalogs");
const catalogStatus = document.getElementById("catalog-status");
const catalogSelect = document.getElementById("catalog-id");
const form = document.getElementById("application-form");
const result = document.getElementById("application-result");

/**
 * 业务作用：只用文本节点渲染合同和身份数据，避免配置中的 HTML 被执行。
 *
 * 参数说明：
 * - `parent`：本地已创建的父容器。
 * - `tag`：固定元素类型。
 * - `text`：不可信数据，只按文本显示。
 * - `className`：本地预定义样式名。
 *
 * 返回：新文本元素，不解析 HTML。
 */
function appendText(parent, tag, text, className) {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) {
    node.className = className;
  }
  parent.appendChild(node);
  return node;
}

/**
 * 业务作用：限制文档导航为当前站点固定目录，拒绝外部、脚本和协议相对地址。
 *
 * 参数说明：
 * - `parent`：本地文档卡片容器。
 * - `text`：链接展示文本。
 * - `path`：服务端目录投影的同源文档地址。
 *
 * 返回：仅合法路径产生链接，否则不提供导航。
 */
function documentLink(parent, text, path) {
  if (
    typeof path !== "string" ||
    !/^\/api\/developer\/(?:catalogs|products|account\/products)\/[A-Za-z0-9/_-]+$/.test(
      path,
    )
  ) {
    return;
  }
  appendText(parent, "a", text).href = path;
}

/**
 * 业务作用：读取同源低敏 JSON，不在后台 fetch 中跟随 SSO 到身份站点。
 *
 * 参数说明：
 * - `path`：页面固定的同源低敏 API 路径。
 *
 * 返回：成功且大小受限的 JSON；登录、依赖或协议失败抛出固定状态错误。
 */
async function readJson(path) {
  const response = await fetch(path, {
    credentials: "same-origin",

    redirect: "error",

    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`请求未完成：${response.status}`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let text = "",
    total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > 4 * 1024 * 1024) {
        throw new Error("响应超出展示容量");
      }
      text += decoder.decode(value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } finally {
    await reader.cancel();
  }
}

/**
 * 业务作用：加载兼容 catalog，文档只通过固定同源路径公开。
 *
 * 参数说明: 无。
 *
 * 返回：更新目录和申请选择项；失败交给状态栏显示。
 */
async function loadCatalogs() {
  const body = await readJson("/api/developer/catalogs");
  for (const catalog of body.catalogs || []) {
    const card = document.createElement("article");
    card.className = "catalog";
    appendText(card, "h3", catalog.title || catalog.id);
    appendText(card, "p", catalog.description || "No description");
    documentLink(card, "OpenAPI document", catalog.openapi_url);
    for (const operation of catalog.operations || []) {
      const row = document.createElement("div");
      row.className = "operation";
      appendText(row, "span", operation.method, "method");
      appendText(
        row,
        "span",
        `${operation.path}${operation.summary ? ` — ${operation.summary}` : ""}`,
      );
      card.appendChild(row);
    }
    catalogsNode.appendChild(card);
    const option = document.createElement("option");
    option.value = catalog.id;
    option.textContent = catalog.title || catalog.id;
    catalogSelect.appendChild(option);
  }
  catalogStatus.textContent = `${(body.catalogs || []).length} 个 catalog`;
}

/** 业务作用：展示同一权限域的产品版本、生命周期和保守兼容差异，不执行 Markdown 或 spec。
 * 参数说明：privateScope 表示已完成当前门户会话验证。
 * 返回：替换产品卡片；权限不成立时不保留旧团队数据。
 */
let productEpoch = 0;
/**
 * 业务作用：按公开或已认证账户范围载入产品文档，迟到响应不得恢复旧身份可见内容。
 *
 * 参数说明：
 * - `privateScope`：是否使用当前已认证账户的可见产品范围。
 *
 * 返回：仅当前产品代际与账户代际仍匹配时更新可见目录。
 */
async function loadProducts(privateScope = false) {
  const epoch = ++productEpoch,
    account = accountEpoch;
  const node = document.getElementById("products");
  node.replaceChildren();
  const body = await readJson(
    privateScope
      ? "/api/developer/account/products"
      : "/api/developer/products",
  );
  if (epoch !== productEpoch || (privateScope && account !== accountEpoch)) {
    return;
  }
  for (const product of body.products || []) {
    const card = appendText(node, "article", "", "catalog");
    appendText(card, "h3", product.title || product.id);
    appendText(card, "p", product.description || "");
    for (const version of product.versions || []) {
      appendText(
        card,
        "h4",
        `${version.id} · ${version.lifecycle} · ${version.visibility}`,
      );
      if (version.deprecated_at) {
        appendText(card, "p", `弃用时间：${version.deprecated_at}`);
      }
      for (const doc of version.documents || []) {
        documentLink(
          appendText(card, "p", ""),
          `${doc.id} · ${doc.format}`,
          doc.url,
        );
      }
      if (version.compatibility_diff) {
        appendText(
          card,
          "pre",
          JSON.stringify(version.compatibility_diff, null, 2),
        );
      }
    }
  }
  document.getElementById("products-status").textContent =
    `${(body.products || []).length} 个可见产品`;
}

let exportCursor = null;
let accountEpoch = 0;
/**
 * 业务作用：刷新会话范围内的应用、套餐和凭据状态，刷新前清除旧授权读面。
 *
 * 参数说明: 无。
 *
 * 返回：只有当前请求完成且身份有效时显示数据；从不把凭据原文保存到浏览器存储。
 */
async function loadAccount() {
  const epoch = ++accountEpoch;
  const node = document.getElementById("applications");
  node.replaceChildren();
  document.getElementById("usage").textContent = "";
  document.getElementById("usage-export").textContent = "";
  exportCursor = null;
  document.getElementById("next-usage").hidden = true;
  try {
    const account = await readJson("/api/developer/account");
    if (epoch !== accountEpoch) {
      return;
    }
    document.getElementById("account-status").textContent = Object.entries(
      account.roles || {},
    )
      .map(([team, role]) => `${team}: ${role}`)
      .join(" · ");
    for (const app of account.applications || []) {
      const card = appendText(node, "article", "", "catalog");
      appendText(card, "h3", app.title || app.id);
      appendText(card, "p", `${app.team} · ${app.state} · ${app.plan}`);
      if (app.quota) {
        appendText(
          card,
          "p",
          `套餐 ${app.quota.requests} 次 / ${app.quota.window_ms} ms；突发 ${app.quota.burst}；实时余量需由限额后端裁决`,
        );
      }
      for (const key of app.credentials || []) {
        appendText(card, "p", `${key.id}: ${key.revoked ? "已撤销" : "有效"}`);
      }
      for (const sub of app.subscriptions || []) {
        appendText(card, "p", `订阅 ${sub.product} / ${sub.version}`);
      }
    }
    await loadProducts(true);
    try {
      const data = await readJson("/api/developer/account/usage");
      if (epoch === accountEpoch) {
        document.getElementById("usage").textContent = JSON.stringify(
          data.usage,
          null,
          2,
        );
      }
    } catch {
      document.getElementById("usage").textContent =
        "持久用量源未启用或暂不可用，不能据此推断零用量。";
    }
  } catch {
    if (epoch !== accountEpoch) {
      return;
    }
    node.replaceChildren();
    document.getElementById("usage").textContent = "";
    document.getElementById("account-status").textContent =
      "会话不可用，请通过企业 SSO 登录。";
    await loadProducts(false).catch(() => {});
  }
}

/**
 * 业务作用：按当前 owner 权限读取有界结算页，不自动遍历整个账本。
 *
 * 参数说明：
 * - `next`：是否沿服务端返回的游标读取下一页。
 *
 * 返回：展示当前页并更新分页按钮；错误清除旧结果和游标。
 */
async function exportUsage(next = false) {
  const node = document.getElementById("usage-export"),
    epoch = accountEpoch;
  node.textContent = "正在读取…";
  try {
    const body = await readJson(
      `/api/developer/account/usage/export${next && exportCursor ? `?cursor=${encodeURIComponent(exportCursor)}` : ""}`,
    );
    if (epoch !== accountEpoch) {
      return;
    }
    exportCursor = body.usage.next_cursor;
    node.textContent = JSON.stringify(body.usage, null, 2);
  } catch {
    if (epoch !== accountEpoch) {
      return;
    }
    exportCursor = null;
    node.textContent = "无权读取或计量源不可用。";
  }
  document.getElementById("next-usage").hidden = !exportCursor;
}

document.getElementById("refresh-account").addEventListener("click", () => {
  void loadAccount();
});
document.getElementById("export-usage").addEventListener("click", () => {
  void exportUsage();
});
document.getElementById("next-usage").addEventListener("click", () => {
  void exportUsage(true);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  result.textContent = "正在提交…";
  const requestedPlan = document.getElementById("requested-plan").value.trim();
  const payload = {
    catalog_id: catalogSelect.value,

    applicant_id: document.getElementById("applicant-id").value.trim(),

    display_name: document.getElementById("display-name").value.trim(),
  };
  if (requestedPlan) {
    payload.requested_plan = requestedPlan;
  }
  try {
    const response = await fetch("/api/developer/key-applications", {
      method: "POST",

      credentials: "same-origin",

      headers: {
        "content-type": "application/json",

        authorization: `Bearer ${document.getElementById("portal-token").value}`,
      },

      body: JSON.stringify(payload),
    });
    const body = await response.json();
    result.textContent = JSON.stringify(body, null, 2);
  } catch (error) {
    result.textContent = String(error);
  }
});

loadCatalogs().catch((error) => {
  catalogStatus.textContent = String(error);
});
loadProducts().catch(() => {
  document.getElementById("products-status").textContent = "产品目录暂不可用。";
});
void loadAccount();
