import { authenticate, request, secureOrigin } from "./http.js";
import { element } from "./dom.js";
import { mount as monitor } from "../views/monitor.js";
import { mount as nodes } from "../views/nodes.js";
import { mount as catalog } from "../views/catalog.js";
import { mount as operations } from "../views/operations.js";
import { mount as routeTraffic } from "../views/routes.js";
import { mount as services } from "../views/services.js";

const root = document.getElementById("view");
const loginForm = document.getElementById("login");
const notice = document.getElementById("notice");
let session = null;
let dispose = null;
let epoch = 0;

/**
 * 业务作用：读取后端返回的实际动作位，不能通过角色名推测权限。
 * 参数说明：
 * - `resource`：页面对应的固定资源域。
 * - `action`：当前操作的风险动作。
 * 返回：后端明确授权时为true。
 */
function allowed(resource, action = "read") {
  return session?.permissions?.[resource]?.includes(action) === true;
}

/**
 * 业务作用：撤销旧视图并按当前能力挂载选择的页面。
 * 参数说明：
 * - `name`：导航中的固定页面标识。
 * - `service`：从当前集群目录选中的逻辑服务，其他页面忽略。
 * 返回：页面只在授权后读取业务数据。
 */
function navigate(name, service = "") {
  dispose?.();
  dispose = null;
  root.replaceChildren();
  for (const button of document.querySelectorAll("[data-view]")) {
    button.setAttribute(
      "aria-current",
      button.dataset.view === name ? "page" : "false",
    );
  }
  if (name === "operations") {
    document.getElementById("title").textContent = "变更提案";
    document.getElementById("subtitle").textContent =
      "共享集群候选 · 双人审阅与集群执行";
    dispose = operations(root, session);
  } else if (
    name === "traffic" &&
    ((allowed("cluster") && allowed("routes")) || session.workspaces?.length)
  ) {
    document.getElementById("title").textContent = "路由实时流量";
    document.getElementById("subtitle").textContent =
      "集群与工作区 · 当前区间、完整覆盖与流结束事实";
    dispose = routeTraffic(root, session);
  } else if (
    name === "services" &&
    ((allowed("cluster") && allowed("upstreams")) || session.workspaces?.length)
  ) {
    document.getElementById("title").textContent = "服务实时状态";
    document.getElementById("subtitle").textContent =
      "集群与工作区 · 当前实例事实与完整节点覆盖";
    dispose = services(root, session, service);
  } else if (name === "nodes" && allowed("cluster")) {
    document.getElementById("title").textContent = "集群节点";
    document.getElementById("subtitle").textContent =
      "当前成员、部署角色、配置与就绪状态";
    dispose = nodes(root);
  } else if (
    name === "catalog" &&
    allowed("cluster") &&
    ["routes", "config", "upstreams"].some((resource) => allowed(resource))
  ) {
    document.getElementById("title").textContent = "路由与入口";
    document.getElementById("subtitle").textContent =
      "集群对象分布 · 每个节点的实际配置目录";
    dispose = catalog(root, session.permissions, (id) =>
      navigate("services", id),
    );
  } else if (name === "monitor" && allowed("cluster")) {
    document.getElementById("title").textContent = "实时监控";
    document.getElementById("subtitle").textContent =
      "当前运行状态 · 无监控历史";
    dispose = monitor(root);
  } else {
    document.getElementById("title").textContent = "当前管理能力";
    document.getElementById("subtitle").textContent =
      "权限由服务器判定，页面仅展示已授予的操作";
    const panel = element("section", "", "panel");
    panel.append(element("h2", session?.principal ?? "未登录"));
    for (const [resource, actions] of Object.entries(
      session?.permissions ?? {},
    )) {
      const line = element("div", "", "state-row");
      line.append(
        element("span", resource),
        element("strong", actions.length ? actions.join(" / ") : "无权限"),
      );
      panel.append(line);
    }
    if (!allowed("cluster")) {
      panel.prepend(
        element(
          "p",
          "当前主体没有平台监控读取权限。获准的工作区可在路由实时流量页面独立查看；其它进程级指标仍需要平台权限。",
          "subtle",
        ),
      );
    }
    root.append(panel);
  }
}

/**
 * 业务作用：清除内存凭据和全部授权内容，旧响应不再具有回填权限。
 * 参数说明: 无。
 * 返回：恢复登录状态，不写入任何浏览器存储。
 */
function logout() {
  epoch += 1;
  authenticate("");
  dispose?.();
  dispose = null;
  session = null;
  root.replaceChildren();
  loginForm.reset();
  loginForm.hidden = false;
  document.getElementById("workspace").hidden = true;
  document.getElementById("principal").textContent = "未登录";
  document.getElementById("signout").hidden = true;
  document.getElementById("title").textContent = "Naway 管理台";
  document.getElementById("subtitle").textContent =
    "连接管理面，查看当前运行状态";
}

/**
 * 业务作用：在页面内存中建立Bearer或Basic会话，再读取真实权限合同。
 * 参数说明：
 * - `event`：登录表单提交事件。
 * 返回：认证成功后打开允许的页面，失败时保持登录表单且清除凭据。
 */
async function login(event) {
  event.preventDefault();
  if (!secureOrigin()) {
    notice.textContent = "远程管理需要 HTTPS；仅本机回环地址允许 HTTP。";
    return;
  }
  const mode = document.getElementById("auth-mode").value;
  const token = document.getElementById("token").value.trim();
  const user = document.getElementById("user").value;
  const password = document.getElementById("password").value;
  let credential = "";
  if (mode === "bearer" && token) {
    credential = `Bearer ${token}`;
  } else if (mode === "basic") {
    const bytes = new TextEncoder().encode(`${user}:${password}`);
    credential = `Basic ${btoa(Array.from(bytes, (value) => String.fromCharCode(value)).join(""))}`;
  }
  logout();
  const attempt = epoch;
  authenticate(credential);
  notice.textContent = "正在验证管理权限…";
  try {
    const { data } = await request("/api/session");
    if (attempt !== epoch) {
      return;
    }
    session = data;
    loginForm.hidden = true;
    document.getElementById("workspace").hidden = false;
    document.getElementById("principal").textContent =
      `${data.principal} · ${data.mode}`;
    document.getElementById("signout").hidden = false;
    document.getElementById("monitor-nav").disabled = !allowed("cluster");
    document.getElementById("traffic-nav").disabled = !(
      (allowed("cluster") && allowed("routes")) ||
      session.workspaces?.length
    );
    document.getElementById("nodes-nav").disabled = !allowed("cluster");
    document.getElementById("services-nav").disabled = !(
      (allowed("cluster") && allowed("upstreams")) ||
      session.workspaces?.length
    );
    document.getElementById("catalog-nav").disabled =
      !allowed("cluster") ||
      !["routes", "config", "upstreams"].some((resource) => allowed(resource));
    notice.textContent = "";
    navigate(
      location.pathname === "/services" &&
        !document.getElementById("services-nav").disabled
        ? "services"
        : location.pathname === "/traffic" &&
            !document.getElementById("traffic-nav").disabled
          ? "traffic"
          : location.pathname === "/operations"
            ? "operations"
            : allowed("cluster")
              ? location.pathname === "/catalog" &&
                !document.getElementById("catalog-nav").disabled
                ? "catalog"
                : location.pathname === "/cluster"
                  ? "nodes"
                  : "monitor"
              : "system",
    );
  } catch (error) {
    if (attempt === epoch && error.name !== "AbortError") {
      logout();
      notice.textContent = error.message;
    }
  }
}

/**
 * 业务作用：按认证方式切换输入栏，隐藏栏中的凭据及时清空。
 * 参数说明: 无。
 * 返回：只保留当前选择的输入方式，不改变已登录主体。
 */
function authModeChanged() {
  const basic = document.getElementById("auth-mode").value === "basic";
  document.getElementById("bearer-fields").hidden = basic;
  document.getElementById("basic-fields").hidden = !basic;
  for (const id of ["token", "user", "password"]) {
    document.getElementById(id).value = "";
  }
}

/**
 * 业务作用：将固定导航事件路由到当前授权页面。
 * 参数说明：
 * - `event`：导航按钮点击。
 * 返回：切换视图并取消旧页请求。
 */
function navigation(event) {
  const button = event.target.closest("button[data-view]");
  if (button && session && !button.disabled) {
    navigate(button.dataset.view);
  }
}

/**
 * 业务作用：认证失效后清除已显示的敏感管理信息。
 * 参数说明: 无。
 * 返回：退出当前主体并给出重新认证提示。
 */
function unauthorized() {
  logout();
  notice.textContent = "认证已失效，请重新登录。";
}

loginForm.addEventListener("submit", login);
document
  .getElementById("auth-mode")
  .addEventListener("change", authModeChanged);
document.getElementById("signout").addEventListener("click", logout);
document.getElementById("navigation").addEventListener("click", navigation);
window.addEventListener("naway:unauthorized", unauthorized);
window.addEventListener("pagehide", logout);
