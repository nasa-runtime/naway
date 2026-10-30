import { request } from "../core/http.js";
import { element } from "../core/dom.js";
import { render } from "./consumers/render.js";

/**
 * 业务作用：读取当前集群或工作区的消费者绑定，在隐藏、换域、暂停或退出时撤下旧身份事实。
 * 参数说明：
 * - `root`：管理壳拥有的页面容器。
 * - `session`：服务器授予的平台权限和可读工作区。
 * 返回：取消读取与定时器并清空目录的退出函数，不存储历史或凭据材料。
 */
export function mount(root, session) {
  const scope = element("select");
  scope.setAttribute("aria-label", "消费者范围");
  if (
    ["cluster", "consumers"].every((name) =>
      session.permissions?.[name]?.includes("read"),
    )
  ) {
    const option = element("option", "平台集群");
    option.value = "";
    scope.append(option);
  }
  for (const workspace of session.workspaces ?? []) {
    const option = element(
      "option",
      `${workspace.id} · ${workspace.tenant} / ${workspace.environment}`,
    );
    option.value = workspace.id;
    scope.append(option);
  }
  const search = element("input");
  search.type = "search";
  search.maxLength = 64;
  search.placeholder = "消费者、入口或路由（区分大小写）";
  search.setAttribute("aria-label", "消费者搜索");
  const submit = element("button", "查询");
  submit.type = "submit";
  const pause = element("button", "暂停");
  pause.type = "button";
  const previous = element("button", "上一页");
  const next = element("button", "下一页");
  previous.type = next.type = "button";
  const toolbar = element("form", "", "monitor-toolbar");
  toolbar.append(scope, search, submit, pause, previous, next);
  const status = element("p", "等待当前消费者目录…", "status-pill");
  status.setAttribute("role", "status");
  const cards = element("section", "", "metric-grid");
  const nodes = element("section", "", "node-list");
  const bindings = element("section", "", "object-list");
  root.append(
    toolbar,
    status,
    cards,
    nodes,
    bindings,
    element(
      "p",
      "仅展示原生 API-Key 显式声明的 consumer 绑定，不枚举外部身份源用户或未绑定 consumer 的密钥。序号属于当前编译配置，不能作为原文编辑下标。配置写入通过变更提案、原目标预览和审批执行。",
      "subtle",
    ),
  );
  let epoch = 0;
  let stopped = false;
  let paused = false;
  let inFlight = null;
  let timer = null;
  let offset = 0;
  let nextOffset = null;
  let etag = null;
  let selected = "";
  let expires = 0;

  /**
   * 业务作用：清空目录及翻页动作，过期或失败不能继续展示旧消费者状态。
   * 参数说明: 无。
   * 返回：只保留查询控件和提示，没有可误用的节点详情。
   */
  function clear() {
    expires = 0;
    nextOffset = null;
    previous.disabled = next.disabled = true;
    cards.replaceChildren();
    nodes.replaceChildren();
    bindings.replaceChildren();
  }

  /**
   * 业务作用：退休当前异步读取的展示权，网络取消晚到也不能写入新的范围。
   * 参数说明: 无。
   * 返回：请求、轮询与现有内容均撤下。
   */
  function suspend() {
    epoch += 1;
    clearTimeout(timer);
    inFlight?.abort();
    inFlight = null;
    clear();
  }

  /**
   * 业务作用：在固定授权接口读取一页当前事实，配置向量变化后重新开始分页。
   * 参数说明: 无。
   * 返回：只展示当前范围且仍新鲜的响应；失败或等待状态清空目录。
   */
  async function poll() {
    if (stopped || paused || document.hidden || inFlight) {
      return;
    }
    const attempt = epoch;
    const workspace = scope.value;
    const controller = new AbortController();
    inFlight = controller;
    const started = performance.now();
    const path = workspace
      ? `/api/workspaces/${encodeURIComponent(workspace)}/cluster/consumers`
      : "/api/cluster/consumers";
    const params = new URLSearchParams({
      search: selected,
      offset: String(offset),
      limit: "25",
    });
    try {
      const result = await request(`${path}?${params}`, {
        signal: controller.signal,
        headers: offset > 0 && etag ? { "If-Match": etag } : {},
      });
      if (stopped || attempt !== epoch) {
        return;
      }
      if (result.status === 202) {
        clear();
        status.textContent = "等待当前集群消费者事实…";
        return;
      }
      const view = result.data;
      const age = Number(result.headers.get("x-naway-sample-age-ms"));
      if (
        view.schema_version !== 1 ||
        view.scope !== (workspace ? "workspace_cluster" : "cluster") ||
        (workspace && view.workspace !== workspace) ||
        !Array.isArray(view.nodes) ||
        view.nodes.length > 128 ||
        !Array.isArray(view.bindings) ||
        view.bindings.length > 25 ||
        view.offset !== offset ||
        !Number.isFinite(age) ||
        age < 0 ||
        !result.headers.has("x-naway-sample-age-ms") ||
        age + performance.now() - started >= 6000
      ) {
        throw new Error("消费者目录范围、格式或有效期不符合约定。");
      }
      clear();
      render(view, cards, nodes, bindings);
      etag = result.headers.get("etag");
      expires = started + 6000 - age;
      nextOffset = view.next_offset;
      previous.disabled = offset === 0 || !etag;
      next.disabled = nextOffset === null || !etag;
      status.textContent = `${workspace || "平台集群"} · 当前第 ${Math.floor(offset / 25) + 1} 页 · ${view.availability === "available" ? "覆盖完整" : "请核对节点覆盖"}`;
    } catch (error) {
      if (attempt === epoch && error.name !== "AbortError") {
        clear();
        if (error.status === 412) {
          offset = 0;
          etag = null;
          status.textContent = "节点配置或覆盖已改变，正在重新读取第一页。";
        } else {
          if ([401, 403, 404].includes(error.status)) {
            // 失去读取权后停止自动请求，旧事实立即撤下，重新读取需要显式恢复。
            paused = true;
            pause.textContent = "恢复";
          }
          status.textContent = error.message;
        }
      }
    } finally {
      if (inFlight === controller) {
        inFlight = null;
      }
      if (!stopped && !paused && !document.hidden && attempt === epoch) {
        timer = setTimeout(poll, 2000);
      }
    }
  }

  /**
   * 业务作用：更换范围或搜索时丢弃上一查询的ETag和页码，避免跨域复用身份。
   * 参数说明：
   * - `event`：查询提交或范围变化事件。
   * 返回：从新范围第一页开始读取，暂停状态仍保持。
   */
  function restart(event) {
    event?.preventDefault();
    suspend();
    offset = 0;
    etag = null;
    selected = search.value.trim();
    void poll();
  }

  /**
   * 业务作用：只在原节点配置向量仍有资格时翻页，服务器最终复验同一ETag。
   * 参数说明：
   * - `target`：当前响应允许的目标页偏移。
   * 返回：撤下旧页并请求相邻页。
   */
  function move(target) {
    if (!etag || target === null) {
      return;
    }
    suspend();
    offset = target;
    void poll();
  }

  /**
   * 业务作用：隐藏页面即清除消费者事实，重新可见时仅读取新结果。
   * 参数说明: 无。
   * 返回：旧请求退休，暂停选择不会被可见性变化覆盖。
   */
  function visibility() {
    suspend();
    if (!document.hidden) {
      void poll();
    }
  }

  toolbar.onsubmit = restart;
  scope.onchange = restart;
  search.oninput = () => {
    suspend();
    offset = 0;
    etag = null;
    selected = search.value.trim();
    status.textContent = "搜索条件已改变，提交后读取当前目录。";
  };
  previous.onclick = () => move(Math.max(0, offset - 25));
  next.onclick = () => move(nextOffset);
  pause.onclick = () => {
    paused = !paused;
    pause.textContent = paused ? "恢复" : "暂停";
    suspend();
    status.textContent = paused
      ? "已暂停，旧目录已清空。"
      : "正在读取当前目录…";
    void poll();
  };
  document.addEventListener("visibilitychange", visibility);
  const expiry = setInterval(() => {
    if (expires && performance.now() >= expires) {
      clear();
      status.textContent = "目录已过期，等待新的节点事实。";
    }
  }, 250);
  clear();
  void poll();
  return () => {
    stopped = true;
    suspend();
    clearInterval(expiry);
    document.removeEventListener("visibilitychange", visibility);
    root.replaceChildren();
  };
}
