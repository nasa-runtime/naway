import { request } from "../core/http.js";
import { card, element } from "../core/dom.js";

const states = {
  available: "目录完整",

  pending: "目录接收中",

  unsupported: "未提供对象目录",

  sampling: "等待节点报告",

  stale: "节点事实已过期",

  capacity: "目录超过容量",

  identity_conflict: "节点身份冲突",

  receiver_unavailable: "管理接收不可用",

  unreachable: "节点不可达",

  timeout: "节点读取超时",

  rejected: "节点拒绝读取",

  not_ready: "节点尚未就绪",
};

const routeFlags = [
  "内部路由",
  "流量限制",
  "HTTP 缓存",
  "请求校验",
  "请求转换",
  "响应转换",
  "响应契约",
  "WAF",
  "GeoIP",
  "Bot",
  "CSRF",
  "DLP",
  "GraphQL",
  "WebSocket 消息治理",
  "OPA",
  "Casbin",
  "Wasm",
  "外部插件",
  "正向代理",
  "BFF",
];

/**
 * 业务作用：显示固定目录位对应的配置能力，不从缺省字段推测未知策略。
 * 参数说明：
 * - `entry`：节点提交的已验证目录描述。
 * 返回：当前目录公开的能力名称，未包含的能力不作支持与否结论。
 */
function capabilities(entry) {
  const labels =
    entry.kind === "route"
      ? routeFlags
      : entry.kind === "listener"
        ? ["HTTP 计划", "TLS 计划", "HTTP/3 计划"]
        : [];
  return (
    labels
      .filter((_, index) => (entry.flags & (2 ** index)) !== 0)
      .join(" / ") || "目录未列出能力位"
  );
}

/**
 * 业务作用：展示集群授权领域的对象分布，保留没有完整目录的节点作为未知覆盖。
 * 参数说明：
 * - `root`：当前页面容器。
 * - `permissions`：后端返回的当前主体领域权限。
 * - `openService`：进入同一授权会话中的集群服务实时状态。
 * 返回：取消读取并清空目录的退出函数，不保留历史或浏览器凭据。
 */
export function mount(root, permissions, openService) {
  let current = null;
  let etag = null;
  let offset = 0;
  let nextOffset = null;
  let epoch = 0;
  let stopped = false;
  let inFlight = null;
  let timer = null;
  let receivedAt = 0;
  let sourceAge = 0;
  const expanded = new Set();
  const toolbar = element("form", "", "monitor-toolbar");
  const domain = element("select");
  domain.setAttribute("aria-label", "对象领域");
  for (const [value, label, resource] of [
    ["routes", "路由", "routes"],
    ["listeners", "HTTP 入口", "config"],
    ["upstreams", "逻辑上游", "upstreams"],
  ]) {
    if (!permissions?.[resource]?.includes("read")) {
      continue;
    }
    const option = element("option", label);
    option.value = value;
    domain.append(option);
  }
  const search = element("input");
  search.type = "search";
  search.maxLength = 64;
  search.placeholder = "对象、入口或工作区";
  search.setAttribute("aria-label", "对象搜索");
  const size = element("select");
  size.setAttribute("aria-label", "每页对象数");
  for (const count of [25, 10, 1, 50, 100]) {
    const option = element("option", `${count} 项 / 页`);
    option.value = String(count);
    size.append(option);
  }
  const submit = element("button", "搜索");
  submit.type = "submit";
  toolbar.append(domain, search, size, submit);
  const status = element("p", "正在读取集群目录…", "status-pill");
  status.setAttribute("role", "status");
  const cards = element("section", "", "metric-grid");
  const nodes = element("section", "", "panel node-list");
  const objects = element("section", "", "panel node-list");
  const pages = element("div", "", "monitor-toolbar");
  const previous = element("button", "上一页");
  const next = element("button", "下一页");
  const position = element("span", "", "subtle");
  pages.append(previous, position, next);
  root.replaceChildren(
    element(
      "p",
      "各节点当前配置对象的分布。入口是配置计划，逻辑上游是声明目录；摘要只比较本页公开字段，不代表监听已绑定、上游健康或完整配置相同。",
      "subtle",
    ),
    toolbar,
    status,
    cards,
    nodes,
    objects,
    pages,
  );

  /**
   * 业务作用：撤下当前目录与分页能力，未知事实不得保留成可继续操作的旧页面。
   * 参数说明: 无。
   * 返回：释放对象和节点内容，保留筛选控件。
   */
  function clear() {
    current = null;
    expanded.clear();
    nextOffset = null;
    cards.replaceChildren();
    nodes.replaceChildren();
    objects.replaceChildren();
    position.textContent = "当前没有有效对象目录。";
    previous.disabled = true;
    next.disabled = true;
  }

  /**
   * 业务作用：按稳定对象身份保留详情展开状态，周期更新不能打断正在阅读的节点或差异。
   * 参数说明：
   * - `key`：当前页范围内唯一的节点或对象键。
   * - `label`：作为纯文本呈现的摘要内容。
   * 返回：绑定当前展开状态的详情元素，移除后的迟到事件不能改写新页面状态。
   */
  function detail(key, label) {
    const details = element("details");
    details.dataset.catalogKey = key;
    details.open = expanded.has(key);
    details.append(element("summary", label));
    details.addEventListener("toggle", () => {
      if (!details.isConnected) {
        return;
      }
      if (details.open) {
        expanded.add(key);
      } else {
        expanded.delete(key);
      }
    });
    return details;
  }

  /**
   * 业务作用：以纯文本呈现节点证据和对象分布，同一摘要只显示一份描述及所属节点。
   * 参数说明: 无。
   * 返回：当前页对象、完整覆盖与未知原因同步更新，不隐藏筛选外的节点分母。
   */
  function render() {
    const focus =
      document.activeElement?.closest("details")?.dataset.catalogKey;
    const present = new Set([
      ...current.nodes.map((node) => `node\0${node.id}`),
      ...current.objects.map(
        (object) => `${object.kind}\0${object.parent}\0${object.id}`,
      ),
    ]);
    for (const key of expanded) {
      if (!present.has(key)) {
        expanded.delete(key);
      }
    }
    const coverage = current.coverage;
    status.textContent = `${current.availability === "available" ? "目录完整" : "部分覆盖"} · 集群`;
    cards.replaceChildren(
      card(
        "完整目录",
        `${coverage.complete} / ${coverage.total}`,
        "已确认 / 全部成员",
      ),
      card("未知目录", String(coverage.unknown), "不作为对象缺失"),
      card("匹配对象", String(current.total_objects), "按稳定对象身份去重"),
    );
    nodes.replaceChildren(element("h2", "逐节点目录"));
    for (const node of current.nodes) {
      const details = detail(
        `node\0${node.id}`,
        `${node.id} · ${node.mode ?? "角色未知"} · ${states[node.availability] ?? "当前无法确认"}`,
      );
      for (const [label, text] of [
        ["启动身份", node.boot_id],
        ["配置版本", node.config_version],
        ["配置指纹", node.config_fingerprint],
        ["目录摘要", node.catalog_digest],
      ]) {
        const row = element("div", "", "state-row");
        row.append(
          element("span", label),
          element("strong", text == null ? "未知" : String(text)),
        );
        details.append(row);
      }
      nodes.append(details);
    }
    if (current.directory.limited_to_local) {
      nodes.append(
        element("p", "当前仅声明接入节点，尚未配置远端成员。", "subtle"),
      );
    }
    if (
      current.directory.directory_stale ||
      current.directory.conflicting_ids ||
      current.directory.truncated
    ) {
      nodes.append(
        element(
          "p",
          "成员目录存在陈旧、冲突或容量缺口，不能据此确认完整集群。",
          "subtle",
        ),
      );
    }
    objects.replaceChildren(element("h2", "对象分布"));
    for (const object of current.objects) {
      const name = object.parent
        ? `${object.parent} / ${object.id}`
        : object.id;
      const details = detail(
        `${object.kind}\0${object.parent}\0${object.id}`,
        `${name} · 存在 ${object.present}/${coverage.total} · ${object.variants.length > 1 ? "摘要有差异" : "已观察摘要一致"}`,
      );
      details.append(
        element("p", `确认缺少：${object.missing.join("、") || "无"}`),
        element("p", `尚未确认：${object.unknown.join("、") || "无"}`),
      );
      if (object.kind === "upstream" && openService) {
        const inspect = element("button", "查看集群服务状态");
        inspect.type = "button";
        inspect.addEventListener("click", () => openService(object.id));
        details.append(inspect);
      }
      for (const variant of object.variants) {
        const entry = variant.description;
        const section = element("section", "", "panel");
        section.append(
          element("h3", variant.nodes.join("、")),
          element(
            "p",
            `归属：${entry.workspace} / ${entry.tenant || "—"} / ${entry.environment || "—"}`,
          ),
        );
        if (entry.kind === "route") {
          section.append(
            element(
              "p",
              `顺序：${entry.order} · 命名服务：${entry.service || "未声明命名服务"}`,
            ),
          );
        }
        section.append(element("p", capabilities(entry)));
        details.append(section);
      }
      objects.append(details);
    }
    if (!current.objects.length) {
      objects.append(
        element(
          "p",
          "当前完整目录中没有匹配对象；未知节点的对象仍未确认。",
          "empty-state",
        ),
      );
    }
    nextOffset = current.next_offset;
    previous.disabled = offset === 0;
    next.disabled = nextOffset == null;
    position.textContent = `${offset + (current.objects.length ? 1 : 0)}–${offset + current.objects.length} / ${current.total_objects}`;
    if (focus) {
      [...root.querySelectorAll("details")]
        .find((details) => details.dataset.catalogKey === focus)
        ?.querySelector("summary")
        ?.focus({ preventScroll: true });
    }
  }

  /**
   * 业务作用：使用当前节点配置向量取得分页，配置变化时撤销旧页并重新从第一页读取。
   * 参数说明: 无。
   * 返回：一份当前集群页面；失败清空事实且不会重复外呼节点。
   */
  async function poll() {
    if (stopped || document.hidden || inFlight) {
      return;
    }
    const attempt = epoch;
    const controller = new AbortController();
    inFlight = controller;
    const params = new URLSearchParams({
      domain: domain.value,

      search: search.value.trim(),

      offset: String(offset),

      limit: size.value,
    });
    try {
      const result = await request(`/api/cluster/catalog?${params}`, {
        signal: controller.signal,

        headers: offset > 0 && etag ? { "If-Match": etag } : {},
      });
      if (attempt !== epoch || stopped) {
        return;
      }
      if (result.status === 202) {
        clear();
        status.textContent =
          result.data.availability === "disabled"
            ? "尚未授权集群成员读取。"
            : "等待当前集群目录…";
        return;
      }
      if (
        result.data.schema_version !== 1 ||
        result.data.scope !== "cluster" ||
        !Array.isArray(result.data.nodes) ||
        result.data.nodes.length > 128 ||
        !Array.isArray(result.data.objects) ||
        result.data.objects.length > 100
      ) {
        throw new Error("对象目录响应不符合约定。");
      }
      current = result.data;
      etag = result.headers.get("etag");
      receivedAt = performance.now();
      sourceAge = Number(result.headers.get("x-naway-sample-age-ms"));
      render();
    } catch (error) {
      if (attempt === epoch && error.name !== "AbortError") {
        clear();
        if (error.status === 412) {
          offset = 0;
          etag = null;
          status.textContent = "节点配置或覆盖发生变化，正在重新读取第一页。";
        } else {
          status.textContent = error.message;
        }
      }
    } finally {
      if (inFlight === controller) {
        inFlight = null;
      }
      if (!stopped && !document.hidden && attempt === epoch) {
        timer = setTimeout(poll, 2000);
      }
    }
  }

  /**
   * 业务作用：取消当前请求并撤销旧响应的展示权，切换条件时不会跨代回填。
   * 参数说明: 无。
   * 返回：当前内容已清除，定时器与网络读取已取消。
   */
  function suspend() {
    epoch += 1;
    clearTimeout(timer);
    inFlight?.abort();
    inFlight = null;
    clear();
  }

  /**
   * 业务作用：筛选或页容量变化后从新视图第一页开始，不沿用另一领域的分页条件。
   * 参数说明：
   * - `event`：表单提交或控件改变。
   * 返回：当前视图重新读取，成员覆盖保持服务器给出的全集群口径。
   */
  function restart(event) {
    event?.preventDefault();
    suspend();
    offset = 0;
    etag = null;
    void poll();
  }

  /**
   * 业务作用：在同一节点配置向量上选择相邻对象页。
   * 参数说明：
   * - `target`：当前响应允许的分页偏移。
   * 返回：取消旧页读取并查询新页，服务端仍复验ETag。
   */
  function move(target) {
    suspend();
    offset = target;
    void poll();
  }

  /**
   * 业务作用：页面隐藏时释放当前对象信息，重新显示必须获取新事实。
   * 参数说明: 无。
   * 返回：停止后台保留，恢复时回到当前第一页。
   */
  function visibility() {
    suspend();
    offset = 0;
    etag = null;
    if (!document.hidden && !stopped) {
      void poll();
    }
  }

  /**
   * 业务作用：到达事实有效期后撤下目录，网络失败不能把旧配置当当前状态。
   * 参数说明: 无。
   * 返回：过期内容已清空，轮询继续等待当前事实。
   */
  function expire() {
    if (current && sourceAge + performance.now() - receivedAt > 6000) {
      clear();
      status.textContent = "当前目录已过期，等待重新读取。";
    }
  }

  toolbar.addEventListener("submit", restart);
  domain.addEventListener("change", restart);
  size.addEventListener("change", restart);
  previous.addEventListener("click", () =>
    move(Math.max(0, offset - Number(size.value))),
  );
  next.addEventListener("click", () => move(nextOffset));
  document.addEventListener("visibilitychange", visibility);
  const ageTimer = setInterval(expire, 1000);
  clear();
  void poll();
  /**
   * 业务作用：退出页面时释放全部目录和异步回填权限。
   * 参数说明: 无。
   * 返回：当前页面没有继续运行的轮询或可见性监听。
   */
  return function dispose() {
    stopped = true;
    suspend();
    clearInterval(ageTimer);
    document.removeEventListener("visibilitychange", visibility);
  };
}
