import { request } from "../core/http.js";
import { card, element, number } from "../core/dom.js";
import { publicationFields } from "./nodes/publication.js";

const states = {
  available: "可用",

  partial: "部分覆盖",

  not_ready: "尚未就绪",

  no_data_nodes: "尚无数据节点",

  capacity: "超出容量",

  identity_conflict: "节点身份冲突",

  rejected: "远端拒绝",

  unreachable: "无法连接",

  timeout: "读取超时",

  budget_exhausted: "本轮未能读取",

  invalid_sample: "事实格式不符",

  stale: "事实已过期",

  protocol: "连接未完成",

  sampling: "等待节点报告",

  receiver_unavailable: "管理接收端不可用",
};

/**
 * 业务作用：展示授权集群中各节点的当前部署事实，单节点失败保留在覆盖范围内。
 * 参数说明：
 * - `root`：当前主体的页面容器。
 * 返回：退出时取消读取并清空事实的清理函数，不保留历史记录。
 */
export function mount(root) {
  let current = null;
  let receivedAt = 0;
  let receivedAge = 0;
  let timer = null;
  let inFlight = null;
  let generation = 0;
  let stopped = false;
  const expanded = new Set();
  const status = element("p", "正在读取集群节点…", "status-pill");
  status.setAttribute("role", "status");
  const scope = element(
    "p",
    "集群节点的当前部署、就绪与本地文件状态。旧配置仍可处理业务时，文件发布可能尚待确认；关闭实时指标采样不影响此页。",
    "subtle",
  );
  const toolbar = element("div", "", "monitor-toolbar");
  const search = element("input");
  search.type = "search";
  search.maxLength = 64;
  search.placeholder = "筛选节点或管理地址";
  search.setAttribute("aria-label", "节点筛选");
  const role = element("select");
  role.setAttribute("aria-label", "节点角色");
  for (const [value, label] of [
    ["all", "全部角色"],
    ["data", "业务节点"],
    ["admin", "纯管理节点"],
  ]) {
    const option = element("option", label);
    option.value = value;
    role.append(option);
  }
  toolbar.append(status, search, role);
  const cards = element("div", "", "metric-grid");
  const coverage = element("section", "", "panel");
  const list = element("section", "", "panel node-list");
  const age = element("p", "", "subtle");
  root.replaceChildren(scope, toolbar, age, cards, coverage, list);

  /**
   * 业务作用：清除当前节点事实，避免失权、隐藏或超龄后继续展示旧节点状态。
   * 参数说明: 无。
   * 返回：保留筛选控件，释放当前实体及展开状态。
   */
  function clear() {
    current = null;
    expanded.clear();
    cards.replaceChildren();
    coverage.replaceChildren();
    list.replaceChildren();
    age.textContent = "当前没有有效节点快照。";
  }

  /**
   * 业务作用：按当前筛选展示完整节点或失败行，不能把不可达成员隐去后声称全量覆盖。
   * 参数说明: 无。
   * 返回：一次发布最多128个节点卡，全部字段均作为文本呈现。
   */
  function render() {
    if (!current) {
      return;
    }
    const value = current.coverage;
    status.textContent = `${states[current.availability] ?? "未知"} · 集群`;
    status.className =
      current.availability === "available"
        ? "status-pill live"
        : "status-pill warning";
    cards.replaceChildren(
      card(
        "可达节点",
        `${value.reachable} / ${value.total}`,
        "已观测 / 当前成员",
      ),
      card("已就绪", String(value.ready), "来自每个节点的实际就绪门"),
      card("业务节点", String(value.data_nodes), "Data / Sidecar / all-in-one"),
      card("纯管理节点", String(value.control_nodes), "Admin"),
    );
    coverage.replaceChildren(element("h2", "当前成员目录"));
    for (const [label, text] of [
      [
        "读取范围",
        value.limited_to_local
          ? "仅声明接入节点，尚未配置远端成员"
          : "已声明集群成员",
      ],
      [
        "成员发现",
        value.discovery_enabled
          ? value.discovery_available
            ? "自动发现可用"
            : "自动发现不可用"
          : "静态成员",
      ],
      [
        "目录状态",
        value.conflicting_ids
          ? "身份冲突，需要核对成员声明"
          : value.directory_stale
            ? "发现失败，保留已知成员"
            : value.truncated
              ? "成员超过当前容量"
              : "当前目录",
      ],
      ["无法观测", String(value.unknown)],
      ["声明目标 / 去重成员", `${value.declared_targets} / ${value.total}`],
    ]) {
      const row = element("div", "", "state-row");
      row.append(element("span", label), element("strong", text));
      coverage.append(row);
    }
    coverage.append(
      element(
        "p",
        "配置版本与指纹属于各节点的实际快照。节点专属地址可能造成指纹不同，请结合期望配置核对。",
        "subtle",
      ),
    );
    const query = search.value.trim().toLowerCase();
    const fragment = document.createDocumentFragment();
    const present = new Set(
      current.nodes.map((node) => `${node.id}\0${node.address}`),
    );
    for (const id of expanded) {
      if (!present.has(id)) {
        expanded.delete(id);
      }
    }
    let count = 0;
    for (const node of current.nodes) {
      const facts = node.facts;
      if (
        role.value !== "all" &&
        (!facts || (facts.mode === "admin") !== (role.value === "admin"))
      ) {
        continue;
      }
      if (
        query &&
        ![node.id, node.address, facts?.node_id].some((text) =>
          text?.toLowerCase().includes(query),
        )
      ) {
        continue;
      }
      count += 1;
      const key = `${node.id}\0${node.address}`;
      const details = element("details");
      details.open = expanded.has(key);
      details.addEventListener("toggle", () => {
        if (details.isConnected) {
          if (details.open) {
            expanded.add(key);
          } else {
            expanded.delete(key);
          }
        }
      });
      details.append(
        element(
          "summary",
          `${node.id} · ${facts?.mode ?? "角色未知"} · ${states[node.availability] ?? "未知"}`,
        ),
      );
      const fields = [["管理地址", node.address]];
      if (facts) {
        fields.push(
          ["节点声明身份", facts.node_id ?? "未声明"],
          ["进程启动身份", facts.boot_id],
          ["实际就绪", facts.ready ? "已就绪" : "未就绪"],
          ["配置版本", String(facts.config_version)],
          ["配置指纹", facts.config_fingerprint ?? "未知"],
          ["注册中心", facts.discovery_enabled ? "启用" : "关闭"],
          ["配置中心", facts.configuration_enabled ? "启用" : "关闭"],
          [
            "监听计划 / 路由 / 上游",
            `${facts.proxies} / ${facts.routes} / ${facts.services}`,
          ],
          ["节点事实年龄", `${number(node.source_age_ms / 1000)} 秒`],
        );
      }
      fields.push(...publicationFields(node));
      for (const [label, text] of fields) {
        const row = element("div", "", "state-row");
        row.append(element("span", label), element("strong", text));
        details.append(row);
      }
      fragment.append(details);
    }
    list.replaceChildren(
      element("h2", `节点明细 · ${count} / ${value.total}`),
      fragment,
    );
    if (count === 0) {
      list.append(element("p", "当前筛选没有匹配的节点。", "empty-state"));
    }
    freshness();
  }

  /**
   * 业务作用：按实际单调年龄撤下超过三周期的节点事实，网络失败不能延长就绪证据。
   * 参数说明: 无。
   * 返回：更新年龄或清空过期内容，不把未知状态显示为零。
   */
  function freshness() {
    if (!current) {
      return;
    }
    const elapsed = receivedAge + performance.now() - receivedAt;
    if (elapsed > 6000) {
      clear();
      status.textContent = "节点事实已过期，等待重新读取。";
      status.className = "status-pill warning";
      return;
    }
    age.textContent = `当前目录 #${current.sample_id} · 数据年龄 ${number(elapsed / 1000)} 秒`;
  }

  /**
   * 业务作用：串行读取共享集群目录，页面退出或授权代变化后丢弃迟到结果。
   * 参数说明: 无。
   * 返回：显示当前事实或明确等待原因，不因浏览器数增加节点抓取频率。
   */
  async function poll() {
    if (stopped || document.hidden || inFlight) {
      return;
    }
    const epoch = generation;
    const controller = new AbortController();
    inFlight = controller;
    try {
      const result = await request("/api/cluster/overview", {
        signal: controller.signal,
      });
      if (epoch !== generation || stopped) {
        return;
      }
      if (result.status === 202) {
        clear();
        status.textContent =
          result.data.availability === "disabled"
            ? "集群节点读取尚未授权。"
            : "正在读取集群节点…";
        return;
      }
      if (
        result.data.schema_version !== 1 ||
        result.data.scope !== "cluster" ||
        !Array.isArray(result.data.nodes) ||
        result.data.nodes.length > 128
      ) {
        throw new Error("集群节点响应不符合约定。");
      }
      current = result.data;
      receivedAt = performance.now();
      receivedAge = Number(result.headers.get("x-naway-sample-age-ms"));
      render();
    } catch (error) {
      if (epoch === generation && error.name !== "AbortError") {
        clear();
        status.textContent = error.message;
        status.className = "status-pill warning";
      }
    } finally {
      if (inFlight === controller) {
        inFlight = null;
      }
      if (!stopped && !document.hidden && epoch === generation) {
        timer = setTimeout(poll, 2000);
      }
    }
  }

  /**
   * 业务作用：撤销隐藏或离开页面的读取权，后续迟到响应不能恢复已清空内容。
   * 参数说明: 无。
   * 返回：取消计时和在途读取，保留页面结构。
   */
  function suspend() {
    generation += 1;
    clearTimeout(timer);
    inFlight?.abort();
    inFlight = null;
    clear();
  }

  /**
   * 业务作用：隐藏页不保留节点状态，重新显示时从当前集群事实恢复。
   * 参数说明: 无。
   * 返回：随可见性停止或恢复有限轮询。
   */
  function visibility() {
    suspend();
    if (!document.hidden && !stopped) {
      void poll();
    }
  }

  search.addEventListener("input", render);
  role.addEventListener("change", render);
  document.addEventListener("visibilitychange", visibility);
  const ageTimer = setInterval(freshness, 1000);
  void poll();
  /**
   * 业务作用：释放节点页面的全部读取任务和事实，避免切页后继续访问管理接口。
   * 参数说明: 无。
   * 返回：停止轮询、清除计时器并移除可见性监听。
   */
  return function dispose() {
    stopped = true;
    suspend();
    clearInterval(ageTimer);
    document.removeEventListener("visibilitychange", visibility);
  };
}
