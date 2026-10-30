import { request } from "../core/http.js";
import { card, element } from "../core/dom.js";

const states = {
  available: "当前事实完整",

  partial: "部分覆盖",

  sampling: "等待当前采样",

  pending: "等待完整目录",

  unknown: "缺少当前事实",

  unsupported: "节点未提供此能力",

  capacity: "观测容量不足",

  stale: "采样已过期",

  unconfigured: "未声明成员",

  disabled: "集群监控未开启",

  control_only: "纯管理节点",

  not_present: "本节点未声明该服务",

  discovery_missing: "尚未收到服务发现",

  discovery_stale: "服务发现已过期",

  identity_conflict: "节点身份冲突",

  authority_mismatch: "工作区权限不一致",

  generation_mismatch: "目录与采样尚未同代",

  ownership_mismatch: "对象归属不一致",
};

const fields = [
  ["instances", "实例观察数"],
  ["configured_selectable", "配置可选"],
  ["manually_down", "手工下线"],
  ["backup", "备用"],
  ["active_rejected", "主动探测拒绝"],
];

/**
 * 业务作用：展示独立逻辑服务的当前集群实例事实，工作区缺口与节点缺席保持未知。
 * 参数说明：
 * - `root`：管理壳拥有的页面容器。
 * - `session`：当前平台权限及可读工作区。
 * - `initialService`：从目录选择的服务身份，空值时等待用户选择。
 * 返回：取消全部读取并清空服务信息的退出函数，不保存历史。
 */
export function mount(root, session, initialService = "") {
  const platform = ["cluster", "upstreams"].every((key) =>
    session.permissions?.[key]?.includes("read"),
  );
  const scope = element("select");
  scope.setAttribute("aria-label", "服务范围");
  if (platform) {
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
  const service = element("input");
  service.type = "search";
  service.maxLength = 128;
  service.value = initialService;
  service.placeholder = "逻辑服务名";
  service.setAttribute("aria-label", "逻辑服务名");
  const submit = element("button", "查看");
  submit.type = "submit";
  const pause = element("button", "暂停");
  pause.type = "button";
  const toolbar = element("form", "", "monitor-toolbar");
  toolbar.append(scope, service, submit, pause);
  const status = element("p", "选择逻辑服务后查看当前状态。", "status-pill");
  status.setAttribute("role", "status");
  const cards = element("section", "", "metric-grid");
  const nodes = element("section", "", "node-list");
  root.append(
    toolbar,
    status,
    cards,
    nodes,
    element(
      "p",
      "实例数按节点观察累计，同一后端可能被多个节点观察。配置可选不代表已经探活；下线、备用和探测拒绝分类可以重叠，最终选择还受请求与保护策略约束。只显示当前状态，无监控历史。",
      "subtle",
    ),
  );
  let selected = initialService;
  let epoch = 0;
  let stopped = false;
  let paused = false;
  let inFlight = null;
  let timer = null;
  let current = null;
  let receivedAt = 0;
  let sourceAge = 0;

  /**
   * 业务作用：撤下旧服务身份、配置代和实例事实，未知状态不能沿用旧值。
   * 参数说明: 无。
   * 返回：只保留输入控件和提示，不保留节点详情。
   */
  function clear() {
    current = null;
    cards.replaceChildren();
    nodes.replaceChildren();
  }

  /**
   * 业务作用：以纯文本展示当前节点事实，空实例集显示零而未知计数保留未知。
   * 参数说明: 无。
   * 返回：当前服务覆盖与各节点状态同步更新，不将总观察数当作物理去重数量。
   */
  function render() {
    const coverage = current.coverage;
    status.textContent = `${selected} · ${states[current.availability] ?? "当前无法确认"}`;
    cards.replaceChildren(
      card(
        "有实例事实的节点",
        `${coverage.observed} / ${coverage.total}`,
        "全部预期成员作为分母",
      ),
      card("未知节点", String(coverage.unknown), "不计为零实例"),
    );
    for (const [key, label] of fields) {
      cards.append(
        card(
          label,
          current.node_observations?.[key] == null
            ? "未知"
            : String(current.node_observations[key]),
          "已观察节点累计",
        ),
      );
    }
    nodes.replaceChildren();
    for (const node of current.nodes) {
      const item = element("article", "", "panel");
      item.append(
        element(
          "h2",
          `${node.id} · ${states[node.availability] ?? "当前无法确认"}`,
        ),
      );
      for (const [label, value] of [
        ["配置版本", node.config_version],
        ["配置指纹", node.config_fingerprint],
        ["采样年龄（毫秒）", node.sample_age_ms],
        ["发现来源", node.service?.source],
        ["工作区", node.service?.workspace],
        [
          "关键服务",
          node.service == null ? null : node.service.critical ? "是" : "否",
        ],
        [
          "主动探测",
          node.service == null
            ? null
            : node.service.active_probes
              ? "已配置"
              : "未配置",
        ],
        ...fields.map(([key, label]) => [label, node.service?.counts?.[key]]),
      ]) {
        const row = element("div", "", "state-row");
        row.append(
          element("span", label),
          element("strong", value == null ? "未知" : String(value)),
        );
        item.append(row);
      }
      nodes.append(item);
    }
  }

  /**
   * 业务作用：在同一读取链上查询明确服务和范围，迟到响应或授权拒绝立即撤下旧信息。
   * 参数说明: 无。
   * 返回：仅保留当前有限样本；隐藏、暂停或退出时不继续轮询。
   */
  async function poll() {
    if (stopped || paused || document.hidden || inFlight || !selected) {
      return;
    }
    const attempt = epoch;
    const workspace = scope.value;
    const controller = new AbortController();
    inFlight = controller;
    const endpoint = workspace
      ? `/api/workspaces/${encodeURIComponent(workspace)}/monitor/services`
      : "/api/monitor/services";
    try {
      const result = await request(
        `${endpoint}?${new URLSearchParams({ service: selected })}`,
        { signal: controller.signal },
      );
      if (attempt !== epoch || stopped) {
        return;
      }
      if (result.status === 202) {
        clear();
        status.textContent = states[result.data.availability] ?? "等待当前事实";
        return;
      }
      const value = result.data;
      const age = Number(result.headers.get("x-naway-sample-age-ms"));
      if (
        value.schema_version !== 1 ||
        value.scope !== (workspace ? "workspace_cluster" : "cluster") ||
        value.workspace !== (workspace || null) ||
        value.service !== selected ||
        !Array.isArray(value.nodes) ||
        value.nodes.length > 128 ||
        ![1000, 2000, 5000, 10000].includes(value.sampling_period_ms) ||
        !Number.isFinite(age) ||
        age < 0 ||
        age > value.sampling_period_ms * 3
      ) {
        throw new Error("服务状态响应不符合当前范围。 ");
      }
      current = value;
      sourceAge = age;
      receivedAt = performance.now();
      render();
    } catch (error) {
      if (attempt === epoch && error.name !== "AbortError") {
        clear();
        status.textContent = error.message;
        if ([403, 404].includes(error.status)) {
          paused = true;
          pause.textContent = "继续";
        }
      }
    } finally {
      if (inFlight === controller) {
        inFlight = null;
      }
      if (!stopped && !paused && !document.hidden && attempt === epoch) {
        timer = setTimeout(poll, current?.sampling_period_ms ?? 2000);
      }
    }
  }

  /**
   * 业务作用：撤销当前异步读取的展示权，切换服务或范围时不混用旧事实。
   * 参数说明: 无。
   * 返回：请求、计时器和已显示实体均已释放。
   */
  function suspend() {
    epoch += 1;
    clearTimeout(timer);
    inFlight?.abort();
    inFlight = null;
    clear();
  }

  /**
   * 业务作用：按当前输入重新建立明确服务观察，清除另一服务的旧内容。
   * 参数说明：
   * - `event`：提交或范围改变事件。
   * 返回：合法身份开始新读取；空输入保持无样本状态。
   */
  function restart(event) {
    event?.preventDefault();
    suspend();
    selected = service.value.trim();
    paused = false;
    pause.textContent = "暂停";
    status.textContent = selected
      ? "正在读取当前服务状态…"
      : "选择逻辑服务后查看当前状态。";
    void poll();
  }

  /**
   * 业务作用：隐藏页面停止观察并撤下服务信息，重新显示从当前授权重新读取。
   * 参数说明: 无。
   * 返回：后台不保留旧服务事实。
   */
  function visibility() {
    suspend();
    if (!document.hidden) {
      void poll();
    }
  }

  /**
   * 业务作用：网络尚未返回时独立撤下过期样本，避免慢请求续期旧实例事实。
   * 参数说明: 无。
   * 返回：超过三周期的可见数据被清空。
   */
  function expire() {
    if (
      current &&
      sourceAge + performance.now() - receivedAt >
        current.sampling_period_ms * 3
    ) {
      clear();
      status.textContent = "当前服务状态已过期，等待重新读取。";
    }
  }

  toolbar.addEventListener("submit", restart);
  scope.addEventListener("change", restart);
  service.addEventListener("input", () => {
    suspend();
    selected = "";
    status.textContent = "输入已改变，请查看新的服务状态。";
  });
  pause.addEventListener("click", () => {
    suspend();
    paused = !paused;
    pause.textContent = paused ? "继续" : "暂停";
    status.textContent = paused
      ? "已暂停，当前事实已清空。"
      : "正在读取当前服务状态…";
    void poll();
  });
  document.addEventListener("visibilitychange", visibility);
  const ageTimer = setInterval(expire, 1000);
  if (platform || session.workspaces?.length) {
    void poll();
  } else {
    paused = true;
    toolbar.hidden = true;
    status.textContent = "当前主体没有服务实时状态读取权限。";
  }
  /**
   * 业务作用：退出视图时释放全部服务内容和异步权威。
   * 参数说明: 无。
   * 返回：没有后台轮询、监听或可回填的旧响应。
   */
  return function dispose() {
    stopped = true;
    suspend();
    clearInterval(ageTimer);
    document.removeEventListener("visibilitychange", visibility);
    root.replaceChildren();
  };
}
