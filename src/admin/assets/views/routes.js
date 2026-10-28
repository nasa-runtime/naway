import { request } from "../core/http.js";
import { card, element, number } from "../core/dom.js";

const states = {
  available: "当前可用",

  partial: "部分覆盖",

  sampling: "正在建立区间",

  pending: "等待完整目录",

  unknown: "缺少当前事实",

  unsupported: "节点未提供此能力",

  capacity: "观测容量不足",

  stale: "采样已过期",

  unconfigured: "未声明工作区成员",

  disabled: "集群监控未开启",

  control_only: "纯管理节点",

  identity_conflict: "节点身份冲突",

  authority_mismatch: "工作区权限不一致",

  generation_mismatch: "目录与采样尚未同代",

  ownership_mismatch: "对象归属不一致",
};

/**
 * 业务作用：展示同一当前采样的路由区间与工作区覆盖，未知数据不会沿用此前数值。
 * 参数说明：
 * - `root`：由管理壳拥有的页面容器。
 * - `session`：服务器给出的平台权限和可见工作区。
 * 返回：取消请求、计时器及所有当前实体的退出函数。
 */
export function mount(root, session) {
  const platform = ["cluster", "routes"].every((key) =>
    session.permissions?.[key]?.includes("read"),
  );
  const scope = element("select");
  scope.setAttribute("aria-label", "流量范围");
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
  if (!platform && !session.workspaces?.length) {
    root.append(element("p", "当前主体没有路由实时监控读取权限。", "panel"));
    return () => {
      root.replaceChildren();
    };
  }
  const search = element("input");
  search.type = "search";
  search.maxLength = 64;
  search.placeholder = "入口、路由或工作区";
  search.setAttribute("aria-label", "路由流量搜索");
  const limit = element("select");
  limit.setAttribute("aria-label", "每页流量行数");
  for (const count of [25, 10, 1, 50, 100]) {
    const option = element("option", `${count} 行 / 页`);
    option.value = String(count);
    limit.append(option);
  }
  const submit = element("button", "搜索");
  submit.type = "submit";
  const pause = element("button", "暂停");
  pause.type = "button";
  const toolbar = element("form", "", "monitor-toolbar");
  toolbar.append(scope, search, limit, submit, pause);
  const status = element("p", "正在读取当前路由流量…", "status-pill");
  status.setAttribute("role", "status");
  const cards = element("section", "", "metric-grid");
  const nodes = element("section", "", "panel node-list");
  const rows = element("section", "", "node-list route-traffic-list");
  const detail = element("section", "", "panel route-traffic-detail");
  detail.hidden = true;
  const previous = element("button", "上一页");
  const next = element("button", "下一页");
  const position = element("span", "", "subtle");
  const paging = element("div", "", "monitor-toolbar");
  paging.append(previous, position, next);
  root.append(
    toolbar,
    status,
    cards,
    nodes,
    rows,
    paging,
    detail,
    element(
      "p",
      "只统计首个公开入口的一次下游请求。内部转路由、叶子与重试不重复计数；字节和EOF在本地交付边界观察。升级只记握手，未命中路由的请求保留在全局指标中。只显示当前区间，无监控历史。",
      "subtle",
    ),
  );
  if (session.workspaces_truncated) {
    root.append(
      element(
        "p",
        "可见工作区列表超过当前页面上限；未显示的工作区不代表不存在。",
        "subtle",
      ),
    );
  }
  let epoch = 0,
    controller = null,
    timer = null,
    stopped = false,
    paused = false;
  let current = null,
    etag = null,
    offset = 0,
    nextOffset = null,
    selected = null;
  let period = 1000,
    received = 0,
    age = 0,
    due = 0;

  /**
   * 业务作用：撤下已经过期或失去查看权的所有事实，保留查询控件供重新采样。
   * 参数说明：
   * - `message`：当前清空原因的固定界面说明。
   * 返回：旧行、详情、分页条件与采样时间全部失效。
   */
  function clear(message) {
    current = null;
    etag = null;
    nextOffset = null;
    selected = null;
    received = 0;
    cards.replaceChildren();
    nodes.replaceChildren();
    rows.replaceChildren();
    detail.replaceChildren();
    detail.hidden = true;
    previous.disabled = true;
    next.disabled = true;
    position.textContent = "";
    status.textContent = message;
  }

  /**
   * 业务作用：阻止已取消范围的迟到响应回填，并释放当前网络请求。
   * 参数说明：
   * - `message`：切换、暂停或失联的当前说明。
   * 返回：旧轮次不再具有展示权，新轮次必须重新采样。
   */
  function invalidate(message) {
    epoch += 1;
    controller?.abort();
    controller = null;
    clear(message);
  }

  /**
   * 业务作用：仅从当前行展开详情，不能用另一个时间或工作区的数据填充指标。
   * 参数说明：
   * - `row`：当前响应内选中的完整路由行。
   * 返回：显示同一区间状态、结局和耗时，缺失值使用未知占位。
   */
  function showDetail(row) {
    selected = [row.proxy, row.route, row.workspace].join("\0");
    detail.replaceChildren(
      element("h2", `${row.proxy} / ${row.route}`),
      element(
        "p",
        `工作区 ${row.workspace} · ${row.valid_nodes}/${row.present_nodes} 个拥有对象的节点已形成区间，另有 ${row.unknown_nodes} 个未知节点。`,
        "subtle",
      ),
    );
    const values = element("div", "", "metric-grid");
    for (const [label, value, unit] of [
      ["入口请求", row.requests_per_second, "次 / 秒"],
      ["当前在途", row.active, "等待头或正文结束"],
      ["响应实体字节", row.response_bytes_per_second, "B / 秒"],
      ["本地 EOF", row.outcomes_per_second?.[0], "次 / 秒"],
      ["正文错误", row.outcomes_per_second?.[1], "次 / 秒"],
      ["提前丢弃", row.outcomes_per_second?.[2], "次 / 秒，不推断责任方"],
      ["协议升级", row.outcomes_per_second?.[3], "次 / 秒，仅握手"],
      ["完整响应均值", row.latency?.mean_ms, "毫秒"],
      ["完整响应 P50", row.latency?.p50_ms, "毫秒，低样本未知"],
      ["完整响应 P95", row.latency?.p95_ms, "毫秒，低样本未知"],
      ["完整响应 P99", row.latency?.p99_ms, "毫秒，低样本未知"],
    ]) {
      values.append(card(label, number(value), unit));
    }
    for (let index = 0; index < 5; index += 1) {
      values.append(
        card(
          `最终 ${index + 1}xx`,
          number(row.responses_per_second?.[index]),
          "次 / 秒，含网关短路与改写",
        ),
      );
    }
    detail.append(
      values,
      element("p", `当前对象节点：${row.nodes.join("、")}`, "subtle"),
    );
    detail.hidden = false;
  }

  /**
   * 业务作用：原子替换当前页面并保留明确缺席覆盖，所有名称均作为纯文本渲染。
   * 参数说明：
   * - `data`：服务器完成权限与完整性门后的当前页面。
   * 返回：只展示本次行及同样本详情，不把未知节点补为零。
   */
  function render(data) {
    current = data;
    status.textContent = states[data.availability] ?? "等待当前事实";
    cards.replaceChildren(
      card(
        "数据节点目录",
        `${data.coverage.complete}/${data.coverage.total - data.coverage.control_nodes}`,
        "未知节点仍在分母中",
      ),
      card(
        "有效区间节点",
        number(data.coverage.valid, 0),
        "逐节点单调时钟求差",
      ),
      card(
        "未知覆盖",
        number(data.coverage.unknown, 0),
        "失联、容量或授权缺口",
      ),
      card("匹配路由", number(data.total_rows, 0), "按入口、路由和工作区区分"),
    );
    nodes.replaceChildren(element("h2", "当前节点覆盖"));
    for (const node of data.nodes) {
      const line = element("div", "", "state-row");
      line.append(
        element("span", node.id),
        element("strong", states[node.availability] ?? "节点不可观测"),
      );
      nodes.append(line);
    }
    rows.replaceChildren();
    for (const row of data.rows) {
      const item = element("article", "", "panel route-traffic-row");
      const open = element(
        "button",
        `${row.proxy} / ${row.route} · ${row.workspace}`,
      );
      open.type = "button";
      open.addEventListener("click", () => {
        showDetail(row);
      });
      item.append(
        open,
        element(
          "p",
          `${states[row.availability] ?? "未知"} · ${row.valid_nodes}/${row.present_nodes} 个节点区间有效 · 请求 ${number(row.requests_per_second)}/s · 在途 ${number(row.active, 0)} · 输出 ${number(row.response_bytes_per_second)} B/s`,
          "subtle",
        ),
      );
      rows.append(item);
    }
    if (!data.rows.length) {
      rows.append(
        element(
          "p",
          data.coverage.unknown
            ? "当前已证明的范围内没有匹配行，其它节点仍未知。"
            : "当前范围内没有匹配路由。",
          "panel",
        ),
      );
    }
    const selectedRow = data.rows.find(
      (row) => [row.proxy, row.route, row.workspace].join("\0") === selected,
    );
    detail.replaceChildren();
    detail.hidden = true;
    if (selectedRow) {
      showDetail(selectedRow);
    } else {
      selected = null;
    }
    nextOffset = data.next_offset;
    previous.disabled = offset === 0;
    next.disabled = nextOffset === null;
    position.textContent = `第 ${data.total_rows ? offset + 1 : 0}–${offset + data.rows.length} 行 / ${data.total_rows}`;
  }

  /**
   * 业务作用：串行请求当前授权范围，绝对年龄超限与新采样分页冲突都撤销旧数据。
   * 参数说明: 无。
   * 返回：发布一次当前页；错误保留明确原因，迟到结果不改变页面。
   */
  async function refresh() {
    if (stopped || paused || document.hidden || controller) {
      return;
    }
    const round = epoch;
    const active = new AbortController();
    controller = active;
    const started = performance.now();
    const base = scope.value
      ? `/api/workspaces/${encodeURIComponent(scope.value)}/monitor/routes`
      : "/api/monitor/routes";
    const query = new URLSearchParams({
      search: search.value,
      offset: String(offset),
      limit: limit.value,
    });
    try {
      const result = await request(`${base}?${query}`, {
        signal: active.signal,
        headers: offset && etag ? { "If-Match": etag } : {},
      });
      if (stopped || round !== epoch || active.signal.aborted) {
        return;
      }
      period = [1000, 2000, 5000, 10000].includes(
        result.data.sampling_period_ms,
      )
        ? result.data.sampling_period_ms
        : 1000;
      if (result.status !== 200) {
        offset = 0;
        clear(states[result.data.availability] ?? "正在建立当前区间");
        return;
      }
      age =
        Number(result.headers.get("x-naway-sample-age-ms") ?? Infinity) +
        performance.now() -
        started;
      if (!Number.isFinite(age) || age > period * 3) {
        clear("当前样本已过期，等待新采样。");
        return;
      }
      received = performance.now();
      etag = result.headers.get("etag");
      render(result.data);
    } catch (error) {
      if (round === epoch && !stopped && error.name !== "AbortError") {
        if (error.status === 412 || error.status === 428) {
          offset = 0;
          clear("实时样本已更新，重新读取首页。");
        } else {
          clear(error.message);
        }
      }
    } finally {
      if (controller === active) {
        controller = null;
        due = performance.now() + period;
      }
    }
  }

  /**
   * 业务作用：在没有网络返回时独立撤下过期值，只保留一个固定周期计时器。
   * 参数说明: 无。
   * 返回：到期清空或请求下一当前样本，无时间序列缓存。
   */
  function tick() {
    if (stopped) {
      return;
    }
    if (current && performance.now() - received + age > period * 3) {
      clear("当前样本已过期，等待新采样。");
    }
    if (performance.now() >= due) {
      void refresh();
    }
    timer = setTimeout(tick, 250);
  }

  /**
   * 业务作用：切换范围或搜索后丢弃旧分页身份，避免另一工作区迟到回填。
   * 参数说明：
   * - `event`：表单或范围变更事件。
   * 返回：当前查询从新首页重新采样。
   */
  function reset(event) {
    event?.preventDefault();
    offset = 0;
    invalidate("正在读取当前范围…");
    void refresh();
  }

  /**
   * 业务作用：从当前完整页携带条件继续翻页，不能把不同采样拼为一个目录。
   * 参数说明：
   * - `target`：当前页提供或由已知页大小计算的下一起点。
   * 返回：取消旧请求并按原样本条件读取目标页。
   */
  function move(target) {
    const condition = etag;
    invalidate("正在读取同一样本页面…");
    etag = condition;
    offset = target;
    void refresh();
  }

  /**
   * 业务作用：暂停立即撤下实时事实，恢复必须重新取样而非延用暂停前的当前值。
   * 参数说明: 无。
   * 返回：暂停态不发起网络请求，恢复从首页建立区间。
   */
  function toggle() {
    paused = !paused;
    pause.textContent = paused ? "继续" : "暂停";
    offset = 0;
    invalidate(paused ? "已暂停，当前值已清空。" : "正在恢复当前采样…");
    void refresh();
  }

  /**
   * 业务作用：隐藏页不继续持有显示权或观察兴趣，返回页面后只取新事实。
   * 参数说明: 无。
   * 返回：取消在途请求并清空当前行，重新可见时恢复采样。
   */
  function visibility() {
    offset = 0;
    invalidate(
      document.hidden ? "页面已隐藏，当前值已清空。" : "正在恢复当前采样…",
    );
    void refresh();
  }

  toolbar.addEventListener("submit", reset);
  scope.addEventListener("change", reset);
  limit.addEventListener("change", reset);
  pause.addEventListener("click", toggle);
  previous.addEventListener("click", () => {
    move(Math.max(0, offset - Number(limit.value)));
  });
  next.addEventListener("click", () => {
    if (nextOffset !== null) {
      move(nextOffset);
    }
  });
  document.addEventListener("visibilitychange", visibility);
  clear("正在读取当前路由流量…");
  tick();

  /**
   * 业务作用：撤销整个页面的所有观察权，退出后不再保留指标、对象名称或网络请求。
   * 参数说明: 无。
   * 返回：清空计时器、监听器和页面，迟到响应保持无效。
   */
  return function dispose() {
    stopped = true;
    invalidate("");
    clearTimeout(timer);
    document.removeEventListener("visibilitychange", visibility);
    root.replaceChildren();
  };
}
