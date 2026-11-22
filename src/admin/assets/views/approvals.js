import { element } from "../core/dom.js";
import { request } from "../core/http.js";

/**
 * 业务作用：展示有权限的配置审批，按原候选摘要单次复核，并区分执行回执与集群收敛。
 * 参数说明：
 * - `root`：当前视图容器。
 * - `session`：服务器确认的主体和权限。
 * 返回：离开页面时撤销在途显示资格，不重发审批或取消已提交动作。
 */
export function mount(root, session) {
  const panel = element("section", "", "panel");
  const toolbar = element("div", "", "monitor-toolbar");
  const refresh = element("button", "刷新审批队列");
  const observe = element("button", "读取原发布进度");
  refresh.type = "button";
  observe.type = "button";
  const status = element("p", "正在读取可见的审批元信息。", "subtle");
  status.setAttribute("role", "status");
  const list = element("div", "", "approval-list");
  const outcome = element("div", "", "configuration-progress");
  toolbar.append(refresh, observe);
  panel.append(
    element("h2", "配置审批队列"),
    element(
      "p",
      "候选原文不在此回读。批准必须由另一主体携带原摘要执行；回执未知时先核对原变更，不自动重发。",
      "subtle",
    ),
    toolbar,
    status,
    list,
    outcome,
  );
  root.append(panel);
  let alive = true;
  let generation = 0;
  let active = null;
  let timer = null;
  let rows = [];
  let rollout = "";
  const unknown = new Set();
  const canObserve = session.permissions?.cluster?.includes("read") === true;

  /**
   * 业务作用：按当前主体和在途请求更新按钮，不把页面资格当成服务端授权。
   * 参数说明: 无。
   * 返回：禁用隐藏或忙碌视图的动作；原回执未知的记录保持锁定。
   */
  function render() {
    const locked = !alive || document.hidden || active !== null;
    refresh.disabled = locked;
    observe.disabled = locked || !canObserve || !rollout;
    list.replaceChildren();
    if (!rows.length) {
      list.append(element("p", "当前没有可见审批记录。", "subtle"));
    }
    for (const row of [...rows].reverse()) {
      const item = element("article", "", "approval-record");
      item.append(
        element("h3", `${row.id} · ${row.resource}`),
        element(
          "p",
          `${row.initiator} · 基线 ${row.base_version} · ${row.status}`,
        ),
      );
      if (row.reason) {
        item.append(element("p", String(row.reason).slice(0, 512)));
      }
      if (unknown.has(row.id)) {
        item.append(
          element(
            "p",
            "此动作回执尚未确认，先刷新并核对原变更；不会自动重发。",
            "subtle",
          ),
        );
      }
      if (row.status === "pending") {
        const buttons = element("div", "", "monitor-toolbar");
        for (const action of ["approve", "reject"]) {
          const button = element(
            "button",
            action === "approve" ? "批准" : "拒绝",
          );
          button.type = "button";
          button.disabled =
            locked ||
            unknown.has(row.id) ||
            !session.permissions?.[row.resource]?.includes("write") ||
            (action === "approve" && row.initiator === session.principal);
          button.addEventListener("click", () => review(row, action));
          buttons.append(button);
        }
        item.append(buttons);
      }
      list.append(item);
    }
  }

  /**
   * 业务作用：使已离开或隐藏的页面失去交付资格，并撤下审批元信息与定时观察。
   * 参数说明: 无。
   * 返回：不改变后台已接受的审批或发布。
   */
  function retire() {
    generation += 1;
    active?.abort();
    active = null;
    clearTimeout(timer);
    timer = null;
    rows = [];
    rollout = "";
    unknown.clear();
    list.replaceChildren();
    outcome.replaceChildren();
    status.textContent = "审批信息已清空；恢复后请刷新原变更状态。";
    render();
  }

  /**
   * 业务作用：串行化视图请求并绑定当前页面代，使迟到响应不能回填已退休页面。
   * 参数说明：
   * - `work`：接收请求信号和页面代的操作。
   * 返回：仅当前可见页面处理结果；权限丢失立即清空。
   */
  async function run(work) {
    if (!alive || document.hidden || active !== null) {
      return;
    }
    const epoch = generation;
    const controller = new AbortController();
    active = controller;
    render();
    try {
      await work(controller.signal, epoch);
    } catch (error) {
      if (alive && epoch === generation && error.name !== "AbortError") {
        if ([401, 403].includes(error.status)) {
          retire();
        }
        status.textContent = error.message;
      }
    } finally {
      if (alive && generation === epoch && active === controller) {
        active = null;
        render();
      }
    }
  }

  /**
   * 业务作用：复验页面仍可交付结果，防止隐藏后的低敏元信息重新出现。
   * 参数说明：
   * - `epoch`：请求开始时的页面代。
   * 返回：当前且可见时正常返回，否则中止交付。
   */
  function current(epoch) {
    if (!alive || document.hidden || generation !== epoch) {
      throw new DOMException("页面已切换", "AbortError");
    }
  }

  /**
   * 业务作用：读取原权限过滤后的审批列表，终态观察不会生成新的审批请求。
   * 参数说明: 无。
   * 返回：更新可见元信息；失败不伪装为空列表。
   */
  function read() {
    return run(async (signal, epoch) => {
      const { data } = await request("/api/changes", { signal });
      current(epoch);
      if (
        data.ok !== true ||
        !Array.isArray(data.changes) ||
        data.changes.length > 4096
      ) {
        throw new Error("审批列表响应不完整或超出页面容量。");
      }
      rows = data.changes;
      for (const row of rows) {
        if (row.status !== "pending") {
          unknown.delete(row.id);
        }
      }
      status.textContent = `${rows.length} 条可见记录；仅待审批记录提供复核，提交者不能批准自己的变更。`;
    });
  }

  /**
   * 业务作用：以原候选身份和摘要发出一次复核，任何未知结果都先锁定同一记录。
   * 参数说明：
   * - `row`：当前读取的固定候选元信息。
   * - `action`：按钮限定的批准或拒绝。
   * 返回：显示真实执行回执；取得rollout身份后才可继续观察集群生效。
   */
  function review(row, action) {
    if (
      row.status !== "pending" ||
      unknown.has(row.id) ||
      !["approve", "reject"].includes(action) ||
      !session.permissions?.[row.resource]?.includes("write") ||
      (action === "approve" && row.initiator === session.principal) ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(row.id) ||
      !/^"sha256-[0-9a-f]{64}"$/.test(row.candidate_etag)
    ) {
      return;
    }
    return run(async (signal, epoch) => {
      clearTimeout(timer);
      timer = null;
      unknown.add(row.id);
      const { data } = await request(
        `/api/changes/${encodeURIComponent(row.id)}/${action}`,
        {
          method: "POST",
          headers: { "If-Match": row.candidate_etag },
          signal,
        },
      );
      current(epoch);
      if (data.ok !== true) {
        throw new Error("审批回执没有明确确认结果，请核对原变更。");
      }
      unknown.delete(row.id);
      row.status = action === "reject" ? "rejected" : "executed";
      rollout =
        typeof data.rollout_id === "string" &&
        /^[A-Za-z0-9_-]{1,128}$/.test(data.rollout_id)
          ? data.rollout_id
          : "";
      outcome.replaceChildren(
        element("h3", "原审批回执"),
        element("p", `变更：${row.id}`),
        element(
          "p",
          `响应状态：${String(data.status ?? action).slice(0, 128)}`,
        ),
      );
      if (rollout) {
        outcome.append(element("p", `发布身份：${rollout}`));
        status.textContent = "配置发布已受理；尚未确认全部节点生效。";
        if (canObserve) {
          timer = setTimeout(observeRollout, 1000);
        }
      } else {
        status.textContent =
          action === "reject"
            ? "原候选已拒绝；未执行配置发布。"
            : "审批动作已返回，请刷新原记录并核对当前配置。";
      }
    });
  }

  /**
   * 业务作用：只观察原审批回执中的发布身份，不把审批已执行当作集群收敛。
   * 参数说明: 无。
   * 返回：显示原rollout的真实状态，隐藏、终态或读取失败时停止自动观察。
   */
  function observeRollout() {
    clearTimeout(timer);
    timer = null;
    if (!canObserve || !rollout) {
      return;
    }
    return run(async (signal, epoch) => {
      const id = rollout;
      const { data } = await request(
        `/api/cluster/rollout?id=${encodeURIComponent(id)}`,
        { signal },
      );
      current(epoch);
      if (
        rollout !== id ||
        data.ok !== true ||
        data.rollout?.id !== id ||
        typeof data.converged !== "boolean"
      ) {
        throw new Error("发布进度与原审批回执不一致。");
      }
      status.textContent = data.converged
        ? "服务端已确认原发布的当前启用节点收敛。"
        : `原发布状态：${String(data.status).slice(0, 128)}；尚未确认全部生效。`;
      if (
        !data.converged &&
        ![
          "failed",
          "rejected",
          "rolled_back",
          "rollback_failed",
          "awaiting_approval",
        ].includes(data.status)
      ) {
        timer = setTimeout(observeRollout, 2000);
      }
    });
  }

  refresh.addEventListener("click", read);
  observe.addEventListener("click", observeRollout);
  document.addEventListener("visibilitychange", retire);
  read();
  return dispose;

  /**
   * 业务作用：注销审批视图并撤下在途响应的显示资格。
   * 参数说明: 无。
   * 返回：解除监听并移除页面，不撤销已提交的后台动作。
   */
  function dispose() {
    alive = false;
    retire();
    document.removeEventListener("visibilitychange", retire);
    panel.remove();
  }
}
