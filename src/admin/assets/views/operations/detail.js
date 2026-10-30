import { element } from "../../core/dom.js";
import { field } from "./form.js";
import { baselineDescription } from "./targets.js";
import { renderExecution } from "./execution.js";
import { previewView } from "./preview.js";

/**
 * 业务作用：展示一个集群提案的真实审阅状态，并要求读取原文后才允许确认审阅。
 * 参数说明：
 * - `root`：当前详情的唯一显示容器。
 * - `record`：已授权的低敏持久记录。
 * - `access`：当前范围的动作位及主体身份。
 * - `load`：加载该记录原文并核对页面代的协调回调。
 * - `review`：按原摘要提交一次审阅的协调回调。
 * - `execute`：按原摘要创建一次持久执行的协调回调。
 * - `preview`：显式读取全部原目标短期差异的协调回调。
 * 返回：锁定和清空详情的句柄；离开时撤销所有迟到回填资格。
 */
export function proposalDetail(
  root,
  record,
  access,
  load,
  review,
  execute,
  preview,
) {
  let alive = true;
  let busy = false;
  let loaded = false;
  const body = element("pre", "", "proposal-source");
  body.hidden = true;
  const checked = element("input");
  checked.type = "checkbox";
  checked.disabled = true;
  const agreement = field("我已阅读原文并确认下面的 SHA-256 摘要", checked);
  agreement.className = "proposal-check";
  const open = element("button", "读取候选原文");
  open.type = "button";
  const actions = element("div", "", "monitor-toolbar");
  const buttons = [];
  const progress = element("section", "", "proposal-execution");
  const previewRoot = element("section", "", "proposal-preview");
  const previewPanel = previewView(previewRoot, record);
  const previewButton = element("button", "预览全部原目标差异");
  previewButton.type = "button";
  const executeButton = element("button", "执行已批准提案");
  executeButton.type = "button";
  const canRead =
    access.review || (access.write && record.creator === access.principal);
  open.hidden = !canRead;
  root.replaceChildren(
    element("h2", `提案 ${record.id}`),
    element(
      "p",
      `状态：${record.status} · 创建者：${record.creator} · 审阅者：${record.reviewer ?? "尚无"}`,
    ),
    element(
      "p",
      `受理代际：${record.admission_epoch} · 首次执行创建截止：${new Date(record.expires_at_ms).toLocaleString()}`,
    ),
    element("p", `候选 SHA-256：${record.candidate_sha256}`, "proposal-digest"),
    element(
      "p",
      "审阅记录不表示目标已预检或配置已生效。原文可能包含敏感配置，只在当前页面内存中显示。",
      "subtle",
    ),
  );
  if (record.execution_started) {
    root.append(
      element(
        "p",
        "执行已创建；提案期限不撤回原执行，当前进度按原目标持续读取。",
        "subtle",
      ),
    );
  }
  const targets = element("ul");
  for (const target of record.targets) {
    const row = element("li");
    row.append(
      element(
        "p",
        `${target.node_id} · 启动 ${target.boot_id} · 基线 ${target.base_version} / ${target.base_fingerprint}`,
      ),
      element("p", baselineDescription(target), "proposal-digest"),
    );
    targets.append(row);
  }
  root.append(
    element("h3", "声明的目标意图"),
    targets,
    open,
    body,
    agreement,
    actions,
    progress,
    previewButton,
    previewRoot,
  );
  if (!canRead) {
    root.append(
      element(
        "p",
        "当前主体只能读取提案元数据，没有候选原文或审阅权限。",
        "subtle",
      ),
    );
  }
  previewButton.addEventListener("click", () => {
    if (
      alive &&
      !busy &&
      access.preview_ready &&
      access.preview_allowed &&
      !record.execution_started &&
      ["awaiting_approval", "approved"].includes(record.status)
    ) {
      previewPanel.pending();
      preview(record);
    }
  });
  actions.append(executeButton);
  executeButton.addEventListener("click", () => {
    if (
      alive &&
      loaded &&
      checked.checked &&
      !busy &&
      access.write &&
      access.execution_ready &&
      !access.execution_pending &&
      record.status === "approved" &&
      !record.execution_started
    ) {
      execute(record);
    }
  });
  for (const [decision, title, allowed] of [
    [
      "approve",
      "批准提案",
      access.review && record.creator !== access.principal,
    ],
    [
      "reject",
      "拒绝提案",
      access.review && record.creator !== access.principal,
    ],
    [
      "cancel",
      "取消自己的提案",
      access.write && record.creator === access.principal,
    ],
  ]) {
    if (!allowed || record.status !== "awaiting_approval") {
      continue;
    }
    const button = element("button", title);
    button.type = "button";
    button.addEventListener("click", () => {
      if (
        alive &&
        loaded &&
        checked.checked &&
        !busy &&
        access.accept_proposals &&
        allowedDecision(decision)
      ) {
        review(record, decision);
      }
    });
    actions.append(button);
    buttons.push({
      button,

      decision,
    });
  }

  /**
   * 业务作用：使审阅按钮依赖原文、摘要确认及当前动作资格，禁用期间不留重复提交入口。
   * 参数说明: 无。
   * 返回：更新当前详情控件；执行资格和提案受理开关保持独立。
   */
  function update() {
    previewButton.hidden =
      !access.preview_supported ||
      !access.preview_allowed ||
      record.execution_started ||
      !["awaiting_approval", "approved"].includes(record.status);
    previewButton.disabled = busy || !alive || !access.preview_ready;
    open.disabled = busy || !alive;
    checked.disabled = busy || !loaded || !alive;
    executeButton.hidden =
      !access.execution_supported ||
      !access.write ||
      record.status !== "approved" ||
      record.execution_started;
    executeButton.disabled =
      busy ||
      !alive ||
      !loaded ||
      !checked.checked ||
      !access.execution_ready ||
      access.execution_pending;
    for (const { button, decision } of buttons) {
      button.disabled =
        busy ||
        !loaded ||
        !checked.checked ||
        !alive ||
        !access.accept_proposals ||
        !allowedDecision(decision);
    }
  }

  /**
   * 业务作用：按最新范围权限限制审阅或本人取消，旧按钮不能保留已经撤销的资格。
   * 参数说明：
   * - `decision`：当前按钮绑定的有限审阅动作。
   * 返回：当前主体仍具对应权限且符合双人约束时为真。
   */
  function allowedDecision(decision) {
    if (decision === "cancel") {
      return access.write && record.creator === access.principal;
    }
    return access.review && record.creator !== access.principal;
  }

  /**
   * 业务作用：显式取得原文后核对不可变摘要，读取失败或页面退休不恢复敏感内容。
   * 参数说明: 无。
   * 返回：只在当前详情仍有效且响应摘要匹配时显示原文。
   */
  async function showSource() {
    if (!alive || busy) {
      return;
    }
    loaded = false;
    checked.checked = false;
    body.textContent = "";
    body.hidden = true;
    update();
    const value = await load(record);
    if (!alive || !value) {
      return;
    }
    body.textContent = value;
    body.hidden = false;
    loaded = true;
    update();
  }

  /**
   * 业务作用：在页面协调器已有请求时禁止重复原文读取和审阅动作。
   * 参数说明：
   * - `locked`：当前是否有尚未结束的管理请求。
   * 返回：更新控件状态，不清除已经确认的持久事实。
   */
  function lock(locked) {
    busy = locked;
    update();
  }

  /**
   * 业务作用：退出详情时立即清空原文和确认状态，使旧网络响应不再具有显示权威。
   * 参数说明: 无。
   * 返回：容器和正文引用清空，后续回调不会重新挂载旧候选。
   */
  function clear() {
    alive = false;
    previewPanel.clear();
    loaded = false;
    checked.checked = false;
    body.textContent = "";
    body.hidden = true;
    root.replaceChildren();
    update();
  }

  /**
   * 业务作用：从最新范围响应更新执行资格，候选原文读取权丢失时立即清空原文和确认。
   * 参数说明：
   * - `current`：同一范围的最新权限与执行能力。
   * 返回：撤销过时按钮资格，不延用已经丢失的原文读取权。
   */
  function authorize(current) {
    access = {
      ...access,

      ...current,
    };
    if (!access.preview_ready || !access.preview_allowed) {
      previewPanel.clear();
    }
    open.hidden = !(
      access.review ||
      (access.write && record.creator === access.principal)
    );
    if (!(
      access.review ||
      (access.write && record.creator === access.principal)
    )) {
      loaded = false;
      checked.checked = false;
      body.textContent = "";
      body.hidden = true;
      open.hidden = true;
    }
    update();
  }

  /**
   * 业务作用：仅向仍有效的原提案详情发布一致执行进度。
   * 参数说明：
   * - `value`：当前请求取得的完整目标视图。
   * 返回：更新实时事实，退出后不恢复旧内容。
   */
  function execution(value) {
    if (alive) {
      renderExecution(progress, record, value);
    }
  }

  checked.addEventListener("change", update);
  open.addEventListener("click", showSource);
  update();
  return {
    lock,

    clear,

    authorize,

    execution,

    /**
     * 业务作用：只向仍有效的原详情交付短期完整差异，退出后不得重新挂载。
     * 参数说明：
     * - `value`：本次全部原目标的服务端结果。
     * 返回：更新当前预览并设置到期清除。
     */

    preview(value) {
      if (alive) {
        previewPanel.show(value);
      }
    },
  };
}
