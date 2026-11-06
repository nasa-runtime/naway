import { element } from "../../core/dom.js";
import { button, fact, field, showCertificate, showTargets } from "./common.js";
import { impactView } from "./impact.js";
import { showExecution } from "./execution.js";

/**
 * 业务作用：区分材料pair审阅、完整影响审批和实际任务，所有写入都绑定当前原记录与明确确认。
 * 参数说明：
 * - `root`：原材料详情容器。
 * - `record`：已核对当前范围和全部目标的材料记录。
 * - `context`：同范围的当前主体、权限和独立功能能力。
 * - `actions`：由页面唯一请求链负责的读取、审阅、影响及执行回调。
 * 返回：详情授权、锁定、原影响与任务展示及退出句柄。
 */
export function materialDetail(root, record, context, actions) {
  let alive = true;
  let busy = false;
  const confirmed = element("input");
  confirmed.type = "checkbox";
  const agreement = field(
    "我已核对原材料公开证书摘要和全部冻结目标；本次pair审阅不批准实际交付",
    confirmed,
  );
  agreement.className = "proposal-check";
  const controls = element("div", "", "monitor-toolbar");
  const impactRoot = element("section");
  const progress = element("section", "", "proposal-execution");
  const readProgress = button("读取原任务进度", () => {
    if (alive && !busy && !document.hidden && !readProgress.disabled) {
      progress.replaceChildren(
        element("p", "正在读取原任务的完整进度…", "subtle"),
      );
      actions.progress(record);
    }
  });
  const reviews = [
    ["approve", "批准材料pair"],
    ["reject", "拒绝材料pair"],
    ["cancel", "取消自己创建的材料"],
  ].map(([decision, title]) => {
    const control = button(title, () => {
      if (alive && !busy && !document.hidden && !control.disabled) {
        actions.review(record, decision);
      }
    });
    controls.append(control);
    return {
      decision,
      control,
    };
  });
  root.replaceChildren(element("h2", `材料提案 ${record.id}`));
  fact(root, "材料状态", record.status);
  fact(root, "材料创建者", record.creator);
  fact(root, "pair审阅者", record.reviewer ?? "尚无");
  fact(root, "原受理代", record.admission_epoch);
  fact(root, "可审阅截止", new Date(record.expires_at_ms).toLocaleString());
  root.append(
    element(
      "p",
      "公开材料摘要不包含私钥。pair批准只保存审阅事实；实际交付还需要独立完整影响批准及明确执行。",
      "subtle",
    ),
  );
  showCertificate(root, record.certificate);
  showTargets(root, record.targets);
  root.append(agreement, controls, impactRoot, readProgress, progress);
  const impact = impactView(impactRoot, record, context, actions.impact);

  /**
   * 业务作用：把当前真实读写和双人约束应用到原pair审阅；过期或未知动作不产生新审阅入口。
   * 参数说明: 无。
   * 返回：更新所有动作状态，查询任务不依赖当前新执行开关。
   */
  function update() {
    const allowed = alive && !busy && !context.pending;
    const active =
      record.status === "awaiting_approval" &&
      Date.now() < record.expires_at_ms;
    confirmed.disabled = !allowed || !context.material?.access?.read || !active;
    readProgress.disabled =
      !alive ||
      busy ||
      !context.material?.access?.read ||
      !context.execution?.execution_supported;
    for (const { decision, control } of reviews) {
      const authority =
        decision === "cancel"
          ? context.material?.access?.write &&
            record.creator === context.principal
          : context.material?.access?.review &&
            record.creator !== context.principal;
      control.disabled =
        !allowed || !active || !authority || !confirmed.checked;
    }
  }

  /**
   * 业务作用：当前能力或请求状态变化时撤去过期动作资格，并同步影响详情。
   * 参数说明：
   * - `value`：同范围的最新主体与独立能力。
   * - `locked`：唯一交互链是否正在处理请求。
   * 返回：更新pair和影响动作；失去材料读权时清空整个详情。
   */
  function access(value, locked) {
    context = value;
    busy = locked;
    if (!context.material?.access?.read) {
      clear();
      return;
    }
    impact.access(value, locked);
    update();
  }

  /**
   * 业务作用：只向当前有效原详情交付完整任务进度，过期请求没有回填权。
   * 参数说明：
   * - `value`：已核对原提案、节点分母及四项效果的任务事实。
   * 返回：原任务公开进度完整替换，不触发任何任务动作。
   */
  function execution(value) {
    if (alive) {
      showExecution(progress, value);
    }
  }

  /**
   * 业务作用：任务读取失败或退到后台时撤去旧进度，失败不能保留为当前成功状态。
   * 参数说明：
   * - `reason`：当前固定的读取或生命周期说明。
   * 返回：撤下全部旧节点和协议事实。
   */
  function clearProgress(reason = "请重新读取原任务进度。") {
    progress.replaceChildren(element("p", reason, "subtle"));
  }

  /**
   * 业务作用：离开详情后撤销所有确认与显示权威，使旧影响或任务响应不能重新挂载。
   * 参数说明: 无。
   * 返回：完整详情清空，所有旧按钮失效。
   */
  function clear() {
    alive = false;
    confirmed.checked = false;
    impact.clear();
    root.replaceChildren();
    update();
  }

  confirmed.addEventListener("change", update);
  update();
  return {
    access,
    clear,
    impact,
    execution,
    clearProgress,
  };
}
