import { element } from "../../core/dom.js";

/**
 * 业务作用：展示全部原目标的当前执行与释放事实，业务终态不会覆盖未关闭的节点代际。
 * 参数说明：
 * - `root`：当前提案详情的进度容器。
 * - `record`：原提案身份、摘要和完整目标集合。
 * - `value`：同一数据库快照返回的低敏进度。
 * 返回：替换当前进度；身份、目标分母或步骤不一致时拒绝显示，缺失收据保留未知。
 */
export function renderExecution(root, record, value) {
  if (value.operation_id !== record.id) {
    throw new Error("执行身份与原提案不一致。");
  }
  if (value.execution_started === false && value.lifecycle === "not_started") {
    root.replaceChildren(
      element(
        "p",
        "尚无已提交的执行；此刻未找到不能证明此前在途请求已经回滚。",
        "subtle",
      ),
    );
    return;
  }
  if (
    value.execution_started !== true ||
    value.target_count !== record.targets.length ||
    !Array.isArray(value.targets) ||
    value.targets.length !== record.targets.length ||
    !Array.isArray(value.steps) ||
    value.steps.length !== record.targets.length * 2
  ) {
    throw new Error("执行目标分母或步骤不完整，不能显示完成比例。");
  }
  const list = element("div", "", "proposal-list");
  for (let index = 0; index < record.targets.length; index += 1) {
    const target = value.targets[index];
    const original = record.targets[index];
    if (
      target.target_index !== index ||
      target.node_id !== original.node_id ||
      target.boot_id !== original.boot_id ||
      target.node_baseline?.store_id !== original.node_baseline?.store_id ||
      target.node_baseline?.node_admission_epoch !==
        original.node_baseline?.node_admission_epoch
    ) {
      throw new Error("执行目标与原审批基线不一致。");
    }
    const row = element("article", "", "proposal-row");
    row.append(
      element("strong", target.node_id),
      element(
        "p",
        `Prepare：${target.prepare_outcome ?? "尚无确定收据"} · Apply：${target.apply_outcome ?? "尚无确定收据"}`,
      ),
      element(
        "p",
        `撤销 Apply：${target.apply_compensation ?? "尚无确定收据"} · 撤销 Prepare：${target.prepare_compensation ?? "尚无确定收据"}`,
      ),
      element(
        "p",
        target.released
          ? "原代际已关闭，占位已释放"
          : "原代际尚未确认关闭，占位保留",
      ),
    );
    for (const [step, expected] of [
      [value.steps[index], `prepare-${String(index).padStart(3, "0")}`],
      [
        value.steps[record.targets.length + index],
        `apply-${String(index).padStart(3, "0")}`,
      ],
    ]) {
      if (step.name !== expected) {
        throw new Error("执行步骤与原目标顺序不一致。");
      }
      row.append(
        element(
          "small",
          `${step.name} · 正向 ${step.forward} · 补偿 ${step.compensation} · 解决 ${step.resolution} · 取消 ${step.cancel}`,
        ),
      );
    }
    list.append(row);
  }
  const released = value.targets.filter(
    (target) => target.released === true,
  ).length;
  if (
    released !== value.released_count ||
    (value.lifecycle === "complete" && released !== value.target_count)
  ) {
    throw new Error("释放统计与完整目标事实不一致。");
  }
  root.replaceChildren(
    element("h3", "集群执行实时进度"),
    element(
      "p",
      `业务：${value.business_status} · 控制：${value.control_state} · 执行：${value.lifecycle}`,
    ),
    element(
      "p",
      `原目标 ${value.target_count} 个 · 已释放 ${released}/${value.target_count} · 当前步骤 ${value.current_step ?? "无"}`,
    ),
    element(
      "p",
      "此处显示原审批目标与持久效果；节点当前在线状态请在集群节点页查看。离线不等于拒绝，业务完成不等于全部代际已经释放。",
      "subtle",
    ),
    list,
  );
}
