import { element } from "../../core/dom.js";
import { fact, hex, logical, targetKey, token } from "./common.js";
import { checkedSources, showSources } from "./conditions.js";

const effects = [
  ["prepare", "forward"],
  ["apply", "forward"],
  ["prepare", "compensation"],
  ["apply", "compensation"],
];
const effectLabels = ["正向准备", "正向应用", "准备补偿", "应用补偿"];
const states = {
  unconfirmed: "尚未确认受理",

  admitted: "已受理，效果尚未确认",

  succeeded: "原稳定收据成功",

  rejected: "已确定拒绝",

  halted: "已停止并保留保护原因",

  not_admitted: "原动作已持久证明未受理",
};

/**
 * 业务作用：把原准备冻结的协议种类映射为完整协议分母，不能只按当前返回数量判断成功。
 * 参数说明：
 * - `required`：节点原报告中的协议组合。
 * 返回：精确协议顺序；缺失或未知组合拒绝。
 */
function protocols(required) {
  const values = {
    https: ["https"],

    https_and_http3: ["https", "http3"],

    stream_tls: ["stream_tls"],
  };
  if (!Object.hasOwn(values, required)) {
    throw new Error("实际执行缺少完整的原协议分母。");
  }
  return values[required];
}

/**
 * 业务作用：逐来源、共享对象和原协议核对成功收据，文件写入或单协议在线不能冒充全部安装成功。
 * 参数说明：
 * - `node`：一个原节点的完整任务投影。
 * - `effect`：原正向应用或应用补偿效果。
 * 返回：完整实际监听证据通过才继续展示；缺项或材料代不一致整体拒绝。
 */
function checkedEvidence(node, effect) {
  const evidence = effect.evidence;
  const groups = evidence?.observed?.groups;
  if (
    !token(evidence?.boot_id) ||
    !Array.isArray(groups) ||
    groups.length !== node.sources.groups.length ||
    !Array.isArray(node.required_protocols) ||
    node.required_protocols.length !== groups.length ||
    !Array.isArray(node.generations) ||
    node.generations.length !== groups.length
  ) {
    throw new Error("材料成功收据缺少完整来源或实际观察进程。");
  }
  for (const [index, group] of groups.entries()) {
    const source = node.sources.groups[index];
    const generation = node.generations[index];
    const goal =
      effect.direction === "forward" ? generation.forward : generation.backward;
    const required = node.required_protocols[index];
    if (
      generation.source_id !== source.source_id ||
      !hex(goal) ||
      goal === source.material_generation ||
      !Array.isArray(group.targets) ||
      group.targets.length !== source.affected.length ||
      !Array.isArray(required) ||
      required.length !== source.affected.length
    ) {
      throw new Error("材料成功收据改变了原来源分母或目标材料代。");
    }
    for (const [position, target] of group.targets.entries()) {
      const expected = protocols(required[position]);
      if (
        !Array.isArray(target.protocols) ||
        target.protocols.length !== expected.length ||
        target.protocols.some(
          (value, offset) =>
            value.protocol !== expected[offset] ||
            value.state !== "different_material" ||
            value.material_generation !== goal ||
            !Number.isInteger(value.bindings) ||
            value.bindings <= 0,
        )
      ) {
        throw new Error("实际监听收据没有完整覆盖原协议与目标材料代。");
      }
    }
  }
}

/**
 * 业务作用：验证执行详情仍覆盖原材料全部逻辑目标和物理节点，所有效果保持独立历史。
 * 参数说明：
 * - `data`：原提案execution接口的完整响应。
 * - `record`：原材料记录。
 * - `cluster`：当前共享集群。
 * - `scope`：当前唯一材料范围。
 * 返回：完整任务或明确尚未找到；异常分母不交付局部成功视图。
 */
export function checkedExecution(data, record, cluster, scope) {
  if (
    data?.schema_version !== 1 ||
    data.cluster_id !== cluster ||
    data.scope !== scope ||
    data.proposal_id !== record.id ||
    typeof data.execution_started !== "boolean"
  ) {
    throw new Error("材料执行响应不属于当前原提案。");
  }
  if (!data.execution_started && data.execution === null) {
    return null;
  }
  const value = data.execution;
  if (
    !data.execution_started ||
    !hex(value?.operation_id, 32) ||
    !hex(value.impact_id, 32) ||
    !["running", "releasing", "halted", "complete"].includes(value.lifecycle) ||
    (["running", "halted"].includes(value.lifecycle)
      ? value.terminal !== null
      : !["completed", "compensated"].includes(value.terminal)) ||
    value.target_count !== record.targets.length ||
    !Array.isArray(value.nodes) ||
    !value.nodes.length ||
    value.nodes.length !== value.node_count ||
    value.nodes.length !==
      new Set(record.targets.map((target) => target.node_id)).size ||
    !Array.isArray(value.steps) ||
    value.steps.length > 256
  ) {
    throw new Error("执行任务没有返回完整原节点与逻辑目标分母。");
  }
  const selected = new Set();
  const members = new Set();
  for (const [position, node] of value.nodes.entries()) {
    if (
      !token(node.node_id) ||
      members.has(node.node_id) ||
      node.node_index !== position ||
      !Array.isArray(node.selections) ||
      !node.selections.length ||
      !Array.isArray(node.effects) ||
      node.effects.length !== 4 ||
      typeof node.reported !== "boolean" ||
      typeof node.released !== "boolean" ||
      (node.released && !["releasing", "complete"].includes(value.lifecycle)) ||
      (!node.released && value.lifecycle === "complete")
    ) {
      throw new Error("执行任务的节点位置或四项效果不完整。");
    }
    members.add(node.node_id);
    checkedSources(node.sources, node.selections.length);
    for (const [offset, selection] of node.selections.entries()) {
      const target = record.targets[selection.index];
      const source = node.sources.groups[node.sources.entries[offset].group];
      if (
        !Number.isInteger(selection.index) ||
        !target ||
        selected.has(selection.index) ||
        !logical(selection.target) ||
        node.original_boot_id !== target.boot_id ||
        targetKey({
          node_id: node.node_id,
          target: selection.target,
        }) !== targetKey(target) ||
        source.certificate_etag !== target.certificate_etag ||
        source.material_generation !== target.material_generation
      ) {
        throw new Error("执行原目标或原材料条件与提案不一致。");
      }
      selected.add(selection.index);
    }
    for (const [index, effect] of node.effects.entries()) {
      if (
        effect.step !== effects[index][0] ||
        effect.direction !== effects[index][1] ||
        !Object.hasOwn(states, effect.state)
      ) {
        throw new Error("执行效果身份不完整，不能合并正向与补偿结果。");
      }
      if (effect.step === "apply" && effect.state === "succeeded") {
        checkedEvidence(node, effect);
      } else if (effect.evidence !== null) {
        throw new Error("非应用成功效果不能携带替代监听收据。");
      }
    }
  }
  if (
    selected.size !== record.targets.length ||
    value.reported_count !==
      value.nodes.filter((node) => node.reported).length ||
    value.released_count !== value.nodes.filter((node) => node.released).length
  ) {
    throw new Error("执行任务的完整目标或报告计数不一致。");
  }
  return value;
}

/**
 * 业务作用：展示原稳定收据中的真实boot、每个共享对象与全部协议，不用当前节点观察覆盖历史事实。
 * 参数说明：
 * - `root`：当前效果的展示容器。
 * - `node`：原节点的完整来源和协议分母。
 * - `effect`：已经核对完整证据的应用效果。
 * 返回：完整协议与材料代的纯文本详情。
 */
function showEvidence(root, node, effect) {
  const evidence = effect.evidence;
  fact(root, "实际观察启动", evidence.boot_id);
  for (const [index, group] of evidence.observed.groups.entries()) {
    const source = node.sources.groups[index];
    const section = element("details");
    section.append(element("summary", `来源 ${index + 1} 的全部实际协议`));
    fact(section, "来源身份", source.source_id);
    for (const [position, target] of group.targets.entries()) {
      const affected = source.affected[position].target;
      section.append(
        element(
          "h5",
          `${affected.kind}/${affected.listener}/${affected.entry}`,
        ),
      );
      for (const observation of target.protocols) {
        const row = element("article", "", "proposal-row");
        fact(row, "协议", observation.protocol);
        fact(row, "原收据状态", observation.state);
        fact(row, "真实选证绑定数", observation.bindings);
        fact(row, "实际加载材料代", observation.material_generation);
        section.append(row);
      }
    }
    root.append(section);
  }
}

/**
 * 业务作用：完整呈现原任务、全部节点、四项效果和释放责任，未知受理不能被后来的补偿成功覆盖。
 * 参数说明：
 * - `root`：原详情的执行容器。
 * - `value`：已经完整验证的任务或明确缺席。
 * 返回：替换当前公开任务事实，不发起执行、补偿或强制释放。
 */
export function showExecution(root, value) {
  root.replaceChildren(element("h3", "原任务执行进度"));
  if (!value) {
    root.append(
      element(
        "p",
        "本次未找到执行任务；未找到不证明另一在途创建已回滚。",
        "subtle",
      ),
    );
    return;
  }
  fact(root, "原任务", value.operation_id);
  fact(root, "原完整影响", value.impact_id);
  fact(
    root,
    "逻辑目标 / 物理节点",
    `${value.target_count} / ${value.node_count}`,
  );
  fact(
    root,
    "已有报告 / 已释放节点",
    `${value.reported_count} / ${value.released_count}`,
  );
  for (const [key, title] of [
    ["lifecycle", "保留生命周期"],
    ["terminal", "持久终态"],
    ["business_status", "工作流业务状态"],
    ["control_state", "工作流控制状态"],
    ["direction", "工作流方向"],
    ["current_step", "当前步骤"],
    ["instance_version", "实例版本"],
    ["control_version", "控制版本"],
  ]) {
    fact(root, title, value[key]);
  }
  for (const node of value.nodes) {
    const section = element("section", "", "proposal-row");
    section.append(
      element(
        "h4",
        `${node.node_index + 1} / ${value.node_count} · ${node.node_id}`,
      ),
    );
    fact(section, "原启动", node.original_boot_id);
    fact(
      section,
      "原逻辑目标索引",
      node.selections.map((selection) => selection.index).join(" / "),
    );
    fact(
      section,
      "完整报告",
      node.reported
        ? `已保存 · 修订 ${node.report_revision}`
        : "尚无报告，不能推定未受理",
    );
    fact(
      section,
      "原节点阶段 / 方向",
      `${node.stage ?? "未知"} / ${node.direction ?? "未知"}`,
    );
    fact(section, "保护原因", node.protection ?? "未报告保护原因");
    fact(section, "终态释放", node.released ? "已确认" : "尚未确认");
    showSources(section, node.sources);
    for (const [index, source] of node.sources.groups.entries()) {
      const plan = element("details");
      plan.append(element("summary", `来源 ${index + 1} 的原协议与预分配代`));
      fact(
        plan,
        "正向材料代",
        node.generations?.[index]?.forward ?? "尚未报告",
      );
      fact(
        plan,
        "补偿材料代",
        node.generations?.[index]?.backward ?? "尚未分配或报告",
      );
      for (const [position, affected] of source.affected.entries()) {
        fact(
          plan,
          `${affected.target.kind}/${affected.target.listener}/${affected.target.entry}`,
          node.required_protocols?.[index]?.[position] ?? "原协议分母尚未报告",
        );
      }
      section.append(plan);
    }
    for (const [index, effect] of node.effects.entries()) {
      const row = element("details");
      row.append(
        element("summary", `${effectLabels[index]} · ${states[effect.state]}`),
      );
      fact(row, "原效果原因", effect.reason ?? "未报告原因");
      if (effect.evidence) {
        showEvidence(row, node, effect);
      }
      section.append(row);
    }
    root.append(section);
  }
  const workflow = element("details");
  workflow.append(
    element("summary", `工作流全部步骤（${value.steps.length}）`),
  );
  for (const step of value.steps) {
    const row = element("article", "", "proposal-row");
    row.append(element("strong", `${step.ordinal} · ${step.name}`));
    for (const [key, title] of [
      ["forward", "正向"],
      ["compensation", "补偿"],
      ["resolution", "未知结果解析"],
      ["cancel", "取消"],
    ]) {
      fact(row, title, step[key]);
    }
    workflow.append(row);
  }
  root.append(workflow);
}
