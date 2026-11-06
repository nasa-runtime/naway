import { element } from "../../core/dom.js";
import {
  button,
  fact,
  field,
  hex,
  logical,
  sameOriginal,
  showCertificate,
  targetKey,
} from "./common.js";
import { checkedSources, showSources } from "./conditions.js";

/**
 * 业务作用：核对完整影响仍绑定原材料、全部目标和每份原来源，部分成功不能成为可审阅对象。
 * 参数说明：
 * - `impact`：服务端保存的唯一完整影响。
 * - `record`：当前材料原记录。
 * - `cluster`：当前共享集群。
 * - `scope`：当前精确材料范围。
 * 返回：完整原影响；身份、目标、来源或分母不一致时整份拒绝。
 */
export function checkedImpact(impact, record, cluster, scope) {
  const proof = impact?.proof;
  if (
    !hex(impact?.id, 32) ||
    impact.proposal_id !== record.id ||
    impact.cluster_id !== cluster ||
    impact.scope !== scope ||
    !hex(impact.impact_sha256) ||
    proof?.schema !== 1 ||
    proof.certificate?.certificate_sha256 !==
      record.certificate.certificate_sha256 ||
    proof.certificate?.leaf_sha256 !== record.certificate.leaf_sha256 ||
    !Array.isArray(proof.targets) ||
    proof.targets.length !== record.targets.length ||
    !Array.isArray(proof.nodes) ||
    !proof.nodes.length ||
    proof.nodes.length > record.targets.length
  ) {
    throw new Error("完整影响不属于当前材料，或没有覆盖全部原目标。");
  }
  for (const [index, target] of proof.targets.entries()) {
    const original = record.targets[index];
    if (
      !logical(target?.target) ||
      targetKey(target) !== targetKey(original) ||
      !sameOriginal(target, original) ||
      target.certificate_etag !== original.certificate_etag ||
      target.material_generation !== original.material_generation
    ) {
      throw new Error("影响证明中的原材料条件与提案不一致。");
    }
  }
  const seen = new Set();
  const nodes = new Set();
  for (const node of proof.nodes) {
    if (
      nodes.has(node.node_id) ||
      !hex(node.impact_sha256) ||
      !Array.isArray(node.target_indices) ||
      !node.target_indices.length
    ) {
      throw new Error("完整影响的原节点分组不合法。");
    }
    nodes.add(node.node_id);
    const sources = checkedSources(node.conditions, node.target_indices.length);
    for (const [offset, index] of node.target_indices.entries()) {
      const target = record.targets[index];
      const group = sources.groups[sources.entries[offset].group];
      if (
        !Number.isInteger(index) ||
        !target ||
        target.node_id !== node.node_id ||
        seen.has(index) ||
        target.certificate_etag !== group.certificate_etag ||
        target.material_generation !== group.material_generation ||
        !group.affected.some(
          (item) =>
            item.source_id === group.source_id &&
            targetKey({
              node_id: node.node_id,
              target: item.target,
            }) === targetKey(target),
        )
      ) {
        throw new Error("完整影响的来源索引遗漏或替换了原目标。");
      }
      seen.add(index);
    }
  }
  if (seen.size !== record.targets.length) {
    throw new Error("完整影响遗漏原目标，不能进行审阅或执行。");
  }
  return impact;
}

/**
 * 业务作用：呈现全部共享来源后独立确认影响审批与执行，旧pair批准不能自动升级为完整影响批准。
 * 参数说明：
 * - `root`：当前材料详情的影响容器。
 * - `record`：完整原材料记录。
 * - `context`：当前主体与材料、影响、执行的独立能力。
 * - `actions`：页面协调的读取、登记、审阅及执行动作。
 * 返回：同一原详情的展示和锁定句柄；隐藏或退出时撤销确认资格。
 */
export function impactView(root, record, context, actions) {
  let alive = true;
  let busy = false;
  let current = null;
  let loaded = false;
  const status = element("p", "尚未读取完整影响。", "subtle");
  const body = element("div");
  const confirmed = element("input");
  confirmed.type = "checkbox";
  const approval = field(
    "我已核对全部原目标、每份共享来源、所有受影响对象和完整影响 SHA-256",
    confirmed,
  );
  approval.className = "proposal-check";
  const executionAvailability = element("p", "", "subtle");
  const read = button("读取完整影响", () => {
    if (alive && !busy && !document.hidden) {
      retire();
      actions.read(record);
    }
  });
  const register = button("为原材料登记完整影响", () => {
    if (alive && !busy && !document.hidden && !register.disabled) {
      actions.register(record);
    }
  });
  const execute = button("执行此完整批准", () => {
    if (alive && !busy && !document.hidden && !execute.disabled) {
      actions.execute(record, current);
    }
  });
  const reviews = [
    ["approve", "批准完整影响"],
    ["reject", "拒绝完整影响"],
    ["cancel", "取消自己登记的影响"],
  ].map(([decision, title]) => {
    const control = button(title, () => {
      if (alive && !busy && !document.hidden && !control.disabled) {
        actions.review(record, current, decision);
      }
    });
    return {
      decision,
      control,
    };
  });
  const controls = element("div", "", "monitor-toolbar");
  controls.append(
    read,
    register,
    ...reviews.map((value) => value.control),
    execute,
  );
  root.replaceChildren(
    element("h3", "完整共享影响与执行"),
    status,
    body,
    approval,
    executionAvailability,
    controls,
  );

  /**
   * 业务作用：使审批与执行分别依赖当前权限、完整原记录和显式确认，来源失效或未知操作立即关闭新动作。
   * 参数说明: 无。
   * 返回：更新动作状态；原记录查询不依赖新执行开关。
   */
  function update() {
    const active = alive && !busy;
    const readable = context.impact?.access?.read === true;
    if (!readable) {
      status.textContent =
        "当前完整影响功能不可用或没有读取资格；材料pair批准不能替代完整影响批准。";
    }
    executionAvailability.textContent = !context.execution?.execution_supported
      ? "当前节点不支持共享材料执行。"
      : !context.execution?.can_request_execution
        ? "当前不能创建新执行；已有原任务仍可查询。"
        : "只有材料pair与完整影响分别批准后，才能明确发起执行。";
    const write = context.impact?.access?.write === true;
    const review = context.impact?.access?.review === true;
    const originalActive =
      ["awaiting_approval", "approved"].includes(record.status) &&
      Date.now() < record.expires_at_ms;
    const awaiting =
      current?.status === "awaiting_approval" &&
      current.parent_active === true &&
      Date.now() < current.expires_at_ms;
    read.disabled = !active || !readable;
    register.disabled =
      !active ||
      !write ||
      !context.impact?.accept_proposals ||
      !loaded ||
      current !== null ||
      !originalActive ||
      context.pending;
    confirmed.disabled = !active || !current || !readable;
    for (const { decision, control } of reviews) {
      const allowed =
        decision === "cancel"
          ? write && current?.creator === context.principal
          : review &&
            current?.creator !== context.principal &&
            current?.material_creator !== context.principal;
      control.disabled =
        !active ||
        !awaiting ||
        !allowed ||
        !confirmed.checked ||
        context.pending;
    }
    execute.disabled =
      !active ||
      !confirmed.checked ||
      record.status !== "approved" ||
      current?.status !== "approved" ||
      current.parent_active !== true ||
      context.execution?.can_request_execution !== true ||
      context.pending ||
      !originalActive;
  }

  /**
   * 业务作用：只向仍有效的详情交付完整原影响，展示所有来源后重新要求明确确认。
   * 参数说明：
   * - `impact`：已由协调器核对原材料及完整分母的影响记录。
   * 返回：替换公开详情；不存在时只说明当前未找到，不断言在途登记已回滚。
   */
  function show(impact) {
    if (!alive) {
      return;
    }
    current = impact;
    loaded = true;
    confirmed.checked = false;
    body.replaceChildren();
    if (!current) {
      status.textContent =
        "本次未找到完整影响；未找到不证明另一在途登记已回滚。";
      update();
      return;
    }
    status.textContent = `完整影响 ${current.id} · ${current.status}；材料 ${current.material_status}。`;
    fact(body, "影响登记者", current.creator);
    fact(body, "材料创建者", current.material_creator);
    fact(body, "影响审阅者", current.reviewer ?? "尚无");
    fact(body, "完整影响 SHA-256", current.impact_sha256);
    fact(body, "原受理代", current.admission_epoch);
    fact(body, "父材料可继续审批", current.parent_active ? "是" : "否");
    showCertificate(body, current.proof.certificate);
    for (const node of current.proof.nodes) {
      const section = element("section");
      section.append(
        element(
          "h4",
          `${node.node_id} · 原目标索引 ${node.target_indices.join(" / ")}`,
        ),
      );
      fact(section, "节点影响 SHA-256", node.impact_sha256);
      for (const [offset, reference] of node.conditions.entries.entries()) {
        const target =
          current.proof.targets[node.target_indices[offset]].target;
        fact(
          section,
          `${target.kind}/${target.listener}/${target.entry}`,
          `${reference.source} · 来源 ${reference.group + 1}`,
        );
      }
      showSources(section, node.conditions);
      body.append(section);
    }
    update();
  }

  /**
   * 业务作用：在重读、失败或失权时撤去旧影响和确认，迟到状态不能借旧按钮发起动作。
   * 参数说明: 无。
   * 返回：完整影响与审批资格清空，不改变服务端持久记录。
   */
  function retire() {
    current = null;
    loaded = false;
    confirmed.checked = false;
    body.replaceChildren();
    status.textContent = "请读取当前完整影响后再确认。";
    update();
  }

  /**
   * 业务作用：把页面当前权限和并发门传播到影响详情，权限失效撤销原确认。
   * 参数说明：
   * - `value`：同范围材料、影响、执行能力及当前主体。
   * - `locked`：页面请求是否占用唯一交互链。
   * 返回：更新全部按钮；没有读权时清空公开影响。
   */
  function access(value, locked) {
    context = value;
    busy = locked;
    if (!context.impact?.access?.read) {
      retire();
    }
    update();
  }

  /**
   * 业务作用：退出原详情后撤去所有影响引用与确认，禁止后续回填。
   * 参数说明: 无。
   * 返回：容器与当前影响清空。
   */
  function clear() {
    alive = false;
    retire();
    root.replaceChildren();
  }

  confirmed.addEventListener("change", update);
  update();
  return {
    show,
    retire,
    access,
    clear,
  };
}
