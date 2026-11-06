import { element } from "../../core/dom.js";
import {
  button,
  fact,
  field,
  logical,
  original,
  sameOriginal,
  targetKey,
  token,
} from "./common.js";
import { conditionNodes, freezeConditions, showSources } from "./conditions.js";

/**
 * 业务作用：从完整授权节点分母选择原声明，再通过真实条件查询冻结材料代，不开放自由路径或JSON目标输入。
 * 参数说明：
 * - `cluster`：共享材料存储绑定的集群。
 * - `scope`：当前精确材料范围的读取函数。
 * - `load`：在页面唯一请求链中读取节点清单或原节点目标。
 * - `inspect`：查询已选全部原目标的真实材料条件。
 * - `changed`：选中集合或冻结状态改变后同步提交资格。
 * 返回：有界目标选择、条件冻结和完整清空句柄；目录过期不会自动替换原目标。
 */
export function materialTargets(cluster, scope, load, inspect, changed) {
  const root = element("section", "", "proposal-picker");
  const status = element(
    "p",
    "请读取当前范围的节点，逐项选择材料目标。",
    "subtle",
  );
  status.setAttribute("role", "status");
  const observed = element("div", "", "proposal-members");
  const selected = element("div", "", "proposal-targets");
  const conditions = element("div");
  let rows = [];
  let frozen = null;
  let timer = null;
  let deadline = 0;
  let readable = false;
  let writable = false;
  let locked = true;
  let observedActions = [];
  const read = button("读取材料节点", () => {
    if (readable && !locked && !document.hidden) {
      clearObserved("正在读取当前范围的完整节点清单…");
      load("");
    }
  });
  const query = button("查询并冻结全部原材料条件", () => {
    if (writable && !locked && rows.length && !document.hidden) {
      clearConditions();
      inspect(rows.slice());
    }
  });
  root.append(
    element("h3", "原节点与材料目标"),
    read,
    status,
    observed,
    selected,
    query,
    conditions,
  );

  /**
   * 业务作用：撤去目录的有限显示权威，已经冻结的原意图保持原样。
   * 参数说明：
   * - `reason`：当前目录不可用或过期的业务说明。
   * 返回：清空可选观察并取消期限计时，不产生新网络请求。
   */
  function clearObserved(reason = "请重新读取材料节点。") {
    clearTimeout(timer);
    timer = null;
    deadline = 0;
    observedActions = [];
    observed.replaceChildren();
    status.textContent = reason;
  }

  /**
   * 业务作用：目标集合变化后撤销旧来源条件，禁止把旧查询结果拼接到新声明。
   * 参数说明: 无。
   * 返回：提交资格撤回，公开来源详情清空。
   */
  function clearConditions() {
    frozen = null;
    conditions.replaceChildren();
    changed(false);
  }

  /**
   * 业务作用：根据真实读写资格与页面并发门更新所有交互入口。
   * 参数说明：
   * - `canRead`：当前材料域的读取资格。
   * - `canWrite`：当前材料域的提交资格。
   * - `busy`：页面是否正在处理另一请求。
   * 返回：失去读取资格时撤下观察，忙碌或只读时不能修改冻结目标。
   */
  function access(canRead, canWrite, busy) {
    if (!readable && canRead) {
      clearObserved("请读取当前范围的节点，逐项选择材料目标。");
    }
    readable = canRead;
    writable = canWrite;
    locked = busy;
    if (!readable) {
      clearObserved("当前没有材料读取资格。");
    }
    read.disabled = !readable || locked;
    query.disabled = !writable || locked || !rows.length;
    for (const action of observedActions) {
      action.control.disabled =
        locked || !readable || (action.write && !writable);
    }
    renderSelected();
  }

  /**
   * 业务作用：展示用户明确选择的全部原目标，并以显式移除撤销对应条件。
   * 参数说明: 无。
   * 返回：保留原分母、原启动与配置；不自动删除失联目标。
   */
  function renderSelected() {
    selected.replaceChildren(
      element(
        "p",
        `已选择 ${rows.length} / 128 个逻辑目标；${frozen ? "原材料条件已冻结" : "尚未冻结材料条件"}。`,
      ),
    );
    for (const row of rows) {
      const section = element("article", "", "proposal-row");
      section.append(
        element(
          "strong",
          `${row.node_id} · ${row.target.kind}/${row.target.listener}/${row.target.entry}`,
        ),
      );
      fact(section, "原启动", row.boot_id);
      fact(section, "原配置", `${row.base_version} · ${row.base_fingerprint}`);
      const remove = button("移除此材料目标", () => {
        if (!writable || locked || document.hidden) {
          return;
        }
        rows = rows.filter((value) => value !== row);
        clearConditions();
        access(readable, writable, locked);
      });
      remove.disabled = !writable || locked;
      section.append(remove);
      selected.append(section);
    }
  }

  /**
   * 业务作用：在点击时重新检查观察年龄并固定同一原节点基线，目录计时延迟不能延长选取资格。
   * 参数说明：
   * - `node`：本次节点响应的原基线。
   * - `target`：该节点明确提供的逻辑声明。
   * 返回：增加一个原目标；重复、混代、过期或超量保持拒绝。
   */
  function choose(node, target) {
    if (!writable || locked || document.hidden) {
      return;
    }
    if (performance.now() >= deadline) {
      clearObserved("观察已过期，请重新读取原节点。");
      return;
    }
    const value = {
      node_id: node.node_id,

      boot_id: node.boot_id,

      base_version: node.base_version,

      base_fingerprint: node.base_fingerprint,

      node_baseline: { ...node.node_baseline },

      target: {
        kind: target.kind,
        listener: target.listener,
        entry: target.entry,
      },
    };
    if (
      rows.length >= 128 ||
      rows.some((row) => targetKey(row) === targetKey(value))
    ) {
      status.textContent = "此目标已选择，或已经达到128个目标上限。";
      return;
    }
    if (
      rows.some(
        (row) => row.node_id === value.node_id && !sameOriginal(row, value),
      )
    ) {
      status.textContent =
        "此节点的原基线已经变化，请先显式移除该节点的全部旧目标。";
      return;
    }
    const candidate = [...rows, value];
    if (
      new TextEncoder().encode(JSON.stringify(candidate)).byteLength > 65536
    ) {
      status.textContent = "原目标元数据超过64 KiB，请减少本次明确选择的目标。";
      return;
    }
    rows = candidate;
    clearConditions();
    renderSelected();
    query.disabled = !writable || locked;
  }

  /**
   * 业务作用：验证当前范围和年龄后交付节点清单或一个节点的全部逻辑目标。
   * 参数说明：
   * - `result`：目标发现接口的完整响应。
   * - `started`：请求发出前的单调时间。
   * - `nodeId`：本次明确选择的节点，空文本代表清单。
   * 返回：只展示真实可用目标；缺席与不支持保留明确状态。
   */
  function show(result, started, nodeId = "") {
    clearObserved();
    const data = result.data;
    if (data?.cluster_id !== cluster || data.scope !== scope()) {
      throw new Error("材料目标响应不属于当前集群或范围。");
    }
    if (result.status === 202) {
      status.textContent = "当前目录正在采样，请稍后重新读取。";
      return;
    }
    const rawAge = result.headers.get("x-naway-sample-age-ms");
    const age = Number(rawAge);
    if (
      result.status !== 200 ||
      rawAge === null ||
      !/^[0-9]+$/.test(rawAge) ||
      !Number.isSafeInteger(age) ||
      age >= 6000 ||
      data.valid_for_ms !== 6000 ||
      !Number.isFinite(started)
    ) {
      throw new Error("材料目标响应或观察年龄不符合约定。");
    }
    deadline = started + 6000 - age;
    if (deadline <= performance.now()) {
      clearObserved("目录已经过期，请重新读取；原目标不会自动更新。");
      return;
    }
    if (nodeId) {
      showNode(data.node, nodeId);
    } else {
      showMembers(data);
    }
    timer = setTimeout(
      () => {
        clearObserved("目录已过期，请重新读取；已选原目标及条件不会自动更新。");
      },
      Math.max(1, deadline - performance.now()),
    );
    access(readable, writable, locked);
  }

  /**
   * 业务作用：保留完整授权成员及不可用原因，不提供隐式全选或按在线情况缩小分母。
   * 参数说明：
   * - `data`：同代授权节点清单。
   * 返回：有限成员列表；截断或冲突目录不提供选择入口。
   */
  function showMembers(data) {
    if (
      !Array.isArray(data.nodes) ||
      data.nodes.length > 128 ||
      data.nodes.some((node) => !token(node?.node_id)) ||
      new Set(data.nodes.map((node) => node.node_id)).size !== data.nodes.length
    ) {
      throw new Error("材料节点清单不完整或存在重复身份。");
    }
    const incomplete =
      data.directory &&
      [
        "truncated",
        "conflicting_ids",
        "directory_stale",
        "limited_to_local",
      ].some((key) => data.directory[key] === true);
    status.textContent = `当前范围 ${data.nodes.length} 个节点 · ${data.availability}${incomplete ? "；目录不完整，暂不可选" : "；请明确选择原节点"}。`;
    for (const node of data.nodes) {
      const row = element("article", "", "proposal-row");
      row.append(
        element("strong", node.node_id),
        element("span", node.availability),
      );
      if (!incomplete && node.availability === "available") {
        const readNode = button(`读取 ${node.node_id} 的材料目标`, () => {
          if (
            readable &&
            !locked &&
            !document.hidden &&
            performance.now() < deadline
          ) {
            clearObserved("正在读取该节点的原声明与基线…");
            load(node.node_id);
          }
        });
        observedActions.push({
          control: readNode,
          write: false,
        });
        row.append(readNode);
      }
      observed.append(row);
    }
  }

  /**
   * 业务作用：展示单节点的明确声明、全部别名及协议集合，不猜测或隐式合并不同声明。
   * 参数说明：
   * - `node`：单节点目标响应。
   * - `nodeId`：本次请求的原节点身份。
   * 返回：有界选择控件；节点不可用时只显示原因。
   */
  function showNode(node, nodeId) {
    if (
      !node ||
      node.node_id !== nodeId ||
      !Array.isArray(node.targets) ||
      node.targets.length > 2048
    ) {
      throw new Error("材料节点响应缺少完整目标。");
    }
    status.textContent = `${nodeId} · ${node.availability} · ${node.targets.length} 个逻辑目标。`;
    if (node.availability !== "available") {
      return;
    }
    if (
      !original(node, cluster) ||
      node.targets.some(
        (row) =>
          !logical(row.target) ||
          !Array.isArray(row.bindings) ||
          !row.bindings.length ||
          row.bindings.some((name) => typeof name !== "string") ||
          !Array.isArray(row.protocols) ||
          !row.protocols.length ||
          row.protocols.some(
            (protocol) => !["https", "http3", "stream_tls"].includes(protocol),
          ),
      )
    ) {
      throw new Error("材料声明或节点原基线不符合约定。");
    }
    const keys = node.targets.map((row) =>
      targetKey({
        node_id: nodeId,
        target: row.target,
      }),
    );
    if (new Set(keys).size !== keys.length) {
      throw new Error("材料目录包含重复声明。");
    }
    const select = element("select");
    select.setAttribute("aria-label", "原材料声明");
    const description = element("p", "", "proposal-digest");
    for (const [index, row] of node.targets.entries()) {
      const option = element(
        "option",
        `${row.target.kind}/${row.target.listener}/${row.target.entry}`,
      );
      option.value = String(index);
      select.append(option);
    }
    /**
     * 业务作用：展示当前原声明的全部实际协议及选证名称，避免把共享绑定误认为单一监听。
     * 参数说明: 无。
     * 返回：更新当前选项的公开说明，不改变原目标集合。
     */
    const describe = () => {
      const row = node.targets[Number(select.value)];
      description.textContent = row
        ? `实际协议：${row.protocols.join(" / ")}；选证名称：${row.bindings.map((name) => name || "默认身份").join(" / ")}`
        : "没有可写的材料声明。";
    };
    select.addEventListener("change", describe);
    const add = button("选取此原材料目标", () => {
      const row = node.targets[Number(select.value)];
      if (row) {
        choose(node, row.target);
      }
    });
    observedActions.push(
      {
        control: select,
        write: true,
      },
      {
        control: add,
        write: true,
      },
    );
    observed.append(field("原材料声明", select), description, add);
    describe();
  }

  /**
   * 业务作用：把完整原条件作为不可自动更新的提案输入，同时展示所有共享来源影响。
   * 参数说明：
   * - `data`：当前唯一条件请求的完整响应。
   * - `requested`：请求发出前的原选择集合。
   * 返回：完整条件通过才开放提交；任何失败保留原分母并关闭提交。
   */
  function freeze(data, requested) {
    clearConditions();
    if (
      requested.length !== rows.length ||
      requested.some((value, index) => value !== rows[index])
    ) {
      throw new Error("查询期间目标选择发生变化，请重新查询全部原目标。");
    }
    const nodes = conditionNodes(data, requested, scope());
    for (const node of nodes) {
      conditions.append(
        element(
          "p",
          `${node.node_id} · ${node.indices.length} 个原目标 · ${node.status}${node.reason ? ` · ${node.reason}` : ""}`,
        ),
      );
    }
    // 不可用节点仍属于原请求；不能用其余节点的成功观察缩小提交分母。
    frozen = freezeConditions(data, requested, scope());
    if (new TextEncoder().encode(JSON.stringify(frozen)).byteLength > 65536) {
      frozen = null;
      throw new Error("完整材料目标超过64 KiB，请显式减少目标后重新查询。");
    }
    conditions.append(
      element(
        "p",
        `已冻结全部 ${frozen.length} 个原材料条件；保存前仍须选择候选材料。`,
      ),
    );
    for (const node of data.nodes) {
      const section = element("section");
      section.append(element("h4", node.node_id));
      showSources(section, node.conditions);
      conditions.append(section);
    }
    renderSelected();
    changed(true);
  }

  /**
   * 业务作用：离开范围、隐藏页面或失权时撤销全部目标与公开条件，旧查询不得恢复它们。
   * 参数说明: 无。
   * 返回：清空所有选择、观察与计时器。
   */
  function clear() {
    clearObserved();
    rows = [];
    clearConditions();
    renderSelected();
  }

  /**
   * 业务作用：仅向材料提交交付完整冻结条件，不允许未查询或部分结果进入正文。
   * 参数说明: 无。
   * 返回：原冻结目标的浅数组副本；没有完整条件时拒绝。
   */
  function value() {
    if (!frozen?.length || frozen.length !== rows.length) {
      throw new Error("请先查询并冻结全部原材料条件。");
    }
    return frozen.slice();
  }

  return {
    node: root,
    access,
    show,
    freeze,
    value,
    clear,
    clearObserved,
  };
}
