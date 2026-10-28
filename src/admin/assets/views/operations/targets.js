import { element } from "../../core/dom.js";

/**
 * 业务作用：从同次节点事实提取可冻结的完整基线，避免将就绪或握手成功当成动作授权。
 * 参数说明：
 * - `node`：当前集群目录中的单个成员。
 * - `cluster`：共享操作库绑定的集群身份。
 * 返回：规范字段顺序的目标声明，或不能选取的低敏原因。
 */
export function declaredTarget(node, cluster) {
  const facts = node.facts;
  if (facts?.mode === "admin") {
    return "纯管理节点不承载业务配置动作。";
  }
  if (node.availability !== "available" || facts?.ready !== true) {
    return "节点尚未提供当前就绪事实。";
  }
  const observation = node.action_baseline;
  if (observation?.availability === "unsupported") {
    return "节点或连接未提供动作基线。";
  }
  if (observation?.availability !== "available") {
    return "当前没有可用的受保护存储基线。";
  }
  const baseline = observation.node_baseline;
  if (baseline?.cluster_id !== cluster) {
    return "节点基线与共享提案不属于同一集群。";
  }
  if (
    !["data", "sidecar", "all-in-one"].includes(facts.mode) ||
    facts.node_id !== node.id ||
    typeof facts.boot_id !== "string" ||
    !/^[A-Za-z0-9_.-]{1,128}$/.test(facts.node_id ?? "") ||
    !/^[A-Za-z0-9_.-]{1,128}$/.test(facts.boot_id ?? "") ||
    !Number.isSafeInteger(facts.config_version) ||
    facts.config_version <= 0 ||
    typeof facts.config_fingerprint !== "string" ||
    !/^[0-9a-f]{16}$/.test(facts.config_fingerprint ?? "") ||
    baseline.schema !== 1 ||
    typeof baseline.store_id !== "string" ||
    !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(baseline.store_id ?? "") ||
    typeof baseline.node_admission_epoch !== "string" ||
    !/^[1-9][0-9]{0,19}$/.test(baseline.node_admission_epoch) ||
    BigInt(baseline.node_admission_epoch) > 18446744073709551615n ||
    typeof baseline.documents_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(baseline.documents_sha256 ?? "")
  ) {
    return "节点身份或原文基线不完整，不能冻结为目标。";
  }
  return {
    node_id: facts.node_id,

    boot_id: facts.boot_id,

    base_version: facts.config_version,

    base_fingerprint: facts.config_fingerprint,

    node_baseline: {
      schema: baseline.schema,

      cluster_id: baseline.cluster_id,

      store_id: baseline.store_id,

      node_admission_epoch: baseline.node_admission_epoch,

      documents_sha256: baseline.documents_sha256,
    },
  };
}

/**
 * 业务作用：明确展示声明中保存的原始基线，缺失证据不能冒充已验证节点。
 * 参数说明：
 * - `target`：手工声明或从集群事实冻结的目标。
 * 返回：只含文本的基线说明，不解释为当前在线状态或执行资格。
 */
export function baselineDescription(target) {
  const baseline = target.node_baseline;
  return baseline
    ? `冻结声明 · 集群 ${baseline.cluster_id} · 存储 ${baseline.store_id} · 节点代际 ${baseline.node_admission_epoch} · 原文 SHA-256 ${baseline.documents_sha256}`
    : "手工声明 · 未附节点存储及原文基线。";
}

/**
 * 业务作用：提供有限期、显式读取的集群目标选取，保留不可选成员及原因。
 * 参数说明：
 * - `cluster`：当前提案集群。
 * - `load`：使用页面唯一请求链读取目录的回调。
 * - `append`：把选取事实冻结到表单的回调。
 * 返回：目录展示、资格更新和清空句柄；不轮询或保存历史。
 */
export function targetPicker(cluster, load, append) {
  const root = element("section", "", "proposal-picker");
  const read = element("button", "读取集群目标");
  read.type = "button";
  const status = element("p", "", "subtle");
  status.setAttribute("role", "status");
  const members = element("div", "", "proposal-members");
  root.append(read, status, members);
  let enabled = false;
  let locked = false;
  let timer = null;
  let generation = 0;
  let deadline = 0;

  /**
   * 业务作用：撤下尚未选取的成员证据，超期或失权后不能继续导入旧事实。
   * 参数说明：
   * - `reason`：当前不可读取或需要重新读取的说明。
   * 返回：释放目录和期限计时器，已经冻结的表单意图不变。
   */
  function clear(reason = "请显式读取当前集群目标；已选行只是冻结声明。") {
    generation += 1;
    clearTimeout(timer);
    timer = null;
    deadline = 0;
    members.replaceChildren();
    status.textContent = reason;
  }

  /**
   * 业务作用：把平台集群读取资格与表单并发门作用于目录入口。
   * 参数说明：
   * - `allowed`：当前范围是否允许平台 Cluster/Read。
   * - `busy`：页面是否禁止编辑和发起新请求。
   * 返回：更新入口状态；失去范围资格时立即清除目录。
   */
  function access(allowed, busy) {
    if (enabled !== allowed) {
      clear();
    }
    enabled = allowed;
    locked = busy;
    read.disabled = !enabled || locked;
    if (!enabled) {
      status.textContent = "此范围不读取平台集群目录，可手工声明目标。";
    }
  }

  /**
   * 业务作用：验证同次目录及年龄后显示有限成员，异常目录不能提供可选目标。
   * 参数说明：
   * - `result`：现有集群接口的状态、响应头和正文。
   * - `started`：请求发起时的单调时间，包含传输消耗。
   * 返回：展示当前可选子集或等待原因，任何旧目录先被撤下。
   */
  function show(result, started) {
    clear();
    if (!enabled) {
      return;
    }
    if (result.status === 202) {
      status.textContent = "集群正在采样或尚未启用，请稍后重新读取。";
      return;
    }
    const data = result.data;
    const rawAge = result.headers.get("x-naway-sample-age-ms");
    const age = Number(rawAge);
    if (
      result.status !== 200 ||
      data?.schema_version !== 1 ||
      data.scope !== "cluster" ||
      !Array.isArray(data.nodes) ||
      data.nodes.length > 128 ||
      !data.coverage ||
      [
        "truncated",
        "conflicting_ids",
        "directory_stale",
        "limited_to_local",
      ].some((key) => typeof data.coverage[key] !== "boolean") ||
      rawAge === null ||
      !/^[0-9]+$/.test(rawAge) ||
      !Number.isSafeInteger(age) ||
      age < 0 ||
      !Number.isFinite(started)
    ) {
      throw new Error("集群目标响应或年龄不符合约定。");
    }
    deadline = started + 6000 - age;
    if (deadline <= performance.now()) {
      clear("目录已过期，请重新读取；原冻结声明不会自动更新。");
      return;
    }
    // 不完整目录不能用已返回的少量节点冒充可确认的目标范围。
    if (
      data.coverage.truncated ||
      data.coverage.conflicting_ids ||
      data.coverage.directory_stale
    ) {
      clear("目录存在截断、身份冲突或过期，当前不能导入目标。");
      return;
    }
    const epoch = generation;
    const seen = new Set();
    for (const node of data.nodes) {
      if (!node || typeof node.id !== "string" || seen.has(node.id)) {
        clear();
        throw new Error("集群成员缺少身份或出现重复身份。");
      }
      seen.add(node.id);
    }
    for (const node of data.nodes) {
      const target = declaredTarget(node, cluster);
      const row = element("article", "", "proposal-row");
      row.append(element("strong", node.id));
      if (typeof target === "string") {
        row.append(element("span", target));
      } else {
        const choose = element("button", `选取节点 ${target.node_id}`);
        choose.type = "button";
        row.append(
          element("span", `${node.facts.mode} · 配置 ${target.base_version}`),
          choose,
        );
        choose.addEventListener("click", () => {
          // 点击时复验期限与视图代，计时器被后台延后也不能延长证据资格。
          if (!enabled || locked || epoch !== generation || document.hidden) {
            return;
          }
          if (performance.now() >= deadline) {
            clear("目录已过期，请重新读取；原冻结声明不会自动更新。");
            return;
          }
          try {
            append(target);
            status.textContent = `已冻结 ${target.node_id} 的声明；未预检、未授权执行。`;
          } catch (error) {
            status.textContent = error.message;
          }
        });
      }
      members.append(row);
    }
    status.textContent = data.coverage.limited_to_local
      ? "目录仅声明接入节点；选取结果不代表整个部署集群。"
      : `当前目录 ${data.nodes.length} 个成员，可逐个选取完整基线；没有默认全选。`;
    timer = setTimeout(
      () => {
        clear("目录已过期，请重新读取；原冻结声明不会自动更新。");
      },
      Math.max(1, deadline - performance.now()),
    );
  }

  read.addEventListener("click", () => {
    if (enabled && !locked && !document.hidden) {
      clear("正在读取当前集群目标…");
      load();
    }
  });
  clear();
  return {
    node: root,

    access,

    show,

    clear,
  };
}
