import { element } from "../../core/dom.js";

const reasons = {
  unsupported: "节点制品不支持预览",

  disabled: "节点未开启预览",

  unavailable: "原节点或基线暂不可用",

  capacity: "节点繁忙或完整结果超过容量",

  expired: "本次预览已超时",

  denied: "当前权限不足",

  baseline_changed: "原启动或配置基线已变化",

  candidate_invalid: "候选未通过该节点的完整构建",
};
const domains = [
  ["routes", "路由"],
  ["upstreams", "上游"],
  ["listeners", "监听"],
  ["sentinel", "Sentinel"],
  ["interface_guard", "接口守卫"],
];

/**
 * 业务作用：维护原提案全部目标的短期审阅视图，过期或退出后清空差异而不保存历史。
 * 参数说明：
 * - `root`：当前详情独占的预览容器。
 * - `record`：原提案身份、摘要和全部冻结目标。
 * 返回：等待、显示和清空句柄；任何不完整或不同基线的响应都不能显示为成功。
 */
export function previewView(root, record) {
  let timer = null;

  /**
   * 业务作用：撤销当前展示期限并清空全部旧差异，隐藏或换提案不能保留过时事实。
   * 参数说明: 无。
   * 返回：不再有预览定时器或可见结果。
   */
  function clear() {
    clearTimeout(timer);
    timer = null;
    root.replaceChildren();
  }

  /**
   * 业务作用：请求期间仍显示每个原目标，不用已有成功节点缩小待验证范围。
   * 参数说明: 无。
   * 返回：所有原目标显示等待状态，不发起自动重试。
   */
  function pending() {
    clear();
    root.append(element("h3", "原目标配置预览"));
    for (const target of record.targets) {
      root.append(element("p", `${target.node_id} · 等待该原目标验证`));
    }
  }

  /**
   * 业务作用：核对原提案及完整分母后展示逐目标差异，失败只显示原因而不伪造零差异。
   * 参数说明：
   * - `value`：服务端本次有界聚合的全部原目标事实。
   * 返回：展示短期完整结果并设置一次到期清除；身份、期限或字段异常时抛出错误。
   */
  function show(value) {
    clear();
    const remaining = value.expires_at_ms - Date.now();
    if (
      value.scope !== "original_targets" ||
      value.proposal_id !== record.id ||
      value.candidate_sha256 !== record.candidate_sha256 ||
      value.admission_epoch !== String(record.admission_epoch) ||
      value.proposal_scope !== record.scope ||
      value.domain !== record.domain ||
      value.target_count !== record.targets.length ||
      !Array.isArray(value.targets) ||
      value.targets.length !== record.targets.length ||
      !Number.isSafeInteger(value.issued_at_ms) ||
      !Number.isSafeInteger(value.expires_at_ms) ||
      value.expires_at_ms - value.issued_at_ms > 20000 ||
      !(remaining > 0 && remaining <= 20000)
    ) {
      throw new Error("预览身份、完整目标或有效期限与原提案不一致。");
    }
    const list = element("div", "", "proposal-list");
    for (let index = 0; index < record.targets.length; index += 1) {
      const original = record.targets[index];
      const result = value.targets[index];
      if (!sameTarget(original, result.target)) {
        throw new Error("预览目标与原节点基线不一致。");
      }
      const row = element("article", "", "proposal-row");
      row.append(element("strong", original.node_id));
      if (
        result.status === "failed" &&
        reasons[result.reason] &&
        !result.diff
      ) {
        row.append(element("p", reasons[result.reason]));
      } else if (result.status === "succeeded") {
        changes(row, result.diff, original);
      } else {
        throw new Error("预览结果状态不完整。");
      }
      list.append(row);
    }
    root.append(
      element("h3", "原目标配置预览"),
      element(
        "p",
        `原目标 ${record.targets.length} 个；仅本次审阅有效，批准和执行仍须重新验证。`,
        "subtle",
      ),
      list,
    );
    timer = setTimeout(() => {
      clear();
      root.append(element("p", "本次预览已过期；需要时可重新发起。", "subtle"));
    }, remaining);
  }

  return {
    clear,

    pending,

    show,
  };
}

/**
 * 业务作用：逐字段核对原目标完整身份，缺失原基线不能被响应中的新基线替代。
 * 参数说明：
 * - `original`：提案冻结的原目标。
 * - `target`：本次响应绑定的目标。
 * 返回：节点、启动、配置和持久基线全部一致时为真。
 */
function sameTarget(original, target) {
  if (
    !target ||
    !["node_id", "boot_id", "base_version", "base_fingerprint"].every(
      (key) => original[key] === target[key],
    )
  ) {
    return false;
  }
  if (!original.node_baseline) {
    return !target.node_baseline;
  }
  return [
    "schema",
    "cluster_id",
    "store_id",
    "node_admission_epoch",
    "documents_sha256",
  ].every((key) => original.node_baseline[key] === target.node_baseline?.[key]);
}

/**
 * 业务作用：展示五个实际比较领域的完整增删改身份，缺失领域不解释为零变化。
 * 参数说明：
 * - `row`：当前原目标的展示容器。
 * - `diff`：该目标完整构建产生的语义比较。
 * - `original`：原配置版本及身份。
 * 返回：追加有限文本；异常字段或超过完整结果容量时拒绝展示。
 */
function changes(row, diff, original) {
  if (!diff || diff.current_version !== original.base_version) {
    throw new Error("预览差异不属于原配置版本。");
  }
  let count = 0;
  let bytes = 0;
  const encoder = new TextEncoder();
  for (const [key, title] of domains) {
    const domain = diff[key];
    const seen = new Set();
    row.append(element("strong", title));
    for (const [action, label] of [
      ["added", "新增"],
      ["removed", "删除"],
      ["changed", "变化"],
    ]) {
      if (!Array.isArray(domain?.[action])) {
        throw new Error("预览差异领域缺失。");
      }
      for (const id of domain[action]) {
        if (typeof id !== "string" || !id || seen.has(id)) {
          throw new Error("预览对象身份无效。");
        }
        seen.add(id);
        count += 1;
        bytes += encoder.encode(id).length;
      }
      if (count > 256 || bytes > 16384) {
        throw new Error("预览完整结果超过容量。");
      }
      row.append(
        element("p", `${label}：${domain[action].join("、") || "无"}`),
      );
    }
  }
}
