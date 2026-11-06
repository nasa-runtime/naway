import { element } from "../../core/dom.js";
import { fact, hex, logical, sameOriginal, targetKey } from "./common.js";

/**
 * 业务作用：验证一批完整共享来源，引用缺项或重复来源不能被解释成独立目标。
 * 参数说明：
 * - `conditions`：同一节点返回的完整来源批次。
 * - `count`：该节点原逻辑目标数。
 * 返回：结构完整的原批次；异常整体拒绝，不截断影响集合。
 */
export function checkedSources(conditions, count) {
  if (
    !conditions ||
    !Array.isArray(conditions.entries) ||
    conditions.entries.length !== count ||
    !Array.isArray(conditions.groups) ||
    !conditions.groups.length ||
    conditions.groups.length > count
  ) {
    throw new Error("节点未返回完整来源条件。");
  }
  const used = new Set();
  for (const entry of conditions.entries) {
    if (
      !["file", "manifest"].includes(entry.source) ||
      !Number.isInteger(entry.group) ||
      entry.group < 0 ||
      entry.group >= conditions.groups.length
    ) {
      throw new Error("材料来源不能用于此项交付，或来源引用不完整。");
    }
    used.add(entry.group);
  }
  if (used.size !== conditions.groups.length) {
    throw new Error("材料来源分母与目标引用不一致。");
  }
  const sources = new Set();
  for (const group of conditions.groups) {
    if (
      !hex(group.source_id) ||
      sources.has(group.source_id) ||
      typeof group.certificate_etag !== "string" ||
      !/^"sha256-[0-9a-f]{64}"$/.test(group.certificate_etag) ||
      !Array.isArray(group.affected) ||
      !group.affected.length ||
      group.affected.length > 128 ||
      !hex(group.material_generation)
    ) {
      throw new Error("来源条件不完整，或原文件尚无受管材料代。");
    }
    sources.add(group.source_id);
    const affected = new Set();
    for (const item of group.affected) {
      if (!logical(item.target) || !hex(item.source_id)) {
        throw new Error("完整影响包含无法识别的对象。");
      }
      const key = JSON.stringify([
        item.target.kind,
        item.target.listener,
        item.target.entry,
      ]);
      if (affected.has(key)) {
        throw new Error("完整影响包含重复对象。");
      }
      affected.add(key);
    }
  }
  return conditions;
}

/**
 * 业务作用：核对条件响应保留全部原节点、索引和基线，使失败节点也能按原分母展示。
 * 参数说明：
 * - `data`：本次条件查询的全部响应。
 * - `originals`：请求发出前冻结的原目标，顺序不可重建。
 * - `scope`：当前唯一材料范围。
 * 返回：包含成功及固定失败原因的完整节点集合；任意缺失、越域或基线改变都拒绝。
 */
export function conditionNodes(data, originals, scope) {
  if (
    data?.scope !== scope ||
    data.target_count !== originals.length ||
    !Number.isInteger(data.complete_count) ||
    data.complete_count < 0 ||
    data.complete_count > originals.length ||
    !Array.isArray(data.nodes) ||
    !data.nodes.length ||
    data.nodes.length > originals.length
  ) {
    throw new Error("材料条件响应没有保留完整原目标分母。");
  }
  const seen = new Set();
  let complete = 0;
  const members = new Set();
  for (const node of data.nodes) {
    if (
      !["complete", "unavailable"].includes(node.status) ||
      members.has(node.node_id) ||
      !Array.isArray(node.indices) ||
      !node.indices.length ||
      !Array.isArray(node.targets) ||
      node.targets.length !== node.indices.length
    ) {
      throw new Error("材料条件缺少原节点或存在重复节点。");
    }
    members.add(node.node_id);
    if (node.status === "complete") {
      complete += node.indices.length;
    } else if (
      ![
        "unsupported",
        "disabled",
        "unavailable",
        "capacity",
        "expired",
        "denied",
        "baseline_changed",
        "target_absent",
        "external_source",
        "storage",
        "impact_unproven",
      ].includes(node.reason)
    ) {
      throw new Error("材料条件缺少明确的节点不可用原因。");
    }
    for (const [offset, index] of node.indices.entries()) {
      const original = originals[index];
      if (
        !Number.isInteger(index) ||
        !original ||
        seen.has(index) ||
        !sameOriginal(original, node) ||
        !logical(node.targets[offset]) ||
        targetKey(original) !==
          targetKey({
            node_id: node.node_id,
            target: node.targets[offset],
          })
      ) {
        throw new Error("材料条件与原请求的完整索引或节点基线不一致。");
      }
      seen.add(index);
    }
  }
  if (seen.size !== originals.length || complete !== data.complete_count) {
    throw new Error("材料条件遗漏原目标或计数不一致，不能缩减分母。");
  }
  return data.nodes;
}

/**
 * 业务作用：只把完整原目标查询的真实PEM ETag和材料代冻结到提案，不接受部分节点成功。
 * 参数说明：
 * - `data`：本次条件查询的全部响应。
 * - `originals`：请求发出前冻结的原目标，顺序不可重建。
 * - `scope`：当前唯一材料范围。
 * 返回：同一原分母上的完整材料目标；任意缺失、越域或基线改变都拒绝。
 */
export function freezeConditions(data, originals, scope) {
  const nodes = conditionNodes(data, originals, scope);
  if (data.complete_count !== originals.length) {
    throw new Error("尚未取得全部原目标的材料条件，请查看各节点原因。");
  }
  const complete = new Array(originals.length);
  for (const node of nodes) {
    const batch = checkedSources(node.conditions, node.indices.length);
    for (const [offset, index] of node.indices.entries()) {
      const original = originals[index];
      const group = batch.groups[batch.entries[offset].group];
      if (
        !group.affected.some(
          (item) =>
            item.source_id === group.source_id &&
            targetKey({
              node_id: node.node_id,
              target: item.target,
            }) === targetKey(original),
        )
      ) {
        throw new Error("完整来源没有覆盖所选的原逻辑目标。");
      }
      complete[index] = {
        ...original,

        certificate_etag: group.certificate_etag,

        material_generation: group.material_generation,
      };
    }
  }
  return complete;
}

/**
 * 业务作用：逐项展示每个实际来源和全部共享影响，使审阅者能识别未直接选中但会受影响的监听。
 * 参数说明：
 * - `root`：当前详情容器。
 * - `conditions`：已经完整验证的来源批次。
 * 返回：所有来源与共享对象的纯文本展示，不省略内容或生成文件访问入口。
 */
export function showSources(root, conditions) {
  for (const [index, group] of conditions.groups.entries()) {
    const section = element("details");
    section.append(
      element(
        "summary",
        `来源 ${index + 1} · 影响 ${group.affected.length} 个逻辑对象`,
      ),
    );
    fact(section, "来源身份", group.source_id);
    fact(section, "原公开 PEM ETag", group.certificate_etag);
    fact(section, "原材料代", group.material_generation);
    for (const item of group.affected) {
      const row = element("article", "", "proposal-row");
      row.append(
        element(
          "strong",
          `${item.target.kind}/${item.target.listener}/${item.target.entry}`,
        ),
      );
      fact(row, "对象写入来源", item.source_id);
      section.append(row);
    }
    root.append(section);
  }
}
