const descriptions = {
  unsupported: "节点未提供恢复状态协议",
  disabled: "未启用节点持久目录",
  uninitialized: "仅持久身份，未启用文件恢复",
  unavailable: "本轮状态未确认",
  protected: "存储证据不符，配置写入已保护",
  idle: "无待完成文件决定",
  preparing: "准备原文，尚未授权文件替换",
  forward: "已决定完成候选，待确认",
  backward: "已决定恢复基线，待确认",
};

/**
 * 业务作用：验证存储计数可在页面原样呈现，避免大代际被浮点数舍入。
 * 参数说明：
 * - `value`：接口中的规范十进制字符串。
 * 返回：合法正 u64 时为真，未知类型或超范围不形成提交证据。
 */
function positiveInteger(value) {
  return (
    typeof value === "string" &&
    /^[1-9][0-9]{0,19}$/.test(value) &&
    BigInt(value) <= 18446744073709551615n
  );
}

/**
 * 业务作用：将同次集群节点观察转为只读文本，未知或矛盾状态不展示旧提交信息。
 * 参数说明：
 * - `node`：当前有效目录中的一个节点，含同次事实和文件决定。
 * 返回：有界字段列表；业务就绪与文件决定分别描述，不提供动作按钮。
 */
export function publicationFields(node) {
  const unknown = [["本地文件状态", descriptions.unavailable]];
  if (!node.facts || node.availability === "identity_conflict") {
    return unknown;
  }
  const value = node.action_baseline?.local_publication;
  if (!value) {
    return [["本地文件状态", descriptions.unsupported]];
  }
  if (value.schema !== 1 || !Object.hasOwn(descriptions, value.state)) {
    return unknown;
  }
  const committed = ["idle", "preparing", "forward", "backward"].includes(
    value.state,
  );
  const storage = value.storage;
  if (!committed) {
    return storage == null
      ? [["本地文件状态", descriptions[value.state]]]
      : unknown;
  }
  if (
    !storage ||
    typeof storage.cluster_id !== "string" ||
    !/^[A-Za-z0-9_.-]{1,128}$/.test(storage.cluster_id) ||
    typeof storage.store_id !== "string" ||
    !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(storage.store_id) ||
    !positiveInteger(storage.node_admission_epoch) ||
    !positiveInteger(storage.revision) ||
    (value.state === "idle"
      ? storage.operation_id != null
      : typeof storage.operation_id !== "string" ||
        !/^[0-9a-f]{32}$/.test(storage.operation_id))
  ) {
    return unknown;
  }
  const fields = [
    ["本地文件状态", descriptions[value.state]],
    ["持久存储集群", storage.cluster_id],
    ["持久存储身份", storage.store_id],
    ["节点受理代际", storage.node_admission_epoch],
    ["存储提交序号", storage.revision],
  ];
  if (storage.operation_id) {
    fields.push(["待完成文件操作", storage.operation_id]);
  }
  return fields;
}
