import { element } from "../../core/dom.js";

/**
 * 业务作用：为材料表单建立可访问的字段标签。
 * 参数说明：
 * - `title`：字段的业务名称。
 * - `input`：对应的单一输入控件。
 * 返回：只使用纯文本的标签节点。
 */
export function field(title, input) {
  const label = element("label", title);
  label.append(input);
  return label;
}

/**
 * 业务作用：构造需要用户明确触发的材料动作按钮。
 * 参数说明：
 * - `title`：动作名称。
 * - `action`：已绑定当前页面状态的回调。
 * 返回：不隐式提交外层表单的按钮。
 */
export function button(title, action) {
  const control = element("button", title);
  control.type = "button";
  control.addEventListener("click", action);
  return control;
}

/**
 * 业务作用：用安全文本呈现身份、基线与完整摘要，未知值不冒充真实状态。
 * 参数说明：
 * - `root`：当前事实的容器。
 * - `title`：事实名称。
 * - `value`：公开值，缺席时明确显示未知。
 * 返回：向容器追加可换行的完整字段。
 */
export function fact(root, title, value) {
  const row = element("div", "", "state-row");
  row.append(
    element("span", title),
    element("strong", value ?? "未知", "proposal-digest"),
  );
  root.append(row);
}

/**
 * 业务作用：核对材料协议中的规范十六进制身份。
 * 参数说明：
 * - `value`：原响应字段。
 * - `length`：协议规定的长度。
 * 返回：只接受完整的小写十六进制字符串。
 */
export function hex(value, length = 64) {
  return (
    typeof value === "string" &&
    value.length === length &&
    /^[0-9a-f]+$/.test(value)
  );
}

/**
 * 业务作用：限定节点和请求身份，避免把远端文本作为可解释路径。
 * 参数说明：
 * - `value`：原身份文本。
 * 返回：符合有界ASCII令牌合同才允许进入后续路径构造。
 */
export function token(value) {
  return typeof value === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(value);
}

/**
 * 业务作用：以字符串保存完整正整数代际，禁止浮点截断或自动换代。
 * 参数说明：
 * - `value`：节点或共享存储的原代际。
 * 返回：规范正u64文本为真。
 */
export function epoch(value) {
  return (
    typeof value === "string" &&
    /^[1-9][0-9]{0,19}$/.test(value) &&
    BigInt(value) <= 18446744073709551615n
  );
}

/**
 * 业务作用：只接收服务端明确的逻辑声明身份，不从名称或匹配次序猜测SNI位置。
 * 参数说明：
 * - `target`：单一逻辑目标。
 * 返回：支持的监听种类与原声明编号完整时为真。
 */
export function logical(target) {
  return (
    target &&
    ["proxy", "stream"].includes(target.kind) &&
    typeof target.listener === "string" &&
    target.listener.length > 0 &&
    new TextEncoder().encode(target.listener).byteLength <= 128 &&
    !/\p{Cc}/u.test(target.listener) &&
    (target.entry === "default" ||
      (typeof target.entry === "string" &&
        /^sni-(0|[1-9][0-9]{0,2})$/.test(target.entry) &&
        Number(target.entry.slice(4)) <= 511))
  );
}

/**
 * 业务作用：检查冻结目标的同集群持久基线与启动身份，安全整数之外的配置版本直接拒绝。
 * 参数说明：
 * - `value`：目标或目标发现节点的公开身份字段。
 * - `cluster`：当前共享材料存储绑定的集群。
 * 返回：完整原基线合法才为真，不代表当前节点仍在线。
 */
export function original(value, cluster) {
  const baseline = value?.node_baseline;
  return (
    token(value?.node_id) &&
    token(value.boot_id) &&
    Number.isSafeInteger(value.base_version) &&
    value.base_version > 0 &&
    hex(value.base_fingerprint, 16) &&
    baseline?.schema === 1 &&
    baseline.cluster_id === cluster &&
    typeof baseline.store_id === "string" &&
    /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(baseline.store_id) &&
    epoch(baseline.node_admission_epoch) &&
    hex(baseline.documents_sha256)
  );
}

/**
 * 业务作用：为一个原节点和逻辑声明构造无歧义的内存索引。
 * 参数说明：
 * - `value`：已验证的原目标。
 * 返回：只用于页面内去重的身份文本，不作为API路径或授权证据。
 */
export function targetKey(value) {
  return JSON.stringify([
    value.node_id,
    value.target.kind,
    value.target.listener,
    value.target.entry,
  ]);
}

/**
 * 业务作用：比较同节点原基线，防止多次选取拼接不同启动或配置代的目标。
 * 参数说明：
 * - `left`：已经冻结的原目标。
 * - `right`：拟加入或回读的目标。
 * 返回：原节点、启动、配置、持久owner和原文摘要均相同才为真。
 */
export function sameOriginal(left, right) {
  return (
    ["node_id", "boot_id", "base_version", "base_fingerprint"].every(
      (key) => left[key] === right[key],
    ) &&
    [
      "schema",
      "cluster_id",
      "store_id",
      "node_admission_epoch",
      "documents_sha256",
    ].every((key) => left.node_baseline[key] === right.node_baseline[key])
  );
}

/**
 * 业务作用：读取完整原提案前核对当前范围、集群及全部目标，不能借部分合法目标接受另一域记录。
 * 参数说明：
 * - `record`：材料单项或列表中的原记录。
 * - `cluster`：当前共享集群身份。
 * - `scope`：当前精确材料范围。
 * 返回：原记录合法时原样返回；缺项、重复、混代或跨范围时整份拒绝。
 */
export function checkedRecord(record, cluster, scope) {
  if (
    !record ||
    !hex(record.id, 32) ||
    record.scope !== scope ||
    !Array.isArray(record.targets) ||
    record.targets.length < 1 ||
    record.targets.length > 128 ||
    !token(record.creator) ||
    !hex(record.certificate?.certificate_sha256) ||
    !hex(record.certificate?.leaf_sha256)
  ) {
    throw new Error("材料记录的身份或完整目标不符合约定。");
  }
  const seen = new Set();
  const nodes = new Map();
  for (const target of record.targets) {
    if (
      !original(target, cluster) ||
      !logical(target.target) ||
      !hex(target.material_generation) ||
      typeof target.certificate_etag !== "string" ||
      !/^"sha256-[0-9a-f]{64}"$/.test(target.certificate_etag)
    ) {
      throw new Error("材料记录的原条件或集群基线不符合约定。");
    }
    const key = targetKey(target);
    if (
      seen.has(key) ||
      (nodes.has(target.node_id) &&
        !sameOriginal(nodes.get(target.node_id), target))
    ) {
      throw new Error("材料记录存在重复目标或不一致的原节点基线。");
    }
    seen.add(key);
    nodes.set(target.node_id, target);
  }
  return record;
}

/**
 * 业务作用：完整展示公开证书摘要与有效期，不向浏览器交付私钥或生成下载入口。
 * 参数说明：
 * - `root`：详情容器。
 * - `certificate`：服务端保存的公开证书摘要。
 * 返回：追加完整公开事实，摘要不以省略文本替代审阅内容。
 */
export function showCertificate(root, certificate) {
  for (const [key, title] of [
    ["certificate_sha256", "证书链 SHA-256"],
    ["leaf_sha256", "叶证书 SHA-256"],
    ["chain_length", "证书链长度"],
  ]) {
    fact(root, title, certificate?.[key]);
  }
  for (const [key, title] of [
    ["not_before_seconds", "生效时间"],
    ["not_after_seconds", "到期时间"],
  ]) {
    const seconds = certificate?.[key];
    fact(
      root,
      title,
      Number.isSafeInteger(seconds) && Math.abs(seconds) <= 8640000000000
        ? new Date(seconds * 1000).toISOString()
        : "未知",
    );
  }
}

/**
 * 业务作用：展示全部原逻辑目标与条件，节点失联后仍保留原分母和原身份。
 * 参数说明：
 * - `root`：原记录容器。
 * - `targets`：已经完整校验的原目标数组。
 * 返回：完整目标清单；不查询或替换为当前在线成员。
 */
export function showTargets(root, targets) {
  const section = element("details");
  section.append(element("summary", `全部原目标（${targets.length}）`));
  for (const target of targets) {
    const row = element("article", "", "proposal-row");
    row.append(
      element(
        "h3",
        `${target.node_id} · ${target.target.kind}/${target.target.listener}/${target.target.entry}`,
      ),
    );
    fact(row, "原启动", target.boot_id);
    fact(row, "原配置", `${target.base_version} · ${target.base_fingerprint}`);
    fact(row, "节点存储", target.node_baseline.store_id);
    fact(row, "节点受理代", target.node_baseline.node_admission_epoch);
    fact(row, "原文 SHA-256", target.node_baseline.documents_sha256);
    fact(row, "公开 PEM ETag", target.certificate_etag);
    fact(row, "原受管材料代", target.material_generation);
    section.append(row);
  }
  root.append(section);
}
