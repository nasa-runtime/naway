import { element } from "../../core/dom.js";
import { button, epoch, fact, field, hex, token } from "./common.js";

// 只保留低敏原请求身份；页面刷新会释放此内存，跨Admin恢复由用户明确携带原标识。
const requests = [];

/**
 * 业务作用：按真实主体、集群和精确范围保留未决身份，秘密正文永不进入恢复台账。
 * 参数说明：
 * - `cluster`：原共享材料集群。
 * - `principal`：当前真实认证主体。
 * - `scope`：当前精确范围的读取函数。
 * - `resolve`：在唯一请求链中执行只读恢复的回调。
 * 返回：原身份登记、明确结果结束、范围筛选和恢复表单；不生成重传正文或新幂等键。
 */
export function recoveryView(cluster, principal, scope, resolve) {
  const root = element("section", "", "panel proposal-recovery");
  const pending = element("div");
  const manual = element("form");
  const kind = element("select");
  kind.setAttribute("aria-label", "原请求类别");
  for (const [value, title] of [
    ["material", "材料保存"],
    ["impact", "完整影响登记"],
    ["execution", "材料执行"],
  ]) {
    const option = element("option", title);
    option.value = value;
    kind.append(option);
  }
  const proposal = element("input");
  proposal.maxLength = 32;
  proposal.setAttribute("aria-label", "原材料提案身份");
  const admission = element("input");
  admission.maxLength = 19;
  admission.setAttribute("aria-label", "原受理代");
  const key = element("input");
  key.maxLength = 128;
  key.setAttribute("aria-label", "原幂等键");
  for (const input of [proposal, admission, key]) {
    input.autocomplete = "off";
    input.spellcheck = false;
  }
  const submit = element("button", "按原身份查询");
  submit.type = "submit";
  const notice = element("p", "", "subtle");
  let alive = true;
  let readable = false;
  let busy = false;
  manual.append(
    field("原请求类别", kind),
    field("原材料提案 id（影响和执行必填）", proposal),
    field("原受理代（材料和影响必填）", admission),
    field("原 Idempotency-Key（材料和影响必填）", key),
    submit,
    notice,
  );
  root.append(
    element("h2", "恢复原请求"),
    element(
      "p",
      "响应丢失、超时或取消不证明服务端未提交。保留原主体、范围及标识，从同一集群任一Admin只读查询。刷新或关闭页面前请自行保存下面的低敏标识；此页不保存PEM或请求正文。",
      "subtle",
    ),
    pending,
    manual,
  );
  manual.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!alive || !readable || busy || document.hidden) {
      return;
    }
    try {
      const entry = begin(kind.value, {
        proposal: proposal.value.trim(),

        epoch: admission.value.trim(),

        key: key.value.trim(),
      });
      resolve(entry);
    } catch (error) {
      notice.textContent = error.message;
    }
  });

  /**
   * 业务作用：只向当前主体和已授权范围公开其原请求身份，切换域不会显示另一域的台账。
   * 参数说明: 无。
   * 返回：本集群、本主体、本域的未决身份数组。
   */
  function entries() {
    return requests.filter(
      (entry) =>
        entry.cluster === cluster &&
        entry.principal === principal &&
        entry.scope === scope(),
    );
  }

  /**
   * 业务作用：在发送首次写入之前固定唯一低敏身份，未知结果不能通过换键或换代覆盖。
   * 参数说明：
   * - `type`：材料、影响、执行或明确审阅的固定类别。
   * - `value`：原键、代际、提案、影响和公开摘要，不允许秘密字段进入台账。
   * 返回：同一原身份的内存记录；格式错误或台账满时不发起新的写入。
   */
  function begin(type, value) {
    if (
      !alive ||
      ![
        "material",
        "impact",
        "execution",
        "material_review",
        "impact_review",
      ].includes(type) ||
      (type !== "material" && !hex(value.proposal, 32)) ||
      (["material", "impact"].includes(type) &&
        (!token(value.key) ||
          !epoch(value.epoch) ||
          BigInt(value.epoch) > 9223372036854775807n))
    ) {
      throw new Error("请提供规范的原请求身份，不能填写新键或替代受理代。");
    }
    const entry = {
      cluster,

      principal,

      scope: scope(),

      kind: type,

      proposal: type === "material" ? "" : value.proposal,

      epoch: ["material", "impact"].includes(type) ? value.epoch : "",

      key: ["material", "impact"].includes(type) ? value.key : "",

      impact: hex(value.impact, 32) ? value.impact : "",

      digest: hex(value.digest) ? value.digest : "",

      decision: ["approve", "reject", "cancel"].includes(value.decision)
        ? value.decision
        : "",
    };
    const existing = entries().find((current) =>
      ["kind", "proposal", "epoch", "key"].every(
        (name) => current[name] === entry[name],
      ),
    );
    if (existing) {
      return existing;
    }
    if (requests.length >= 32) {
      throw new Error("未决身份已达到32项，请先查询并确认已有原请求。");
    }
    requests.push(entry);
    render();
    return entry;
  }

  /**
   * 业务作用：只有明确回读或确定拒绝后才结束一个原身份，不能因超时、取消或未找到而抹去未决状态。
   * 参数说明：
   * - `entry`：当前页面已经核对结果的原台账对象。
   * 返回：精确移除该对象，保留其它域和其它未决请求。
   */
  function complete(entry) {
    const index = requests.indexOf(entry);
    if (index >= 0) {
      requests.splice(index, 1);
    }
    render();
  }

  /**
   * 业务作用：提供完整可人工携带的低敏原身份，恢复按钮始终只读原事实。
   * 参数说明: 无。
   * 返回：只显示当前获权范围的全部未决身份。
   */
  function render() {
    pending.replaceChildren();
    if (!alive || !readable) {
      return;
    }
    for (const entry of entries()) {
      const row = element("article", "", "proposal-row");
      row.append(element("h3", `结果待确认 · ${entry.kind}`));
      for (const [name, title] of [
        ["cluster", "原集群"],
        ["principal", "原主体"],
        ["scope", "原范围"],
        ["proposal", "原材料提案"],
        ["epoch", "原受理代"],
        ["key", "原幂等键"],
        ["impact", "原完整影响"],
        ["digest", "原公开摘要"],
        ["decision", "原审阅决定"],
      ]) {
        if (entry[name]) {
          fact(row, title, entry[name]);
        }
      }
      const read = button("查询此原请求", () => {
        if (alive && readable && !busy && !document.hidden) {
          resolve(entry);
        }
      });
      read.disabled = busy;
      row.append(read);
      pending.append(row);
    }
  }

  /**
   * 业务作用：按当前材料读权和并发门限制恢复入口，低敏台账也不能跨主体展示。
   * 参数说明：
   * - `allowed`：当前范围真实材料读权。
   * - `locked`：当前唯一请求链是否忙碌。
   * 返回：更新恢复表单与每个原请求读取按钮。
   */
  function access(allowed, locked) {
    readable = allowed;
    busy = locked;
    for (const control of [kind, proposal, admission, key, submit]) {
      control.disabled = !alive || !readable || busy;
    }
    render();
  }

  /**
   * 业务作用：隐藏或切换范围时撤去手工输入，原未决身份仅在内存台账中按原域保留。
   * 参数说明: 无。
   * 返回：清空表单文本与当前显示，不删除未知请求。
   */
  function clear() {
    proposal.value = admission.value = key.value = "";
    notice.textContent = "";
    pending.replaceChildren();
  }

  /**
   * 业务作用：退出当前主体视图后撤去恢复控件，内存中不含秘密的原身份仍只能由同主体同域读取。
   * 参数说明: 无。
   * 返回：页面内容清空，旧事件回调失效。
   */
  function dispose() {
    alive = false;
    clear();
    root.replaceChildren();
  }

  access(false, true);
  return {
    node: root,
    begin,
    complete,
    entries,
    access,
    clear,
    dispose,
  };
}
