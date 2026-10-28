import { element } from "../../core/dom.js";
import { baselineDescription, targetPicker } from "./targets.js";

/**
 * 业务作用：将可编辑值与可读标签绑定，避免字段只依赖占位提示。
 * 参数说明：
 * - `title`：字段的业务名称。
 * - `input`：当前字段控件。
 * 返回：包含控件的可访问标签。
 */
export function field(title, input) {
  const label = element("label", title);
  label.append(input);
  return label;
}

/**
 * 业务作用：提供有界候选和结构化目标输入，不把录入校验当节点预检。
 * 参数说明：
 * - `capacity`：后端公开的单候选和目标上限。
 * - `submit`：用户明确提交后的页面协调回调。
 * - `loadTargets`：按当前范围读取一次集群目标的协调回调。
 * 返回：可读取、锁定和清空的表单；不创建网络或后台任务。
 */
export function proposalForm(capacity, submit, loadTargets) {
  const form = element("form", "", "panel proposal-form");
  const fields = element("fieldset");
  fields.append(element("legend", "保存新提案"));
  fields.append(
    element(
      "p",
      "只保存候选与目标意图，不执行配置发布。候选可能包含秘密，请使用受控的 SecretSource 引用。",
      "subtle",
    ),
  );
  const candidate = element("textarea");
  candidate.rows = 10;
  candidate.maxLength = capacity.max_candidate_bytes;
  candidate.spellcheck = false;
  candidate.required = true;
  candidate.autocomplete = "off";
  candidate.setAttribute("aria-label", "候选 YAML");
  const ttl = element("input");
  ttl.type = "number";
  ttl.min = String(capacity.min_ttl_seconds);
  ttl.max = String(capacity.max_ttl_seconds);
  ttl.step = "1";
  ttl.value = "600";
  ttl.required = true;
  const targets = element("div", "", "proposal-targets");
  const rows = [];
  const picker = targetPicker(capacity.cluster_id, loadTargets, addFrozen);
  let locked = false;
  let discoverable = false;
  const add = element("button", "增加目标");
  add.type = "button";
  const save = element("button", "保存提案", "primary");
  save.type = "submit";
  fields.append(
    field("候选 YAML", candidate),
    field("提案有效期（秒）", ttl),
    element(
      "p",
      "可手工声明目标，或从当前集群事实冻结完整基线。已选目标不会随刷新变化；保存不表示节点已预检或配置已生效。",
      "subtle",
    ),
    picker.node,
    targets,
    add,
    save,
  );
  form.append(fields);

  /**
   * 业务作用：新增一组有限目标字段，单个目标身份由服务器最终验证。
   * 参数说明：
   * - `frozen`：来自同次集群观察的完整声明；缺失时创建手工输入。
   * 返回：达到目标上限后不再增加字段。
   */
  function addTarget(frozen = null) {
    if (rows.length >= capacity.max_targets) {
      return;
    }
    const group = element("fieldset", "", "proposal-target");
    group.append(element("legend", "目标意图"));
    const values = {};
    for (const [key, label, max] of [
      ["node_id", "节点身份", 128],
      ["boot_id", "启动身份", 128],
      ["base_version", "基线配置版本", 16],
      ["base_fingerprint", "基线配置指纹（16 位小写十六进制）", 16],
    ]) {
      const input = element("input");
      input.type = "text";
      input.maxLength = max;
      input.required = true;
      input.autocomplete = "off";
      values[key] = input;
      if (frozen) {
        input.value = String(frozen[key]);
        input.readOnly = true;
      }
      group.append(field(label, input));
    }
    const remove = element("button", "移除此目标");
    remove.type = "button";
    remove.addEventListener("click", () => {
      const index = rows.findIndex((row) => row.values === values);
      if (index >= 0) {
        rows.splice(index, 1);
        group.remove();
        add.disabled = false;
      }
    });
    group.append(
      element("p", baselineDescription(frozen ?? {}), "proposal-digest"),
      remove,
    );
    rows.push({
      values,

      frozen,

      group,
    });
    targets.append(group);
    add.disabled = rows.length >= capacity.max_targets;
  }

  /**
   * 业务作用：把一次选取冻结为只读声明，刷新不能改写已经准备提交的目标。
   * 参数说明：
   * - `target`：完整且同集群的节点身份与原文基线。
   * 返回：增加一个目标；重复或超量时保留原表单并拒绝。
   */
  function addFrozen(target) {
    if (
      rows.some((row) => row.values.node_id.value.trim() === target.node_id)
    ) {
      throw new Error("此节点已在声明中，请先移除旧行再重新选取。");
    }
    const empty =
      rows.length === 1 &&
      !rows[0].frozen &&
      Object.values(rows[0].values).every((input) => !input.value.trim());
    if (!empty && rows.length >= capacity.max_targets) {
      throw new Error("已达到目标数量上限，请先移除不需要的声明。");
    }
    if (empty) {
      rows.pop().group.remove();
    }
    addTarget(target);
  }

  /**
   * 业务作用：冻结当前完整输入，后续重试不能读取已被用户编辑的另一意图。
   * 参数说明: 无。
   * 返回：有界候选、期限和目标数组；输入不合法时不给网络层提交值。
   */
  function read() {
    const text = candidate.value;
    const seconds = Number(ttl.value);
    if (
      !text ||
      new TextEncoder().encode(text).byteLength > capacity.max_candidate_bytes
    ) {
      throw new Error("候选为空或超过 UTF-8 字节上限。");
    }
    if (
      !Number.isInteger(seconds) ||
      seconds < capacity.min_ttl_seconds ||
      seconds > capacity.max_ttl_seconds
    ) {
      throw new Error("提案有效期超出允许范围。");
    }
    if (!rows.length || rows.length > capacity.max_targets) {
      throw new Error("请至少声明一个目标，并遵守目标数量上限。");
    }
    const seen = new Set();
    const declared = rows.map((row) => {
      const values = row.values;
      const node = values.node_id.value.trim();
      const boot = values.boot_id.value.trim();
      const version = Number(values.base_version.value);
      const fingerprint = values.base_fingerprint.value.trim();
      if (
        !/^[A-Za-z0-9_.-]{1,128}$/.test(node) ||
        !/^[A-Za-z0-9_.-]{1,128}$/.test(boot) ||
        seen.has(node) ||
        !Number.isSafeInteger(version) ||
        version <= 0 ||
        !/^[0-9a-f]{16}$/.test(fingerprint)
      ) {
        throw new Error("目标身份重复或不合法，或基线版本、指纹不完整。");
      }
      seen.add(node);
      if (row.frozen) {
        return row.frozen;
      }
      return {
        node_id: node,

        boot_id: boot,

        base_version: version,

        base_fingerprint: fingerprint,
      };
    });
    return {
      candidate: text,

      ttl_seconds: seconds,

      targets: declared,
    };
  }

  /**
   * 业务作用：在提交中或持有未知意图时阻止表单改写原请求。
   * 参数说明：
   * - `value`：当前是否禁止编辑及再次保存。
   * 返回：整组输入切换可编辑状态，原值仍仅在页面内存中。
   */
  function lock(value) {
    locked = value;
    fields.disabled = locked;
    picker.access(discoverable, locked);
  }

  /**
   * 业务作用：工作区或缺少集群读取权限时撤销平台目录入口，避免扩大可见范围。
   * 参数说明：
   * - `allowed`：当前视图是否有平台集群读取资格。
   * 返回：更新目录入口并在失权时撤下待选事实。
   */
  function discover(allowed) {
    discoverable = allowed;
    picker.access(discoverable, locked);
  }

  /**
   * 业务作用：退出当前提案录入时清空可能包含秘密的正文和目标。
   * 参数说明: 无。
   * 返回：恢复空白输入，不保留浏览器草稿。
   */
  function clear() {
    candidate.value = "";
    ttl.value = "600";
    for (const row of rows) {
      for (const input of Object.values(row.values)) {
        input.value = "";
      }
    }
    rows.length = 0;
    targets.replaceChildren();
    picker.clear();
    addTarget();
  }

  add.addEventListener("click", () => {
    addTarget();
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    submit();
  });
  addTarget();
  return {
    node: form,

    read,

    lock,

    clear,

    discover,

    showTargets: picker.show,

    clearTargets: picker.clear,
  };
}
