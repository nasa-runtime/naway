import { element } from "../../../core/dom.js";
import { draftFields } from "./schema.js";
import { fieldRow } from "./controls.js";
import { nestedFields } from "./nested.js";

/**
 * 业务作用：按对象类别生成常用字段及完整扩展字段编辑，修改仅指向用户选择的原始声明。
 * 参数说明：
 * - `kind`：对象类别。
 * - `values`：服务端无求值读取的原始对象。
 * - `capacity`：单候选字节上限。
 * 返回：只读出显式字段 patch 的控件组，不发送网络请求或保存草稿。
 */
export function draftFieldPanel(kind, values, capacity) {
  const node = element("div", "", "draft-fields");
  const rows = new Map();
  const known = draftFields(kind);
  const remaining = Object.keys(values).filter(
    (key) =>
      key !== "id" &&
      !(key === "name" && ["credential", "secret_provider"].includes(kind)) &&
      !known.some(([name]) => name === key),
  );
  if (known.length + remaining.length > 128) {
    throw new Error("此对象字段过多，请在原始 YAML 中编辑。");
  }
  for (const [name, title, type] of known) {
    const row = fieldRow(
      name,
      title,
      type,
      Object.hasOwn(values, name) ? values[name] : undefined,
      capacity,
      kind !== "consumer_binding",
    );
    rows.set(name, row);
    node.append(row.node);
  }
  const nested = nestedFields(kind, values, capacity);
  node.append(nested.node);
  const complex = element("details");
  complex.append(element("summary", "其它声明与复杂策略"));
  for (const name of remaining) {
    const value = values[name];
    const type = ["string", "boolean", "number"].includes(typeof value)
      ? typeof value
      : "json";
    const row = fieldRow(name, name, type, value, capacity);
    rows.set(name, row);
    complex.append(row.node);
  }
  const addName = element("input");
  addName.maxLength = 128;
  addName.autocomplete = "off";
  addName.setAttribute("aria-label", "新增字段名");
  const add = element("button", "添加字段控件");
  add.type = "button";
  const note = element(
    "p",
    "新增字段使用 JSON 值；现有未知字段会保持原声明。",
    "subtle",
  );
  add.addEventListener("click", () => {
    const name = addName.value;
    if (
      !name ||
      name === "id" ||
      (name === "name" && ["credential", "secret_provider"].includes(kind)) ||
      rows.has(name) ||
      /[\x00-\x1f\x7f]/.test(name) ||
      new TextEncoder().encode(name).length > 128 ||
      rows.size >= 128
    ) {
      note.textContent = "字段名为空、重复、受保护或超过容量。";
      return;
    }
    const row = fieldRow(name, name, "json", undefined, capacity);
    rows.set(name, row);
    complex.append(row.node);
    complex.open = true;
    addName.value = "";
    note.textContent = "已添加控件；选择设置值后才会修改候选。";
  });
  const addLabel = element("label", "新增字段名");
  addLabel.append(addName);
  complex.append(addLabel, add, note);
  if (kind === "consumer_binding") {
    node.append(
      element(
        "p",
        "解除显式套餐绑定请删除此对象；组成员及身份凭据不受影响。",
        "subtle",
      ),
    );
  } else {
    node.append(complex);
  }

  /**
   * 业务作用：收集明确编辑的键，不从展示值重建整个对象。
   * 参数说明: 无。
   * 返回：独立设置和移除列表，至少一项显式动作才允许生成候选。
   */
  function read() {
    const fields = Object.create(null);
    const remove = [];
    for (const row of rows.values()) {
      const action = row.read();
      if (action?.remove) {
        remove.push(action.name);
      } else if (action) {
        fields[action.name] = action.value;
      }
    }
    const edits = nested.read();
    for (const edit of edits) {
      if (
        Object.hasOwn(fields, edit.path[0]) ||
        remove.includes(edit.path[0])
      ) {
        throw new Error(
          "同一字段不能同时整值修改和编辑子项，请只选择一种方式。",
        );
      }
    }
    if (!remove.length && !Object.keys(fields).length && !edits.length) {
      throw new Error("请先为需要修改的字段选择设置值或移除声明。");
    }
    if (edits.length) {
      return {
        fields,

        remove,

        edits,
      };
    }
    return {
      fields,

      remove,
    };
  }
  return {
    node,

    read,
  };
}
