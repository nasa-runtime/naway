import { element } from "../../../core/dom.js";
import { draftFields } from "./schema.js";

/**
 * 业务作用：拒绝浏览器无法精确表达的显式数字，避免字段编辑悄悄改变整数含义。
 * 参数说明：
 * - `value`：即将明确写入候选的字段值。
 * 返回：有限且精确的 JSON 值；不支持的数字须改用原始 YAML 输入。
 */
function exactValue(value) {
  const stack = [value];
  while (stack.length) {
    const current = stack.pop();
    if (
      typeof current === "number" &&
      (!Number.isFinite(current) ||
        (Number.isInteger(current) && !Number.isSafeInteger(current)))
    ) {
      throw new Error(
        "字段包含无法精确表示的数字，请使用原始 YAML 编辑该字段。",
      );
    }
    if (current && typeof current === "object") {
      for (const child of Object.values(current)) {
        stack.push(child);
      }
    }
  }
  return value;
}

/**
 * 业务作用：对一个原始字段显式选择保持、设置或移除，缺省与 false、空串、null 彼此独立。
 * 参数说明：
 * - `name`：原始配置键。
 * - `title`：业务标签。
 * - `type`：常用控件类型或 JSON。
 * - `value`：原始声明值，缺失时为 undefined。
 * - `capacity`：候选字节上限，用于输入控件容量。
 * 返回：字段节点与显式修改读取器；保持状态不重新编码原始值。
 */
function fieldRow(name, title, type, value, capacity) {
  const row = element("div", "", "draft-field");
  const mode = element("select");
  mode.setAttribute("aria-label", `${name} 修改方式`);
  for (const [key, text] of [
    ["keep", "保持原声明"],
    ["set", "设置值"],
    ["remove", "移除声明"],
  ]) {
    const option = element("option", text);
    option.value = key;
    mode.append(option);
  }
  const compatible =
    value === undefined ||
    (type === "lines"
      ? Array.isArray(value) && value.every((item) => typeof item === "string")
      : typeof value === type);
  const actual = compatible ? type : "json";
  const input = element(
    actual === "boolean"
      ? "select"
      : ["lines", "json"].includes(actual)
        ? "textarea"
        : "input",
  );
  input.setAttribute("aria-label", `${name} 字段值`);
  input.autocomplete = "off";
  input.spellcheck = false;
  input.maxLength = capacity;
  if (actual === "boolean") {
    for (const text of ["true", "false"]) {
      const option = element("option", text);
      option.value = text;
      input.append(option);
    }
  } else if (actual === "number") {
    input.type = "number";
    input.step = "any";
  } else if (["lines", "json"].includes(actual)) {
    input.rows = 4;
  }
  input.value =
    value === undefined
      ? actual === "boolean"
        ? "false"
        : actual === "json"
          ? "null"
          : ""
      : actual === "lines"
        ? value.join("\n")
        : actual === "json"
          ? JSON.stringify(value, null, 2)
          : String(value);
  input.disabled = true;
  mode.addEventListener("change", () => {
    input.disabled = mode.value !== "set";
  });
  const label = element(
    "label",
    `${title} · ${name}${value === undefined ? "（未声明）" : ""}`,
  );
  label.append(input);
  row.append(label, mode);

  /**
   * 业务作用：只输出用户明确选择的字段动作，原始声明不因控件展示而被改写。
   * 参数说明: 无。
   * 返回：保持时为 null；设置和移除携带独立动作，非法类型拒绝提交。
   */
  function read() {
    if (mode.value === "keep") {
      return null;
    }
    if (mode.value === "remove") {
      return {
        name,

        remove: true,
      };
    }
    let result;
    try {
      result =
        actual === "boolean"
          ? input.value === "true"
          : actual === "number"
            ? input.value.trim()
              ? Number(input.value)
              : NaN
            : actual === "lines"
              ? input.value
                ? input.value.split("\n")
                : []
              : actual === "json"
                ? JSON.parse(input.value)
                : input.value;
    } catch {
      throw new Error(
        `${name} 需要合法 JSON；null 是值，移除须选择“移除声明”。`,
      );
    }
    return {
      name,

      value: exactValue(result),
    };
  }
  return {
    node: row,

    read,
  };
}

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
    (key) => key !== "id" && !known.some(([name]) => name === key),
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
    );
    rows.set(name, row);
    node.append(row.node);
  }
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
  node.append(complex);

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
    if (!remove.length && !Object.keys(fields).length) {
      throw new Error("请先为需要修改的字段选择设置值或移除声明。");
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
