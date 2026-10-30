import { element } from "../../../core/dom.js";

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
 * - `removable`：该字段是否允许独立移除，必需的标量绑定须通过对象删除解除。
 * 返回：字段节点与显式修改读取器；保持状态不重新编码原始值。
 */
export function fieldRow(name, title, type, value, capacity, removable = true) {
  const row = element("div", "", "draft-field");
  const mode = element("select");
  mode.setAttribute("aria-label", `${name} 修改方式`);
  for (const [key, text] of [
    ["keep", "保持原声明"],
    ["set", "设置值"],
    ["remove", "移除声明"],
  ]) {
    if (key === "remove" && !removable) {
      continue;
    }
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
      if (!removable) {
        throw new Error("此字段不能单独移除，解除绑定请删除对象。");
      }
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
