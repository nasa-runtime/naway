import { element } from "../../../core/dom.js";
import { draftFields } from "./schema.js";
import { draftFieldPanel } from "./fields.js";
import { fieldRow } from "./controls.js";
import { fieldAction } from "./nested.js";

/**
 * 业务作用：列出常用列表与原文已声明的扩展数组，不把未知值转换成列表。
 * 参数说明：
 * - `kind`：当前对象类别。
 * - `values`：只用于展示的原始字段投影。
 * 返回：有界列表位置、元素控件类型和原始展示值。
 */
function lists(kind, values) {
  const result = draftFields(kind)
    .filter((field) => field[2] === "lines")
    .map(([key, title]) => ({
      path: [key],
      title,
      type: "string",
    }));
  if (kind === "service") {
    result.push({
      path: ["instances"],
      title: "静态上游实例",
      type: "instance",
    });
  }
  for (const [key, value] of Object.entries(values)) {
    if (
      key !== "id" &&
      Array.isArray(value) &&
      !result.some((item) => item.path[0] === key)
    ) {
      result.push({
        path: [key],
        title: key,
        type: "json",
      });
    }
  }
  if (kind === "interface_rule") {
    result.push({
      path: ["match", "methods"],
      title: "接口请求方法",
      type: "string",
    });
  }
  if (kind === "proxy") {
    result.push({
      path: ["http3", "capabilities"],
      title: "HTTP/3 协议扩展",
      type: "string",
    });
  }
  return result.map((item) => {
    let current = values;
    let valid = true;
    for (const key of item.path) {
      if (current === undefined) {
        continue;
      }
      if (!current || Array.isArray(current) || typeof current !== "object") {
        valid = false;
        break;
      }
      current = Object.hasOwn(current, key) ? current[key] : undefined;
    }
    return {
      ...item,
      values: current,
      valid: valid && (current === undefined || Array.isArray(current)),
    };
  });
}

/**
 * 业务作用：为当前对象提供单个列表动作，原始子树留在服务端，索引只绑定当前候选。
 * 参数说明：
 * - `object`：已读取并冻结的对象身份。
 * - `values`：列表和元素的展示投影，不作为未编辑字段输出。
 * - `capacity`：单候选输入容量。
 * - `submit`：通过统一摘要与授权门生成候选的回调。
 * - `changed`：撤销编辑状态变化前的在途结果。
 * 返回：列表编辑面板；每次只提交一个明确动作，不保存或发布活动配置。
 */
export function sequenceEditor(object, values, capacity, submit, changed) {
  const node = element("details", "", "draft-sequence");
  node.append(element("summary", "逐项编辑有序列表"));
  node.append(
    element(
      "p",
      "列表操作单独生成候选；普通字段控件中尚未生成的修改不会随本次提交。位置从 0 开始，移动目标表示最终位置。",
      "subtle",
    ),
  );
  const choices = lists(object.kind, values);
  const list = element("select");
  list.setAttribute("aria-label", "列表字段");
  choices.forEach((item, index) => {
    const option = element(
      "option",
      item.title + " · " + item.path.join(" → "),
    );
    option.value = String(index);
    list.append(option);
  });
  const item = element("select");
  item.setAttribute("aria-label", "列表元素位置");
  const operation = element("select");
  operation.setAttribute("aria-label", "列表操作");
  for (const [value, title] of [
    ["keep", "选择列表操作"],
    ["patch", "编辑对象元素字段"],
    ["insert", "插入新元素"],
    ["set", "替换整个元素"],
    ["remove", "删除元素"],
    ["move", "移动元素"],
  ]) {
    const option = element("option", title);
    option.value = value;
    operation.append(option);
  }
  const position = element("input");
  position.type = "number";
  position.min = "0";
  position.step = "1";
  position.setAttribute("aria-label", "插入或移动目标位置");
  const body = element("div");
  const confirm = element("input");
  confirm.type = "checkbox";
  confirm.setAttribute("aria-label", "确认删除列表元素");
  const confirmation = element("label", "确认删除当前候选中的这个元素");
  confirmation.append(confirm);
  const button = element("button", "生成列表编辑后的候选");
  button.type = "button";
  const note = element("p", "", "subtle");
  note.setAttribute("role", "status");
  for (const [title, input] of [
    ["列表字段", list],
    ["现有元素位置", item],
    ["列表操作", operation],
    ["插入或移动后的目标位置", position],
  ]) {
    const label = element("label", title);
    label.append(input);
    node.append(label);
  }
  node.append(body, confirmation, button, note);
  let fields = null;
  let value = null;

  /**
   * 业务作用：切换操作或元素后重新建立显式输入，不能沿用另一元素的待写字段。
   * 参数说明: 无。
   * 返回：更新控件及删除确认；非列表或超限目标不开放动作。
   */
  function show() {
    changed();
    fields = value = null;
    body.replaceChildren();
    confirm.checked = false;
    confirmation.hidden = operation.value !== "remove";
    position.disabled = !["insert", "move"].includes(operation.value);
    const selected = choices[Number(list.value)];
    const entries = selected?.values ?? [];
    button.disabled =
      !selected?.valid || entries.length > 4096 || operation.value === "keep";
    note.textContent = !selected?.valid
      ? "当前位置不是列表或父字段类型不符，不能隐式覆盖。"
      : entries.length > 4096
        ? "列表超过逐项编辑容量，请使用原始 YAML。"
        : "仅明确输入的新值会写入候选，未编辑元素保持原声明。";
    if (button.disabled) {
      return;
    }
    const current = entries[Number(item.value)];
    if (operation.value === "patch") {
      if (!current || Array.isArray(current) || typeof current !== "object") {
        button.disabled = true;
        note.textContent = "当前元素不是对象，不能编辑子字段。";
        return;
      }
      fields = draftFieldPanel(selected.type, current, capacity);
      body.append(fields.node);
    } else if (["insert", "set"].includes(operation.value)) {
      if (selected.type === "instance") {
        fields = draftFieldPanel("instance", {}, capacity);
        body.append(
          element(
            "p",
            "新实例仅包含本次明确设置的字段；替换会移除旧元素的其它字段。",
            "subtle",
          ),
          fields.node,
        );
      } else {
        value = fieldRow(
          "列表元素",
          "明确的新元素值",
          selected.type,
          operation.value === "set" ? current : undefined,
          capacity,
        );
        body.append(value.node);
      }
    }
  }

  /**
   * 业务作用：按选中列表的原始顺序建立下标目录，不复制或提交其完整元素。
   * 参数说明: 无。
   * 返回：有界元素选择器与未选择动作，缺失列表只允许后续首次插入。
   */
  function selectList() {
    item.replaceChildren();
    const selected = choices[Number(list.value)];
    const entries = selected?.valid ? (selected.values ?? []) : [];
    entries.slice(0, 4096).forEach((entry, index) => {
      const label =
        typeof entry === "string"
          ? entry
          : typeof entry?.uri === "string"
            ? entry.uri
            : "元素";
      const option = element("option", index + " · " + label.slice(0, 160));
      option.value = String(index);
      item.append(option);
    });
    operation.value = "keep";
    position.value = String(entries.length);
    show();
  }

  /**
   * 业务作用：解析用户明确填写的有限列表位置，空串不能被当成零下标。
   * 参数说明：
   * - `text`：下标控件原始字符串。
   * 返回：0至4096的整数；其它输入拒绝生成动作。
   */
  function index(text) {
    if (!/^(0|[1-9][0-9]*)$/.test(text) || Number(text) > 4096) {
      throw new Error("请填写有效的列表位置。");
    }
    return Number(text);
  }

  button.addEventListener("click", () => {
    try {
      if (button.disabled) {
        return;
      }
      const selected = choices[index(list.value)];
      const op = operation.value;
      let edit;
      if (op === "move") {
        edit = {
          op,
          from: index(item.value),
          to: index(position.value),
        };
      } else if (op === "remove") {
        if (!confirm.checked) {
          throw new Error("请先确认删除当前元素。");
        }
        edit = {
          op,
          index: index(item.value),
        };
      } else if (op === "patch") {
        const action = fieldAction(object, fields.read(), false);
        const edits =
          action.type === "patch_nested"
            ? action.edits
            : [
                ...Object.entries(action.fields).map(([key, value]) => ({
                  op: "set",
                  path: [key],
                  value,
                })),
                ...action.remove.map((key) => ({
                  op: "remove",
                  path: [key],
                })),
              ];
        edit = {
          op,
          index: index(item.value),
          edits,
        };
      } else if (op === "insert" || op === "set") {
        const action = fields
          ? fieldAction(object, fields.read(), true)
          : value.read();
        if (!action || action.remove) {
          throw new Error("请明确设置新元素值。");
        }
        edit = {
          op,
          index: index(op === "insert" ? position.value : item.value),
          value: fields ? action.fields : action.value,
        };
      } else {
        throw new Error("请先选择列表操作。");
      }
      submit({
        type: "patch_sequence",
        object,
        path: selected.path,
        edit,
      });
    } catch (error) {
      note.textContent = error.message;
    }
  });
  list.addEventListener("change", selectList);
  item.addEventListener("change", show);
  operation.addEventListener("change", show);
  node.addEventListener("input", changed);
  node.addEventListener("change", changed);
  selectList();
  return node;
}
