import { element } from "../../../core/dom.js";
import { fieldRow } from "./controls.js";
import {
  layerContextFields,
  validateLayerContextDeclaration,
} from "./route_layer.js";

/**
 * 业务作用：识别可逐名编辑的可信上下文映射，不把数组或标量转成授权声明。
 * 参数说明：
 * - `value`：原始字段的展示投影。
 * 返回：仅非 null 且非数组的对象为 true，缺失声明由调用者按首次声明处理。
 */
function layerContextMapping(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * 业务作用：对选中路由的精确上下文名提交独立草稿动作，原始上下文及其它策略不随展示重新编码。
 * 参数说明：
 * - `object`：已读取并冻结的路由身份。
 * - `values`：当前路由的原始字段投影，仅用于展示与选择。
 * - `capacity`：单候选输入字节容量。
 * - `submit`：沿统一摘要、范围和选择代门提交候选编辑的回调。
 * - `changed`：输入变化时撤销旧在途结果的回调。
 * 返回：有界上下文编辑面板；只生成候选，不保存或发布配置。
 */
export function layerContextEditor(object, values, capacity, submit, changed) {
  const node = element("details", "", "draft-layer-context");
  node.append(element("summary", "逐项编辑 layer 命名上下文"));
  node.append(
    element(
      "p",
      "上下文动作单独生成候选，普通字段的待写输入不会随本次提交。编辑子字段保留其余原声明；整值替换只包含本次明确设置的字段。改名请显式新增并删除旧名。",
      "subtle",
    ),
  );
  const policy = values.layer;
  const entries = layerContextMapping(policy) ? policy.context : undefined;
  const valid =
    (policy === undefined || layerContextMapping(policy)) &&
    (entries === undefined || layerContextMapping(entries));
  const names = valid ? Object.keys(entries ?? {}).sort() : [];
  const selected = element("select");
  selected.setAttribute("aria-label", "layer 已有上下文名");
  for (const [index, name] of names.slice(0, 16).entries()) {
    const option = element("option", name.slice(0, 128));
    option.value = String(index);
    selected.append(option);
  }
  const operation = element("select");
  operation.setAttribute("aria-label", "layer 上下文操作");
  for (const [value, title] of [
    ["keep", "选择上下文操作"],
    ["patch", "编辑原上下文字段"],
    ["insert", "新增上下文名"],
    ["set", "替换原上下文声明"],
    ["remove", "删除原上下文声明"],
  ]) {
    const option = element("option", title);
    option.value = value;
    operation.append(option);
  }
  const name = element("input");
  name.maxLength = 128;
  name.autocomplete = "off";
  name.setAttribute("aria-label", "layer 新上下文名");
  const confirm = element("input");
  confirm.type = "checkbox";
  confirm.setAttribute("aria-label", "确认删除 layer 上下文");
  const confirmation = element("label", "确认删除当前候选中的这个上下文");
  confirmation.append(confirm);
  const body = element("div");
  const note = element("p", "", "subtle");
  note.setAttribute("role", "status");
  const button = element("button", "生成 layer 上下文候选");
  button.type = "button";
  for (const [title, control] of [
    ["已有 分层 上下文名", selected],
    ["上下文操作", operation],
    ["新增 分层 上下文名", name],
  ]) {
    const label = element("label", title);
    label.append(control);
    node.append(label);
  }
  node.append(body, confirmation, button, note);
  let rows = [];

  /**
   * 业务作用：切换上下文或动作时丢弃旧待写字段，非映射祖先和超限目录不开放逐项写入。
   * 参数说明: 无。
   * 返回：重建三字段控件及删除确认，未声明字段不填充缺省值。
   */
  function showContext() {
    changed();
    rows = [];
    body.replaceChildren();
    name.value = "";
    confirm.checked = false;
    confirmation.hidden = operation.value !== "remove";
    name.disabled = operation.value !== "insert";
    const currentName = names[Number(selected.value)];
    const current =
      currentName === undefined ? undefined : entries[currentName];
    button.disabled =
      !valid ||
      names.length > 16 ||
      operation.value === "keep" ||
      (operation.value === "insert"
        ? names.length >= 16
        : currentName === undefined) ||
      (operation.value === "patch" && !layerContextMapping(current));
    note.textContent = !valid
      ? "layer 或 context 不是映射，不能隐式覆盖；请使用整值字段或原始 YAML。"
      : names.length > 16
        ? "上下文超过逐项编辑容量，请使用原始 YAML。"
        : "只提交精确上下文名的明确动作；最终类型、必需值与组合由原目标构建器校验。";
    if (button.disabled) {
      return;
    }
    if (["patch", "insert", "set"].includes(operation.value)) {
      rows = layerContextFields.map(([key, title, type]) => {
        const value =
          operation.value === "patch" && Object.hasOwn(current, key)
            ? current[key]
            : undefined;
        return fieldRow("layer 上下文 → " + key, title, type, value, capacity);
      });
      body.append(...rows.map((row) => row.node));
    }
    if (operation.value === "remove") {
      button.disabled = true;
    }
  }

  button.addEventListener("click", () => {
    if (button.disabled) {
      return;
    }
    try {
      const op = operation.value;
      const key = op === "insert" ? name.value : names[Number(selected.value)];
      if (
        op === "insert" &&
        (!/^[0-9A-Za-z._-]{1,128}$/.test(key) ||
          ["__proto__", "prototype", "constructor"].includes(key) ||
          Object.hasOwn(entries ?? {}, key))
      ) {
        throw new Error("新增上下文名必须是唯一的 分层 标识符，最多128字节。");
      }
      const path = ["layer", "context", key];
      let edits;
      if (op === "remove") {
        if (!confirm.checked) {
          throw new Error("请先确认删除当前上下文。");
        }
        edits = [
          {
            op: "remove",
            path,
          },
        ];
      } else {
        const patch = rows
          .map((row, index) => ({
            action: row.read(),
            key: layerContextFields[index][0],
          }))
          .filter((item) => item.action);
        if (!patch.length) {
          throw new Error("请先明确设置或移除需要修改的上下文字段。");
        }
        if (op === "patch") {
          edits = patch.map(({ action, key }) =>
            action.remove
              ? {
                  op: "remove",
                  path: [...path, key],
                }
              : {
                  op: "set",
                  path: [...path, key],
                  value: action.value,
                },
          );
        } else {
          const value = Object.create(null);
          for (const item of patch) {
            if (!item.action.remove) {
              value[item.key] = item.action.value;
            }
          }
          validateLayerContextDeclaration(value);
          edits = [
            {
              op: "set",
              path,
              value,
            },
          ];
        }
      }
      submit({
        type: "patch_nested",
        object,
        edits,
      });
    } catch (error) {
      note.textContent = error.message;
    }
  });
  operation.addEventListener("change", showContext);
  selected.addEventListener("change", showContext);
  confirm.addEventListener("change", () => {
    button.disabled =
      !confirm.checked ||
      operation.value !== "remove" ||
      !valid ||
      names.length > 16 ||
      !names.length;
  });
  node.addEventListener("input", changed);
  node.addEventListener("change", changed);
  showContext();
  return node;
}
