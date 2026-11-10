import { element } from "../../../core/dom.js";
import { fieldRow } from "./controls.js";

const degraphqlVariableFields = [
  ["source", "固定来源（path / query / header / literal）", "string"],
  ["name", "来源字段名（literal 须移除或留空）", "string"],
  ["value", "literal 的固定非 null JSON 值", "json"],
  ["kind", "文本类型（string / integer / number / boolean）", "string"],
  ["required", "文本来源缺失时拒绝请求", "boolean"],
  ["max_value_bytes", "文本来源单值上限（1–65536 UTF-8 字节）", "number"],
];

/**
 * 业务作用：识别可逐键编辑的声明，避免把已有标量或列表隐式替换成映射。
 * 参数说明：
 * - `value`：服务端提供的原始声明投影。
 * 返回：仅普通映射为 true；缺失值由调用方按首次声明处理。
 */
function degraphqlMapping(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * 业务作用：显式编辑受信 GraphQL 文档和有界 REST 映射，未修改的查询与变量声明保持原值。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供六项原生字段；不生成查询、变量或缺省预算。
 */
export function routeDegraphqlFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["degraphql"],
      "固定 REST 到 GraphQL 映射",
      [
        ["query", "受信的固定 GraphQL 文档", "multiline"],
        ["operation_name", "多 operation 文档的固定选择名", "string"],
        ["upstream_path", "固定上游绝对 path（无 query / fragment）", "string"],
        [
          "rest_path_template",
          "与 PathTemplate 签名一致的 path 变量模板",
          "string",
        ],
        ["variables", "按 GraphQL 变量名声明的完整来源映射", "json"],
        [
          "max_body_bytes",
          "生成 JSON envelope 上限（1024–1048576 字节）",
          "number",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：对选中路由的精确变量名提交独立草稿动作，原始变量及其它策略不随展示重新编码。
 * 参数说明：
 * - `object`：已读取并冻结的路由身份。
 * - `values`：当前路由的原始字段投影，仅用于展示与选择。
 * - `capacity`：单候选输入字节容量。
 * - `submit`：沿统一摘要、范围和选择代门提交候选编辑的回调。
 * - `changed`：输入变化时撤销旧在途结果的回调。
 * 返回：有界变量编辑面板；只生成候选，不保存或发布配置。
 */
export function degraphqlVariableEditor(
  object,
  values,
  capacity,
  submit,
  changed,
) {
  const node = element("details", "", "draft-degraphql-variables");
  node.append(element("summary", "逐项编辑 degraphql 命名变量"));
  node.append(
    element(
      "p",
      "变量动作单独生成候选，普通字段的待写输入不会随本次提交。编辑子字段保留其余原声明；整值替换只包含本次明确设置的字段。改名请显式新增并删除旧名。",
      "subtle",
    ),
  );
  const policy = values.degraphql;
  const entries = degraphqlMapping(policy) ? policy.variables : undefined;
  const valid =
    (policy === undefined || degraphqlMapping(policy)) &&
    (entries === undefined || degraphqlMapping(entries));
  const names = valid ? Object.keys(entries ?? {}).sort() : [];
  const selected = element("select");
  selected.setAttribute("aria-label", "degraphql 已有变量名");
  for (const [index, name] of names.slice(0, 64).entries()) {
    const option = element("option", name.slice(0, 128));
    option.value = String(index);
    selected.append(option);
  }
  const operation = element("select");
  operation.setAttribute("aria-label", "degraphql 变量操作");
  for (const [value, title] of [
    ["keep", "选择变量操作"],
    ["patch", "编辑原变量字段"],
    ["insert", "新增变量名"],
    ["set", "替换原变量声明"],
    ["remove", "删除原变量声明"],
  ]) {
    const option = element("option", title);
    option.value = value;
    operation.append(option);
  }
  const name = element("input");
  name.maxLength = 128;
  name.autocomplete = "off";
  name.setAttribute("aria-label", "degraphql 新变量名");
  const confirm = element("input");
  confirm.type = "checkbox";
  confirm.setAttribute("aria-label", "确认删除 degraphql 变量");
  const confirmation = element("label", "确认删除当前候选中的这个变量");
  confirmation.append(confirm);
  const body = element("div");
  const note = element("p", "", "subtle");
  note.setAttribute("role", "status");
  const button = element("button", "生成 degraphql 变量候选");
  button.type = "button";
  for (const [title, control] of [
    ["已有 GraphQL 变量名", selected],
    ["变量操作", operation],
    ["新增 GraphQL 变量名", name],
  ]) {
    const label = element("label", title);
    label.append(control);
    node.append(label);
  }
  node.append(body, confirmation, button, note);
  let rows = [];

  /**
   * 业务作用：切换变量或动作时丢弃旧待写字段，非映射祖先和超限目录不开放逐项写入。
   * 参数说明: 无。
   * 返回：重建六字段控件及删除确认，未声明字段不填充缺省值。
   */
  function showVariable() {
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
      names.length > 64 ||
      operation.value === "keep" ||
      (operation.value === "insert"
        ? names.length >= 64
        : currentName === undefined) ||
      (operation.value === "patch" && !degraphqlMapping(current));
    note.textContent = !valid
      ? "degraphql 或 variables 不是映射，不能隐式覆盖；请使用整值字段或原始 YAML。"
      : names.length > 64
        ? "变量超过逐项编辑容量，请使用原始 YAML。"
        : "只提交精确变量名的明确动作；最终类型、必需值与组合由原目标构建器校验。";
    if (button.disabled) {
      return;
    }
    if (["patch", "insert", "set"].includes(operation.value)) {
      rows = degraphqlVariableFields.map(([key, title, type]) => {
        const value =
          operation.value === "patch" && Object.hasOwn(current, key)
            ? current[key]
            : undefined;
        return fieldRow(
          "degraphql 变量 → " + key,
          title,
          type,
          value,
          capacity,
        );
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
        (!/^[_A-Za-z][_0-9A-Za-z]{0,127}$/.test(key) ||
          Object.hasOwn(entries ?? {}, key))
      ) {
        throw new Error("新增变量名必须是唯一的 GraphQL 标识符，最多128字节。");
      }
      const path = ["degraphql", "variables", key];
      let edits;
      if (op === "remove") {
        if (!confirm.checked) {
          throw new Error("请先确认删除当前变量。");
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
            key: degraphqlVariableFields[index][0],
          }))
          .filter((item) => item.action);
        if (!patch.length) {
          throw new Error("请先明确设置或移除需要修改的变量字段。");
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
          if (!Object.keys(value).length) {
            throw new Error("新增或替换变量至少需要一个明确的新字段。");
          }
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
  operation.addEventListener("change", showVariable);
  selected.addEventListener("change", showVariable);
  confirm.addEventListener("change", () => {
    button.disabled =
      !confirm.checked ||
      operation.value !== "remove" ||
      !valid ||
      names.length > 64 ||
      !names.length;
  });
  node.addEventListener("input", changed);
  node.addEventListener("change", changed);
  showVariable();
  return node;
}
