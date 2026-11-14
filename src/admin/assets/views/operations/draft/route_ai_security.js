import { element } from "../../../core/dom.js";
import { fieldRow } from "./controls.js";

/**
 * 业务作用：独立编辑治理身份与保留声明，不从客户端头或展示值生成授权。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供原生六项身份字段和显式保留策略，必需值由原目标预检复验。
 */
export function routeAiSecurityFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["llm"],
      "AI 治理完整声明（需 ai-governance）",
      [
        [
          "governance",
          "完整治理（移除同时关闭固定模板、RAG 与输出裁决，保留模型及路由认证）",
          "json",
        ],
      ],
    ],
    [
      ["llm", "governance"],
      "AI 治理身份与保留",
      [
        [
          "security",
          "完整安全身份（替换整个身份声明；治理存在时不可缺失）",
          "json",
        ],
        [
          "retention",
          "显式保留策略（仅 request_only；不持久化本次治理正文）",
          "string",
        ],
      ],
    ],
    [
      ["llm", "governance", "security"],
      "AI 可信租户与身份来源",
      [
        [
          "tenant",
          "固定路由租户（非空，最多256字节，不含空白或控制字符）",
          "string",
        ],
        [
          "allowed_origins",
          "完整允许 Origin 名单（每行一项，最多32项；有 Origin 时必须精确匹配）",
          "lines",
        ],
        [
          "tenant_claim",
          "已验签租户 claim 名（声明后必须存在且等于固定 tenant）",
          "string",
        ],
        [
          "groups_claim",
          "已验签组 claim 名（字符串或字符串数组，最多64项）",
          "string",
        ],
        [
          "scopes_claim",
          "已验签 scope claim 名（移除后读取 scope，不接受客户端自报权限）",
          "string",
        ],
        [
          "consumer_groups",
          "完整已认证 consumer 到组的映射（替换全部，最多1024个 consumer，每个最多64组）",
          "json",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：让允许来源按原候选位置修改，不把名单显示顺序当作额外授权。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供 Origin 字符串列表，不生成任何默认来源。
 */
export function routeAiSecurityDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["llm", "governance", "security", "allowed_origins"],
      title: "AI 治理允许 Origin",
      type: "string",
    },
  ];
}

/**
 * 业务作用：识别逐键编辑所需的映射边界，已有其它类型不能被静默替换。
 * 参数说明：
 * - `value`：服务端原始声明的展示投影。
 * 返回：普通映射为 true，缺失值由调用方决定是否允许首次声明。
 */
function mapping(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * 业务作用：为单个已认证 consumer 编辑固定组名单，保留其它 consumer 和治理原声明。
 * 参数说明：
 * - `object`：当前已读取的完整路由身份。
 * - `values`：只用于展示和选择的原始路由投影。
 * - `capacity`：单候选输入字节容量。
 * - `submit`：沿原选择代、摘要与权限门提交草稿动作的回调。
 * - `changed`：输入变化时撤销旧在途结果的回调。
 * 返回：有界逐键编辑面板；新增不继承组，删除须确认，不创建或认证 consumer。
 */
export function aiConsumerGroupEditor(
  object,
  values,
  capacity,
  submit,
  changed,
) {
  const node = element("details", "", "draft-ai-consumer-groups");
  node.append(
    element("summary", "逐项编辑 AI consumer 组映射"),
    element(
      "p",
      "每次只替换一个 consumer 的完整组名单或删除该映射，保留其它成员。只应用于路由已认证的 consumer，不创建身份、不读取客户端自报组；改名须显式新增并删除旧名。普通字段待写输入不会随此动作提交。",
      "subtle",
    ),
  );
  const path = ["llm", "governance", "security", "consumer_groups"];
  let entries = values;
  let valid = true;
  for (const key of path) {
    if (entries === undefined) {
      continue;
    }
    if (!mapping(entries)) {
      valid = false;
      break;
    }
    entries = Object.hasOwn(entries, key) ? entries[key] : undefined;
  }
  valid &&= entries === undefined || mapping(entries);
  const names = valid ? Object.keys(entries ?? {}).sort() : [];
  const selected = element("select");
  selected.setAttribute("aria-label", "AI 已有 consumer");
  for (const [index, name] of names.slice(0, 1024).entries()) {
    const option = element("option", name);
    option.value = String(index);
    selected.append(option);
  }
  const operation = element("select");
  operation.setAttribute("aria-label", "AI consumer 映射操作");
  for (const [value, title] of [
    ["keep", "选择映射操作"],
    ["insert", "新增 consumer 映射"],
    ["set", "替换此 consumer 的组名单"],
    ["remove", "删除此 consumer 映射"],
  ]) {
    const option = element("option", title);
    option.value = value;
    operation.append(option);
  }
  const name = element("input");
  name.maxLength = 128;
  name.autocomplete = "off";
  name.setAttribute("aria-label", "AI 新 consumer 名");
  const confirm = element("input");
  confirm.type = "checkbox";
  confirm.setAttribute("aria-label", "确认删除 AI consumer 映射");
  const confirmation = element("label", "确认删除此 consumer 的组映射");
  confirmation.append(confirm);
  const body = element("div");
  const note = element("p", "", "subtle");
  note.setAttribute("role", "status");
  const button = element("button", "生成 AI consumer 组候选");
  button.type = "button";
  for (const [title, control] of [
    ["已有 consumer", selected],
    ["映射操作", operation],
    ["新增 consumer 名", name],
  ]) {
    const label = element("label", title);
    label.append(control);
    node.append(label);
  }
  node.append(body, confirmation, button, note);
  let row;

  /**
   * 业务作用：切换 consumer 或动作后丢弃旧输入，避免把另一身份的组名单作为新授权。
   * 参数说明: 无。
   * 返回：只对合法映射开放动作，新增保持空值且仍须明确设置，删除重新确认。
   */
  function show() {
    changed();
    row = null;
    body.replaceChildren();
    name.value = "";
    confirm.checked = false;
    name.disabled = operation.value !== "insert";
    confirmation.hidden = operation.value !== "remove";
    button.disabled =
      !valid ||
      names.length > 1024 ||
      operation.value === "keep" ||
      (operation.value === "insert"
        ? names.length >= 1024
        : names[Number(selected.value)] === undefined) ||
      operation.value === "remove";
    note.textContent = !valid
      ? "治理身份或 consumer_groups 不是映射，不能隐式覆盖；请使用整值字段或原始 YAML。"
      : names.length > 1024
        ? "consumer 数量超过逐键编辑容量，请使用原始 YAML。"
        : "逐键路径最多128字节；更长合法名称请使用完整映射。最终身份、组及容量由原目标预检复验。";
    if (!button.disabled && ["insert", "set"].includes(operation.value)) {
      row = fieldRow(
        "AI consumer 组名单",
        "此 consumer 的完整组名单（每行一项，最多64项；空名单不授予组）",
        "lines",
        operation.value === "set"
          ? entries[names[Number(selected.value)]]
          : undefined,
        capacity,
        false,
      );
      body.append(row.node);
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
        typeof key !== "string" ||
        !key ||
        new TextEncoder().encode(key).length > 128 ||
        /[\s\x00-\x1f\x7f]/u.test(key)
      ) {
        throw new Error(
          "逐键 consumer 名须为不含空白或控制字符的1–128字节名称。",
        );
      }
      if (op === "insert" && Object.hasOwn(entries ?? {}, key)) {
        throw new Error("此 consumer 映射已存在，请选择原项替换。");
      }
      let edit;
      if (op === "remove") {
        if (!confirm.checked) {
          throw new Error("请先确认删除此 consumer 映射。");
        }
        edit = { op: "remove", path: [...path, key] };
      } else if (["insert", "set"].includes(op)) {
        const action = row.read();
        if (
          !action ||
          action.remove ||
          !Array.isArray(action.value) ||
          action.value.length > 64 ||
          action.value.some(
            (group) =>
              typeof group !== "string" ||
              !group ||
              new TextEncoder().encode(group).length > 256 ||
              /[\s\x00-\x1f\x7f]/u.test(group),
          )
        ) {
          throw new Error("请明确设置最多64个合法组；空名单须显式设置为空。");
        }
        edit = { op: "set", path: [...path, key], value: action.value };
      } else {
        throw new Error("请先选择映射操作。");
      }
      submit({ type: "patch_nested", object, edits: [edit] });
    } catch (error) {
      note.textContent = error.message;
    }
  });
  operation.addEventListener("change", show);
  selected.addEventListener("change", show);
  confirm.addEventListener("change", () => {
    button.disabled =
      !confirm.checked ||
      operation.value !== "remove" ||
      !valid ||
      !names.length ||
      names.length > 1024;
  });
  node.addEventListener("input", changed);
  node.addEventListener("change", changed);
  show();
  return node;
}
