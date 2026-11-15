import { element } from "../../../core/dom.js";

const nativeRoles = ["viewer", "developer", "owner"];

/**
 * 业务作用：按原文成员身份编辑固定团队角色映射，不将 SSO 身份键解释为路径或客户端授权。
 * 参数说明：
 * - `object`：当前已读取的独立团队身份。
 * - `values`：只用于选择成员与展示已有角色的原始字段投影。
 * - `submit`：经过同一候选摘要和授权门提交单个成员动作的回调。
 * - `changed`：选择、角色或确认改变时撤销在途结果的回调。
 * 返回：有界团队角色控件；其它对象返回 null，不保存或发布活动配置。
 */
export function portalTeamRoleEditor(object, values, submit, changed) {
  if (object.kind !== "portal_team") {
    return null;
  }
  const node = element("details", "", "draft-team-roles");
  node.append(element("summary", "逐项编辑团队角色映射"));
  node.append(
    element(
      "p",
      "每次只修改一个明确成员；JSON 字段中未生成的修改不会合并。本界面不建立 SSO，空映射不授予任何人权限。成员键为1–256个 UTF-8 字节，斜线和点均为普通字符。",
      "subtle",
    ),
  );
  const validValues =
    values && !Array.isArray(values) && typeof values === "object";
  const choices = ["group_roles", "subject_roles"].map((name) => {
    const mapping = values?.[name];
    const valid =
      validValues &&
      (mapping === undefined ||
        (mapping && !Array.isArray(mapping) && typeof mapping === "object"));
    return { name, valid, entries: valid ? Object.entries(mapping ?? {}) : [] };
  });
  const total = choices.reduce((sum, choice) => sum + choice.entries.length, 0);
  const field = element("select");
  field.setAttribute("aria-label", "团队角色映射");
  for (const [name, title] of [
    ["group_roles", "可信 SSO 组角色"],
    ["subject_roles", "可信 SSO subject 角色"],
  ]) {
    const option = element("option", title);
    option.value = name;
    field.append(option);
  }
  const existing = element("select");
  existing.setAttribute("aria-label", "已有团队成员键");
  const operation = element("select");
  operation.setAttribute("aria-label", "团队角色操作");
  for (const [value, title] of [
    ["keep", "选择成员操作"],
    ["insert", "插入新成员"],
    ["replace", "替换已有成员角色"],
    ["remove", "删除已有成员"],
  ]) {
    const option = element("option", title);
    option.value = value;
    operation.append(option);
  }
  const key = element("input");
  key.maxLength = 256;
  key.autocomplete = "off";
  key.spellcheck = false;
  key.setAttribute("aria-label", "新增团队成员键");
  const role = element("select");
  role.setAttribute("aria-label", "团队成员角色");
  for (const [value, title] of [
    ["", "明确选择角色"],
    ...nativeRoles.map((value) => [value, value]),
  ]) {
    const option = element("option", title);
    option.value = value;
    role.append(option);
  }
  const original = element("p", "", "subtle");
  const confirm = element("input");
  confirm.type = "checkbox";
  confirm.setAttribute("aria-label", "确认删除团队成员");
  const confirmation = element("label", "确认删除此映射中的成员授权");
  confirmation.append(confirm);
  const button = element("button", "生成团队角色候选");
  button.type = "button";
  const note = element("p", "", "subtle");
  note.setAttribute("role", "status");
  for (const [title, input] of [
    ["团队角色映射", field],
    ["已有成员键", existing],
    ["成员操作", operation],
    ["新成员完整身份", key],
    ["明确的新角色", role],
  ]) {
    const label = element("label", title);
    label.append(input);
    node.append(label);
  }
  node.append(original, confirmation, button, note);

  /**
   * 业务作用：让字段、成员或操作切换退休旧请求，并清除不能继承的新角色与删除确认。
   * 参数说明: 无。
   * 返回：仅固定且有界的原始映射开放动作，错型、超量或缺少已有成员时保持关闭。
   */
  function show() {
    changed();
    confirm.checked = false;
    key.value = "";
    role.value = "";
    key.disabled = operation.value !== "insert";
    role.disabled = !["insert", "replace"].includes(operation.value);
    confirmation.hidden = operation.value !== "remove";
    const selected = choices.find((choice) => choice.name === field.value);
    const current = /^(0|[1-9][0-9]*)$/.test(existing.value)
      ? selected?.entries[Number(existing.value)]
      : undefined;
    const valid = choices.every((choice) => choice.valid) && total <= 256;
    button.disabled =
      !selected ||
      !valid ||
      operation.value === "keep" ||
      (operation.value === "insert" && total === 256) ||
      (["replace", "remove"].includes(operation.value) && !current);
    original.textContent = current
      ? `已有角色：${nativeRoles.includes(current[1]) ? current[1] : "非原生角色声明，未编辑内容由目标预检裁决"}`
      : "当前映射没有选中的已有成员。";
    note.textContent = !valid
      ? "角色映射错型或两类成员总数超过256，请明确重建完整 JSON 映射。"
      : total === 256 && operation.value === "insert"
        ? "两类角色映射合计已达到256项，不能新增成员。"
        : "已有身份不能改名；新增不覆盖旧成员，替换与删除必须选择已有成员。";
  }

  /**
   * 业务作用：从固定原文映射建立纯文本成员目录，不通过 JavaScript 属性赋值处理身份键。
   * 参数说明: 无。
   * 返回：有界原始键目录与未选择动作；缺失映射只允许明确插入，null 或错型不改为空映射。
   */
  function selectField() {
    existing.replaceChildren();
    const selected = choices.find((choice) => choice.name === field.value);
    for (const [index, [name]] of (selected?.entries ?? [])
      .slice(0, 256)
      .entries()) {
      const option = element("option", name);
      option.value = String(index);
      existing.append(option);
    }
    operation.value = "keep";
    show();
  }

  button.addEventListener("click", () => {
    try {
      if (button.disabled) {
        return;
      }
      const selected = choices.find((choice) => choice.name === field.value);
      const current = /^(0|[1-9][0-9]*)$/.test(existing.value)
        ? selected?.entries[Number(existing.value)]
        : undefined;
      const member = operation.value === "insert" ? key.value : current?.[0];
      if (
        typeof member !== "string" ||
        !member.length ||
        new TextEncoder().encode(member).length > 256 ||
        /[\x00-\x1f\x7f-\x9f]/.test(member)
      ) {
        throw new Error("成员键必须是1–256个 UTF-8 字节，且不能包含控制字符。");
      }
      if (
        operation.value === "insert" &&
        selected.entries.some(([name]) => name === member)
      ) {
        throw new Error("成员已存在；改变其权限须明确选择替换。");
      }
      const edit = { op: operation.value, key: member };
      if (operation.value === "remove") {
        // 删除确认绑定当前字段和成员，切换选择后不能沿用另一份授权的撤销意图。
        if (!confirm.checked) {
          throw new Error("请先确认删除当前成员授权。");
        }
      } else {
        if (!nativeRoles.includes(role.value)) {
          throw new Error("请明确选择 viewer、developer 或 owner 角色。");
        }
        edit.role = role.value;
      }
      submit({ type: "team_roles", object, field: selected.name, edit });
    } catch (error) {
      note.textContent = error.message;
    }
  });
  field.addEventListener("change", selectField);
  existing.addEventListener("change", show);
  operation.addEventListener("change", show);
  key.addEventListener("input", changed);
  role.addEventListener("change", changed);
  confirm.addEventListener("change", changed);
  selectField();
  return node;
}
