import { element } from "../../../core/dom.js";

/**
 * 业务作用：只在本次成功生成候选后短时显示密钥原值，关闭或退休后无法重新读取。
 * 参数说明: 无。
 * 返回：独立展示区域及显示、清除方法；不使用存储、网络或剪贴板。
 */
export function keySecret() {
  const node = element("div", "", "draft-key-secret");
  const value = element("textarea");
  value.readOnly = true;
  value.autocomplete = "off";
  value.spellcheck = false;
  value.setAttribute("aria-label", "本次生成的密钥原值");
  const close = element("button", "已保存，清除密钥原值");
  close.type = "button";
  node.append(
    element(
      "p",
      "密钥仅本次显示，60 秒后清除。请先安全保存，再保存提案、审批和执行。当前尚未生效。",
    ),
    value,
    close,
  );
  let timer = null;

  /**
   * 业务作用：立即丢弃原值展示并撤销到期回调，旧对象或会话不能恢复秘密。
   * 参数说明: 无。
   * 返回：展示隐藏，原值和定时器引用均清空。
   */
  function clear() {
    clearTimeout(timer);
    timer = null;
    value.value = "";
    node.hidden = true;
  }

  /**
   * 业务作用：在当前候选已接受摘要后交付原值，限定本次可见窗口。
   * 参数说明：
   * - `secret`：只存在于浏览器内存的本次随机密钥。
   * 返回：替换原展示并启动一次60秒清除，不写入配置或浏览器存储。
   */
  function show(secret) {
    clear();
    value.value = secret;
    node.hidden = false;
    timer = setTimeout(clear, 60000);
  }
  close.addEventListener("click", clear);
  clear();
  return {
    node,

    show,

    clear,
  };
}

/**
 * 业务作用：围绕精确路由声明编辑密钥，原值只在浏览器生成且服务端仅接收校验摘要。
 * 参数说明：
 * - `object`：当前已读取的显式路由身份。
 * - `perform`：绑定候选、选择代和权限的草稿请求链。
 * - `publish`：替换当前候选并撤下旧对象的同步回调。
 * - `capture`：冻结当前对象和候选，返回异步阶段的有效性检查。
 * - `secretView`：页面独占的一次性原值展示器。
 * 返回：查看、追加、状态调整及确认删除面板，不自动保存或执行提案。
 */
export function keyEditor(object, perform, publish, capture, secretView) {
  const node = element("details", "", "draft-keys");
  const load = element("button", "读取路由密钥");
  const generate = element("button", "生成密钥并追加候选");
  const change = element("button", "生成密钥状态候选");
  const remove = element("button", "从候选删除密钥声明");
  for (const button of [load, generate, change, remove]) {
    button.type = "button";
  }
  const choices = element("select");
  const enabled = element("select");
  for (const [value, title] of [
    ["false", "禁用凭据"],
    ["true", "启用凭据"],
  ]) {
    const option = element("option", title);
    option.value = value;
    enabled.append(option);
  }
  const consumer = element("input");
  const name = element("input");
  for (const input of [consumer, name]) {
    input.maxLength = 128;
    input.autocomplete = "off";
  }
  name.value = "x-api-key";
  const source = element("select");
  for (const kind of ["header", "query"]) {
    const option = element("option", kind);
    option.value = kind;
    source.append(option);
  }
  const confirm = element("input");
  confirm.type = "checkbox";
  const note = element("p", "先读取此路由的原始密钥声明。", "subtle");
  note.setAttribute("role", "status");
  node.append(
    element("summary", "消费者 API-Key"),
    element(
      "p",
      "这里只编辑当前候选。禁用保留认证保护；删除最后一条声明会被拒绝。需先生成普通字段修改，再执行密钥动作。",
      "subtle",
    ),
    load,
  );
  for (const [title, control] of [
    ["已有密钥声明", choices],
    ["密钥目标状态", enabled],
    ["确认删除密钥声明", confirm],
    ["新密钥消费者", consumer],
    ["新密钥来源", source],
    ["新密钥来源名称", name],
  ]) {
    control.setAttribute("aria-label", title);
    const label = element("label", title);
    label.append(control);
    node.append(label);
  }
  node.append(change, remove, generate, note);
  let entries = [];
  let version = 0;
  let generating = false;
  change.disabled = remove.disabled = true;

  /**
   * 业务作用：对当前路由包装唯一密钥动作，继续使用共享候选请求和摘要校验。
   * 参数说明：
   * - `edit`：明确的目录或单凭据编辑动作。
   * - `receive`：仅当前响应可执行的同步发布步骤。
   * 返回：沿用请求链的完成状态，不额外创建后台请求。
   */
  function submit(edit, receive) {
    const current = capture();
    const expected = version;
    return perform(
      {
        type: "keys",

        object,

        edit,
      },
      (data) => {
        if (!current() || version !== expected) {
          throw new DOMException("密钥选择已变化", "AbortError");
        }
        receive(data);
      },
    );
  }

  /**
   * 业务作用：按服务端原声明身份提交状态或删除动作，不能从显示名称推导另一条凭据。
   * 参数说明：
   * - `op`：set_enabled 或 remove。
   * 返回：当前选择合法时交给草稿链；无选择或未确认不发送请求。
   */
  function editSelected(op) {
    const selected = entries[Number(choices.value)];
    if (!selected || (op === "remove" && !confirm.checked)) {
      return;
    }
    version += 1;
    secretView.clear();
    const edit = {
      op,

      index: selected.index,

      fingerprint: selected.fingerprint,
    };
    if (op === "set_enabled") {
      edit.enabled = enabled.value === "true";
    }
    submit(edit, publish);
  }

  load.addEventListener("click", () => {
    version += 1;
    secretView.clear();
    choices.replaceChildren();
    entries = [];
    change.disabled = remove.disabled = true;
    submit({ op: "inspect" }, (data) => {
      if (
        JSON.stringify(data.selected) !== JSON.stringify(object) ||
        !Array.isArray(data.keys) ||
        data.keys.length > 4096 ||
        data.keys.some(
          (entry) =>
            !Number.isInteger(entry.index) ||
            entry.index < 0 ||
            entry.index >= 4096 ||
            !/^[0-9a-f]{64}$/.test(entry.fingerprint) ||
            !["header", "query"].includes(entry.source) ||
            typeof entry.name !== "string" ||
            (entry.consumer !== null && typeof entry.consumer !== "string") ||
            typeof entry.enabled !== "boolean" ||
            !["sha256", "secret_source"].includes(entry.material),
        )
      ) {
        throw new Error("密钥目录或原声明身份不合法。");
      }
      entries = data.keys;
      entries.forEach((entry, index) => {
        const option = element(
          "option",
          `${entry.index} · ${entry.consumer ?? "未绑定消费者"} · ${entry.source}:${entry.name} · ${entry.enabled ? "启用" : "禁用"} · ${entry.material}`,
        );
        option.value = String(index);
        choices.append(option);
      });
      change.disabled = !entries.length;
      remove.disabled = entries.length <= 1 || !confirm.checked;
      note.textContent = `读取 ${entries.length} 条显式密钥声明；只展示身份和状态，不读取秘密材料。`;
    });
  });
  change.addEventListener("click", () => editSelected("set_enabled"));
  remove.addEventListener("click", () => editSelected("remove"));
  for (const control of [choices, enabled, confirm, consumer, name, source]) {
    control.addEventListener("input", () => {
      version += 1;
      secretView.clear();
    });
    control.addEventListener("change", () => {
      version += 1;
      secretView.clear();
      remove.disabled = entries.length <= 1 || !confirm.checked;
    });
  }
  generate.addEventListener("click", async () => {
    if (generating) {
      return;
    }
    const current = capture();
    const expected = ++version;
    const fields = {
      consumer: consumer.value,

      source: source.value,

      name: name.value,
    };
    let secret = "";
    secretView.clear();
    generating = generate.disabled = true;
    try {
      if (
        !/^[A-Za-z0-9_.\/-]{1,128}$/.test(fields.consumer) ||
        !/^[A-Za-z0-9_.\/-]{1,128}$/.test(fields.name)
      ) {
        throw new Error(
          "请填写字面消费者与来源名称，仅支持字母、数字、点、下划线、短横线和斜线。",
        );
      }
      if (!globalThis.crypto?.getRandomValues || !globalThis.crypto?.subtle) {
        throw new Error(
          "当前页面无法使用 Web Crypto，请通过受信 HTTPS 管理入口生成密钥。",
        );
      }
      // 256 位随机材料只留在本次闭包；向服务端提交的是最终密钥文本的摘要。
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      secret =
        "nwy_" +
        Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
          "",
        );
      bytes.fill(0);
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(secret),
      );
      if (!current() || version !== expected) {
        throw new DOMException("密钥草稿已退休", "AbortError");
      }
      const sha256 = Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join("");
      await submit(
        {
          op: "add",

          ...fields,

          sha256,
        },
        (data) => {
          // 原值只能对应实际接受了摘要的新候选，空动作不能被当成密钥已创建。
          if (data.changed !== true) {
            throw new Error("密钥摘要未追加到候选，原值已丢弃。");
          }
          publish(data);
          secretView.show(secret);
        },
      );
    } catch (error) {
      secretView.clear();
      if (current() && version === expected && error.name !== "AbortError") {
        note.textContent = error.message;
      }
    } finally {
      secret = "";
      generating = generate.disabled = false;
    }
  });
  return node;
}
