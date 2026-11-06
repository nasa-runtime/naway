import { element } from "../../core/dom.js";
import { field } from "./common.js";
import { materialTargets } from "./targets.js";

/**
 * 业务作用：收取短期内存中的候选PEM及完整原材料条件，保存动作不隐式批准或执行。
 * 参数说明：
 * - `cluster`：当前共享材料集群。
 * - `scope`：精确范围的读取函数。
 * - `actions`：页面协调的节点读取、条件查询与提交回调。
 * 返回：可锁定、读取和清空的表单；不写入浏览器存储或保存文件路径。
 */
export function materialForm(cluster, scope, actions) {
  const form = element("form", "", "panel proposal-form");
  const fields = element("fieldset");
  fields.append(element("legend", "保存新证书材料"));
  const certificate = element("textarea");
  const privateKey = element("textarea");
  for (const [input, label] of [
    [certificate, "候选证书链 PEM"],
    [privateKey, "候选私钥 PEM"],
  ]) {
    input.rows = 7;
    input.required = true;
    input.maxLength = 1024 * 1024;
    input.spellcheck = false;
    input.autocomplete = "off";
    input.setAttribute("aria-label", label);
  }
  const ttl = element("input");
  ttl.type = "number";
  ttl.min = "60";
  ttl.max = "86400";
  ttl.step = "1";
  ttl.value = "600";
  ttl.required = true;
  const confirm = element("input");
  confirm.type = "checkbox";
  confirm.required = true;
  const agreement = field(
    "我已核对全部原目标和共享来源；此次仅保存材料，不批准或执行换证",
    confirm,
  );
  agreement.className = "proposal-check";
  const save = element("button", "保存材料提案", "primary");
  save.type = "submit";
  const availability = element("p", "正在确认当前材料受理资格…", "subtle");
  let context = null;
  let busy = true;
  let frozen = false;
  const targets = materialTargets(
    cluster,
    scope,
    actions.load,
    actions.inspect,
    (ready) => {
      frozen = ready;
      update();
    },
  );
  fields.append(
    element(
      "p",
      "证书与私钥只在本页短期内存中输入，保存后由服务端加密保管。切换范围、隐藏或退出页面会清空输入。",
      "subtle",
    ),
    availability,
    targets.node,
    field("候选证书链 PEM", certificate),
    field("候选私钥 PEM", privateKey),
    field("提案有效期（秒）", ttl),
    agreement,
    save,
  );
  form.append(fields);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!save.disabled && !document.hidden) {
      actions.submit();
    }
  });
  confirm.addEventListener("change", update);

  /**
   * 业务作用：按当前服务器权限、独立受理开关和完整条件限制提交，普通读取不能上传秘密。
   * 参数说明: 无。
   * 返回：同步输入及提交状态，不创建受理身份。
   */
  function update() {
    const writable =
      context?.access?.write === true && context.accept_proposals === true;
    const blocked = busy || !writable;
    certificate.disabled =
      privateKey.disabled =
      ttl.disabled =
      confirm.disabled =
        blocked;
    save.disabled = blocked || !frozen || !confirm.checked;
    availability.textContent = !context
      ? "当前未取得材料受理资格。"
      : !writable
        ? "当前只读，或新材料受理已关闭。原请求仍可查询。"
        : "允许保存新材料；全部原目标条件及明确确认缺一不可。";
  }

  /**
   * 业务作用：将同范围真实材料上下文与页面串行门应用到表单。
   * 参数说明：
   * - `value`：当前context响应；失权或未读取时为空。
   * - `locked`：页面正在处理请求或存在未决提交。
   * 返回：只读主体保留公开选择读取入口，提交须同时具备写入和受理资格。
   */
  function access(value, locked) {
    context = value;
    busy = locked;
    const writable =
      context?.access?.write === true && context.accept_proposals === true;
    targets.access(context?.access?.read === true, writable, busy);
    update();
  }

  /**
   * 业务作用：在首次明确提交之前一次冻结完整正文，禁止过期受理代或超量秘密进入请求。
   * 参数说明: 无。
   * 返回：完整原正文；调用者发送后必须释放该对象并清空表单，不自动重建重试。
   */
  function read() {
    if (
      busy ||
      !context?.access?.write ||
      !context.accept_proposals ||
      !confirm.checked ||
      document.hidden
    ) {
      throw new Error("当前不能提交新的材料提案。");
    }
    if (
      !Number.isSafeInteger(context.admission_epoch) ||
      context.admission_epoch <= 0 ||
      !Number.isSafeInteger(context.epoch_expires_at_ms) ||
      Date.now() >= context.epoch_expires_at_ms
    ) {
      throw new Error("材料受理窗口已结束，请刷新当前范围后重新确认。");
    }
    const maximum = context.capacity?.max_material_bytes;
    const bytes =
      new TextEncoder().encode(certificate.value).byteLength +
      new TextEncoder().encode(privateKey.value).byteLength;
    if (
      !Number.isSafeInteger(maximum) ||
      maximum <= 0 ||
      maximum > 1024 * 1024 ||
      !certificate.value.trim() ||
      !privateKey.value.trim() ||
      bytes > maximum
    ) {
      throw new Error("证书链与私钥不能为空，且合计不得超过当前材料字节上限。");
    }
    const seconds = Number(ttl.value);
    if (!Number.isInteger(seconds) || seconds < 60 || seconds > 86400) {
      throw new Error("提案有效期必须为60至86400秒的整数。");
    }
    return {
      admission_epoch: context.admission_epoch,

      ttl_seconds: seconds,

      targets: targets.value(),

      certificate_pem: certificate.value,

      private_key_pem: privateKey.value,
    };
  }

  /**
   * 业务作用：及时移除页面持有的PEM引用，未知提交只保留低敏原请求身份。
   * 参数说明: 无。
   * 返回：清空两份材料文本和确认状态，不承诺浏览器内部内存已覆写。
   */
  function clearSecrets() {
    certificate.value = "";
    privateKey.value = "";
    confirm.checked = false;
    update();
  }

  /**
   * 业务作用：撤去旧范围的全部表单状态与条件，取消后的响应不能复用原输入。
   * 参数说明: 无。
   * 返回：材料、目标、观察与受理资格全部清空。
   */
  function clear() {
    context = null;
    targets.clear();
    clearSecrets();
    ttl.value = "600";
    update();
  }

  update();
  return {
    node: form,
    targets,
    access,
    read,
    clearSecrets,
    clear,
  };
}
