import { element } from "../../../core/dom.js";
import { draftFieldPanel } from "./fields.js";
import { objectKinds, objectLabel } from "./schema.js";
import { fieldAction } from "./nested.js";

/**
 * 业务作用：围绕当前候选提供显式对象编辑，所有结果仍须进入共享提案和原目标执行。
 * 参数说明：
 * - `candidate`：原始 YAML 输入，不读取接入节点的活动文件。
 * - `capacity`：候选字节容量。
 * - `domain`：读取当前已授权领域的回调。
 * - `requestDraft`：唯一页面请求链协调器，回调仅在当前范围仍有效时运行。
 * 返回：可清空的编辑面板；范围退休或原文变化会撤下全部旧对象。
 */
export function draftEditor(candidate, capacity, domain, requestDraft) {
  const node = element("fieldset", "", "draft-editor");
  node.append(
    element("legend", "按对象编辑候选"),
    element(
      "p",
      "这里只编辑上方原始声明，不展开 profile、imports 或秘密引用。生成候选会重排 YAML 并丢弃注释；尚未保存、预检或发布到任何节点。",
      "subtle",
    ),
  );
  const notice = element("p", "先读取当前候选的对象目录。", "subtle");
  notice.setAttribute("role", "status");
  const load = element("button", "读取草稿对象");
  const inspect = element("button", "读取对象字段");
  const apply = element("button", "生成编辑后的候选");
  const remove = element("button", "从候选删除对象");
  const create = element("button", "准备新对象");
  for (const button of [load, inspect, apply, remove, create]) {
    button.type = "button";
  }
  const selector = element("select");
  selector.setAttribute("aria-label", "草稿对象");
  const selectedLabel = element("label", "草稿对象");
  selectedLabel.append(selector);
  const kind = element("select");
  kind.setAttribute("aria-label", "新增对象类型");
  const name = element("input");
  const parent = element("input");
  for (const input of [name, parent]) {
    input.maxLength = 256;
    input.autocomplete = "off";
  }
  name.setAttribute("aria-label", "新增对象身份");
  parent.setAttribute("aria-label", "所属 HTTP 入口身份");
  const createPanel = element("details");
  createPanel.append(element("summary", "新增对象"));
  for (const [title, input] of [
    ["新增对象类型", kind],
    ["新增对象身份", name],
    ["所属 HTTP 入口身份（仅路由；单入口为 default）", parent],
  ]) {
    const label = element("label", title);
    label.append(input);
    createPanel.append(label);
  }
  createPanel.append(create);
  const body = element("div");
  const identity = element("p", "", "proposal-digest");
  const agreement = element("input");
  agreement.type = "checkbox";
  const agreeLabel = element(
    "label",
    "我确认从当前候选删除此对象（包含其子声明）",
    "proposal-check",
  );
  agreeLabel.append(agreement);
  const actions = element("div", "", "monitor-toolbar");
  actions.append(apply, remove);
  node.append(
    load,
    selectedLabel,
    inspect,
    createPanel,
    notice,
    identity,
    body,
    agreeLabel,
    actions,
  );
  let generation = 0;
  let objects = [];
  let selected = null;
  let fields = null;
  let creating = false;

  /**
   * 业务作用：撤下已读取字段，防止另一对象的输入沿用到新的选择。
   * 参数说明: 无。
   * 返回：销毁原字段引用和删除确认，不改写候选。
   */
  function clearSelection() {
    generation += 1;
    selected = null;
    fields = null;
    creating = false;
    body.replaceChildren();
    identity.textContent = "";
    agreement.checked = false;
    agreeLabel.hidden = true;
    apply.disabled = remove.disabled = true;
  }

  /**
   * 业务作用：切换原文、领域或会话时立即丢弃原对象，异步结果不能恢复旧字段。
   * 参数说明: 无。
   * 返回：目录与字段清空，新对象类型按当前领域重建。
   */
  function clear() {
    clearSelection();
    objects = [];
    selector.replaceChildren();
    inspect.disabled = true;
    name.value = parent.value = "";
    kind.replaceChildren();
    for (const [value, title] of objectKinds[domain()] ?? []) {
      const option = element("option", title);
      option.value = value;
      kind.append(option);
    }
    notice.textContent = "先读取当前候选的对象目录。";
  }

  /**
   * 业务作用：在字段动作期间绑定源原文和本地选择代，原文被修改后拒绝回填。
   * 参数说明：
   * - `action`：精确对象声明动作。
   * - `receive`：仅当前响应可调用的同步发布步骤。
   * 返回：交给统一请求链，失败不会自动重试或保存提案。
   */
  function perform(action, receive) {
    const epoch = generation;
    const source = candidate.value;
    requestDraft(source, action, (data) => {
      if (generation !== epoch || candidate.value !== source) {
        throw new DOMException("草稿已变化", "AbortError");
      }
      receive(data);
    });
  }

  /**
   * 业务作用：只在明确字段动作成功后替换候选，目标与有效期保持原意图。
   * 参数说明：
   * - `data`：已核对范围、源摘要及结果摘要的服务端回复。
   * 返回：候选更新并清空旧对象，用户仍须显式保存共享提案。
   */
  function publish(data) {
    candidate.value = data.candidate;
    clear();
    notice.textContent = data.changed
      ? "候选已更新；请重新读取对象或保存提案。尚未对任何节点生效。"
      : "声明没有变化，候选原文字节已保留。";
  }

  /**
   * 业务作用：展示仅属于选中身份的原始字段，新增对象也须通过相同显式字段动作。
   * 参数说明：
   * - `object`：独立类型化身份。
   * - `values`：原始声明或新对象的空字段。
   * - `isNew`：是否准备创建新对象。
   * 返回：字段面板挂接成功后才开放生成与删除资格。
   */
  function show(object, values, isNew) {
    clearSelection();
    fields = draftFieldPanel(object.kind, values, capacity);
    selected = object;
    creating = isNew;
    body.append(fields.node);
    identity.textContent = `${isNew ? "准备新增" : "当前对象"}：${objectLabel(object)}`;
    apply.disabled = false;
    agreeLabel.hidden = isNew;
    notice.textContent =
      "仅显式设置或移除的字段进入候选，最终合法性由目标完整构建器判断。";
  }

  load.addEventListener("click", () => {
    clear();
    perform({ type: "inspect" }, (data) => {
      if (!Array.isArray(data.objects) || data.objects.length > 1024) {
        throw new Error("对象目录不合法或超出容量。");
      }
      objects = data.objects;
      objects.forEach((object, index) => {
        const option = element("option", objectLabel(object));
        option.value = String(index);
        selector.append(option);
      });
      inspect.disabled = !objects.length;
      notice.textContent = `读取 ${objects.length} 个显式对象；选择后读取字段。`;
    });
  });
  selector.addEventListener("change", clearSelection);
  inspect.addEventListener("click", () => {
    const object = objects[Number(selector.value)];
    if (!object) {
      return;
    }
    clearSelection();
    perform(
      {
        type: "inspect",

        object,
      },
      (data) => {
        if (
          JSON.stringify(data.selected) !== JSON.stringify(object) ||
          !data.fields ||
          Array.isArray(data.fields) ||
          typeof data.fields !== "object"
        ) {
          throw new Error("对象字段与所选身份不一致。");
        }
        show(object, data.fields, false);
      },
    );
  });
  create.addEventListener("click", () => {
    try {
      if (
        !name.value ||
        !kind.value ||
        (kind.value === "route" && !parent.value)
      ) {
        throw new Error("请填写对象身份；新增路由还需完整的所属入口身份。");
      }
      const object =
        kind.value === "service"
          ? {
              kind: kind.value,

              name: name.value,
            }
          : kind.value === "route"
            ? {
                kind: kind.value,

                proxy: parent.value,

                id: name.value,
              }
            : {
                kind: kind.value,

                id: name.value,
              };
      show(object, {}, true);
    } catch (error) {
      notice.textContent = error.message;
    }
  });
  apply.addEventListener("click", () => {
    if (!fields || !selected) {
      return;
    }
    try {
      const patch = fields.read();
      perform(fieldAction(selected, patch, creating), publish);
    } catch (error) {
      notice.textContent = error.message;
    }
  });
  agreement.addEventListener("change", () => {
    remove.disabled = !agreement.checked || !selected || creating;
  });
  remove.addEventListener("click", () => {
    if (selected && !creating && agreement.checked) {
      perform(
        {
          type: "delete",

          object: selected,
        },
        publish,
      );
    }
  });
  candidate.addEventListener("input", clear);
  clear();
  return {
    node,

    clear,
  };
}
