import { element } from "../core/dom.js";
import {
  completeYamlText,
  yamlEditor,
  yamlEditingHelp,
  replaceYamlText,
} from "../core/yaml_editor.js";
import { request } from "../core/http.js";

const gatewayDocument = {
  resource: "config",
  documentKind: "gateway",
  endpoint: "/api/config/current",
  validateEndpoint: "/api/config/dry-run",
  formatEndpoint: "/api/config/format",
};

export const configurationPages = Object.freeze({
  configuration: {
    ...gatewayDocument,
    title: "系统 YAML",
    guidance:
      "编辑完整主文档。Nacos、Redis、数据库、Kafka及启动依赖在此管理；需重启的字段由服务端明确拒绝在线替换。",
    sections: ["config_source", "discovery", "runtime_state", "admin"],
  },
  "bootstrap-configuration": {
    ...gatewayDocument,
    title: "启动依赖与配置中心",
    guidance:
      "这里仍编辑完整主文档。连接地址、身份和启动期资源必须符合节点启动合同，保存不会绕过重启要求。",
    sections: ["config_source", "discovery", "runtime_state", "reload"],
  },
  "observability-configuration": {
    ...gatewayDocument,
    title: "日志与遥测 YAML",
    guidance:
      "日志、访问日志和遥测配置属于系统配置；修改完整主文档前请核对来源及需要重启的字段。",
    sections: ["log", "access_log", "telemetry"],
  },
  "proxy-configuration": {
    ...gatewayDocument,
    title: "路由、上游与监听 YAML",
    guidance:
      "编辑完整主文档中的代理入口、路由、上游、监听和扩展链；保存仍对整份候选执行校验及CAS。",
    sections: ["proxies", "routes", "upstreams", "stream", "snippets"],
  },
  "security-configuration": {
    ...gatewayDocument,
    title: "安全与认证 YAML",
    guidance:
      "全局ACL、可信来源和路由认证策略位于主文档；独立HTTP接口守卫使用本组的专用YAML入口。",
    sections: ["acl", "client_ip_policy", "proxies", "routes"],
  },
  "certificate-configuration": {
    ...gatewayDocument,
    title: "证书与密钥来源 YAML",
    guidance:
      "管理主文档中的TLS和密钥来源引用；活动证书与受控材料交付仍使用专用入口。请优先使用SecretSource引用。",
    sections: ["secret_providers", "crypto_providers", "proxies", "stream"],
  },
  "workspace-configuration": {
    ...gatewayDocument,
    title: "工作区、归属与预算 YAML",
    guidance:
      "此处是平台管理员的完整主文档编辑，不授予工作区用户跨工作区读取或修改权限。",
    sections: ["ownership"],
  },
  "portal-configuration": {
    ...gatewayDocument,
    title: "API产品、团队与门户 YAML",
    guidance:
      "产品、团队、应用与套餐声明位于完整主文档，发布后由各节点执行同一配置校验与归属门禁。",
    sections: ["developer_portal", "usage_plans", "proxies", "routes"],
  },
  "ai-configuration": {
    ...gatewayDocument,
    title: "AI与Agent YAML",
    guidance:
      "在路由的llm和agent配置中管理模型、provider、RAG与工具。支持范围由当前制品和服务端校验确定。",
    sections: ["proxies", "routes", "upstream_credentials"],
  },
  sentinel: {
    resource: "sentinel",
    documentKind: "sentinel",
    endpoint: "/api/sentinel",
    validateEndpoint: "/api/sentinel/dry-run",
    formatEndpoint: "/api/sentinel/format",
    title: "Sentinel 规则 YAML",
    guidance:
      "直接编辑流控、预热、排队、熔断与降级规则；不要求启用共享提案数据库。另两份文档按整体基线保留。",
    sections: ["flow", "degrade"],
  },
  "interface-guard-configuration": {
    resource: "interface-guard",
    documentKind: "interface-guard",
    endpoint: "/api/interface-guard",
    validateEndpoint: "/api/interface-guard/dry-run",
    formatEndpoint: "/api/interface-guard/format",
    title: "HTTP接口守卫 YAML",
    guidance:
      "编辑独立接口守卫文档；整体ETag同时保护主文档和Sentinel，集群发布仍写入同一Nacos原子配置集。",
    sections: ["rules"],
  },
});

/**
 * 业务作用：在当前管理权限下读取、编辑和发布 Nacos 集群配置，并区分远端提交与节点收敛。
 * 参数说明：
 * - `root`：当前页面的唯一显示容器。
 * - `session`：服务端确认的主体与动作权限。
 * - `page`：菜单映射的固定文档或主配置业务分区，不接受任意API路径。
 * 返回：页面清理函数；离开或隐藏时撤销旧响应资格并清空配置原文。
 */
export function mount(root, session, page = "configuration") {
  const definition = configurationPages[page];
  if (!definition) {
    throw new Error("未知配置页面。");
  }
  const permissions = session.permissions?.[definition.resource] ?? [];
  const writable = permissions.includes("write");
  const inspectable = permissions.includes("dry-run");
  const clusterReadable =
    session.permissions?.cluster?.includes("read") === true;
  const panel = element("section", "", "panel");
  const toolbar = element("div", "", "monitor-toolbar");
  const load = element("button", "读取当前配置并清空编辑");
  const validate = element("button", "校验候选");
  const publish = element("button", "保存并推送集群", "primary");
  const progress = element("button", "读取发布进度");
  const clear = element("button", "清空配置原文");
  const format = element("button", "两空格格式化预览");
  const complete = element("button", "补齐光标处");
  const adoptFormat = element("button", "采用格式化结果");
  const cancelFormat = element("button", "取消格式化预览");
  for (const button of [
    load,
    validate,
    publish,
    progress,
    clear,
    format,
    complete,
    adoptFormat,
    cancelFormat,
  ]) {
    button.type = "button";
  }
  const source = element("p", "尚未读取配置来源。", "subtle");
  const guidance = element("p", definition.guidance, "subtle");
  const moduleChoice = element("select");
  const modulePicker = element("label", "配置文件 ");
  modulePicker.append(moduleChoice);
  modulePicker.hidden = true;
  const status = element(
    "p",
    "请显式读取当前配置。原文可能包含敏感配置，仅保留在当前页面内存。",
    "subtle",
  );
  status.setAttribute("role", "status");
  const editor = yamlEditor(element("textarea"));
  editor.rows = 24;
  editor.spellcheck = false;
  editor.autocomplete = "off";
  editor.setAttribute(
    "aria-label",
    page === "configuration" ? "集群配置 YAML" : definition.title,
  );
  editor.readOnly = !writable;
  const label = element(
    "label",
    page === "configuration" ? "集群配置 YAML" : definition.title,
    "configuration-editor",
  );
  label.append(editor);
  const result = element("div", "", "configuration-progress");
  const position = element(
    "p",
    "行 1 · 字符列 1 · 两空格缩进",
    "yaml-editor-status",
  );
  const formatPanel = element("section", "", "configuration-format-preview");
  formatPanel.hidden = true;
  const formatSource = element("pre", "", "proposal-source");
  formatPanel.append(
    element("h3", "两空格格式化预览（尚未替换或保存）"),
    element(
      "p",
      "格式化由naml重新编码；注释、锚点和原有排版不能保留。先检查预览，再明确采用；采用后可撤销。",
      "subtle",
    ),
    adoptFormat,
    cancelFormat,
    formatSource,
  );
  const sections = element("div", "", "configuration-sections");
  for (const key of definition.sections) {
    const jump = element("button", `定位 ${key}`);
    jump.type = "button";
    jump.addEventListener("click", () => locate(key));
    sections.append(jump);
  }
  toolbar.append(load, validate, format, complete, publish, progress, clear);
  panel.append(
    element("h2", definition.title),
    guidance,
    element(
      "p",
      "保存后由服务端完整校验并按当前发布策略处理。审批、灰度、Nacos 写入与全节点生效分别核对，节点接收推送后各自校验并热加载。",
      "subtle",
    ),
    source,
    modulePicker,
    toolbar,
    status,
    sections,
    label,
    position,
    formatPanel,
    element("p", yamlEditingHelp, "subtle"),
    result,
  );
  root.append(panel);
  let alive = true;
  let generation = 0;
  let active = null;
  let baseline = null;
  let target = definition;
  let rollout = "";
  let pendingChange = "";
  let formatPreview = null;
  let unknown = false;
  let capacity = 1024 * 1024;
  let timer = null;

  /**
   * 业务作用：展示原文的光标位置、字节预算与缩进约定，不把视觉折行计为配置换行。
   * 参数说明: 无。
   * 返回：更新低频辅助文字，不改变原文或发布资格。
   */
  function showPosition() {
    const value = editor.value;
    const cursor = editor.selectionStart ?? 0;
    const before = value.slice(0, cursor);
    const row = before.split("\n").length;
    const start = before.lastIndexOf("\n") + 1;
    const column = Array.from(before.slice(start)).length + 1;
    const original = originalLineEndings(value);
    const bytes = new TextEncoder().encode(original).length;
    position.textContent = `行 ${row} · 字符列 ${column} · ${bytes} / ${capacity} UTF-8字节 · 两空格缩进`;
  }

  /**
   * 业务作用：定位当前原文中的固定配置键，帮助操作者在完整主文档内找到业务分区。
   * 参数说明：
   * - `key`：菜单元数据提供的固定顶层键。
   * 返回：只移动文本选区，不解析、创建或删除任何配置。
   */
  function locate(key) {
    if (editor.disabled) {
      return;
    }
    const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const found = new RegExp(`^${escaped}:`, "m").exec(editor.value);
    if (!found) {
      status.textContent = `当前原文没有找到顶层 ${key} 文本；可按现有配置合同在完整文档中显式添加。`;
      return;
    }
    editor.focus({ preventScroll: true });
    editor.setSelectionRange(found.index, found.index + key.length);
    const row = editor.value.slice(0, found.index).split("\n").length - 1;
    const lineHeight =
      Number.parseFloat(getComputedStyle(editor).lineHeight) || 24;
    editor.scrollTop = Math.max(0, row * lineHeight - editor.clientHeight / 3);
    showPosition();
    status.textContent = `已定位 ${key} 文本；保存仍校验并发布完整文档。`;
  }

  /**
   * 业务作用：请求naml两空格格式化结果并先展示预览，不把格式化当作配置发布。
   * 参数说明: 无。
   * 返回：同一候选和整体ETag的结果可供采用；失败保留原文，不发送写请求。
   */
  function previewFormatting() {
    if (!inspectable || baseline === null) {
      return;
    }
    return run(async (signal, epoch) => {
      const body = candidate();
      const before = editor.value;
      const etag = baseline.etag;
      const { data } = await request(target.formatEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/yaml",
          "If-Match": etag,
        },
        body,
        signal,
      });
      current(epoch);
      if (
        editor.value !== before ||
        baseline?.etag !== etag ||
        data.ok !== true ||
        data.applied !== false ||
        data.document !== target.documentKind ||
        data.source_etag !== etag ||
        data.indentation !== 2 ||
        data.comments_preserved !== false ||
        typeof data.content !== "string" ||
        new TextEncoder().encode(data.content).length > capacity
      ) {
        throw new Error(
          "格式化结果与当前候选、容量或基线不一致，原文保持不变。",
        );
      }
      formatPreview = {
        before,
        content: data.content,
      };
      formatSource.textContent = data.content;
      formatSource.tabIndex = 0;
      formatPanel.hidden = false;
      formatPanel.scrollIntoView?.({ block: "start" });
      status.textContent =
        "已生成两空格预览；尚未替换原文，也未校验完整业务配置或写入Nacos。";
    });
  }

  /**
   * 业务作用：只在操作者确认且候选未变化时采用格式化结果，沿浏览器原生撤销栈提交。
   * 参数说明: 无。
   * 返回：成功后撤下旧校验；浏览器事务不可用时保留预览和原文供人工处理。
   */
  function adoptFormatting() {
    if (!writable || !formatPreview || editor.value !== formatPreview.before) {
      return;
    }
    const value = formatPreview.content;
    if (!replaceYamlText(editor, value)) {
      status.textContent =
        "当前浏览器不能提交可撤销的全文替换；原文未变，请手动核对预览。";
      return;
    }
    formatPreview = null;
    formatSource.textContent = "";
    formatPanel.hidden = true;
    status.textContent =
      "已采用两空格格式化，可撤销；请重新校验后再保存。尚未写入Nacos。";
    showPosition();
    update();
  }

  /**
   * 业务作用：撤下格式化预览及其原文引用，不改变用户正在编辑的候选。
   * 参数说明: 无。
   * 返回：隐藏预览并保持当前配置基线。
   */
  function cancelFormatting() {
    formatPreview = null;
    formatSource.textContent = "";
    formatPanel.hidden = true;
    status.textContent = "格式化预览已取消；编辑区原文未变。";
    update();
  }

  /**
   * 业务作用：从显式按钮补齐编辑光标处的唯一候选，供快捷键被系统占用时使用。
   * 参数说明: 无。
   * 返回：通过原生事务更新局部文本；没有唯一可用候选时保留原文并给出提示。
   */
  function completeAtCursor() {
    if (!completeYamlText(editor)) {
      status.textContent = "光标处没有可用的唯一补齐，原文未修改。";
    }
  }

  /**
   * 业务作用：按原变更身份读取审批状态，不将已执行登记解释为集群已经收敛。
   * 参数说明: 无。
   * 返回：只显示本主体可见的原记录；失去可见性或进入终态后停止自动读取。
   */
  function readApproval() {
    return run(async (signal, epoch) => {
      const id = pendingChange;
      const { data } = await request("/api/changes", { signal });
      current(epoch);
      const change = Array.isArray(data.changes)
        ? data.changes.find((value) => value.id === id)
        : null;
      if (pendingChange !== id || data.ok !== true || !change) {
        throw new Error(
          "原审批记录不在当前可见范围或已过期，请到审批队列核对。",
        );
      }
      result.replaceChildren(
        element("h3", "配置审批状态"),
        element("p", `变更身份：${id}`),
        element("p", `当前状态：${String(change.status).slice(0, 128)}`),
      );
      status.textContent = ["pending", "executing"].includes(change.status)
        ? "原变更仍在审批或执行中；尚未确认Nacos写入或全节点生效。"
        : "原变更已结束审批处理；执行登记不等于集群收敛，请核对复核人的发布回执与当前节点配置。";
      if (["pending", "executing"].includes(change.status)) {
        timer = setTimeout(readProgress, 2000);
      }
    });
  }

  /**
   * 业务作用：使读写入口依赖当前页面、真实来源、动作权限和未确认结果，阻止重复发布。
   * 参数说明: 无。
   * 返回：同步当前可见控件资格，不授予服务端未确认的权限。
   */
  function update() {
    const locked = !alive || document.hidden || active !== null;
    load.disabled = locked;
    moduleChoice.disabled = locked;
    clear.disabled = !alive;
    editor.disabled = locked || baseline === null;
    validate.disabled =
      locked || !inspectable || baseline === null || !editor.value;
    publish.disabled =
      locked ||
      !writable ||
      !(baseline?.named ? target.writeAvailable : baseline?.source === "nacos") ||
      !editor.value ||
      unknown;
    progress.disabled =
      locked || (!pendingChange && (!clusterReadable || !rollout));
    format.disabled =
      locked || !inspectable || baseline === null || !editor.value;
    complete.disabled = locked || !writable || baseline === null;
    adoptFormat.disabled =
      locked || !writable || formatPreview === null || editor.readOnly;
    cancelFormat.disabled = locked || formatPreview === null;
    for (const button of sections.querySelectorAll("button")) {
      button.disabled = locked || baseline === null;
    }
  }

  /**
   * 业务作用：取消本页在途读取并清除原文，防止隐藏或退休页面回填敏感配置。
   * 参数说明: 无。
   * 返回：原基线、候选和进度引用撤下；已经发送的发布不会被解释为回滚。
   */
  function retire() {
    generation += 1;
    active?.abort();
    active = null;
    clearTimeout(timer);
    timer = null;
    editor.value = "";
    baseline = null;
    rollout = "";
    pendingChange = "";
    formatPreview = null;
    formatSource.textContent = "";
    formatPanel.hidden = true;
    unknown = false;
    result.replaceChildren();
    showPosition();
    source.textContent = "尚未读取配置来源。";
    guidance.textContent = definition.guidance;
    status.textContent =
      "配置原文已清空；已经发送的发布可能继续，请重新核对当前配置与集群状态。";
    update();
  }

  /**
   * 业务作用：将一次管理请求绑定当前页面代，失败或页面退出后不交付迟到结果。
   * 参数说明：
   * - `work`：只在持有当前请求资格时执行的异步操作。
   * 返回：当前请求结束后解除并发门；权限丢失时立即清空配置。
   */
  async function run(work) {
    if (!alive || document.hidden || active !== null) {
      return;
    }
    const epoch = generation;
    const controller = new AbortController();
    active = controller;
    update();
    try {
      await work(controller.signal, epoch);
    } catch (error) {
      if (alive && generation === epoch && error.name !== "AbortError") {
        if ([401, 403].includes(error.status)) {
          retire();
        }
        status.textContent = error.message;
      }
    } finally {
      if (alive && generation === epoch && active === controller) {
        active = null;
        update();
      }
    }
  }

  /**
   * 业务作用：检查响应仍属于可见的当前页面，使旧请求不能恢复已经清空的配置。
   * 参数说明：
   * - `epoch`：请求开始时捕获的页面代。
   * 返回：当前代有效时正常返回，否则中止后续显示。
   */
  function current(epoch) {
    if (!alive || document.hidden || generation !== epoch) {
      throw new DOMException("页面已切换", "AbortError");
    }
  }

  /**
   * 业务作用：显式读取已上线原文与整体 ETag，为后续 Nacos CAS 发布建立同代基线。
   * 参数说明: 无。
   * 返回：成功后显示来源和原文；读取失败不沿用旧候选或旧比较令牌。
   */
  function readCurrent() {
    retire();
    return run(async (signal, epoch) => {
      target = await resolveTarget(signal, epoch);
      const { data, headers } = await request(target.endpoint, {
        signal,
      });
      current(epoch);
      if (
        data.ok !== true ||
        typeof data.content !== "string" ||
        !["file", "nacos"].includes(data.source) ||
        (target.documentKind !== "gateway" &&
          data.document !== target.documentKind) ||
        typeof data.etag !== "string" ||
        headers.get("etag") !== data.etag
      ) {
        throw new Error("当前配置响应缺少一致的原文与 ETag。");
      }
      const limit = data.max_config_body_bytes ?? 1024 * 1024;
      if (
        !Number.isSafeInteger(limit) ||
        limit <= 0 ||
        limit > 16 * 1024 * 1024 ||
        new TextEncoder().encode(data.content).length > limit
      ) {
        throw new Error("当前配置超过管理入口容量。");
      }
      capacity = limit;
      editor.value = data.content;
      baseline = {
        etag: data.etag,
        source: data.source,
        named: target !== definition,
        content: data.content,
        displayedContent: editor.value,
        crlf: data.content.includes("\r\n") && !data.content.replaceAll("\r\n", "").includes("\n"),
      };
      showPosition();
      if (baseline.named) {
        guidance.textContent = `编辑 ${target.documentKind}。发布时服务端校验其与其它模块和当前活动配置的关系。`;
      }
      publish.textContent = data.source === "nacos" ? "保存并推送集群" : "保存本地 YAML";
      source.textContent =
        data.source === "nacos"
          ? `配置来源：Nacos · ${target.documentKind} · 当前接入节点配置版本 ${data.version}`
          : `配置来源：本地文件 · ${target.documentKind} · 当前接入节点配置版本 ${data.version}`;
      status.textContent =
        baseline.named && !target.writeAvailable
          ? "当前配置可读取。写入取决于配置来源和主体权限。"
          : data.source === "nacos"
          ? "修改后可保存并推送集群。并发修改由整体 ETag 和 Nacos CAS 检查。"
          : baseline.named
            ? "保存时重新校验完整配置，并提交所选 YAML 文件。"
            : "集群发布需要启用 config_source.nacos 并配置 bundle_data_id；本页可读取和校验当前配置。";
    });
  }

  /**
   * 业务作用：按当前页面权限从活动目录选择原始 YAML，传统入口沿用已有 API。
   * 参数说明：
   * - `signal`：当前页面请求的取消信号。
   * - `epoch`：读取开始时的页面代。
   * 返回：所选模块或传统入口的固定请求目标；目录不可信时拒绝读取。
   */
  async function resolveTarget(signal, epoch) {
    let catalog;
    try {
      catalog = await request("/api/config/modules", { signal });
    } catch (error) {
      current(epoch);
      if (error.status !== 404) {
        throw error;
      }
      modulePicker.hidden = true;
      moduleChoice.replaceChildren();
      return definition;
    }
    current(epoch);
    if (catalog.data.ok !== true || !Array.isArray(catalog.data.documents)) {
      throw new Error("配置目录响应不完整。");
    }
    const names = catalog.data.documents
      .filter((entry) => entry.resource === definition.resource && entry.readable === true)
      .map((entry) => entry.name);
    if (!names.length || names.some((name) => typeof name !== "string" || !/^[A-Za-z0-9_.-]{1,128}\.ya?ml$/.test(name))) {
      throw new Error("当前没有可读取的配置文件。");
    }
    const preferred = page === "proxy-configuration" ? "proxy.yml" : "naway.yml";
    const selected = names.includes(moduleChoice.value)
      ? moduleChoice.value
      : names.includes(preferred)
        ? preferred
        : names[0];
    moduleChoice.replaceChildren(...names.map((name) => {
      const option = element("option", name);
      option.value = name;
      return option;
    }));
    moduleChoice.value = selected;
    modulePicker.hidden = false;
    const endpoint = `/api/config/modules/${selected}`;
    return {
      documentKind: selected,
      writeAvailable: catalog.data.documents.some((entry) =>
        entry.name === selected && entry.resource === definition.resource && entry.write_available === true),
      endpoint,
      validateEndpoint: `${endpoint}/dry-run`,
      formatEndpoint: `${endpoint}/format`,
    };
  }

  /**
   * 业务作用：恢复编辑器规范化之前的统一换行约定，保证无编辑时逐字节返回原文。
   * 参数说明：
   * - `value`：浏览器编辑区当前显示的文本。
   * 返回：原样文本，或按原文统一的 CRLF 约定编码的新文本。
   */
  function originalLineEndings(value) {
    if (baseline?.displayedContent === value) {
      return baseline.content;
    }
    return baseline?.crlf ? value.replaceAll("\n", "\r\n") : value;
  }

  /**
   * 业务作用：保留未编辑原文的换行字节，并在发出请求前拒绝空文档或超限候选。
   * 参数说明: 无。
   * 返回：合法时返回本次候选原文，空文档或超限时抛出错误。
   */
  function candidate() {
    // textarea会规范化换行；显示内容未变时仍提交原文，避免仅打开页面就改变远端配置字节。
    const value = originalLineEndings(editor.value);
    if (!value.trim() || new TextEncoder().encode(value).length > capacity) {
      throw new Error("候选为空或超过管理入口容量。");
    }
    return value;
  }

  /**
   * 业务作用：调用真实构建器校验当前候选，明确不把校验成功解释为发布。
   * 参数说明: 无。
   * 返回：显示构建和监听准备边界；不改变配置基线或集群状态。
   */
  function validateCandidate() {
    if (!inspectable || baseline === null) {
      return;
    }
    return run(async (signal, epoch) => {
      const body = candidate();
      const { data } = await request(target.validateEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/yaml",
          "If-Match": baseline.etag,
        },
        body,
        signal,
      });
      current(epoch);
      if (data.ok !== true || data.applied !== false) {
        throw new Error("候选校验未返回明确的不发布结果。");
      }
      status.textContent = data.listener_prepare_required
        ? "候选构建通过，发布时仍需准备实际监听资源；尚未写入 Nacos。"
        : "候选构建通过；尚未写入 Nacos，尚未对集群生效。";
    });
  }

  /**
   * 业务作用：仅按原 ETag 发出一次 Nacos 发布，失去回执时保留未知状态而不自动重发。
   * 参数说明: 无。
   * 返回：明确受理后保存原 rollout 身份；冲突和未知结果须先重新读取核对，页面不自动重发。
   */
  function publishCandidate() {
    if (!writable || !(baseline?.named ? target.writeAvailable : baseline?.source === "nacos") || unknown) {
      return;
    }
    return run(async (signal, epoch) => {
      const body = candidate();
      const etag = baseline.etag;
      // 请求发出后不能通过取消、切页或超时推断远端没有写入；先关闭再次发布资格。
      unknown = true;
      try {
        const { data, status: responseStatus } = await request(
          target.endpoint,
          {
            method: "PUT",
            headers: {
              "Content-Type": "application/yaml",
              "If-Match": etag,
            },
            body,
            signal,
          },
        );
        current(epoch);
        if (data.ok !== true) {
          throw new Error("发布没有返回明确受理结果。");
        }
        if (baseline.named && ["committed", "applied", "pending"].includes(data.status)) {
          baseline = null;
          unknown = false;
          if (data.source === "nacos") {
            status.textContent = data.local_applied
              ? "已写入 Nacos，本机已生效。请在集群监控核对其余节点。"
              : "已写入 Nacos，等待节点应用。请在集群监控核对。";
          } else {
            status.textContent = data.local_applied
              ? "文件已保存，本机已生效。"
              : "文件已保存，等待本机应用。";
          }
        } else if (
          responseStatus === 202 &&
          data.status === "awaiting_approval" &&
          typeof data.change_id === "string" &&
          /^[A-Za-z0-9_-]{1,128}$/.test(data.change_id)
        ) {
          pendingChange = data.change_id;
          baseline = null;
          unknown = false;
          status.textContent = `变更 ${pendingChange} 已进入独立审批；尚未写入Nacos，也未对集群生效。请在“变更与发布 / 审批队列”复核。`;
          timer = setTimeout(readProgress, 1000);
        } else if (
          responseStatus === 202 &&
          typeof data.rollout_id === "string" &&
          /^[A-Za-z0-9_-]{1,128}$/.test(data.rollout_id)
        ) {
          rollout = data.rollout_id;
          baseline = null;
          status.textContent = `发布 ${rollout} 已受理；请按原发布身份核对审批、Nacos 写入与节点生效。`;
          if (clusterReadable) {
            timer = setTimeout(readProgress, 1000);
          }
        } else if (
          responseStatus === 200 &&
          data.status === "already_published"
        ) {
          baseline = null;
          unknown = false;
          status.textContent =
            "Nacos 当前内容与候选相同，本次无需写入；可重新读取当前配置并核对节点状态。";
        } else {
          throw new Error("发布响应不完整，请核对 Nacos 与节点当前状态。");
        }
      } catch (error) {
        if (alive && generation === epoch) {
          if ([400, 401, 403, 409, 412, 413, 415, 428].includes(error.status)) {
            unknown = false;
            baseline = null;
            status.textContent = "发布被拒绝，请重新读取当前配置后核对候选。";
          } else {
            status.textContent =
              "发布结果未确认；请核对 Nacos 与节点状态，不要重复发送。";
          }
          const failure = new Error(status.textContent, { cause: error });
          failure.status = error.status;
          throw failure;
        }
        throw error;
      }
    });
  }

  /**
   * 业务作用：只读取原发布身份的收敛事实，不能用远端受理或单节点成功代替全节点生效。
   * 参数说明: 无。
   * 返回：显示原发布进度；等待期间有限频率重读，失败或页面隐藏后停止读取。
   */
  function readProgress() {
    clearTimeout(timer);
    timer = null;
    if (pendingChange && !rollout) {
      return readApproval();
    }
    if (!clusterReadable || !rollout) {
      return;
    }
    return run(async (signal, epoch) => {
      const id = rollout;
      const { data } = await request(
        `/api/cluster/rollout?id=${encodeURIComponent(id)}`,
        { signal },
      );
      current(epoch);
      if (
        rollout !== id ||
        data.ok !== true ||
        data.rollout?.id !== id ||
        typeof data.converged !== "boolean"
      ) {
        throw new Error("发布进度与原发布身份不一致。");
      }
      result.replaceChildren(
        element("h3", "集群发布进度"),
        element("p", `发布身份：${id}`),
        element("p", `当前状态：${String(data.status).slice(0, 128)}`),
      );
      if (data.converged) {
        status.textContent =
          "服务端已确认当前启用成员收敛；新加入或离线节点恢复后仍需核对当前配置。";
      } else {
        status.textContent =
          data.status === "awaiting_approval"
            ? "发布等待独立审批；尚未确认全局 Nacos 配置写入或全节点生效。"
            : ["canary_published", "observing", "promoting"].includes(
                  data.status,
                )
              ? "发布处于灰度或晋级阶段；尚未确认全局配置与全部节点生效。"
              : "发布尚未确认全部生效；请按原身份核对 Nacos 与各节点当前状态。";
        if (
          ![
            "failed",
            "rejected",
            "rolled_back",
            "rollback_failed",
            "awaiting_approval",
          ].includes(data.status)
        ) {
          timer = setTimeout(readProgress, 2000);
        }
      }
    });
  }

  /**
   * 业务作用：候选发生编辑时撤下此前校验提示，防止把旧候选结果用于新内容。
   * 参数说明: 无。
   * 返回：更新提示和容量门，不触发校验或发布。
   */
  function edited() {
    formatPreview = null;
    formatSource.textContent = "";
    formatPanel.hidden = true;
    showPosition();
    status.textContent = "候选已修改；保存时服务端将重新校验。";
    update();
  }

  /**
   * 业务作用：隐藏与恢复均清空原文并退休旧请求，恢复页面后由操作者显式重新读取。
   * 参数说明: 无。
   * 返回：撤下候选与比较令牌，后台已提交操作保持原有业务语义。
   */
  function visibility() {
    retire();
  }

  /**
   * 业务作用：离开页面时撤销显示权威、定时读取和敏感原文引用。
   * 参数说明: 无。
   * 返回：移除生命周期监听，旧请求不会向新页面回填。
   */
  function dispose() {
    alive = false;
    retire();
    document.removeEventListener("visibilitychange", visibility);
    panel.remove();
  }

  load.addEventListener("click", readCurrent);
  moduleChoice.addEventListener("change", readCurrent);
  validate.addEventListener("click", validateCandidate);
  publish.addEventListener("click", publishCandidate);
  progress.addEventListener("click", readProgress);
  clear.addEventListener("click", retire);
  editor.addEventListener("input", edited);
  editor.addEventListener("select", showPosition);
  editor.addEventListener("keyup", showPosition);
  format.addEventListener("click", previewFormatting);
  complete.addEventListener("click", completeAtCursor);
  adoptFormat.addEventListener("click", adoptFormatting);
  cancelFormat.addEventListener("click", cancelFormatting);
  document.addEventListener("visibilitychange", visibility);
  update();
  return dispose;
}
