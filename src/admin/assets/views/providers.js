import { request } from "../core/http.js";
import { card, element } from "../core/dom.js";
import { yamlEditor } from "../core/yaml_editor.js";

const phases = {
  warming: "尚未观察",

  current: "读取时有效",

  degraded: "读取时降级",

  stale: "读取时已陈旧",
};
const objectStates = {
  active: "活动",

  tombstone: "删除声明",

  expired: "已过期",

  conflict: "冲突",
};
const outcomes = {
  published: "发布",

  rejected: "拒绝",

  unavailable: "来源不可用",
};

/**
 * 业务作用：只显示浏览器可精确表示的原生整数，不能把版本或代际舍入为另一个身份。
 * 参数说明：
 * - value：来源接口交付的可选整数。
 * 返回：精确十进制文本、未知或不可精确显示的说明。
 */
function integer(value) {
  return value === null || value === undefined
    ? "—"
    : Number.isSafeInteger(value)
      ? String(value)
      : "超出精确显示范围";
}

/**
 * 业务作用：不完整的来源身份或条件不能继续提供动作资格，按条件冲突撤下当前读面。
 * 参数说明：
 * - message：页面定义的固定错误说明，不含服务端原文。
 * 返回：具有冲突状态的错误，由唯一错误分支清除旧来源与原文。
 */
function invalid(message) {
  return Object.assign(new Error(message), {
    status: 409,
  });
}

/**
 * 业务作用：仅访问当前接入节点已授权的来源，不把本地来源状态当成集群发布结果。
 * 参数说明：
 * - root：管理壳提供的页面容器。
 * - session：当前认证会话及原生功能、领域权限。
 * 返回：取消请求、清除原文和可见事实的退出函数，不使用浏览器存储或自动轮询。
 */
export function mount(root, session) {
  if (
    !session.features?.config_providers ||
    !(
      session.permissions?.config?.includes("read") ||
      session.workspaces?.length
    )
  ) {
    root.replaceChildren(
      element("section", "当前入口或主体没有配置来源读取能力。", "panel"),
    );
    return () => {
      root.replaceChildren();
    };
  }
  const toolbar = element("div", "", "monitor-toolbar");
  const scope = element("select");
  scope.setAttribute("aria-label", "来源范围");
  const all = element("option", "全部已授权来源");
  all.value = "";
  scope.append(all);
  if (session.permissions?.config?.includes("read")) {
    const platform = element("option", "平台来源");
    platform.value = "platform";
    scope.append(platform);
  }
  for (const workspace of session.workspaces ?? []) {
    const option = element(
      "option",
      workspace.id + " · " + workspace.tenant + " / " + workspace.environment,
    );
    option.value = workspace.id;
    scope.append(option);
  }
  const refresh = element("button", "刷新来源并清空候选");
  refresh.type = "button";
  toolbar.append(scope, refresh);
  const status = element("p", "请读取已授权来源。", "status-pill");
  status.setAttribute("role", "status");
  const directory = element("section", "", "provider-directory");
  const detail = element("section", "", "panel provider-detail");
  detail.hidden = true;
  const heading = element("h2");
  const readNote = element("p", "", "subtle");
  const facts = element("div", "", "metric-grid");
  const reload = element("button", "重读来源并清空候选");
  const exportButton = element("button", "导出重放候选原文");
  reload.type = exportButton.type = "button";
  const actions = element("div", "", "monitor-toolbar");
  actions.append(reload, exportButton);
  const explanation = element("section", "", "provider-explanation");
  const limit = element("select");
  limit.setAttribute("aria-label", "来源解释每页行数");
  for (const value of [25, 64, 128]) {
    const option = element("option", value + " 行 / 页");
    option.value = String(value);
    limit.append(option);
  }
  const previous = element("button", "上一页来源对象");
  const next = element("button", "下一页来源对象");
  previous.type = next.type = "button";
  const position = element("span", "", "subtle");
  const paging = element("div", "", "monitor-toolbar");
  paging.append(limit, previous, position, next);
  const format = element("select");
  format.setAttribute("aria-label", "候选格式");
  for (const [value, title] of [
    ["application/json", "JSON"],
    ["application/yaml", "YAML"],
  ]) {
    const option = element("option", title);
    option.value = value;
    format.append(option);
  }
  const candidate = yamlEditor(element("textarea"));
  candidate.setAttribute("aria-label", "完整来源候选");
  candidate.autocomplete = "off";
  candidate.spellcheck = false;
  candidate.rows = 14;
  const validate = element("button", "完整构建校验（不发布）");
  const diff = element("button", "语义差异（不发布）");
  validate.type = diff.type = "button";
  const candidateActions = element("div", "", "monitor-toolbar");
  candidateActions.append(format, validate, diff);
  const candidateNote = element("p", "", "subtle");
  const result = element("section", "", "provider-result");
  const exportPanel = element("section", "", "provider-export");
  const exportText = element("textarea");
  exportText.setAttribute("aria-label", "来源导出原文");
  exportText.readOnly = true;
  exportText.rows = 12;
  exportText.spellcheck = false;
  exportPanel.append(
    element("h3", "导出的原始 JSON"),
    element(
      "p",
      "这是包含 declaration 的重放候选外壳。导出不提交版本；独立写入方仍须检查事实源并执行 CAS。需要校验时，显式提供其中完整 declaration，不能提交整个外壳。",
      "subtle",
    ),
    exportText,
  );
  exportPanel.hidden = true;
  detail.append(
    heading,
    readNote,
    facts,
    actions,
    element("h3", "当前声明的对象解释"),
    explanation,
    paging,
    element("h3", "单来源完整候选"),
    element(
      "p",
      "只向当前来源的完整构建器交付原文。校验与语义差异均不发布、不续期，也不写回事实源。",
      "subtle",
    ),
    candidateNote,
    candidate,
    candidateActions,
    result,
    exportPanel,
  );
  root.replaceChildren(
    element(
      "p",
      "接入节点：" +
        location.host +
        "。以下是最近一次显式读取结果，年龄和阶段以读取时为准；不是集群汇总或持续可服务证明。",
      "subtle",
    ),
    toolbar,
    status,
    directory,
    detail,
  );
  let alive = true;
  let epoch = 0;
  let controller = null;
  let sources = [];
  let selected = null;
  let metadata = null;
  let etag = null;
  let offset = 0;
  let nextOffset = null;

  /**
   * 业务作用：候选或导出不能沿用另一次操作的结果，清除可能含配置原文的输出。
   * 参数说明: 无。
   * 返回：撤下已有校验结果与导出文本。
   */
  function clearResults() {
    result.replaceChildren();
    exportText.value = "";
    exportPanel.hidden = true;
  }

  /**
   * 业务作用：同时约束来源条件、当前请求和后端能力位，页面不把读取权限升级为候选资格。
   * 参数说明: 无。
   * 返回：所有动作按钮按当前条件启停。
   */
  function controls() {
    const busy = controller !== null;
    const readable = !!(selected && metadata && etag);
    const writable =
      readable &&
      metadata.can_validate === true &&
      Number.isSafeInteger(metadata.max_body_bytes) &&
      metadata.max_body_bytes >= 1024 &&
      metadata.max_body_bytes <= 4 * 1024 * 1024;
    reload.disabled = !selected || busy;
    exportButton.disabled = !readable || busy;
    previous.disabled = !readable || busy || offset === 0;
    next.disabled = !readable || busy || nextOffset === null;
    limit.disabled = !readable || busy;
    candidate.disabled =
      format.disabled =
      validate.disabled =
      diff.disabled =
        !writable || busy;
  }

  /**
   * 业务作用：来源、范围、可见性或权限变化时先撤销旧请求权威，再清除原文及同条件分页。
   * 参数说明：
   * - message：当前需要重新读取的固定说明。
   * 返回：旧响应无回填资格，当前详情和候选为空。
   */
  function clear(message) {
    epoch += 1;
    controller?.abort();
    controller = null;
    selected = metadata = etag = null;
    offset = 0;
    nextOffset = null;
    candidate.value = "";
    facts.replaceChildren();
    explanation.replaceChildren();
    position.textContent = "";
    heading.textContent = readNote.textContent = candidateNote.textContent = "";
    clearResults();
    detail.hidden = true;
    status.textContent = message;
    controls();
  }

  /**
   * 业务作用：条件不一致或撤权后清除来源存在性和原文，禁止旧条件继续导出或构建。
   * 参数说明：
   * - error：同源请求返回的固定状态或本地结构错误。
   * 返回：认证、授权和条件错误撤下整个读面，其余错误只保留用户尚未提交的意图。
   */
  function failed(error) {
    if ([403, 404, 409, 412, 428].includes(error.status)) {
      clear(error.message + " 请重新读取来源。");
      sources = [];
      directory.replaceChildren();
    } else {
      clearResults();
      status.textContent = error.message;
    }
  }

  /**
   * 业务作用：在单条可取消请求链中绑定来源身份和条件，阻止切换后的迟到详情或原文回填。
   * 参数说明：
   * - suffix：页面固定的单来源动作路径。
   * - options：原文格式、正文及响应类型。
   * - publish：同一轮仍有效时展示有限结果。
   * 返回：本轮成功发布读取结果时为真；取消、失权、换代或拒绝时为假。
   */
  async function run(suffix, options, publish) {
    if (!alive || controller || !selected || document.hidden) {
      return false;
    }
    const round = epoch;
    const id = selected;
    const active = new AbortController();
    controller = active;
    controls();
    try {
      const response = await request(
        "/api/providers/" + encodeURIComponent(id) + suffix,
        {
          ...options,

          signal: active.signal,

          headers: {
            ...options.headers,

            ...(etag ? { "If-Match": etag } : {}),
          },
        },
      );
      if (
        !alive ||
        round !== epoch ||
        active.signal.aborted ||
        selected !== id
      ) {
        return false;
      }
      publish(response);
      return true;
    } catch (error) {
      if (alive && round === epoch && error.name !== "AbortError") {
        failed(error);
      }
      return false;
    } finally {
      if (controller === active) {
        controller = null;
        controls();
      }
    }
  }

  /**
   * 业务作用：按本主体已授权的来源目录展示固定低敏摘要，范围筛选不请求其它主体或节点。
   * 参数说明: 无。
   * 返回：最多三十二个可选来源；无匹配是本次授权结果，不推断其它来源不存在。
   */
  function renderSources() {
    directory.replaceChildren();
    let count = 0;
    for (const source of sources) {
      if (scope.value && source.owner?.workspace !== scope.value) {
        continue;
      }
      count += 1;
      const row = element("article", "", "panel provider-source");
      const open = element("button", source.id);
      open.type = "button";
      open.addEventListener("click", () => {
        void choose(source.id);
      });
      row.append(
        open,
        element(
          "p",
          source.namespace +
            " · " +
            source.owner.workspace +
            " · " +
            (phases[source.phase] ?? "未知阶段"),
          "subtle",
        ),
      );
      directory.append(row);
    }
    if (!count) {
      directory.append(element("p", "本次授权范围内没有来源。", "panel"));
    }
  }

  /**
   * 业务作用：显式刷新前清除旧来源和用户候选，目录读取仍由服务器逐来源裁定权限。
   * 参数说明: 无。
   * 返回：显示最新低敏目录；失败或取消不保留此前来源存在性。
   */
  async function list() {
    clear("正在读取接入节点来源…");
    sources = [];
    directory.replaceChildren();
    if (!alive || document.hidden) {
      return;
    }
    const round = epoch;
    const active = new AbortController();
    controller = active;
    controls();
    try {
      const response = await request("/api/providers", {
        signal: active.signal,
      });
      if (!alive || round !== epoch || active.signal.aborted) {
        return;
      }
      const rows = response.data.sources;
      if (
        !Array.isArray(rows) ||
        rows.length > 32 ||
        rows.some(
          (row) =>
            !/^[A-Za-z0-9_-]{1,64}$/.test(row.id ?? "") ||
            typeof row.namespace !== "string" ||
            typeof row.owner?.workspace !== "string",
        )
      ) {
        throw invalid("来源目录不完整，无法展示。");
      }
      sources = rows;
      renderSources();
      status.textContent = "已读取接入节点的授权来源；选择一个来源查看。";
    } catch (error) {
      if (alive && round === epoch && error.name !== "AbortError") {
        failed(error);
      }
    } finally {
      if (controller === active) {
        controller = null;
        controls();
      }
    }
  }

  /**
   * 业务作用：每次选择都取得原生条件与能力，不使用列表缓存作为导出或候选的授权。
   * 参数说明：
   * - id：本次授权目录中已选择的固定来源。
   * 返回：同条件状态与首页解释；原文和此前其它来源结果不保留。
   */
  async function choose(id) {
    clear("正在读取所选来源…");
    if (
      !/^[A-Za-z0-9_-]{1,64}$/.test(id) ||
      !sources.some((source) => source.id === id)
    ) {
      return;
    }
    selected = id;
    const ok = await run("/status", {}, (response) => {
      const value = response.data;
      const condition = response.headers.get("etag");
      if (value.id !== id || !/^"sha256-[0-9a-f]{64}"$/.test(condition ?? "")) {
        throw invalid("来源身份或条件不完整，请重新读取。");
      }
      metadata = value;
      etag = condition;
      heading.textContent = id + " · " + value.namespace;
      readNote.textContent =
        "读取时间：" +
        new Date().toLocaleString("zh-CN") +
        "。阶段与年龄仅代表此次读取；后续动作仍须通过同条件和当前权限复验。";
      facts.replaceChildren(
        card("阶段", phases[value.phase] ?? "未知", "读取时的已发布证据"),
        card("声明 revision", integer(value.revision), "浏览器不舍入整数身份"),
        card("对象数", integer(value.objects), "当前来源声明"),
        card("证据年龄", integer(value.age_ms), "毫秒，读取时"),
        card("最大陈旧期", integer(value.max_stale_ms), "毫秒，来源权威边界"),
        card(
          "连续失败",
          integer(value.consecutive_failures),
          outcomes[value.last_outcome] ?? "尚无固定观测结果",
        ),
      );
      facts.append(
        element(
          "p",
          "归属：" +
            value.owner.workspace +
            " · " +
            value.owner.tenant +
            " / " +
            value.owner.environment +
            "；优先级：" +
            integer(value.priority),
          "subtle",
        ),
      );
      candidate.maxLength = Number.isSafeInteger(value.max_body_bytes)
        ? value.max_body_bytes
        : 0;
      candidateNote.textContent =
        value.can_validate === true
          ? "当前主体可校验，原生正文上限 " +
            integer(value.max_body_bytes) +
            " 字节（UTF-8）。"
          : "当前主体只读，不能交付候选。";
      detail.hidden = false;
      status.textContent = "已读取来源条件，候选与导出尚未执行。";
    });
    if (ok && selected === id) {
      await explain(0);
    }
  }

  /**
   * 业务作用：解释页始终携带同一来源ETag，不拼接更新前后的对象清单。
   * 参数说明：
   * - at：当前页边界计算出的有限偏移。
   * 返回：一次有界对象页；条件失效时撤下整个来源读面并要求重读。
   */
  async function explain(at) {
    if (!etag || !Number.isSafeInteger(at) || at < 0 || at > 8192) {
      return;
    }
    explanation.replaceChildren();
    clearResults();
    const size = Number(limit.value);
    await run("/explain?offset=" + at + "&limit=" + size, {}, (response) => {
      const value = response.data;
      if (
        response.headers.get("etag") !== etag ||
        value.source?.id !== selected ||
        !Array.isArray(value.objects) ||
        value.objects.length > size ||
        !(
          value.next_offset === null ||
          (Number.isSafeInteger(value.next_offset) &&
            value.next_offset === at + size &&
            value.next_offset <= 8192 &&
            value.objects.length === size)
        )
      ) {
        throw invalid("来源解释条件或分页不完整，请重新读取。");
      }
      offset = at;
      nextOffset = value.next_offset;
      for (const object of value.objects) {
        const row = element("article", "", "provider-object");
        row.append(
          element(
            "h4",
            object.identity.namespace +
              " / " +
              object.identity.kind +
              " / " +
              object.identity.name,
          ),
          element(
            "p",
            "generation " +
              integer(object.generation) +
              " · " +
              (objectStates[object.state] ?? "未知状态") +
              " · 选中来源 " +
              object.selected_source +
              " · " +
              (object.compiled === true
                ? "已编译"
                : object.waiting_dependencies === true
                  ? "等待依赖"
                  : "未编译"),
            "subtle",
          ),
        );
        explanation.append(row);
      }
      if (!value.objects.length) {
        explanation.append(element("p", "本页没有可见对象。", "subtle"));
      }
      position.textContent =
        "第 " +
        (value.objects.length ? at + 1 : 0) +
        "–" +
        (at + value.objects.length) +
        " 项";
      status.textContent = "已读取同条件对象解释。";
    });
  }

  /**
   * 业务作用：保留导出响应的原始JSON字节文本，不能经浮点解析和重新编码改变revision或generation。
   * 参数说明: 无。
   * 返回：只读原文；导出本身不占用事实源版本、不发布也不写回。
   */
  async function exportSource() {
    if (!etag) {
      return;
    }
    clearResults();
    await run("/export", { responseType: "text" }, (response) => {
      if (
        response.headers.get("etag") !== etag ||
        typeof response.data !== "string"
      ) {
        throw invalid("来源导出条件不完整，请重新读取。");
      }
      exportText.value = response.data;
      exportPanel.hidden = false;
      status.textContent = "已导出重放候选原文，尚未发布或写入事实源。";
    });
  }

  /**
   * 业务作用：将用户明确提供的完整声明原文交给原生完整构建器，UTF-8预算与ETag共同约束请求。
   * 参数说明：
   * - action：固定的dry-run或diff业务动作。
   * 返回：显示未发布的完整构建结论及有界语义差异；拒绝不重试、不改写用户原文。
   */
  async function validateSource(action) {
    if (
      !etag ||
      metadata?.can_validate !== true ||
      !["dry-run", "diff"].includes(action)
    ) {
      return;
    }
    clearResults();
    const bytes = new TextEncoder().encode(candidate.value).byteLength;
    if (
      !bytes ||
      !Number.isSafeInteger(metadata.max_body_bytes) ||
      bytes > metadata.max_body_bytes ||
      metadata.max_body_bytes > 4 * 1024 * 1024
    ) {
      status.textContent = "候选为空或超过当前来源的UTF-8字节上限。";
      return;
    }
    if (!["application/json", "application/yaml"].includes(format.value)) {
      status.textContent = "请选择明确的JSON或YAML候选格式。";
      return;
    }
    await run(
      "/" + action,
      {
        method: "POST",

        headers: {
          "Content-Type": format.value,
        },

        body: candidate.value,
      },
      (response) => {
        if (
          response.headers.get("etag") !== etag ||
          response.data.published !== false ||
          !response.data.diff
        ) {
          throw invalid("没有取得明确的未发布构建结论，请重新读取。");
        }
        result.append(
          element("h3", "完整构建通过 · 未发布"),
          element(
            "p",
            "该结果未提交事实源、未续期、未发布数据面。各类最多展示100项身份。",
            "subtle",
          ),
        );
        for (const [key, title] of [
          ["added", "新增"],
          ["removed", "移除"],
          ["changed", "变更"],
        ]) {
          const rows = response.data.diff[key];
          if (!Array.isArray(rows) || rows.length > 8192) {
            throw invalid("语义差异结果不完整，请重新读取。");
          }
          result.append(element("h4", title + " " + rows.length + " 项"));
          for (const row of rows.slice(0, 100)) {
            result.append(
              element(
                "p",
                row.namespace + " / " + row.kind + " / " + row.name,
                "subtle",
              ),
            );
          }
        }
        status.textContent = "完整构建通过，候选未发布。";
      },
    );
  }

  /**
   * 业务作用：隐藏页面立即撤去已读来源、用户候选和导出原文，恢复后必须显式重新读取。
   * 参数说明: 无。
   * 返回：不在后台自动读取来源，不保留隐藏前的显示权威。
   */
  function visibility() {
    if (document.hidden) {
      clear("页面已隐藏，来源与原文已清空；请显式刷新。");
      sources = [];
      directory.replaceChildren();
    }
  }
  refresh.addEventListener("click", () => {
    void list();
  });
  scope.addEventListener("change", () => {
    void list();
  });
  reload.addEventListener("click", () => {
    if (selected) {
      void choose(selected);
    }
  });
  previous.addEventListener("click", () => {
    void explain(Math.max(0, offset - Number(limit.value)));
  });
  next.addEventListener("click", () => {
    if (nextOffset !== null) {
      void explain(nextOffset);
    }
  });
  limit.addEventListener("change", () => {
    void explain(0);
  });
  exportButton.addEventListener("click", () => {
    void exportSource();
  });
  validate.addEventListener("click", () => {
    void validateSource("dry-run");
  });
  diff.addEventListener("click", () => {
    void validateSource("diff");
  });
  candidate.addEventListener("input", clearResults);
  document.addEventListener("visibilitychange", visibility);
  controls();
  void list();

  /**
   * 业务作用：退出当前页面时清除来源身份、配置原文与迟到请求的显示资格。
   * 参数说明: 无。
   * 返回：释放页面和可见性监听，不写Storage或保留历史结果。
   */
  return function dispose() {
    alive = false;
    clear("");
    sources = [];
    document.removeEventListener("visibilitychange", visibility);
    root.replaceChildren();
  };
}
