import { request } from "../core/http.js";
import { card, element } from "../core/dom.js";
import {
  bounded,
  fields,
  invalid,
  metadata,
  proposal,
  samples,
} from "./diagnostics/model.js";

/**
 * 业务作用：创建带业务名称的诊断输入，浏览器约束只辅助输入，原生验证仍是最终裁决。
 * 参数说明：
 * - parent：当前表单或正文策略容器。
 * - title：可访问名称。
 * - value：明确的初始值。
 * - range：可选的原生整数上下界。
 * 返回：独立输入控件。
 */
function input(parent, title, value = "", range = null) {
  const label = element("label", title);
  const control = element("input");
  control.setAttribute("aria-label", title);
  control.type = range ? "number" : "text";
  control.value = String(value);
  if (range) {
    control.min = String(range[0]);
    control.max = String(range[1]);
    control.step = "1";
  } else {
    control.maxLength = 128;
    control.autocomplete = "off";
    control.spellcheck = false;
  }
  label.append(control);
  parent.append(label);
  return control;
}

/**
 * 业务作用：将逐行显式字段列表交给与响应相同的正文白名单门，不忽略空行之外的非法条目。
 * 参数说明：
 * - value：用户输入的每行一个字段名。
 * 返回：有限原样字段数组；重复、敏感名或非法字符直接拒绝。
 */
function fieldList(value) {
  return fields(value.split(/\r?\n/).filter((line) => line !== ""));
}

/**
 * 业务作用：在接入进程上申请、双人复核和显式交付限时诊断，不推断远端节点已采集。
 * 参数说明：
 * - root：管理壳的页面容器。
 * - session：当前主体实际诊断动作位和本机配置能力。
 * 返回：清除申请输入、已交付样本、定时器与旧请求权威的退出函数。
 */
export function mount(root, session) {
  const permissions = session.permissions?.diagnostics ?? [];
  const readable = permissions.includes("read");
  const writable = permissions.includes("write");
  if (!session.diagnostics?.enabled || (!readable && !writable)) {
    root.replaceChildren(
      element("section", "当前入口或主体没有诊断能力。", "panel"),
    );
    return () => {
      root.replaceChildren();
    };
  }
  const toolbar = element("div", "", "monitor-toolbar");
  const refresh = element("button", "重新读取诊断会话");
  refresh.type = "button";
  refresh.disabled = !readable;
  const pause = element("button", "暂停并清空页面");
  pause.type = "button";
  toolbar.append(refresh, pause);
  const status = element("p", "尚未读取诊断会话。", "status-pill");
  status.setAttribute("role", "status");
  const form = element("form", "", "panel diagnostics-form");
  form.append(
    element("h2", "申请限时诊断"),
    element(
      "p",
      "精确物理入口和路由；可选 consumer 只匹配认证后的可信身份。申请先等待另一名主体复核，批准后才开始 TTL。",
      "subtle",
    ),
  );
  const controlsGrid = element("div", "", "diagnostics-fields");
  const proxy = input(controlsGrid, "诊断物理入口 proxy");
  const route = input(controlsGrid, "诊断路由 route");
  const consumer = input(controlsGrid, "可信 consumer（可选）");
  const ttl = input(controlsGrid, "活动 TTL（秒）", 60, [1, 300]);
  const maximumSamples = input(controlsGrid, "最多样本数", 16, [1, 128]);
  const recordBytes = input(controlsGrid, "单条字节上限", 4096, [256, 4096]);
  const totalBytes = input(controlsGrid, "累计字节上限", 65536, [256, 262144]);
  const downloads = input(controlsGrid, "最多下载次数", 1, [1, 3]);
  const bodyLabel = element("label", "显式申请正文脱敏字段");
  const body = element("input");
  body.type = "checkbox";
  body.setAttribute("aria-label", "显式申请正文脱敏字段");
  body.checked = false;
  bodyLabel.prepend(body);
  const bodyPanel = element("fieldset", "", "diagnostics-body");
  bodyPanel.hidden = true;
  bodyPanel.append(
    element("legend", "固定策略：redact"),
    element(
      "p",
      "只识别 JSON 顶层字段是否存在，所有值固定为 [REDACTED]；不解压、不显示原文。每方向最多16个字段，每行一个，只允许 ASCII 字母、数字与下划线，敏感名称拒绝。",
      "subtle",
    ),
  );
  const inspectBytes = input(bodyPanel, "正文检查字节上限", 4096, [1, 65536]);
  const requestFields = element("textarea");
  requestFields.setAttribute("aria-label", "请求正文字段（每行一个）");
  const responseFields = element("textarea");
  responseFields.setAttribute("aria-label", "响应正文字段（每行一个）");
  for (const [title, control] of [
    ["请求正文字段（每行一个）", requestFields],
    ["响应正文字段（每行一个）", responseFields],
  ]) {
    const label = element("label", title);
    control.rows = 4;
    control.maxLength = 1040;
    control.spellcheck = false;
    label.append(control);
    bodyPanel.append(label);
  }
  const propose = element("button", "提交诊断申请");
  propose.type = "submit";
  form.append(controlsGrid, bodyLabel, bodyPanel, propose);
  const directory = element("section", "", "diagnostics-directory");
  const detail = element("section", "", "panel diagnostics-detail");
  detail.hidden = true;
  const heading = element("h2");
  const facts = element("div", "", "metric-grid");
  const frozen = element("pre", "", "diagnostics-frozen");
  frozen.setAttribute("aria-label", "冻结诊断申请与原摘要");
  const actions = element("div", "", "monitor-toolbar");
  const approve = element("button", "按原摘要批准诊断");
  const stop = element("button", "停止并销毁此会话");
  const download = element("button", "下载到页面（消耗一次额度）");
  for (const button of [approve, stop, download]) {
    button.type = "button";
  }
  actions.append(approve, stop, download);
  const output = element("section", "", "diagnostics-samples");
  detail.append(
    heading,
    facts,
    element("h3", "复核完整冻结范围"),
    frozen,
    element(
      "p",
      "批准使用此处原摘要作为 If-Match；停止和下载绑定此会话唯一身份。下载次数在交付前扣除，传输或审计失败不退款，不自动重试。停止会立即销毁样本。",
      "subtle",
    ),
    actions,
    output,
  );
  root.replaceChildren(
    element(
      "p",
      "接入节点：" +
        location.host +
        "。只操作当前进程的本机诊断目录，不是集群或远端 Data 诊断。最多8个待批或活动会话，待批窗口60秒；页面不自动续期、刷新或采样。",
      "subtle",
    ),
    toolbar,
    status,
    form,
    directory,
    detail,
  );
  let alive = true;
  let epoch = 0;
  let controller = null;
  let rows = [];
  let selected = null;
  let blocked = false;
  let expiryTimer = null;
  const inputs = [
    proxy,
    route,
    consumer,
    ttl,
    maximumSamples,
    recordBytes,
    totalBytes,
    downloads,
    body,
    inspectBytes,
    requestFields,
    responseFields,
  ];

  /**
   * 业务作用：动作只依据当前有效元信息和独立权限，不允许申请者自批或超额度下载。
   * 参数说明: 无。
   * 返回：过期、暂停、未知结果或请求进行中时撤去动作资格。
   */
  function controls() {
    const busy = controller !== null;
    const current = selected && selected.deadline > performance.now();
    refresh.disabled = !readable || busy;
    pause.disabled = false;
    for (const control of inputs) {
      control.disabled = !writable || blocked || busy;
    }
    bodyPanel.disabled = !body.checked || !writable || blocked || busy;
    propose.disabled = !writable || blocked || busy;
    approve.disabled =
      !writable ||
      !current ||
      blocked ||
      busy ||
      selected.state !== "pending" ||
      selected.initiator === session.principal;
    stop.disabled = !writable || !current || blocked || busy;
    download.disabled =
      !readable ||
      !current ||
      blocked ||
      busy ||
      selected.state !== "active" ||
      selected.downloads >= selected.request.max_downloads;
  }

  /**
   * 业务作用：取消旧显示权威并清除已经交付的样本，页面清空不被解释为后端停止。
   * 参数说明：
   * - message：需要显式重新读取的固定说明。
   * - clearInputs：是否一并撤去用户输入的精确选择器和正文列表。
   * 返回：旧响应不能回填，后台已有采集仍由原生TTL或显式停止决定。
   */
  function clear(message, clearInputs = false) {
    epoch += 1;
    controller?.abort();
    controller = null;
    clearTimeout(expiryTimer);
    expiryTimer = null;
    selected = null;
    rows = [];
    directory.replaceChildren();
    output.replaceChildren();
    frozen.textContent = heading.textContent = "";
    facts.replaceChildren();
    detail.hidden = true;
    if (clearInputs) {
      proxy.value =
        route.value =
        consumer.value =
        requestFields.value =
        responseFields.value =
          "";
      body.checked = false;
      bodyPanel.hidden = true;
    }
    status.textContent = message;
    controls();
  }

  /**
   * 业务作用：使用单调到期时刻撤下元信息与样本，不把审计或网络耗时当成新增授权时间。
   * 参数说明: 无。
   * 返回：只保留仍有效的会话，并安排一次最近到期清除；不发网络请求。
   */
  function expire() {
    clearTimeout(expiryTimer);
    expiryTimer = null;
    const now = performance.now();
    rows = rows.filter((row) => row.deadline > now);
    if (selected && selected.deadline <= now) {
      selected = null;
      detail.hidden = true;
      output.replaceChildren();
      frozen.textContent = heading.textContent = "";
      facts.replaceChildren();
      status.textContent =
        "所选诊断会话已到期，样本与动作已清除；请显式重新读取。";
    }
    renderDirectory();
    controls();
    if (rows.length) {
      expiryTimer = setTimeout(
        expire,
        Math.max(1, Math.min(...rows.map((row) => row.deadline)) - now),
      );
    }
  }

  /**
   * 业务作用：展示最多八个本机低敏会话，选择时先清除另一会话的样本。
   * 参数说明: 无。
   * 返回：有限目录；不保存以前的目录或跨节点合并结果。
   */
  function renderDirectory() {
    directory.replaceChildren(element("h2", "本机诊断会话"));
    for (const row of rows) {
      const article = element("article", "", "panel");
      const open = element("button", row.id);
      open.type = "button";
      open.addEventListener("click", () => {
        if (controller || row.deadline <= performance.now()) {
          return;
        }
        output.replaceChildren();
        selected = row;
        renderDetail();
      });
      article.append(
        open,
        element(
          "p",
          row.request.proxy +
            " / " +
            row.request.route +
            " · " +
            (row.state === "pending" ? "待另一主体复核" : "已批准") +
            " · 申请者 " +
            row.initiator,
          "subtle",
        ),
      );
      directory.append(article);
    }
    if (!rows.length) {
      directory.append(
        element(
          "p",
          readable
            ? "本次没有仍有效的本机会话。"
            : "当前主体没有会话列表读取权限；可以提交申请，不能据此推断其它会话不存在。",
          "subtle",
        ),
      );
    }
  }

  /**
   * 业务作用：在批准前显示完整申请、唯一身份和原摘要，不能用表单编辑值替代冻结范围。
   * 参数说明: 无。
   * 返回：当前会话的元信息及动作位，配置代无法精确显示时明确未知。
   */
  function renderDetail() {
    if (!selected) {
      return;
    }
    heading.textContent = selected.id;
    const generation = Number.isSafeInteger(selected.generation)
      ? String(selected.generation)
      : "超出精确显示范围";
    facts.replaceChildren(
      card(
        "当前状态",
        selected.state === "pending" ? "待复核" : "已批准",
        "以本次读取为准",
      ),
      card(
        "样本数",
        String(selected.samples),
        "上限 " + selected.request.max_samples,
      ),
      card(
        "已占字节",
        String(selected.bytes),
        "上限 " + selected.request.max_total_bytes,
      ),
      card(
        "已下载",
        String(selected.downloads),
        "最多 " + selected.request.max_downloads + " 次",
      ),
    );
    frozen.textContent = JSON.stringify(
      {
        id: selected.id,

        digest: selected.digest,

        generation,

        owner: selected.owner,

        initiator: selected.initiator,

        approver: selected.approver,

        request: selected.request,
      },
      null,
      2,
    );
    detail.hidden = false;
    controls();
  }

  /**
   * 业务作用：单条有界请求链隔离迟到结果；任何已发出的动作失败都按可能已提交处理。
   * 参数说明：
   * - path：固定本机诊断路径。
   * - options：固定动作方法、正文和原摘要。
   * - publish：验证响应后发布有限结果。
   * 返回：成功时更新页面；失败不重试，动作恢复必须先显式回读。
   */
  async function run(path, options, publish) {
    if (!alive || controller || document.hidden) {
      return;
    }
    const round = epoch;
    const active = new AbortController();
    const mutation = options.method === "POST";
    const started = performance.now();
    controller = active;
    if (mutation) {
      // 取消只撤销本页等待，不能撤销服务端已完成的审批、停止或下载扣费。
      blocked = true;
    }
    output.replaceChildren();
    controls();
    try {
      const response = await request(path, {
        ...options,

        signal: active.signal,
      });
      if (!alive || round !== epoch || active.signal.aborted) {
        return;
      }
      publish(response, started);
      blocked = false;
      expire();
    } catch (error) {
      if (alive && round === epoch) {
        clear(
          mutation
            ? "动作结果尚不确定，可能已执行或扣除下载次数。不会自动重试；请显式重新读取后再决定。"
            : error.message,
          true,
        );
        blocked = true;
      }
    } finally {
      if (controller === active) {
        controller = null;
      }
      controls();
    }
  }

  /**
   * 业务作用：显式读取最新目录解除未知动作门，旧样本、范围和摘要在请求前即撤下。
   * 参数说明: 无。
   * 返回：最新最多八个本机有效会话；读取失败继续保持动作关闭。
   */
  async function list() {
    if (!readable || controller) {
      return;
    }
    clear("正在重新读取本机诊断目录…");
    blocked = true;
    await run("/api/diagnostics", {}, (response, started) => {
      if (
        !Array.isArray(response.data.sessions) ||
        response.data.sessions.length > 8
      ) {
        throw invalid();
      }
      const next = response.data.sessions.map((row) => metadata(row, started));
      if (new Set(next.map((row) => row.id)).size !== next.length) {
        throw invalid();
      }
      rows = next;
      status.textContent = "已重新读取本机目录；选择会话复核完整范围。";
    });
  }

  /**
   * 业务作用：从完整类型化表单提交一次申请，正文默认关闭，不发送客户端自报认证事实。
   * 参数说明：
   * - event：用户显式提交事件。
   * 返回：显示待复核原摘要；非法输入不发送请求，服务端仍复验范围与预算。
   */
  async function submit(event) {
    event.preventDefault();
    if (!writable || blocked || controller) {
      return;
    }
    let value;
    try {
      value = proposal({
        proxy: proxy.value,

        route: route.value,

        consumer: consumer.value === "" ? null : consumer.value,

        ttl_seconds: bounded(Number(ttl.value), 1, 300),

        max_samples: bounded(Number(maximumSamples.value), 1, 128),

        max_record_bytes: bounded(Number(recordBytes.value), 256, 4096),

        max_total_bytes: bounded(
          Number(totalBytes.value),
          Number(recordBytes.value),
          262144,
        ),

        max_downloads: bounded(Number(downloads.value), 1, 3),

        body: body.checked
          ? {
              mask: "redact",

              max_inspect_bytes: bounded(Number(inspectBytes.value), 1, 65536),

              request_fields: fieldList(requestFields.value),

              response_fields: fieldList(responseFields.value),
            }
          : null,
      });
    } catch {
      status.textContent =
        "申请未发送：请检查精确名称、整数预算及非敏感正文白名单。";
      return;
    }
    await run(
      "/api/diagnostics",
      {
        method: "POST",

        headers: { "Content-Type": "application/json" },

        body: JSON.stringify(value),
      },
      (response, started) => {
        const next = metadata(response.data, started);
        if (
          response.status !== 202 ||
          next.initiator !== session.principal ||
          next.state !== "pending" ||
          JSON.stringify(next.request) !== JSON.stringify(value)
        ) {
          throw invalid();
        }
        rows = [
          ...rows
            .filter(
              (row) => row.id !== next.id && row.deadline > performance.now(),
            )
            .slice(0, 7),
          next,
        ];
        selected = next;
        renderDetail();
        status.textContent =
          "申请已创建，等待另一主体按原摘要批准；尚未开始采集。";
      },
    );
  }

  /**
   * 业务作用：对当前冻结会话执行唯一一次显式动作，批准原摘要与下载身份均逐项复验。
   * 参数说明：
   * - action：固定的approve、stop或download。
   * 返回：更新同一会话或显示受控样本；失败后必须重新读取，不退款或自动重试。
   */
  async function act(action) {
    expire();
    const previous = selected;
    if (
      !previous ||
      blocked ||
      controller ||
      !["approve", "stop", "download"].includes(action)
    ) {
      return;
    }
    if (
      action === "download"
        ? !readable ||
          previous.state !== "active" ||
          previous.downloads >= previous.request.max_downloads
        : !writable ||
          (action === "approve" &&
            (previous.state !== "pending" ||
              previous.initiator === session.principal))
    ) {
      return;
    }
    await run(
      "/api/diagnostics/" + encodeURIComponent(previous.id) + "/" + action,
      {
        method: "POST",

        headers:
          action === "approve"
            ? { "If-Match": '"' + previous.digest + '"' }
            : {},
      },
      (response, started) => {
        if (action === "stop") {
          if (response.data.ok !== true) {
            throw invalid();
          }
          rows = rows.filter((row) => row.id !== previous.id);
          selected = null;
          detail.hidden = true;
          frozen.textContent = heading.textContent = "";
          facts.replaceChildren();
          status.textContent = "此会话及样本已停止并销毁。";
          return;
        }
        const next = metadata(
          action === "download" ? response.data.session : response.data,
          started,
        );
        if (
          next.id !== previous.id ||
          next.digest !== previous.digest ||
          next.initiator !== previous.initiator ||
          JSON.stringify(next.request) !== JSON.stringify(previous.request) ||
          next.state !== "active" ||
          (action === "approve" && next.approver !== session.principal) ||
          (action === "download" && next.downloads !== previous.downloads + 1)
        ) {
          throw invalid();
        }
        const captured =
          action === "download"
            ? samples(response.data.samples, next.request)
            : null;
        rows = rows.map((row) => (row.id === next.id ? next : row));
        selected = next;
        renderDetail();
        if (captured) {
          output.append(
            element("h3", "本次交付的脱敏样本 · " + captured.length + " 条"),
          );
          for (const sample of captured) {
            output.append(element("pre", JSON.stringify(sample, null, 2)));
          }
        }
        status.textContent =
          action === "approve"
            ? "已按原摘要批准，活动 TTL 现已开始。"
            : "已交付到本页并扣除一次下载额度；不自动再次下载。";
      },
    );
  }

  /**
   * 业务作用：暂停或隐藏立即撤下样本、申请输入和旧动作权威，不暗示后端采集已停止。
   * 参数说明: 无。
   * 返回：恢复后仍需显式读取；后台会话按原TTL或显式停止销毁。
   */
  function suspend() {
    blocked = true;
    clear(
      "页面已暂停并清空；后台会话仍按原 TTL 或显式停止结束。请重新读取。",
      true,
    );
  }

  /**
   * 业务作用：隐藏时释放页面内的诊断结果，重新可见不会自动恢复网络或动作。
   * 参数说明: 无。
   * 返回：隐藏状态触发暂停，保留原生会话生命周期边界。
   */
  function visibility() {
    if (document.hidden) {
      suspend();
    }
  }
  form.addEventListener("submit", (event) => {
    void submit(event);
  });
  refresh.addEventListener("click", () => {
    void list();
  });
  pause.addEventListener("click", suspend);
  body.addEventListener("change", () => {
    bodyPanel.hidden = !body.checked;
    if (!body.checked) {
      requestFields.value = responseFields.value = "";
    }
    controls();
  });
  for (const [button, action] of [
    [approve, "approve"],
    [stop, "stop"],
    [download, "download"],
  ]) {
    button.addEventListener("click", () => {
      void act(action);
    });
  }
  document.addEventListener("visibilitychange", visibility);
  controls();
  if (readable) {
    void list();
  } else {
    renderDirectory();
  }

  /**
   * 业务作用：退出或切换页面时撤销显示权威并释放已交付内容，不保留诊断历史或凭据。
   * 参数说明: 无。
   * 返回：取消请求、释放到期和可见性监听，页面数据全部清空。
   */
  return function dispose() {
    alive = false;
    clear("", true);
    document.removeEventListener("visibilitychange", visibility);
    root.replaceChildren();
  };
}
