import { request } from "../core/http.js";
import { element } from "../core/dom.js";

const kinds = {
  blacklist: ["IP封禁与解封", "acl", "emergency-kill"],

  interface_disable: ["动态接口禁用", "interface-guard", "emergency-kill"],

  connections: ["本机长连接关闭与排空", "connections", "emergency-kill"],

  cache_invalidate: ["路由缓存失效", "cache", "write"],
};

/**
 * 业务作用：拒绝未能完整复核的运行态合同，不回显底层错误或不受控结果。
 * 参数说明: 无。
 * 返回：页面固定错误，动作失败不能解释为未执行。
 */
function invalid() {
  return new Error(
    "当前范围、输入或原生结果不完整，请重新读取并核对实际状态。",
  );
}

/**
 * 业务作用：保持配置代和毫秒数的u64十进制精度，不经浮点数转换。
 * 参数说明：
 * - value：控件或能力响应中的规范十进制字符串。
 * - maximum：对应字段的精确上限。
 * 返回：原字符串；溢出、符号、空白、指数及前导零拒绝。
 */
function decimal(value, maximum = "18446744073709551615") {
  if (
    typeof value !== "string" ||
    !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
    value.length > maximum.length ||
    (value.length === maximum.length && value > maximum)
  ) {
    throw invalid();
  }
  return value;
}

/**
 * 业务作用：验证原样选择器的UTF-8预算，中文和URI保留字符只作为JSON数据交付。
 * 参数说明：
 * - value：用户明确输入的精确文本。
 * - maximum：原生字段字节预算。
 * 返回：未经trim、URI编码或二次解码的原值。
 */
function text(value, maximum) {
  if (
    typeof value !== "string" ||
    !value.length ||
    new TextEncoder().encode(value).length > maximum ||
    /[\p{Cc}]/u.test(value)
  ) {
    throw invalid();
  }
  return value;
}

/**
 * 业务作用：只在接入进程上执行一次明确复核的原生运行态动作，不把共享事实源写入包装成集群完成。
 * 参数说明：
 * - root：管理壳提供的当前页面容器。
 * - session：已认证主体的原生独立动作位。
 * 返回：撤销显示权威、清空用户输入和释放监听器的退出函数，不保存历史或浏览器存储。
 */
export function mount(root, session) {
  /**
   * 业务作用：把页面动作与登录时的实际资源动作位相交，不能通过角色名扩大权限。
   * 参数说明：
   * - kind：页面固定动作名。
   * 返回：当前会话明确拥有该原生动作位时为真。
   */
  const permitted = (kind) => {
    const entry = kinds[kind];
    return (
      !!entry && session.permissions?.[entry[1]]?.includes(entry[2]) === true
    );
  };
  if (!Object.keys(kinds).some(permitted)) {
    root.replaceChildren(
      element("section", "当前主体没有运行态治理动作权限。", "panel"),
    );
    return () => {
      root.replaceChildren();
    };
  }
  const toolbar = element("div", "", "monitor-toolbar");
  const refresh = element("button", "读取当前运行态动作条件");
  refresh.type = "button";
  const pause = element("button", "暂停并清空运行态动作");
  pause.type = "button";
  toolbar.append(refresh, pause);
  const status = element("p", "尚未读取当前条件。", "status-pill");
  status.setAttribute("role", "status");
  const authority = element("p", "", "subtle");
  const form = element("form", "", "panel runtime-actions-form");
  const chooseLabel = element("label", "运行态动作");
  const choose = element("select");
  choose.setAttribute("aria-label", "运行态动作");
  chooseLabel.append(choose);
  const fields = element("section", "", "runtime-fields");
  const note = element("p", "", "subtle");
  const review = element("button", "复核完整运行态动作");
  review.type = "submit";
  form.append(element("h2", "明确操作范围"), chooseLabel, note, fields, review);
  form.hidden = true;
  const preview = element("section", "", "panel runtime-action-preview");
  const frozen = element("pre");
  frozen.setAttribute("aria-label", "冻结运行态动作与原条件");
  const execute = element("button", "执行已复核运行态动作");
  execute.type = "button";
  preview.append(
    element("h2", "执行前复核"),
    frozen,
    element(
      "p",
      "以下动作不提供自动回滚。连接关闭只表示发出信号，延迟排空只表示已安排；动态事实源写入与本机刷新不证明其它节点已观察到变化。",
      "subtle",
    ),
    execute,
  );
  preview.hidden = true;
  const result = element("section", "", "panel runtime-action-result");
  result.hidden = true;
  root.replaceChildren(
    element(
      "p",
      "接入节点：" +
        location.host +
        "。操作当前进程的原生运行态；不是多节点持久提案或集群执行任务。共享动态事实源与缓存后端是否覆盖其它节点，以实际部署和独立观测为准。",
      "subtle",
    ),
    toolbar,
    status,
    authority,
    form,
    preview,
    result,
  );
  let alive = true;
  let epoch = 0;
  let controller = null;
  let capability = null;
  let condition = null;
  let prepared = null;
  let operation = "apply";
  let selector = "route";
  let values = {};
  let inputs = [];
  let uncertain = false;

  /**
   * 业务作用：编辑任何输入后撤下旧复核，不让旧条件或另一范围的结果继续提供执行资格。
   * 参数说明: 无。
   * 返回：冻结动作和当前结果为空，必须重新显式复核。
   */
  function edited() {
    prepared = null;
    frozen.textContent = "";
    preview.hidden = true;
    result.replaceChildren();
    result.hidden = true;
    controls();
  }

  /**
   * 业务作用：创建完整的文本、整数或正文输入，业务字符串始终保留原样。
   * 参数说明：
   * - key：当前固定表单字段身份。
   * - title：业务名称和可访问标签。
   * - initial：明确的初始值。
   * - maximum：当前字段字符输入上限，提交时另复验UTF-8预算。
   * - multiline：是否使用多行正文输入。
   * 返回：当前表单中的独立控件。
   */
  function field(key, title, initial = "", maximum = 256, multiline = false) {
    const label = element("label", title);
    const control = element(multiline ? "textarea" : "input");
    control.setAttribute("aria-label", title);
    control.value = initial;
    control.maxLength = maximum;
    control.spellcheck = false;
    control.autocomplete = "off";
    if (multiline) {
      control.rows = 4;
    } else {
      control.type = "text";
    }
    control.addEventListener("input", edited);
    label.append(control);
    fields.append(label);
    values[key] = control;
    inputs.push(control);
    return control;
  }

  /**
   * 业务作用：使用固定枚举选择副作用或互斥范围，切换时丢弃另一种动作的输入和复核。
   * 参数说明：
   * - title：可访问业务名称。
   * - options：页面定义的固定值与说明。
   * - current：当前明确选择。
   * - change：选择变化后更新枚举并重建表单。
   * 返回：有限选择控件，不接受任意动作名。
   */
  function select(title, options, current, change) {
    const label = element("label", title);
    const control = element("select");
    control.setAttribute("aria-label", title);
    for (const [value, title] of options) {
      const option = element("option", title);
      option.value = value;
      control.append(option);
    }
    control.value = current;
    control.addEventListener("change", () => {
      change(control.value);
      render();
    });
    label.append(control);
    fields.append(label);
    inputs.push(control);
    return control;
  }

  /**
   * 业务作用：按固定原生动作展示全部业务字段，不把隐藏字段或上一种范围带入候选。
   * 参数说明: 无。
   * 返回：只有当前动作的完整类型化输入和明确作用范围。
   */
  function render() {
    edited();
    values = {};
    inputs = [];
    fields.replaceChildren();
    switch (choose.value) {
      case "blacklist":
        note.textContent =
          "写入当前动态事实源并刷新本机黑名单。封禁会同时向本机该IP的长连接发出关闭信号；解封包含本机豁免窗口，不证明其它节点已恢复。";
        select(
          "IP操作",
          [
            ["apply", "封禁IP"],
            ["revoke", "解封IP"],
          ],
          operation,
          (value) => {
            operation = value;
          },
        );
        field("ip", "精确IP（支持IPv4和IPv6）", "", 64);
        if (operation === "apply") {
          field("ttl", "IP封禁 TTL（毫秒；留空为永久）", "60000", 20);
        }
        break;
      case "interface_disable":
        note.textContent =
          "规则按原生Glob与HTTP方法匹配。发布前通过同一规则编译器；成功表示写入事实源并完成本机刷新，不是配置文件发布或集群确认。";
        select(
          "接口规则操作",
          [
            ["apply", "发布禁用规则"],
            ["revoke", "撤销禁用规则"],
          ],
          operation,
          (value) => {
            operation = value;
          },
        );
        field("id", "动态规则精确id", "", 1024);
        if (operation === "apply") {
          field("path", "接口路径Glob", "", 2048);
          field(
            "methods",
            "HTTP方法（每行一个；留空为全部）",
            "GET",
            528,
            true,
          );
          field("status", "固定响应状态（200至599）", "503", 3);
          field("body", "固定UTF-8响应正文", "disabled", 4096, true);
          field("ttl", "接口禁用 TTL（毫秒；留空为永久）", "60000", 20);
        }
        break;
      case "connections":
        note.textContent =
          "只操作本机注册表。按路由名字关闭覆盖本机所有入口上的同名路由；按IP或可信consumer匹配全部协议。关闭不能撤回；安排旧代排空不等于连接已经结束。";
        select(
          "长连接选择器",
          [
            ["route", "路由名字（跨本机入口）"],
            ["ip", "精确IP"],
            ["consumer", "可信consumer"],
            ["stale", "早于配置代并带宽限期"],
          ],
          selector,
          (value) => {
            selector = value;
          },
        );
        if (selector === "route") {
          field("route", "本机路由精确名字");
        } else if (selector === "ip") {
          field("ip", "精确IP（支持IPv4和IPv6）", "", 64);
        } else if (selector === "consumer") {
          field("consumer", "认证后的精确consumer");
        } else {
          field(
            "before",
            "早于配置代（完整十进制）",
            capability?.config_version ?? "",
            20,
          );
          field(
            "grace",
            "排空宽限期（毫秒）",
            capability?.default_grace_ms ?? "0",
            20,
          );
        }
        break;
      case "cache_invalidate":
        note.textContent =
          "精确失效当前proxy和route的原生缓存策略。L1属于接入进程，L2按该策略的实际共享后端执行；返回的是缓存generation，不是配置发布或逐节点确认。";
        field("proxy", "缓存物理入口 proxy");
        field("route", "缓存路由 route");
        break;
      default:
        note.textContent = "当前没有可用的已授权动作。";
    }
    controls();
  }

  /**
   * 业务作用：当前原条件和配置能力共同控制动作，条件不是服务端租约或一次性令牌。
   * 参数说明: 无。
   * 返回：请求进行中、缺少原条件、失权或配置未启用时禁用复核与执行。
   */
  function controls() {
    const busy = controller !== null;
    const current = capability && condition;
    const enabled =
      current &&
      permitted(choose.value) &&
      capability.actions[choose.value]?.enabled === true;
    refresh.disabled = busy;
    choose.disabled = busy || !current;
    for (const input of inputs) {
      input.disabled = busy || !enabled;
    }
    review.disabled = busy || !enabled;
    execute.disabled = busy || !enabled || !prepared;
  }

  /**
   * 业务作用：取消旧响应权威并释放输入、条件和结果，不把取消等待解释成已撤销后台动作。
   * 参数说明：
   * - message：当前需要显式重新读取的固定说明。
   * 返回：当前页面不再持有可执行候选，不自动回读、重发或补偿。
   */
  function clear(message) {
    epoch += 1;
    controller?.abort();
    controller = null;
    capability = condition = prepared = null;
    values = {};
    inputs = [];
    fields.replaceChildren();
    choose.replaceChildren();
    form.hidden = preview.hidden = result.hidden = true;
    frozen.textContent = authority.textContent = note.textContent = "";
    result.replaceChildren();
    status.textContent = message;
    controls();
  }

  /**
   * 业务作用：显式读取当前主体的最小动作能力与原生条件，不枚举或推断其它节点对象。
   * 参数说明: 无。
   * 返回：当前可复核的原条件；重读当前条件不代表此前未知动作没有执行。
   */
  async function load() {
    clear("正在读取接入进程的当前动作条件…");
    if (!alive || document.hidden) {
      return;
    }
    const round = epoch;
    const active = new AbortController();
    controller = active;
    controls();
    try {
      const response = await request("/api/runtime-actions", {
        signal: active.signal,
      });
      if (!alive || round !== epoch || active.signal.aborted) {
        return;
      }
      const value = response.data;
      const tag = response.headers.get("etag");
      if (
        !/^"runtime-[0-9a-f]{64}"$/.test(tag ?? "") ||
        value.schema_version !== 1 ||
        value.cluster_execution !== false ||
        value.max_body_bytes !== 8192 ||
        !["admin", "all-in-one"].includes(value.mode)
      ) {
        throw invalid();
      }
      decimal(value.config_version);
      decimal(value.max_grace_ms, "31536000000");
      decimal(value.default_grace_ms, value.max_grace_ms);
      for (const kind of Object.keys(kinds)) {
        if (
          typeof value.actions?.[kind]?.allowed !== "boolean" ||
          typeof value.actions[kind].enabled !== "boolean" ||
          (value.actions[kind].enabled && !value.actions[kind].allowed)
        ) {
          throw invalid();
        }
      }
      capability = value;
      condition = tag;
      for (const [kind, entry] of Object.entries(kinds)) {
        if (!permitted(kind) || !value.actions[kind].allowed) {
          continue;
        }
        const option = element(
          "option",
          entry[0] + (value.actions[kind].enabled ? "" : "（当前未启用）"),
        );
        option.value = kind;
        option.disabled = !value.actions[kind].enabled;
        choose.append(option);
      }
      const available = Object.keys(kinds).find(
        (kind) => permitted(kind) && value.actions[kind].enabled,
      );
      choose.value = available ?? "";
      operation = "apply";
      selector = "route";
      authority.textContent =
        "当前部署：" +
        value.mode +
        " · 配置代 " +
        value.config_version +
        "。执行时仍复验原实例、配置条件与当前权限。";
      form.hidden = false;
      render();
      status.textContent = uncertain
        ? "已重读当前权限与条件。此前动作结果仍未确定，请先核对实际事实或审计，再决定是否提交其它动作。"
        : "已读取当前条件，请填写并复核完整动作。";
    } catch (error) {
      if (alive && round === epoch) {
        clear(error.message);
      }
    } finally {
      if (controller === active) {
        controller = null;
      }
      controls();
    }
  }

  /**
   * 业务作用：从当前可见控件建立一次完整动作，不把隐藏字段或浮点配置代送入执行入口。
   * 参数说明: 无。
   * 返回：当前固定JSON合同，越界或范围不完整时拒绝本地复核。
   */
  function candidate() {
    /**
     * 业务作用：从当前可见字段读取精确选择器，不使用其它动作遗留的隐藏值。
     * 参数说明：
     * - key：当前固定字段名。
     * - maximum：对应原生UTF-8预算。
     * 返回：已验证的原样文本。
     */
    const value = (key, maximum = 256) => text(values[key]?.value, maximum);
    /**
     * 业务作用：只把明确留空解释成永久声明，零和非法十进制不能获得永久副作用。
     * 参数说明: 无。
     * 返回：明确的永久null或正u64十进制字符串。
     */
    const ttl = () => {
      const raw = values.ttl.value;
      if (raw === "") {
        return null;
      }
      const result = decimal(raw);
      if (result === "0") {
        throw invalid();
      }
      return result;
    };
    if (choose.value === "blacklist") {
      return {
        kind: "blacklist",

        ip: value("ip", 64),

        blocked: operation === "apply",

        ttl_ms: operation === "apply" ? ttl() : null,
      };
    }
    if (choose.value === "interface_disable") {
      const disabled = operation === "apply";
      let rule = null;
      if (disabled) {
        const methods = values.methods.value
          .split(/\r?\n/)
          .filter((method) => method !== "");
        const status = Number(values.status.value);
        if (
          methods.length > 16 ||
          methods.some(
            (method) => !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$/.test(method),
          ) ||
          !Number.isSafeInteger(status) ||
          status < 200 ||
          status > 599 ||
          new TextEncoder().encode(values.body.value).length > 4096
        ) {
          throw invalid();
        }
        rule = {
          path: value("path", 2048),

          methods,

          status,

          body: values.body.value,

          ttl_ms: ttl(),
        };
      }
      return {
        kind: "interface_disable",

        id: value("id", 1024),

        disabled,

        rule,
      };
    }
    if (choose.value === "connections") {
      let scope;
      if (selector === "stale") {
        scope = {
          by: "stale",

          before: decimal(values.before.value),

          grace_ms: decimal(values.grace.value, capability.max_grace_ms),
        };
      } else if (["route", "ip", "consumer"].includes(selector)) {
        scope = {
          by: selector,

          [selector]: value(selector, selector === "ip" ? 64 : 256),
        };
      } else {
        throw invalid();
      }
      return {
        kind: "connections",

        selector: scope,
      };
    }
    if (choose.value === "cache_invalidate") {
      return {
        kind: "cache_invalidate",

        proxy: value("proxy"),

        route: value("route"),
      };
    }
    throw invalid();
  }

  /**
   * 业务作用：冻结完整用户意图和原条件，复核不会写事实源、关闭连接或失效缓存。
   * 参数说明：
   * - event：用户显式复核表单事件。
   * 返回：固定预览和一次执行按钮；编辑或隐藏撤销本页复核，条件变化仍由执行入口拒绝。
   */
  function prepare(event) {
    event.preventDefault();
    edited();
    if (
      !capability ||
      !condition ||
      controller ||
      !capability.actions[choose.value]?.enabled
    ) {
      return;
    }
    try {
      const action = candidate();
      const body = JSON.stringify(action);
      if (new TextEncoder().encode(body).length > capability.max_body_bytes) {
        throw invalid();
      }
      prepared = {
        kind: choose.value,

        body,

        condition,
      };
      frozen.textContent = JSON.stringify(
        {
          instance_condition: condition,

          config_version: capability.config_version,

          action,
        },
        null,
        2,
      );
      preview.hidden = false;
      status.textContent = uncertain
        ? "动作已复核，尚未执行。此前未知结果仍须独立核对；当前复核不提供补偿或幂等保证。"
        : "完整动作已复核，尚未执行；请核对后显式执行一次。";
    } catch {
      status.textContent =
        "复核未完成：请检查精确名称、规范十进制整数、正文预算和完整范围。";
    }
    controls();
  }

  /**
   * 业务作用：只提交一次冻结原文和原条件，后台任务可能在HTTP取消之后继续完成。
   * 参数说明: 无。
   * 返回：原生固定结果或结果未知说明；任何下一动作均要求显式重读与重新复核，不自动重试。
   */
  async function submit() {
    if (
      !prepared ||
      !capability ||
      controller ||
      !capability.actions[prepared.kind]?.enabled
    ) {
      return;
    }
    const frozenAction = prepared;
    clear("正在提交已复核运行态动作…");
    const round = epoch;
    const active = new AbortController();
    controller = active;
    uncertain = true;
    controls();
    try {
      const response = await request("/api/runtime-actions", {
        method: "POST",

        signal: active.signal,

        headers: {
          "Content-Type": "application/json",

          "If-Match": frozenAction.condition,
        },

        body: frozenAction.body,
      });
      if (!alive || round !== epoch || active.signal.aborted) {
        return;
      }
      const value = response.data;
      if (
        value.ok !== true ||
        value.kind !== frozenAction.kind ||
        value.cluster_execution !== false ||
        !value.result
      ) {
        throw invalid();
      }
      const heading = element("h2", "本次原生动作结果");
      let description;
      if (value.kind === "cache_invalidate") {
        description =
          "原生路由缓存已失效，缓存 generation：" +
          decimal(value.result.generation) +
          "。这不是配置发布或逐节点确认。";
      } else if (
        value.kind === "connections" ||
        (value.kind === "blacklist" && JSON.parse(frozenAction.body).blocked)
      ) {
        const count = decimal(value.result.signals);
        if (typeof value.result.scheduled !== "boolean") {
          throw invalid();
        }
        description = value.result.scheduled
          ? "已安排本机旧代连接排空，安排时匹配 " +
            count +
            " 条；不代表连接已经结束。"
          : "本机首次发出关闭信号 " + count + " 条；不代表对端已经关闭。";
        if (value.kind === "blacklist") {
          description = "IP封禁已写事实源并刷新本机。" + description;
        }
      } else {
        if (value.result.acknowledged !== true) {
          throw invalid();
        }
        description =
          "原生动态事实写入与本机刷新已完成；不证明其它节点已经观察到此变化。";
      }
      result.replaceChildren(heading, element("p", description));
      result.hidden = false;
      uncertain = false;
      status.textContent =
        "本次动作已返回原生结果。再次执行前必须重新读取当前条件并复核。";
    } catch (error) {
      if (alive && round === epoch) {
        if (error.operationMayHaveCompleted === false) {
          uncertain = false;
          clear(
            "原生入口已明确拒绝本次动作，尚未执行。请检查权限、输入与原实例条件，再显式重新读取并复核。",
          );
        } else {
          clear(
            "动作结果尚不确定，可能已写入事实源、发出关闭信号或失效缓存。不会自动重试；请核对实际事实或审计，再显式重新读取。取消页面等待不会撤销后台动作。",
          );
        }
      }
    } finally {
      if (controller === active) {
        controller = null;
      }
      controls();
    }
  }

  /**
   * 业务作用：暂停或隐藏清除全部输入和动作条件，不自动停止或重试已受理的副作用。
   * 参数说明: 无。
   * 返回：恢复可见后仍须显式重读，旧响应不能回填。
   */
  function suspend() {
    clear(
      "页面已暂停，输入、条件和结果已清空。后台已受理动作可能继续完成；恢复后请显式重新读取。",
    );
  }

  /**
   * 业务作用：隐藏页面时撤销本页复核资格，避免用户离开后旧动作仍可直接提交。
   * 参数说明: 无。
   * 返回：隐藏时暂停，可见时保持等待显式操作。
   */
  function visibility() {
    if (document.hidden) {
      suspend();
    }
  }
  refresh.addEventListener("click", () => {
    void load();
  });
  pause.addEventListener("click", suspend);
  choose.addEventListener("change", () => {
    operation = "apply";
    selector = "route";
    render();
  });
  form.addEventListener("submit", prepare);
  execute.addEventListener("click", () => {
    void submit();
  });
  document.addEventListener("visibilitychange", visibility);
  controls();
  void load();

  /**
   * 业务作用：退出或切换页面时清除原条件、响应正文和未提交意图，不保留运维历史。
   * 参数说明: 无。
   * 返回：释放可见性监听和全部显示内容；实际后台任务仍遵守其原生生命周期。
   */
  return function dispose() {
    alive = false;
    clear("");
    document.removeEventListener("visibilitychange", visibility);
    root.replaceChildren();
  };
}
