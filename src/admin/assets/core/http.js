let authorization = "";
let generation = 0;
const active = new Set();

/**
 * 业务作用：切换或撤销页面内存凭据，同时撤去所有旧请求的显示权威。
 * 参数说明：
 * - `value`：已在本页构造的Authorization值，退出时为空。
 * 返回：旧请求被取消，凭据不写入浏览器持久存储。
 */
export function authenticate(value) {
  generation += 1;
  for (const controller of active) {
    controller.abort();
  }
  active.clear();
  authorization = value;
}

/**
 * 业务作用：限制管理凭据仅在HTTPS或本机回环连接上传递。
 * 参数说明: 无。
 * 返回：当前页面是否具备安全的管理传输条件。
 */
export function secureOrigin() {
  return (
    location.protocol === "https:" ||
    ["127.0.0.1", "localhost", "[::1]"].includes(location.hostname)
  );
}

/**
 * 业务作用：统一执行同源、有期限和响应容量上限的管理请求。
 * 参数说明：
 * - `path`：由页面功能确定的管理API路径。
 * - `options`：动作参数和当前视图取消信号。
 * 返回：已解析JSON与状态/响应头；认证变化、超限、超时或拒绝时不发布旧数据。
 */
export async function request(path, options = {}) {
  const { responseType = "json", ...fetchOptions } = options;
  if (!["json", "text"].includes(responseType)) {
    throw new Error("未知管理响应格式。");
  }
  const target = new URL(path, location.origin);
  if (
    target.origin !== location.origin ||
    !/^\/(api|admin)\//.test(target.pathname) ||
    !secureOrigin()
  ) {
    throw new Error("管理接口需要同源 HTTPS，本机回环地址可使用 HTTP。");
  }
  const epoch = generation;
  const controller = new AbortController();
  /**
   * 业务作用：把视图退出或绝对期限传递到网络读取，禁止无限等待。
   * 参数说明: 无。
   * 返回：当前请求被取消，已有响应片段不再发布。
   */
  const cancel = () => {
    controller.abort();
  };
  if (options.signal?.aborted) {
    throw new DOMException("已取消", "AbortError");
  }
  options.signal?.addEventListener("abort", cancel, { once: true });
  active.add(controller);
  const timer = setTimeout(cancel, 5000);
  const headers = new Headers(options.headers);
  if (authorization) {
    headers.set("Authorization", authorization);
  }
  try {
    const response = await fetch(target, {
      ...fetchOptions,

      headers,

      signal: controller.signal,

      credentials: "omit",

      redirect: "error",

      cache: "no-store",

      referrerPolicy: "no-referrer",
    });
    if (generation !== epoch || controller.signal.aborted) {
      controller.abort();
      throw new DOMException("会话或页面已切换", "AbortError");
    }
    if (response.status === 401) {
      authenticate("");
      window.dispatchEvent(new Event("naway:unauthorized"));
      throw new Error("认证已失效，请重新登录。");
    }
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error("管理接口未返回响应体。");
    }
    const decoder = new TextDecoder("utf-8", { fatal: true });
    const chunks = [];
    let length = 0;
    const capacity =
      target.pathname === "/api/cluster/catalog" ||
      target.pathname === "/api/cluster/consumers" ||
      /^\/api\/workspaces\/[^/]+\/cluster\/consumers$/.test(target.pathname) ||
      target.pathname === "/api/operations/proposals" ||
      /^\/api\/operations\/proposals\/[0-9a-f]{32}\/preview$/.test(
        target.pathname,
      ) ||
      target.pathname === "/api/operations/proposals/draft"
        ? 4 * 1024 * 1024
        : 1024 * 1024;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }
        length += value.byteLength;
        if (length > capacity) {
          throw new Error(`管理响应超过 ${capacity / 1024 / 1024} MiB 上限。`);
        }
        chunks.push(decoder.decode(value, { stream: true }));
      }
      chunks.push(decoder.decode());
    } finally {
      await reader.cancel().catch(() => {});
    }
    if (generation !== epoch || controller.signal.aborted) {
      throw new DOMException("会话或页面已切换", "AbortError");
    }
    if (!response.ok) {
      let code = "";
      try {
        const declared = JSON.parse(chunks.join("")).error;
        if (
          [
            "invalid_proposal",
            "proposal_conflict",
            "proposal_capacity",
            "admission_epoch_expired",
            "authority_unavailable",
            "outcome_unknown",
            "not_found",
            "forbidden",
          ].includes(declared)
        ) {
          code = declared;
        }
      } catch {
        // 错误正文不可信；只交付固定错误身份，不把代理HTML或秘密带入页面。
      }
      const failure = new Error(
        response.status === 403
          ? "当前主体没有此项权限。"
          : code === "outcome_unknown"
            ? "提交结果尚不确定，请保持原身份回读。"
            : code === "admission_epoch_expired"
              ? "原请求受理窗口已结束，不能自动换代重新提交。"
              : `管理请求未完成（HTTP ${response.status}）。`,
      );
      failure.status = response.status;
      failure.code = code;
      throw failure;
    }
    const text = chunks.join("");
    const data = responseType === "text" ? text : JSON.parse(text);
    return {
      data,

      status: response.status,

      headers: response.headers,
    };
  } finally {
    clearTimeout(timer);
    active.delete(controller);
    options.signal?.removeEventListener("abort", cancel);
  }
}
