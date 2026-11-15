const sensitive =
  /auth|cookie|secret|token|password|credential|private|key|certificate|session/i;
const bodyStates = new Set([
  "not_requested",
  "unsupported",
  "too_large",
  "malformed",
  "incomplete",
  "complete",
]);

/**
 * 业务作用：拒绝不完整的诊断合同，避免把未知范围或原始正文当成已授权结果。
 * 参数说明: 无。
 * 返回：固定错误，不携带服务端或采集原文。
 */
export function invalid() {
  return new Error("诊断响应不完整或超出脱敏合同，请显式重新读取。");
}

/**
 * 业务作用：让诊断预算保持精确整数，页面不能舍入或截断授权范围。
 * 参数说明：
 * - value：输入或响应中的数值。
 * - minimum：原生下界。
 * - maximum：原生上界。
 * 返回：合法整数；越界时拒绝整份请求或响应。
 */
export function bounded(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw invalid();
  }
  return value;
}

/**
 * 业务作用：保留精确的路由和可信消费者选择器，不展开通配符或改写名称。
 * 参数说明：
 * - value：用户输入或冻结范围中的名称。
 * 返回：不含控制字符且满足UTF-8预算的原值。
 */
function selector(value) {
  if (
    typeof value !== "string" ||
    !value.length ||
    new TextEncoder().encode(value).length > 128 ||
    /[\p{Cc}]/u.test(value)
  ) {
    throw invalid();
  }
  return value;
}

/**
 * 业务作用：正文只允许明确且非敏感的顶层字段存在性，禁止重复或扩大字段集合。
 * 参数说明：
 * - values：一个方向的字段数组。
 * 返回：最多十六个原始字段名的独立副本。
 */
export function fields(values) {
  if (
    !Array.isArray(values) ||
    values.length > 16 ||
    new Set(values).size !== values.length ||
    values.some(
      (value) =>
        typeof value !== "string" ||
        !/^[A-Za-z0-9_]{1,64}$/.test(value) ||
        sensitive.test(value),
    )
  ) {
    throw invalid();
  }
  return [...values];
}

/**
 * 业务作用：构造诊断的完整有限申请，所有显式正文授权均进入冻结请求。
 * 参数说明：
 * - value：表单或原生响应提供的申请字段。
 * 返回：只含当前原生合同字段的申请；任何预算或正文策略不一致均拒绝。
 */
export function proposal(value) {
  if (
    !value ||
    Object.keys(value).some(
      (key) =>
        ![
          "proxy",
          "route",
          "consumer",
          "ttl_seconds",
          "max_samples",
          "max_record_bytes",
          "max_total_bytes",
          "max_downloads",
          "body",
        ].includes(key),
    )
  ) {
    throw invalid();
  }
  const result = {
    proxy: selector(value?.proxy),

    route: selector(value?.route),

    consumer: value.consumer === null ? null : selector(value.consumer),

    ttl_seconds: bounded(value.ttl_seconds, 1, 300),

    max_samples: bounded(value.max_samples, 1, 128),

    max_record_bytes: bounded(value.max_record_bytes, 256, 4096),

    max_total_bytes: bounded(
      value.max_total_bytes,
      value.max_record_bytes,
      262144,
    ),

    max_downloads: bounded(value.max_downloads, 1, 3),

    body: null,
  };
  if (value.body !== null && value.body !== undefined) {
    if (
      value.body.mask !== "redact" ||
      Object.keys(value.body).some(
        (key) =>
          ![
            "mask",
            "max_inspect_bytes",
            "request_fields",
            "response_fields",
          ].includes(key),
      )
    ) {
      throw invalid();
    }
    result.body = {
      mask: "redact",

      max_inspect_bytes: bounded(value.body.max_inspect_bytes, 1, 65536),

      request_fields: fields(value.body.request_fields),

      response_fields: fields(value.body.response_fields),
    };
    if (
      !result.body.request_fields.length &&
      !result.body.response_fields.length
    ) {
      throw invalid();
    }
  }
  return result;
}

/**
 * 业务作用：验证申请身份和冻结范围，剩余时间必须扣除本次网络与审计等待。
 * 参数说明：
 * - value：原生低敏元信息。
 * - started：本次请求发出前的单调时刻。
 * 返回：有限元信息及保守到期时刻；配置代只供显示，不作为浮点动作身份。
 */
export function metadata(value, started) {
  if (
    !/^[A-Za-z0-9-]{1,64}$/.test(value?.id ?? "") ||
    !/^[0-9a-f]{64}$/.test(value.digest ?? "") ||
    !["pending", "active"].includes(value.state) ||
    typeof value.initiator !== "string" ||
    !value.initiator.length ||
    !(value.approver === null || typeof value.approver === "string") ||
    (value.state === "pending") !== (value.approver === null)
  ) {
    throw invalid();
  }
  const request = proposal(value.request);
  let owner = null;
  if (value.owner !== null) {
    if (
      !value.owner ||
      Object.keys(value.owner).some(
        (key) => !["workspace", "tenant", "environment"].includes(key),
      )
    ) {
      throw invalid();
    }
    owner = {
      workspace: selector(value.owner.workspace),

      tenant: selector(value.owner.tenant),

      environment: selector(value.owner.environment),
    };
  }
  const remaining = bounded(
    value.remaining_ms,
    0,
    value.state === "pending" ? 60000 : request.ttl_seconds * 1000,
  );
  return {
    id: value.id,

    digest: value.digest,

    generation: value.generation,

    owner,

    initiator: value.initiator,

    approver: value.approver,

    state: value.state,

    request,

    samples: bounded(value.samples, 0, request.max_samples),

    bytes: bounded(value.bytes, 0, request.max_total_bytes),

    downloads: bounded(value.downloads, 0, request.max_downloads),

    deadline: started + remaining,
  };
}

/**
 * 业务作用：交付前复验正文状态和每个遮蔽值，未知采集字段不能进入页面。
 * 参数说明：
 * - value：一个方向的原生正文摘要。
 * - allowed：冻结申请明确授权的字段集合。
 * 返回：仅固定状态及原样的REDACTED标记；不接受任何原始字段值。
 */
function masked(value, allowed) {
  if (
    !value ||
    !bodyStates.has(value.state) ||
    Object.keys(value).some((key) => !["state", "fields"].includes(key)) ||
    (value.fields !== undefined &&
      (!value.fields ||
        typeof value.fields !== "object" ||
        Array.isArray(value.fields))) ||
    (value.state !== "not_requested" && value.fields === undefined)
  ) {
    throw invalid();
  }
  const entries = Object.entries(value.fields ?? {});
  if (
    (value.state !== "complete" && entries.length > 0) ||
    (value.state === "complete" && !allowed.length) ||
    (value.state === "not_requested" && allowed.length > 0) ||
    entries.length > allowed.length ||
    entries.some(
      ([key, text]) => !allowed.includes(key) || text !== "[REDACTED]",
    )
  ) {
    throw invalid();
  }
  return {
    state: value.state,

    fields: Object.fromEntries(entries),
  };
}

/**
 * 业务作用：只交付固定头摘要和已授权的遮蔽正文，任何额外采集字段均整批拒绝。
 * 参数说明：
 * - values：一次显式下载的样本集合。
 * - request：对应会话的完整冻结申请。
 * 返回：可安全显示的有限样本，原始正文从未进入渲染器。
 */
export function samples(values, request) {
  if (!Array.isArray(values) || values.length > request.max_samples) {
    throw invalid();
  }
  return values.map((value) => {
    const keys = ["method", "status", "elapsed_us"];
    if (request.body) {
      keys.push("request_body", "response_body");
    }
    if (
      !value ||
      Object.keys(value).some((key) => !keys.includes(key)) ||
      typeof value.method !== "string" ||
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$/.test(value.method) ||
      !Number.isInteger(value.elapsed_us) ||
      value.elapsed_us < 0
    ) {
      throw invalid();
    }
    const result = {
      method: value.method,

      status: bounded(value.status, 100, 599),

      elapsed_us: Number.isSafeInteger(value.elapsed_us)
        ? value.elapsed_us
        : "超出精确显示范围",
    };
    if (request.body) {
      result.request_body = masked(
        value.request_body,
        request.body.request_fields,
      );
      result.response_body = masked(
        value.response_body,
        request.body.response_fields,
      );
    }
    return result;
  });
}
