export const scriptPluginFields = [
  ["id", "脚本稳定 id（1–128字节，仅字母、数字、-、_、.）", "string"],
  [
    "source_file",
    "配置根内的 UTF-8 Lua 文件（路径1–4096字节，源码最多64KiB）",
    "string",
  ],
  [
    "phase",
    "相位：request_headers / request_body / request_body_stream / response_headers / response_body / response_body_stream",
    "string",
  ],
  [
    "failure_mode",
    "必须显式声明 closed / open；open 只跳过解释器依赖不可用",
    "string",
  ],
  ["circuit", "必须显式声明的熔断阈值与保护期（完整 JSON）", "json"],
  ["include_headers", "可读普通头的完整名单（每行一项，最多32项）", "lines"],
  [
    "mutation_headers",
    "可写普通头的完整名单（每行一项，最多32项；body 相位须为空）",
    "lines",
  ],
  ["max_memory_bytes", "单调用内存上限（262144–33554432 字节）", "number"],
  ["max_instructions", "单调用 Lua 指令上限（1000–100000000）", "number"],
  ["max_allocations", "单调用累计分配与扩容次数上限（100–1000000）", "number"],
  ["max_cpu_ms", "线程 CPU 上限（1–1000毫秒，且不超过 timeout_ms）", "number"],
  [
    "timeout_ms",
    "含排队、初始化、工厂和回调的墙钟期限（1–1000毫秒）",
    "number",
  ],
  [
    "max_header_bytes",
    "输入及最终修改后 head 上限（256–65536 字节）",
    "number",
  ],
  ["max_mutations", "单调用头部变更上限（1–128）", "number"],
  [
    "max_body_bytes",
    "body 相位必填：聚合1–16777216字节，逐帧1–1048576字节；head 相位须移除",
    "number",
  ],
];

/**
 * 业务作用：按原始位置维护显式 Lua 脚本链，使字段修改不改变已有脚本身份和其它元素。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供类型化脚本列表，不自动开启 lua-scripts 或补入执行预算。
 */
export function routeScriptDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["script_plugins"],
      title: "有界 Lua 脚本链",
      type: "script_plugin",
    },
  ];
}

/**
 * 业务作用：独立修改熔断声明而保留其它原始约束，避免通过展示重建完整 JSON。
 * 参数说明：
 * - `kind`：当前脚本编辑类别。
 * 返回：仅 Lua 脚本提供两项熔断字段；声明变更不表示清空运行中的失败事实。
 */
export function scriptCircuitFieldGroups(kind) {
  if (!["script_plugin", "script_plugin_new"].includes(kind)) {
    return [];
  }
  return [
    [
      ["circuit"],
      "Lua 脚本熔断保护",
      [
        ["failure_threshold", "进入保护态的连续失败阈值（1–100）", "number"],
        ["open_ms", "保留原始失败原因的保护期（10–60000毫秒）", "number"],
      ],
    ],
  ];
}
