export const externalPluginFields = [
  ["id", "插件稳定 id（唯一，1–128 字节ASCII字母、数字、_、- 或 .）", "string"],
  ["target", "固定服务 origin：HTTP(S) 或 lb://service", "string"],
  ["path", "服务绝对路径（1–2048 字节，无 query）", "string"],
  ["phase", "执行相位：request_headers / response_headers", "string"],
  ["timeout_ms", "单次调用总期限（1–60000 毫秒，含响应正文）", "number"],
  ["fail_open", "依赖失败时丢弃本插件结果后继续", "boolean"],
  ["authorization", "完整服务 Authorization 值 SecretSource", "string"],
  ["include_request_headers", "可见请求头名单（每行一项，最多32项）", "lines"],
  [
    "include_response_headers",
    "可见响应头名单（仅响应相位，每行一项，最多32项）",
    "lines",
  ],
  [
    "mutation_headers",
    "当前相位允许设置或移除的头名单（每行一项，最多32项）",
    "lines",
  ],
  [
    "max_header_value_bytes",
    "单个输入或输出头值上限（1–65536 UTF-8 字节）",
    "number",
  ],
  ["max_input_bytes", "完整编码输入上限（256–1048576 字节）", "number"],
  ["max_response_bytes", "处理器响应上限（16–1048576 字节）", "number"],
  [
    "max_local_response_body_bytes",
    "本地响应正文上限（1–1048576 UTF-8 字节）",
    "number",
  ],
];

/**
 * 业务作用：按原始位置维护外部头部插件链，不把不同执行相位合并或隐式授予头部权限。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供类型化插件列表；原有 id 在字段编辑时保持，新增或替换须显式填写。
 */
export function routeExternalPluginDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["external_plugins"],
      title: "外部 HTTP 头部插件链",
      type: "external_plugin",
    },
  ];
}
