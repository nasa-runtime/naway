/**
 * 业务作用：显式选择受信外部处理器的可见相位、资源预算和可写权限，不替节点开启未编译能力。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十九项原生声明；秘密引用、未编辑开关与预算保持原值。
 */
export function routeExtProcFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["ext_proc"],
      "Envoy External Processing 双向流",
      [
        ["target", "受信 gRPC 服务：HTTP(S) origin 或 lb://service", "string"],
        ["fail_open", "仅可分类依赖故障时永久绕过本请求后续处理", "boolean"],
        [
          "authorization",
          "服务 Authorization metadata SecretSource（解析后最多16384字节）",
          "string",
        ],
        [
          "request_headers",
          "发送全部原始请求头（含其中的业务凭据）",
          "boolean",
        ],
        ["response_headers", "发送全部原始响应头", "boolean"],
        ["request_body", "请求正文相位：none / buffered / streamed", "string"],
        ["response_body", "响应正文相位：none / buffered / streamed", "string"],
        ["request_trailers", "发送完整请求 trailers", "boolean"],
        ["response_trailers", "发送完整响应 trailers", "boolean"],
        ["message_timeout_ms", "每相位响应期限（1–60000 毫秒）", "number"],
        [
          "total_timeout_ms",
          "整流总期限（不低于每相位，最多900000 毫秒）",
          "number",
        ],
        [
          "max_message_bytes",
          "单条 protobuf payload 上限（256–16777216 字节）",
          "number",
        ],
        [
          "max_total_bytes",
          "双向协议总字节（不低于单条，最多134217728，含 envelope）",
          "number",
        ],
        [
          "max_body_bytes",
          "每方向正文上限（1–67108864 字节，且不超过协议总量）",
          "number",
        ],
        ["max_in_flight", "本路由同时处理流上限（1–65536）", "number"],
        [
          "failure_threshold",
          "打开 circuit 的连续依赖失败数（1–10000）",
          "number",
        ],
        ["reset_timeout_ms", "circuit 冷却期限（1–60000 毫秒）", "number"],
        [
          "mutation_headers",
          "允许变更的普通头名单（每行一项，最多128项）",
          "lines",
        ],
        [
          "writable_metadata_namespaces",
          "可写 metadata namespace（每行一项，最多32项）",
          "lines",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：逐项维护处理器的头部与本请求 metadata 写权限，不随展示扩大授权名单。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的两个字符串列表，修改仅作用于选定的原始位置。
 */
export function routeExtProcDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["ext_proc", "mutation_headers"],
      title: "External Processing 可写头名单",
      type: "string",
    },
    {
      path: ["ext_proc", "writable_metadata_namespaces"],
      title: "External Processing 可写 metadata namespace",
      type: "string",
    },
  ];
}
