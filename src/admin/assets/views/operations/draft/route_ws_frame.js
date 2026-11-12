export const wsMessagePluginFields = [
  [
    "type",
    "消息插件类型：acl / json_schema / redact / rate_limit / external",
    "string",
  ],
  ["consumers", "ACL 可信消费者名单（每行一项，最多128项）", "lines"],
  ["opcodes", "ACL 消息类别（text / binary，每行一项）", "lines"],
  ["schema", "完整消息 JSON Schema（不读取远程或本地引用）", "json"],
  ["pointers", "Redact JSON Pointer 名单（每行一项）", "lines"],
  ["messages", "每连接每方向窗口消息数（1–1000000）", "number"],
  ["window_ms", "消息计数窗口（1–3600000毫秒）", "number"],
  [
    "endpoint",
    "固定外呼 HTTP(S) URL（不含 query、fragment 或 userinfo）",
    "string",
  ],
  ["authorization", "完整 Authorization 值 SecretSource（不求值）", "string"],
  ["ca_certificate", "外呼 HTTPS CA SecretSource（不求值）", "string"],
  ["fail_open", "仅外呼依赖故障时保留原消息继续", "boolean"],
  ["allow_rewrite", "明确允许外呼 replace 完整消息", "boolean"],
  ["include_consumer", "向外呼附带冻结的可信消费者身份", "boolean"],
];

/**
 * 业务作用：显式维护双向 WebSocket 帧与消息预算，保持透明模式和内容处理权限的声明边界。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十一项原生声明；未编辑的字段、插件顺序和引用保持原值。
 */
export function routeWsFrameFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["ws_frame"],
      "WebSocket 帧与双向消息治理",
      [
        [
          "max_frame_bytes",
          "单帧载荷上限（大于0，不得大于消息上限）",
          "number",
        ],
        ["max_message_bytes", "完整消息载荷上限（大于0）", "number"],
        ["max_fragments", "每条消息的分片数上限（大于0）", "number"],
        [
          "max_plugin_payload_bytes",
          "完整插件输入/输出上限（1–1048576字节）",
          "number",
        ],
        ["plugin_timeout_ms", "单插件执行期限（1–60000毫秒）", "number"],
        ["max_decompress_ratio", "最大解压比（大于0）", "number"],
        [
          "permessage_deflate",
          "明确开放每消息独立的 permessage-deflate",
          "boolean",
        ],
        [
          "message_timeout_ms",
          "从消息首帧至交付完成的总期限（1–60000毫秒）",
          "number",
        ],
        [
          "on_violation",
          "违规动作：drop / policy_close / upstream_close",
          "string",
        ],
        [
          "client_plugins",
          "完整 client→server 消息链（最多16步，按顺序执行）",
          "json",
        ],
        [
          "server_plugins",
          "完整 server→client 消息链（最多16步，按顺序执行）",
          "json",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：按原始位置维护双向消息插件，不把控制帧或另一方向纳入本次编辑。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供两个类型化有序列表；新增或替换须明确选择插件类型。
 */
export function routeWsFrameDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["ws_frame", "client_plugins"],
      title: "WebSocket 客户端消息链",
      type: "ws_message_plugin",
    },
    {
      path: ["ws_frame", "server_plugins"],
      title: "WebSocket 服务端消息链",
      type: "ws_message_plugin",
    },
  ];
}
