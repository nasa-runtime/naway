const mqttBudgetFields = [
  ["enabled", "启用 MQTT 协议治理", "boolean"],
  ["max_connections", "每监听器连接上限（含 TLS 与 CONNECT 预读）", "number"],
  ["max_packet_bytes", "单个完整 MQTT 包的字节上限", "number"],
  ["packet_timeout_ms", "从首字节到完整包的期限（毫秒，不计纯空闲）", "number"],
  ["max_buffered_bytes", "监听器双向包缓冲的总预留预算（字节）", "number"],
  ["max_topic_bytes", "Topic Name / Filter 的 UTF-8 字节上限", "number"],
  ["max_subscriptions", "每连接已生效与待确认的去重订阅上限", "number"],
  ["max_inflight_messages", "每连接双向在途 QoS 与控制包上限", "number"],
];

const mqttAccessFields = [
  [
    "client_id_allow",
    "允许的 client id（每行一项，空列表不额外限制）",
    "lines",
  ],
  [
    "publish_topic_allow",
    "允许发布的 Topic Filter（每行一项，空列表拒绝全部）",
    "lines",
  ],
  [
    "subscribe_topic_allow",
    "允许订阅的 Topic Filter 边界（每行一项，空列表拒绝全部）",
    "lines",
  ],
];

/**
 * 业务作用：提供流监听器的 MQTT 资源与访问声明，区分空白名单的不同授权语义。
 * 参数说明：
 * - `kind`：所属候选对象类型。
 * 返回：仅流监听器拥有的精确子字段，不隐式启用协议、预读或授予 topic 权限。
 */
export function mqttFieldGroups(kind) {
  if (kind !== "stream") {
    return [];
  }
  return [
    [["mqtt"], "MQTT 连接与协议预算", mqttBudgetFields],
    [["mqtt"], "MQTT 客户端与 Topic 授权", mqttAccessFields],
  ];
}

/**
 * 业务作用：按原候选顺序编辑 MQTT 白名单的一项声明，避免覆盖其它访问规则。
 * 参数说明：
 * - `kind`：所属候选对象类型。
 * 返回：流监听器的三个字符串列表；其它对象不提供 MQTT 列表入口。
 */
export function mqttDraftLists(kind) {
  if (kind !== "stream") {
    return [];
  }
  return mqttAccessFields.map(([key, title]) => ({
    path: ["mqtt", key],
    title,
    type: "string",
  }));
}
