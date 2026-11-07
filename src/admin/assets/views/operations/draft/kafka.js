const kafkaBudgetFields = [
  ["enabled", "启用 Kafka 协议治理", "boolean"],
  ["max_connections", "每监听器连接上限（含 TLS 阶段）", "number"],
  ["max_frame_bytes", "完整请求或响应帧上限（字节，含长度前缀）", "number"],
  ["frame_timeout_ms", "从长度前缀首字节到完整帧的期限（毫秒）", "number"],
  ["max_buffered_bytes", "监听器双向帧缓冲的总预留预算（字节）", "number"],
  ["max_inflight_requests", "每连接未收到响应的 correlation id 上限", "number"],
  ["max_client_id_bytes", "请求 client id 的 UTF-8 字节上限", "number"],
  ["max_topic_bytes", "topic 名的 UTF-8 字节上限", "number"],
  ["max_group_bytes", "consumer group id 的 UTF-8 字节上限", "number"],
  ["max_array_items", "任一协议数组的元素上限", "number"],
];

const kafkaAccessFields = [
  [
    "client_id_allow",
    "允许的 client id（每行一项，空列表不额外限制）",
    "lines",
  ],
  ["topic_allow", "允许的精确 topic（每行一项，空列表拒绝全部）", "lines"],
  ["group_allow", "允许的精确 group（每行一项，空列表拒绝全部）", "lines"],
  [
    "sasl_mechanism_allow",
    "允许的 SASL mechanism（每行一项，空列表拒绝握手）",
    "lines",
  ],
];

export const kafkaBrokerFields = [
  ["from_host", "broker 响应中的原主机", "string"],
  ["from_port", "broker 响应中的原端口", "number"],
  ["to_host", "客户端应连接的代理主机", "string"],
  ["to_port", "客户端应连接的代理端口", "number"],
];

/**
 * 业务作用：区分 Kafka 协议预算、精确访问名单与显式地址改写，不扩大支持的 API 范围。
 * 参数说明：
 * - `kind`：所属候选对象类型。
 * 返回：仅流监听器的 Kafka 子字段，不隐式启用协议或生成 broker 映射。
 */
export function kafkaFieldGroups(kind) {
  if (kind !== "stream") {
    return [];
  }
  return [
    [["kafka"], "Kafka 连接与协议预算", kafkaBudgetFields],
    [["kafka"], "Kafka 客户端与资源授权", kafkaAccessFields],
    [
      ["kafka"],
      "Kafka broker 地址改写",
      [["broker_rewrite", "broker 地址改写列表（完整声明）", "json"]],
    ],
  ];
}

/**
 * 业务作用：按原候选位置编辑 Kafka 白名单及 broker 映射，保留未选择的列表元素。
 * 参数说明：
 * - `kind`：所属候选对象类型。
 * 返回：流监听器的四个字符串列表和一个类型化地址列表；其它对象无此入口。
 */
export function kafkaDraftLists(kind) {
  if (kind !== "stream") {
    return [];
  }
  return [
    ...kafkaAccessFields.map(([key, title]) => ({
      path: ["kafka", key],
      title,
      type: "string",
    })),
    {
      path: ["kafka", "broker_rewrite"],
      title: "Kafka broker 地址映射",
      type: "kafka_broker",
    },
  ];
}
