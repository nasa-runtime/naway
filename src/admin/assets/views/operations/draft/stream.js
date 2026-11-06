const prereadFields = [
  ["ssl_preread", "预读 TLS ClientHello 以选择 SNI 路由", "boolean"],
  ["mqtt_connect", "预读 MQTT CONNECT 的 client id", "boolean"],
  ["timeout_ms", "首段协议预读期限（毫秒）", "number"],
  ["max_bytes", "协议预读字节上限", "number"],
];

const udpFields = [
  ["idle_timeout_ms", "双向无数据后的会话回收期限（毫秒）", "number"],
  ["max_sessions", "每个监听器客户端会话上限", "number"],
  ["queue_capacity", "每会话下行报文队列容量", "number"],
  ["max_datagram_bytes", "单个报文接收字节上限", "number"],
];

const upstreamProxyFields = [
  ["enabled", "向上游发送 PROXY protocol 前导", "boolean"],
  ["version", "发送版本：v1 / v2", "string"],
];

/**
 * 业务作用：为流监听器区分首段预读、UDP 会话预算和上游来源前导，保持各传输的配置边界。
 * 参数说明：
 * - `kind`：所属候选对象类型。
 * 返回：流监听器的精确子字段；不会选择协议或替调用者改写路由。
 */
export function streamTransportFieldGroups(kind) {
  if (kind !== "stream") {
    return [];
  }
  return [
    [["preread"], "流协议预读", prereadFields],
    [["udp"], "UDP 会话与报文预算", udpFields],
    [["proxy_protocol_to_upstream"], "发往上游的来源前导", upstreamProxyFields],
  ];
}
