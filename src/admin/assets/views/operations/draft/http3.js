const protocolFields = [
  ["enabled", "启用 HTTP/3", "boolean"],
  ["capabilities", "协议扩展（每行一项）", "lines"],
  ["advertise_alt_svc", "在 HTTPS 响应中发布 Alt-Svc", "boolean"],
  ["alt_svc_max_age_seconds", "Alt-Svc 广告缓存时间（秒）", "number"],
];

const connectionFields = [
  ["max_connections", "入口物理连接上限", "number"],
  ["max_connections_per_ip", "每个来源 IP 的物理连接上限", "number"],
  ["max_pending_handshakes", "未决握手数量上限", "number"],
  ["max_pending_handshake_bytes", "每个未决握手缓冲字节上限", "number"],
  ["max_idle_timeout_ms", "连接空闲期限（毫秒）", "number"],
];

const streamFields = [
  ["max_bidi_streams_per_connection", "每连接双向流上限", "number"],
  [
    "max_uni_streams_per_connection",
    "每连接单向流上限（含 control/QPACK）",
    "number",
  ],
  ["max_request_header_bytes", "解码后请求头字节上限", "number"],
  ["max_stream_buffer_bytes", "每请求流缓冲字节上限", "number"],
  ["max_connect_udp_sessions", "每连接 CONNECT-UDP 会话上限", "number"],
  ["max_datagram_queue", "每会话下行 DATAGRAM 队列数量上限", "number"],
  ["max_datagram_bytes", "每个 UDP payload 字节上限", "number"],
];

const retryFields = [
  ["retry", "地址验证 Retry：off / auto / always", "string"],
  ["retry_token_lifetime_seconds", "Retry token 最长有效期（秒）", "number"],
  [
    "retry_token_rotation_seconds",
    "Retry token 认证主密钥轮换周期（秒）",
    "number",
  ],
];

const earlyFields = [
  ["zero_rtt", "在 TLS 层接受 0-RTT", "boolean"],
  ["multi_node", "多节点部署", "boolean"],
  ["early_data_shared_replay_cache", "具备共享早期数据重放保护", "boolean"],
  [
    "early_data_session_rotation_seconds",
    "TLS 恢复代最长轮换周期（秒）",
    "number",
  ],
];

/**
 * 业务作用：为 HTTP 入口提供协议、资源和早期数据的独立声明，保留各预算的真实作用范围。
 * 参数说明：
 * - `kind`：当前候选的配置对象类型。
 * 返回：完整 HTTP/3 字段分组；不自动启用扩展、授权路由或放宽目标节点的能力校验。
 */
export function http3FieldGroups(kind) {
  if (kind !== "proxy") {
    return [];
  }
  const prefix = ["http3"];
  return [
    [prefix, "HTTP/3 协议与广告", protocolFields],
    [prefix, "QUIC 连接与握手预算", connectionFields],
    [prefix, "HTTP/3 流与 DATAGRAM 预算", streamFields],
    [prefix, "QUIC Retry 地址验证", retryFields],
    [prefix, "HTTP/3 早期数据", earlyFields],
  ];
}
