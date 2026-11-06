const downstreamFields = [
  ["max_connections", "入口共享物理连接上限（0 不限制）", "number"],
  ["max_headers", "HTTP/1 请求头数量上限", "number"],
  ["max_header_bytes", "H1 读取缓冲 / H2 头列表近似字节上限", "number"],
  ["max_body_bytes", "请求正文上限（字节，0 不限制）", "number"],
  ["max_concurrent_streams", "HTTP/2 每连接并发流上限", "number"],
  ["h2_initial_stream_window_bytes", "HTTP/2 流初始接收窗口（字节）", "number"],
  [
    "h2_initial_connection_window_bytes",
    "HTTP/2 连接初始接收窗口（字节）",
    "number",
  ],
  ["max_path_bytes", "路由与权限检查的路径字节上限（0 不限制）", "number"],
  ["max_path_segments", "路径段数上限（0 不限制）", "number"],
];

const upstreamFields = [
  ["upstream_pending_limit", "每上游实例在途请求上限（0 不限制）", "number"],
  ["pool_max_per_upstream", "每上游身份空闲连接上限（0 不保留）", "number"],
  [
    "h2_connection_shards_per_upstream",
    "每个 H2/H2C 上游的连接池分片数",
    "number",
  ],
  [
    "pool_max_connections_per_upstream",
    "每上游身份物理连接上限（0 不限制）",
    "number",
  ],
  ["keepalive_requests", "每代连接池请求数上限（0 不按次数轮换）", "number"],
  ["pool_idle_timeout_ms", "上游空闲连接期限（毫秒，0 关闭）", "number"],
  [
    "old_pool_retain_ms",
    "旧代连接池缓存保留期（毫秒，0 下次清理即淘汰）",
    "number",
  ],
];

const timeoutFields = [
  ["upstream_ttfb_timeout_ms", "上游响应头期限（毫秒，0 关闭）", "number"],
  ["header_read_timeout_ms", "完整请求头读取期限（毫秒，0 关闭）", "number"],
  ["connection_timeout_ms", "物理连接总寿命（毫秒，0 关闭）", "number"],
  [
    "stream_idle_timeout_ms",
    "HTTP 正文与 trailer 帧间空闲期限（毫秒，0 关闭）",
    "number",
  ],
  ["downstream_write_timeout_ms", "下游待写操作期限（毫秒，0 关闭）", "number"],
  [
    "websocket_idle_timeout_ms",
    "WebSocket 双向活动空闲期限（毫秒，0 关闭）",
    "number",
  ],
  [
    "websocket_max_lifetime_ms",
    "WebSocket 升级后总寿命（毫秒，0 关闭）",
    "number",
  ],
  ["drain_timeout_ms", "终止时等待在途请求完成的期限（毫秒）", "number"],
];

const proxyFields = [
  ["enabled", "启用 PROXY protocol 前导解析", "boolean"],
  ["versions", "接受的协议版本（每行 v1 或 v2，空列表接受两者）", "lines"],
  ["accept_from", "可信直连前置代理 CIDR（每行一项）", "lines"],
  ["timeout_ms", "PROXY 前导读取期限（毫秒）", "number"],
];

/**
 * 业务作用：按连接、请求和池代边界展示 HTTP 入口预算，不把不同字段的零值语义混为一谈。
 * 参数说明：
 * - `kind`：候选对象类型。
 * 返回：HTTP 入口的精确子字段分组；不补运行默认值或授予前置代理信任。
 */
export function listenerFieldGroups(kind) {
  if (kind !== "proxy") {
    return [];
  }
  return [
    [["limits"], "HTTP 下游连接与请求预算", downstreamFields],
    [["limits"], "HTTP 上游连接池预算", upstreamFields],
    [["timeouts"], "HTTP 分层超时", timeoutFields],
    [["proxy_protocol"], "可信前置代理协议", proxyFields],
  ];
}

/**
 * 业务作用：允许按原候选位置编辑前置协议版本和可信来源，不重新序列化其它声明。
 * 参数说明：
 * - `kind`：所属候选对象类型。
 * 返回：HTTP 入口的两个字符串列表；其它对象不获得前置协议列表入口。
 */
export function listenerDraftLists(kind) {
  if (kind !== "proxy") {
    return [];
  }
  return proxyFields
    .filter((field) => field[2] === "lines")
    .map(([key, title]) => ({
      path: ["proxy_protocol", key],
      title,
      type: "string",
    }));
}
