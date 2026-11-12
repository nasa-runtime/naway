/**
 * 业务作用：显式维护固定 WebTransport 上游、浏览器来源与会话预算，避免普通路由被隐式转换为隧道。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十一项原生声明，不自动授予 HTTP/3 能力、修改方法或移除其它后端。
 */
export function routeWebTransportFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["webtransport"],
      "WebTransport 固定上游与会话预算",
      [
        ["upstream", "固定 HTTPS 上游 URL（包含 session 路径）", "string"],
        [
          "allowed_origins",
          "精确 Origin 名单（每行一项；不接受通配符或路径）",
          "lines",
        ],
        [
          "ca_file",
          "上游 CA PEM 文件（相对主配置目录；未声明时用系统根）",
          "string",
        ],
        ["connect_timeout_ms", "上游建连总期限（毫秒；1–60000）", "number"],
        [
          "max_bidi_streams",
          "会话双向流上限（0–4096；两类流不可同时为0）",
          "number",
        ],
        ["max_uni_streams", "会话单向流上限（0–4096）", "number"],
        [
          "max_datagram_queue",
          "单方向 DATAGRAM 队列数量上限（1–4096）",
          "number",
        ],
        [
          "max_datagram_bytes",
          "单个 DATAGRAM 字节上限（1–65527；单方向队列总字节不超过16 MiB）",
          "number",
        ],
        ["max_bytes", "会话双向合计字节上限（0不增加此限制）", "number"],
        ["idle_timeout_ms", "会话空闲回收期限（毫秒；必须大于0）", "number"],
        [
          "max_lifetime_ms",
          "会话最长寿命（毫秒；0不增加此限制，最长7天）",
          "number",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：按原位置编辑浏览器 Origin 授权集合，保留未编辑来源的原始声明。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供字符串名单，插入、替换、移动和删除均须显式选择。
 */
export function routeWebTransportDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["webtransport", "allowed_origins"],
      title: "WebTransport 允许 Origin",
      type: "string",
    },
  ];
}
