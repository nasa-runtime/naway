export const cgiFields = [
  [
    "protocol",
    "明确记录协议（fastcgi/uwsgi/scgi；目标须有对应 feature）",
    "string",
  ],
  ["script_root", "固定绝对脚本根（不读取客户端路径）", "string"],
  ["script_filename", "根内固定绝对脚本文件名", "string"],
  ["script_name", "固定绝对 SCRIPT_NAME", "string"],
  ["server_name", "固定服务主机名称（1–255字节）", "string"],
  ["server_port", "固定服务端口（1–65535；移除按监听协议选择）", "number"],
  ["max_header_bytes", "响应头字节上限（1024–65536）", "number"],
  ["max_headers", "响应头数量上限（1–128）", "number"],
  ["max_params", "环境参数数量上限（16–128）", "number"],
  ["max_param_bytes", "环境参数编码容量（1024–65535字节）", "number"],
  ["max_stderr_bytes", "FastCGI 诊断流容量（0–1048576字节）", "number"],
  ["max_inflight", "当前路由记录会话上限（1–1024）", "number"],
  ["keep_conn", "明确允许 FastCGI 单请求连接复用", "boolean"],
  [
    "fastcgi_termination",
    "明确收尾（streams 或 php_fpm；后者仅 FastCGI）",
    "string",
  ],
  ["idle_timeout_ms", "无进展 I/O 与空闲连接上限（100–60000毫秒）", "number"],
  [
    "request_headers",
    "明确传入环境的请求头白名单（每行一项，最多32项）",
    "lines",
  ],
];

/**
 * 业务作用：显式维护固定 CGI 脚本和记录预算，不用请求路径选脚本或自动改变关联服务协议。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十六个原生字段；协议 feature、服务绑定和路径边界仍由原目标完整预检。
 */
export function routeCgiFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [[["cgi"], "固定 CGI 脚本与记录协议", cgiFields]];
}

/**
 * 业务作用：按原始位置编辑传入 CGI 的 HTTP 头白名单，不隐式开放其它客户端环境来源。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供字符串列表；规范化重名、保留头和协议歧义仍由原目标拒绝。
 */
export function routeCgiDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["cgi", "request_headers"],
      title: "CGI 请求头白名单",
      type: "string",
    },
  ];
}
