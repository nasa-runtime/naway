/**
 * 业务作用：显式编辑终端重定向的目标与路径策略，保留未覆盖的入站信息和其它后端声明。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供七项原生字段；省略项保持省略，不自动填入状态或修改上游 URI。
 */
export function routeRedirectFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["gateway_redirect"],
      "终端 HTTP 重定向",
      [
        ["scheme", "目标 scheme（http / https；省略时保留监听协议）", "string"],
        [
          "hostname",
          "目标 hostname（不含端口；DNS、IPv4 或方括号 IPv6）",
          "string",
        ],
        ["port", "显式目标端口（1–65535）", "number"],
        ["status_code", "状态码（301 / 302 / 303 / 307 / 308）", "number"],
        [
          "replace_full_path",
          "替换完整路径（以 / 开头，最多2048字节）",
          "string",
        ],
        [
          "replace_prefix_match",
          "替换匹配前缀（须同时声明 matched_prefix）",
          "string",
        ],
        ["matched_prefix", "原匹配前缀（与前缀替换成对声明）", "string"],
      ],
    ],
  ];
}
