/**
 * 业务作用：显式维护 CONNECT 目标授权和隧道预算，避免把空名单或零值误认为额外放行许可。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供八项原生声明，不自动设置 CONNECT 断言、私网权限或后端。
 */
export function routeForwardProxyFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["forward_proxy"],
      "受控 CONNECT 正向代理",
      [
        [
          "allowed_ports",
          "允许端口（非空 JSON 数字数组；目标端口为1–65535）",
          "json",
        ],
        [
          "allowed_hosts",
          "域名名单（每行一项；可用 *.example.com，不接受裸 *）",
          "lines",
        ],
        [
          "allowed_cidrs",
          "允许目标 CIDR（每行一项；字面量 IP 必须命中）",
          "lines",
        ],
        [
          "allow_private",
          "明确允许私网目标（仍拒绝环回、链路本地和自身监听）",
          "boolean",
        ],
        ["idle_timeout_ms", "隧道空闲期限（毫秒；0不增加此限制）", "number"],
        ["max_lifetime_ms", "隧道最长寿命（毫秒；0不增加此限制）", "number"],
        ["max_bytes", "双向合计转发字节上限（0不增加此限制）", "number"],
        [
          "connect_timeout_ms",
          "建连期限（毫秒；0仍按至少1毫秒执行）",
          "number",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：按原始位置维护端口、域名和 CIDR 名单，不把展示值重建为另一组目标授权。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供三个独立列表，端口为数值元素，域名和 CIDR 为字符串元素。
 */
export function routeForwardProxyDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["forward_proxy", "allowed_ports"],
      title: "CONNECT 允许端口",
      type: "number",
    },
    {
      path: ["forward_proxy", "allowed_hosts"],
      title: "CONNECT 允许域名",
      type: "string",
    },
    {
      path: ["forward_proxy", "allowed_cidrs"],
      title: "CONNECT 允许 CIDR",
      type: "string",
    },
  ];
}
