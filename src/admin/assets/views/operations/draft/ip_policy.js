/**
 * 业务作用：提供全局静态 ACL 与可信客户端来源的独立字段，不从展示动作注入默认策略。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：根策略的两个字段组；其它对象不获得全局访问控制编辑能力。
 */
export function ipPolicyFieldGroups(kind) {
  if (kind !== "ip_policy") {
    return [];
  }
  return [
    [
      ["acl"],
      "全局 IP 访问控制",
      [
        ["mode", "访问模式：off / whitelist / blacklist", "string"],
        ["entries", "IP 或 CIDR（每行一项，最多 4096 项）", "lines"],
      ],
    ],
    [
      ["client_ip_policy"],
      "可信客户端来源",
      [
        ["mode", "来源模式：socket_addr / forwarded", "string"],
        ["header", "唯一来源头：x_forwarded_for / forwarded", "string"],
        ["max_forwarded_hops", "来源链总元素上限（1–64）", "number"],
      ],
    ],
  ];
}

/**
 * 业务作用：允许按原始顺序维护 ACL 条目，不把缺失列表解释成允许全部。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：静态 ACL 的字符串列表位置；其它对象没有此入口。
 */
export function ipPolicyDraftLists(kind) {
  if (kind !== "ip_policy") {
    return [];
  }
  return [
    {
      path: ["acl", "entries"],
      title: "全局 ACL 地址与网段",
      type: "string",
      maxItems: 4096,
    },
  ];
}
