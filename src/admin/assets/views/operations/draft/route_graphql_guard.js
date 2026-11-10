/**
 * 业务作用：显式编辑 GraphQL 查询预算和协议放行范围，保持未编辑的资源限制与独立授权策略。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供七项原生字段，不默认开启 introspection 或订阅，也不生成缺省预算。
 */
export function routeGraphqlGuardFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["graphql_guard"],
      "GraphQL 查询预算",
      [
        ["max_body_bytes", "POST 实体上限（1–4194304 字节）", "number"],
        [
          "max_query_bytes",
          "解码后查询文档上限（1–1048576 UTF-8 字节）",
          "number",
        ],
        [
          "max_tokens",
          "每查询文档 token 上限（1–262144，且不超过查询字节上限）",
          "number",
        ],
        ["max_depth", "查询选择深度上限（1–128，根字段为 1）", "number"],
        [
          "max_complexity",
          "每个选定 operation 字段成本（1–10000000，fragment 每次展开计费）",
          "number",
        ],
        [
          "allow_introspection",
          "允许 __* introspection 字段（包含 __typename）",
          "boolean",
        ],
        [
          "allow_websocket_subscriptions",
          "允许标准及 legacy GraphQL WebSocket 透明订阅",
          "boolean",
        ],
      ],
    ],
  ];
}
