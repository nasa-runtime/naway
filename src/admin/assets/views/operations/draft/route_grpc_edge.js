/**
 * 业务作用：按独立路由声明边缘动作、可信身份、授权范围和队列预算，保持普通 gRPC 的关闭语义。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供三十五项原生叶字段，不自动启用边缘模式或填入默认预算。
 */
export function routeGrpcEdgeFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["grpc_edge"],
      "gRPC 边缘动作与分面",
      [
        ["enabled", "启用边缘模式（关闭时保持普通 L7 透传）", "boolean"],
        [
          "allowed_actions",
          "允许动作（每行一项：subscribe / publish / push；订阅与发布分面）",
          "lines",
        ],
        [
          "action_header",
          "动作二次确认 header（与 group、target 头不同）",
          "string",
        ],
        ["group_header", "订阅或群播 group header", "string"],
        ["target_header", "定向 push 的 user header", "string"],
        ["auth", "身份分面：required（订阅）/ service（发布或推送）", "string"],
        ["delivery", "投递语义：at_most_once", "string"],
        ["encoding", "消息编码：identity", "string"],
        [
          "max_msg_bytes",
          "旧兼容消息上限（1–16777216；优先使用 limits.max_msg_bytes）",
          "number",
        ],
        [
          "ws_bridge_path",
          "可选 WS 订阅桥接绝对路径（最多256字节，不同于 RPC 路径）",
          "string",
        ],
      ],
    ],
    [
      ["grpc_edge", "methods"],
      "边缘动作精确 RPC 路径",
      [
        [
          "subscribe",
          "订阅 RPC（/package.Service/Method，最多256字节）",
          "string",
        ],
        ["publish", "单消息群播 RPC", "string"],
        ["publish_stream", "可选流式群播 RPC（需要 publish 动作）", "string"],
        ["push", "定向单播 RPC", "string"],
      ],
    ],
    [
      ["grpc_edge", "identity"],
      "已验证主体的边缘身份",
      [
        [
          "tenant_claim",
          "可选租户 claim（1–256可见 ASCII 字节；省略为 default tenant）",
          "string",
        ],
        [
          "user_claim",
          "用户 claim（1–256可见 ASCII 字节，不得以 -bin 结尾）",
          "string",
        ],
      ],
    ],
    [
      ["grpc_edge", "authz"],
      "边缘动作授权（空名单拒绝对应动作）",
      [
        [
          "subscribe_groups",
          "允许订阅的 group 模式（每行一项，单项最多512字节）",
          "lines",
        ],
        ["publish_groups", "允许群播的 group 模式（每行一项）", "lines"],
        ["push_targets", "允许定向推送的 user 模式（每行一项）", "lines"],
      ],
    ],
    [
      ["grpc_edge", "send_queue"],
      "每订阅流的有界发送队列",
      [
        ["max_messages", "队列消息数上限（1–65536）", "number"],
        [
          "max_bytes",
          "队列完整帧字节上限（1–1073741824，至少容纳最大消息加5字节）",
          "number",
        ],
        [
          "overflow",
          "队满策略：drop_oldest / drop_new / latest_by_key / close_slow",
          "string",
        ],
      ],
    ],
    [
      ["grpc_edge", "publish_stream"],
      "PublishStream 单流预算",
      [
        ["max_lifetime_ms", "最长寿命（1–86400000 毫秒）", "number"],
        ["max_messages", "累计消息数（1–100000000）", "number"],
        ["max_msgs_per_sec", "每秒消息节流速率（1–1000000）", "number"],
        [
          "max_total_bytes",
          "累计完整帧字节（1–1099511627776，至少容纳最大消息加5字节）",
          "number",
        ],
      ],
    ],
    [
      ["grpc_edge", "limits"],
      "边缘节点预算与身份基数",
      [
        [
          "max_msg_bytes",
          "单条 protobuf body 上限（1–16777216，不含5字节前缀）",
          "number",
        ],
        [
          "max_id_bytes",
          "tenant / group / user 身份字节上限（1–1024）",
          "number",
        ],
        ["max_streams_per_node", "节点订阅流数上限（1–10000000）", "number"],
        ["max_groups_per_node", "节点 group 数上限（1–10000000）", "number"],
        [
          "max_members_per_group",
          "单 group 成员数上限（1–10000000）",
          "number",
        ],
        ["max_sessions_per_user", "单 user 会话数上限（1–64）", "number"],
        [
          "max_payload_bytes",
          "节点唯一 payload 驻留字节（1–17179869184，至少容纳最大完整帧）",
          "number",
        ],
        ["max_queue_refs", "节点队列引用总数上限（1–100000000）", "number"],
        ["max_fanout_jobs", "并发 fanout job 上限（1–65536）", "number"],
      ],
    ],
  ];
}

/**
 * 业务作用：逐项维护边缘动作和三个授权名单，使每次变更只作用于选定原始位置。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供四个字符串列表，不推断授权模式或添加未声明动作。
 */
export function routeGrpcEdgeDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["grpc_edge", "allowed_actions"],
      title: "gRPC 边缘允许动作",
      type: "string",
    },
    {
      path: ["grpc_edge", "authz", "subscribe_groups"],
      title: "gRPC 边缘订阅 group 授权",
      type: "string",
    },
    {
      path: ["grpc_edge", "authz", "publish_groups"],
      title: "gRPC 边缘群播 group 授权",
      type: "string",
    },
    {
      path: ["grpc_edge", "authz", "push_targets"],
      title: "gRPC 边缘定向 user 授权",
      type: "string",
    },
  ];
}
