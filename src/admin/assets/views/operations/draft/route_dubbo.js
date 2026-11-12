/**
 * 业务作用：显式维护固定 Dubbo 调用签名、可信附件和协议资源门，不改变上游或自动选择 codec。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十七项原生声明；未编辑的引用、名单和预算保持原值。
 */
export function routeDubboFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["dubbo"],
      "HTTP 到 Dubbo 固定调用",
      [
        ["interface", "固定 service interface（最多256字节）", "string"],
        ["method", "固定业务方法（最多128字节；wire 使用 $invoke）", "string"],
        [
          "parameter_types",
          "完整 Java 参数类型名单（每行一项，最多64项，顺序对应 arguments）",
          "lines",
        ],
        ["version", "固定 service version（最多128字节，可为空串）", "string"],
        ["group", "固定 service group（最多128字节，可为空串）", "string"],
        [
          "serialization",
          "显式 json 或 hessian2；Hessian2 需目标制品启用 dubbo-hessian2",
          "string",
        ],
        [
          "max_request_body_bytes",
          "下游 JSON 请求体上限（1–16777216字节）",
          "number",
        ],
        [
          "max_request_frame_bytes",
          "编码后请求 frame body 上限（1–16777216字节）",
          "number",
        ],
        [
          "max_response_body_bytes",
          "响应 frame body 上限（1–16777216字节）",
          "number",
        ],
        [
          "max_hessian_string_bytes",
          "仅 Hessian2：单值 UTF-8 字符串上限（1–16777216字节）",
          "number",
        ],
        [
          "max_hessian_binary_bytes",
          "仅 Hessian2：单值 binary 上限（1–16777216字节）",
          "number",
        ],
        [
          "max_hessian_collection_items",
          "仅 Hessian2：frame 内 collection/object 字段总数（1–1000000）",
          "number",
        ],
        [
          "max_hessian_depth",
          "仅 Hessian2：collection/object 递归深度（1–128）",
          "number",
        ],
        ["connect_timeout_ms", "TCP 建连期限（10–120000毫秒）", "number"],
        [
          "request_timeout_ms",
          "写入与完整响应读取的共同期限（10–120000毫秒）",
          "number",
        ],
        [
          "max_idle_connections",
          "每 endpoint 的空闲连接上限（0–64；0 关闭复用）",
          "number",
        ],
        [
          "attachments",
          "完整固定附件映射（最多32项，值为 SecretSource 引用，不求值）",
          "json",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：按原始位置维护 Java 参数签名，不重建其它参数或扩大客户端可选调用范围。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供参数类型字符串列表，保持类型与 arguments 的声明顺序。
 */
export function routeDubboDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["dubbo", "parameter_types"],
      title: "Dubbo Java 参数类型",
      type: "string",
    },
  ];
}
