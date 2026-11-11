/**
 * 业务作用：显式选择 descriptor JSON 转码的 RPC 暴露范围、协议开关与消息资源预算。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十二项原生声明，不自动加载 descriptor 或开启 JSON 协议。
 */
export function routeGrpcTranscodingFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["grpc_transcoding"],
      "Descriptor 驱动 gRPC JSON 转码",
      [
        [
          "descriptor_set_file",
          "受信 FileDescriptorSet 文件（相对主配置目录）",
          "string",
        ],
        [
          "services",
          "允许暴露的 service full name（每行一项，1–128项）",
          "lines",
        ],
        [
          "methods",
          "method full name 子集（每行一项，最多2048项；空表示所选 service 的全部方法）",
          "lines",
        ],
        ["google_http", "启用 descriptor 中的 google.api.http 映射", "boolean"],
        ["connect_json", "启用 Connect unary 和 streaming JSON", "boolean"],
        [
          "reject_unknown_fields",
          "拒绝 descriptor 未声明的 JSON 字段",
          "boolean",
        ],
        [
          "max_descriptor_bytes",
          "descriptor 文件上限（1024–33554432 字节）",
          "number",
        ],
        [
          "max_input_message_bytes",
          "单条输入 protobuf 消息上限（1–67108864 字节）",
          "number",
        ],
        [
          "max_output_message_bytes",
          "单条输出 protobuf 消息上限（1–67108864 字节）",
          "number",
        ],
        [
          "max_json_bytes",
          "单条 JSON 上限（1–67108864 字节，不超过输入和输出消息上限）",
          "number",
        ],
        ["max_stream_messages", "每 stream 消息数上限（1–10000000）", "number"],
        [
          "max_stream_buffer_bytes",
          "未完成 envelope/JSON 保留上限（1–67108864 字节，不超过输入输出较大上限）",
          "number",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：逐项维护受信 descriptor 的 service 和 method 暴露名单，保持其它符号与预算原声明。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由的两个字符串列表，操作绑定所选原始位置，不扩展其它 RPC 权限。
 */
export function routeGrpcTranscodingDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["grpc_transcoding", "services"],
      title: "gRPC JSON service 暴露名单",
      type: "string",
    },
    {
      path: ["grpc_transcoding", "methods"],
      title: "gRPC JSON method 暴露子集",
      type: "string",
    },
  ];
}
