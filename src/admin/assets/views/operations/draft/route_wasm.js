export const wasmPluginFields = [
  ["id", "插件稳定 id（唯一，1–128 UTF-8 字节）", "string"],
  [
    "module_file",
    "本地 wasm 文件（相对主配置目录，与 module_source 二选一）",
    "string",
  ],
  ["module_source", "HTTPS / OCI 受信来源声明（整段设置或移除）", "json"],
  [
    "phase",
    "相位：request_headers / request_body / request_body_stream / response_headers / response_body / response_body_stream",
    "string",
  ],
  ["config", "传给客体的 JSON 配置（编码后最多65536字节）", "json"],
  ["fail_open", "可开放的客体执行错误跳过本插件，丢弃本次部分输出", "boolean"],
  ["max_module_bytes", "wasm 原始文件上限（1–67108864 字节）", "number"],
  ["max_memory_bytes", "单实例线性内存上限（65536–268435456 字节）", "number"],
  ["max_fuel", "单调用 fuel 上限（1–1000000000）", "number"],
  ["timeout_ms", "单调用墙钟上限（1–1000 毫秒）", "number"],
  [
    "max_mutations",
    "单调用 header / local-response 变更次数（1–1024）",
    "number",
  ],
  [
    "max_header_bytes",
    "插件可见与交付的完整 header map 上限（1–1048576 字节）",
    "number",
  ],
  ["max_body_bytes", "body 相位的读取与变更上限（1–16777216 字节）", "number"],
  [
    "max_local_response_body_bytes",
    "客体本地响应 body 上限（1–1048576 字节）",
    "number",
  ],
  [
    "callout_clusters",
    "固定 callout 上游列表（最多32项；name、origin、ca_certificate、allow_cleartext、http2_prior_knowledge）",
    "json",
  ],
  ["max_callouts", "单调用可登记 callout 总数（1–32）", "number"],
  [
    "max_callout_response_bytes",
    "单 callout 响应体可见上限（1–16777216 字节）",
    "number",
  ],
  ["shared_namespace", "固定共享命名空间（最多128 UTF-8 字节）", "string"],
  ["max_shared_entries", "shared-data key 数量上限（1–65536）", "number"],
  [
    "max_shared_bytes",
    "shared data / property / queue payload 驻留总量（1–67108864 字节）",
    "number",
  ],
  ["max_shared_queues", "shared queue 数量上限（1–4096）", "number"],
  ["max_queue_entries", "单 shared queue 消息数上限（1–65536）", "number"],
  ["max_metrics", "内部 metric 数量上限（1–4096）", "number"],
];

/**
 * 业务作用：显式维护 Proxy-Wasm 插件链的原始位置，使新增身份与已有插件字段修改分开。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供类型化插件列表，不自动装载模块、开放 callout 或选择执行相位。
 */
export function routeWasmDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["wasm_plugins"],
      title: "Proxy-Wasm 插件链",
      type: "wasm_plugin",
    },
  ];
}

/**
 * 业务作用：逐项编辑远程模块来源和签名约束，避免为更改一个预算而重写完整信任声明。
 * 参数说明：
 * - `kind`：当前插件编辑类别。
 * 返回：仅 Proxy-Wasm 插件提供来源与 attestation 控件；没有编辑的 SecretSource 保持原文。
 */
export function wasmSourceFieldGroups(kind) {
  if (!["wasm_plugin", "wasm_plugin_new"].includes(kind)) {
    return [];
  }
  return [
    [
      ["module_source"],
      "远程模块与摘要信任",
      [
        [
          "reference",
          "固定 HTTPS URL 或 OCI reference（1–4096字节）",
          "string",
        ],
        ["sha256", "最终 wasm 原始字节 SHA-256", "string"],
        [
          "manifest_sha256",
          "OCI manifest SHA-256（tag 必填，仅 OCI 使用）",
          "string",
        ],
        ["authorization", "来源 Authorization 完整值 SecretSource", "string"],
        ["ca_certificate", "附加 TLS CA PEM 的 SecretSource", "string"],
        ["cache_dir", "可选内容寻址缓存目录（相对主配置目录）", "string"],
        ["timeout_ms", "获取共享总期限（100–30000 毫秒）", "number"],
        ["signature", "detached Ed25519 签名 Base64 SecretSource", "string"],
        ["public_key", "32-byte Ed25519 公钥 Base64 SecretSource", "string"],
        [
          "attestation",
          "签名 in-toto statement 约束（整段设置或移除）",
          "json",
        ],
      ],
    ],
    [
      ["module_source", "attestation"],
      "签名来源证明约束",
      [
        ["statement", "精确 UTF-8 JSON statement 的 SecretSource", "multiline"],
        ["signature", "statement detached Ed25519 签名 SecretSource", "string"],
        ["public_key", "statement signer 的32-byte公钥 SecretSource", "string"],
        ["predicate_type", "受信 predicateType（1–1024字节）", "string"],
        ["builder_id", "受信 predicate.builder.id（1–1024字节）", "string"],
        ["subject_name", "可选精确 subject name（最多1024字节）", "string"],
      ],
    ],
  ];
}
