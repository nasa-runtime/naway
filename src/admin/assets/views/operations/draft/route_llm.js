/**
 * 业务作用：显式维护 LLM 入口协议与请求资源预算，避免编辑预算时重建模型凭据或其它治理声明。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供八项原生声明，不自动选择模型、注入凭据或修改其它终端后端。
 */
export function routeLlmFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["llm"],
      "LLM 入口协议与请求预算",
      [
        [
          "api_type",
          "API 类型（如 chat_completions、responses、embeddings；须与模型兼容）",
          "string",
        ],
        ["max_body_bytes", "请求实体字节上限（1–16777216）", "number"],
        ["max_prompt_tokens", "提示词估算 token 上限（1–16777216）", "number"],
        [
          "max_completion_tokens",
          "补全 token 上限（1–16777216；请求未声明时也生效）",
          "number",
        ],
        [
          "max_response_bytes",
          "响应字节上限（1–16777216；原生长连接按协议计量）",
          "number",
        ],
        [
          "max_stream_frame_bytes",
          "流事件、行或原生帧上限（正数；不超过响应上限和4194304）",
          "number",
        ],
        [
          "max_duration_ms",
          "单次模型请求或长连接期限（毫秒；1–86400000）",
          "number",
        ],
        [
          "max_cost_microusd",
          "估算费用上限（正数，微美元；保留原声明的仅观测模式）",
          "number",
        ],
      ],
    ],
  ];
}
export const llmModelFields = [
  ["id", "模型稳定 id（1–64字节，仅字母、数字、.、_、-）", "string"],
  [
    "provider",
    "固定 provider（如 openai、anthropic、google、ollama）",
    "string",
  ],
  ["uri", "固定模型后端（http(s):// 或 lb://service）", "string"],
  ["model", "发送给 provider 的模型名（非空，最多256字节）", "string"],
  ["path", "固定 API path（留空使用对应 provider/API 的原生缺省）", "string"],
  ["stream_path", "Google/Vertex Chat 流式 path（其它组合须留空）", "string"],
  [
    "api_key",
    "provider API key 的 SecretSource 引用（空表示不注入）",
    "string",
  ],
  ["anthropic_version", "Anthropic API 版本（其它 provider 须留空）", "string"],
  ["api_version", "provider API 版本（如 Azure 固定 query 版本）", "string"],
  ["region", "云 provider 固定 region（须满足原生 provider 组合）", "string"],
  ["project", "Vertex AI 固定 project（用于受信 API path）", "string"],
  [
    "aws_access_key_id",
    "Bedrock AWS access key id 的 SecretSource 引用",
    "string",
  ],
  [
    "aws_secret_access_key",
    "Bedrock AWS secret access key 的 SecretSource 引用",
    "string",
  ],
  [
    "aws_session_token",
    "可选 AWS session token 的 SecretSource 引用",
    "string",
  ],
  [
    "native_passthrough",
    "保留 provider 原生实体，须与路由 API/provider 兼容",
    "boolean",
  ],
  [
    "input_cost_microusd_per_million",
    "每百万提示 token 单价（微美元；0表示未知）",
    "number",
  ],
  [
    "output_cost_microusd_per_million",
    "每百万补全 token 单价（微美元；0表示未知）",
    "number",
  ],
  [
    "fixed_cost_microusd",
    "请求固定估算费用（微美元；正数时优先于 token 单价）",
    "number",
  ],
  [
    "capabilities",
    "完整能力名单（每行一项，最多32项，不重复的1–64字节安全 ASCII token）",
    "lines",
  ],
  [
    "expected_first_token_latency_ms",
    "catalog 首 token 预期（毫秒；0表示未声明）",
    "number",
  ],
  ["weight", "weighted 相对权重（0–1000000；0保留回退资格）", "number"],
];

/**
 * 业务作用：按原始位置编辑固定模型目录，避免重建其它模型或默认授予端点、凭据和能力。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供模型列表；新增与整值替换须显式提供身份及真实后端，已有身份不由字段补丁改写。
 */
export function routeLlmDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["llm", "models"],
      title: "LLM 固定模型目录",
      type: "llm_model",
    },
  ];
}
