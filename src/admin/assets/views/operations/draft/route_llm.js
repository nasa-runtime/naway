export const llmModerationFields = [
  ["uri", "固定判定服务（http(s):// 或 lb://service）", "string"],
  ["model", "固定 Moderation 模型名（显式非空，最多256字节）", "string"],
  ["path", "固定 API path（空使用 /v1/moderations）", "string"],
  ["api_key", "判定服务 API key 的 SecretSource 引用（不读取秘密）", "string"],
  ["timeout_ms", "单次判定含完整正文期限（毫秒；1–60000）", "number"],
  ["max_request_bytes", "序列化判定请求字节上限（1–16777216）", "number"],
  ["max_response_bytes", "判定响应聚合字节上限（1–4194304）", "number"],
  [
    "fail_mode",
    "依赖故障策略（closed、open；明确 flagged 始终拒绝）",
    "string",
  ],
];

/**
 * 业务作用：显式维护 LLM 入口预算、选择、配额、缓存和内容策略，避免重建模型凭据或其它治理配置。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供独立字段，不自动添加模型、注入凭据、授予副本发送权或放宽额度。
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
    [
      ["llm"],
      "LLM 本地内容护栏完整声明",
      [
        [
          "guardrails",
          "完整本地护栏（移除关闭本地规则与可信提示，保留外部判定）",
          "json",
        ],
      ],
    ],
    [
      ["llm", "governance"],
      "LLM 固定提示完整声明",
      [["prompt", "完整固定模板（移除只关闭模板注入，保留治理身份）", "json"]],
    ],
    [
      ["llm", "governance", "prompt"],
      "LLM 固定提示模板（需 ai-governance）",
      [
        ["name", "模板名称（固定业务身份）", "string"],
        ["revision", "模板修订标识（配置固定，客户端不能覆盖）", "string"],
        ["file", "UTF-8 模板文件（相对配置目录，最多64KiB）", "string"],
        ["variables", "完整固定字符串变量映射（设置会替换整份映射）", "json"],
      ],
    ],
    [
      ["llm"],
      "LLM 语义缓存完整声明",
      [
        [
          "semantic_cache",
          "完整语义缓存（移除关闭缓存，保留模型和认证）",
          "json",
        ],
      ],
    ],
    [
      ["llm", "semantic_cache"],
      "LLM 缓存容量与隔离",
      [
        ["ttl_ms", "条目存活时间（1–604800000毫秒）", "number"],
        ["max_entries", "每路由与隔离范围条目上限（1–1000000）", "number"],
        ["max_response_bytes", "可回填响应字节上限（1–16777216）", "number"],
        ["similarity_threshold", "余弦相似度阈值（0–1）", "number"],
        [
          "max_candidates",
          "单次最近候选上限（1–1024；与维度乘积不超过1048576）",
          "number",
        ],
        ["l2", "使用共享 Redis L2（须已配置 Redis 后端）", "bool"],
        [
          "scope",
          "可信身份隔离（consumer、api_key；route 须允许公共复用）",
          "string",
        ],
        ["embedding", "完整 embedding 服务（设置会替换整个子声明）", "json"],
      ],
    ],
    [
      ["llm", "semantic_cache", "embedding"],
      "LLM Embedding 服务",
      [
        ["uri", "固定 embedding 服务 URI（http、https 或 lb）", "string"],
        ["model", "固定 embedding 模型名", "string"],
        ["path", "API 路径（空使用 /v1/embeddings）", "string"],
        ["api_key", "凭据 SecretSource（空表示不注入）", "string"],
        ["max_dimensions", "接受的向量维度上限（1–65536）", "number"],
      ],
    ],
    [
      ["llm", "guardrails"],
      "LLM 本地内容规则与可信提示",
      [
        ["rules", "完整结构化规则列表（设置值会替换整个名单）", "json"],
        [
          "stream_window_bytes",
          "解码文本保留窗口（有规则时64–65536；须覆盖最长响应匹配）",
          "number",
        ],
        [
          "system_prompt",
          "前置可信 system 提示（保留换行；空表示不注入）",
          "multiline",
        ],
        [
          "blocked_substrings",
          "输入阻断完整短语名单（每行一项，最多64条）",
          "lines",
        ],
        [
          "blocked_response_substrings",
          "输出阻断完整短语名单（每行一项，最多64条）",
          "lines",
        ],
      ],
    ],
    [
      ["llm"],
      "LLM 外部内容判定完整声明",
      [
        [
          "moderation",
          "完整 Moderation 声明（移除关闭该判定，保留模型与认证）",
          "json",
        ],
      ],
    ],
    [["llm", "moderation"], "LLM 外部 Moderation 判定", llmModerationFields],
    [
      ["llm"],
      "LLM Token 配额完整声明",
      [
        [
          "token_quota",
          "完整 Token 配额（移除关闭配额，保留模型与认证）",
          "json",
        ],
      ],
    ],
    [
      ["llm", "token_quota"],
      "LLM Token 预留与结算配额",
      [
        ["tokens", "每窗口补充 Token 数（正数）", "number"],
        ["window_ms", "配额补充窗口（毫秒；1–86400000）", "number"],
        ["burst", "额外突发 Token 容量（0表示无额外容量）", "number"],
        ["dimension", "已验证额度身份（route、consumer、api_key）", "string"],
        ["max_active_keys", "同规则真实活跃维度上限（1–1000000）", "number"],
        [
          "active_keys_fail_open",
          "维度表满时允许未记账的新维度（不放开已有桶）",
          "boolean",
        ],
      ],
    ],
    [
      ["llm"],
      "LLM 选择策略完整声明",
      [["selection", "完整选择声明（移除恢复原生缺省，保留模型目录）", "json"]],
    ],
    [
      ["llm", "selection"],
      "LLM 模型选择与独立副本",
      [
        [
          "strategy",
          "首选策略（ordered、cost、latency、weighted、joint）",
          "string",
        ],
        [
          "required_capabilities",
          "必需能力完整名单（每行一项，最多16项，全部满足才保留模型）",
          "lines",
        ],
        [
          "preferred_capabilities",
          "joint 软偏好完整名单（每行一项，最多16项）",
          "lines",
        ],
        [
          "max_first_token_latency_ms",
          "joint 首 token 排序边界（毫秒；0不声明，不替代请求期限）",
          "number",
        ],
        [
          "shadow_model",
          "独立后台副本的固定模型 id（须与正数采样份额同时声明）",
          "string",
        ],
        [
          "shadow_basis_points",
          "shadow 采样份额（0–10000；0须同时解除模型引用）",
          "number",
        ],
        [
          "rollout_model",
          "灰度首选固定模型 id（失败仍回退，不能与 shadow 相同）",
          "string",
        ],
        [
          "rollout_basis_points",
          "rollout 采样份额（0–10000；0须同时解除模型引用）",
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

export const llmGuardrailFields = [
  ["id", "规则稳定 id（1–64字节，仅字母、数字、.、_、-）", "string"],
  [
    "category",
    "固定分类（prompt_injection、jailbreak、pii、secret、content）",
    "string",
  ],
  [
    "directions",
    "完整方向名单（每行 request 或 response，不空且不重复）",
    "lines",
  ],
  [
    "contains",
    "固定包含文本（保留换行；与 regex、detector 三选一）",
    "multiline",
  ],
  [
    "regex",
    "有界正则（不能空匹配；与 contains、detector 三选一）",
    "multiline",
  ],
  [
    "detector",
    "固定检测器（email、phone、national_id、api_key、private_key、bearer）",
    "string",
  ],
];

/**
 * 业务作用：按原始位置编辑模型、能力和内容规则名单，避免重建其它声明或默认授予端点、凭据和能力。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供明确类型的名单；新增模型与规则须声明身份，已有身份不由字段补丁改写。
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
    {
      path: ["llm", "selection", "required_capabilities"],
      title: "LLM 必需能力",
      type: "string",
    },
    {
      path: ["llm", "selection", "preferred_capabilities"],
      title: "LLM 软偏好能力",
      type: "string",
    },
    {
      path: ["llm", "guardrails", "blocked_substrings"],
      title: "LLM 输入阻断短语",
      type: "string",
    },
    {
      path: ["llm", "guardrails", "blocked_response_substrings"],
      title: "LLM 输出阻断短语",
      type: "string",
    },
    {
      path: ["llm", "guardrails", "rules"],
      title: "LLM 内容分类规则",
      type: "llm_guardrail",
    },
  ];
}
