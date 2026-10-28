//! 模型路由、配额、嵌入缓存与内容治理声明。

use super::*;

/// 路由级 AI/LLM 代理配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmRouteCfg {
    /// 显式的身份、模板、检索来源、引用和输出 moderation 计划。
    #[serde(default)]
    pub governance: Option<crate::ai::governance::config::GovernanceCfg>,
    /// 下游与上游共同使用的独立 API 契约；不同类型不会经 Chat Completions 适配器转换。
    #[serde(default)]
    pub api_type: LlmApiTypeCfg,
    /// 可接受的 JSON 请求体硬上限；LLM 格式转换需要显式有界缓冲。
    #[serde(default = "default_llm_max_body_bytes")]
    pub max_body_bytes: u64,
    /// tokenizer-independent prompt 估算硬上限；超出在调用模型前返回 413。
    #[serde(default = "default_llm_max_prompt_tokens")]
    pub max_prompt_tokens: u64,
    /// completion 允许上限；请求未声明 `max_tokens` 时也会注入该值，防无限输出。
    #[serde(default = "default_llm_max_completion_tokens")]
    pub max_completion_tokens: u64,
    /// 非流式 provider response 聚合硬上限；SSE/JSONL 使用累计字节门，Realtime 用作单消息硬门。
    #[serde(default = "default_llm_max_response_bytes")]
    pub max_response_bytes: u64,
    /// SSE、JSONL 或 WebSocket 单帧硬上限。
    #[serde(default = "default_llm_max_stream_frame_bytes")]
    pub max_stream_frame_bytes: u64,
    /// 单次 provider 请求或长连接最长持续时间；到期停止转发，单位毫秒。
    #[serde(default = "default_llm_max_duration_ms")]
    pub max_duration_ms: u64,
    /// 请求可选择模型的估算费用上限，单位微美元；`u64::MAX` 保留兼容的仅观测模式，
    /// 其它值在价格未知或估算超限时于 provider I/O 前拒绝。
    #[serde(default = "default_llm_max_cost_microusd")]
    pub max_cost_microusd: u64,
    /// 可选共享 token 配额；一次原子预留 prompt 估算 + completion 上限。
    #[serde(default)]
    pub token_quota: Option<LlmTokenQuotaCfg>,
    /// Prompt 注入/越权短语护栏。
    #[serde(default)]
    pub guardrails: LlmGuardrailsCfg,
    /// 可选外部 OpenAI-compatible moderation；在缓存、配额预留和模型调用前执行。
    #[serde(default)]
    pub moderation: Option<LlmModerationCfg>,
    /// 可选精确 + embedding 语义缓存。未配置时不会计算缓存键、聚合额外响应或访问 Redis。
    #[serde(default)]
    pub semantic_cache: Option<LlmSemanticCacheCfg>,
    /// 多模型首选策略；无论策略如何，连接错误/超时/5xx 仍按剩余模型降级。
    #[serde(default)]
    pub selection: LlmSelectionCfg,
    /// 依次尝试的模型；首项是主模型，后续项只在连接错误、超时或 5xx 时 fallback。
    pub models: Vec<LlmModelCfg>,
}

/// AI route 的 wire/API 类型；每个变体拥有独立 content-type、流协议与预算语义。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmApiTypeCfg {
    /// OpenAI Chat Completions JSON/SSE。
    #[default]
    ChatCompletions,
    /// OpenAI Responses JSON/SSE。
    Responses,
    /// 向量 embedding JSON。
    Embeddings,
    /// 文档重排 JSON。
    Rerank,
    /// 图片生成或编辑；JSON 或 route 固定的 multipart 原生请求。
    Image,
    /// 语音生成、转写或翻译；JSON 或 route 固定的 multipart 原生请求。
    Audio,
    /// 视频生成；JSON 或 route 固定的 multipart 原生请求。
    Video,
    /// 异步批处理 JSON。
    Batch,
    /// 文件上传/读取原生协议。
    File,
    /// WebSocket Realtime 双向事件协议。
    Realtime,
}

/// 外部 OpenAI-compatible moderation 配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmModerationCfg {
    /// moderation 服务地址，支持 `http(s)://` 与 `lb://service`。
    pub uri: String,
    /// moderation model 名称，例如 `omni-moderation-latest`；必须显式配置以保持策略可审计。
    pub model: String,
    /// API path；空时使用 `/v1/moderations`。
    #[serde(default)]
    pub path: String,
    /// provider API key SecretSource；空表示不注入凭据。
    #[serde(default)]
    pub api_key: String,
    /// 一次 moderation 调用总超时(ms)。
    #[serde(default = "default_llm_moderation_timeout_ms")]
    pub timeout_ms: u64,
    /// 序列化 moderation request 的硬上限。
    #[serde(default = "default_llm_moderation_max_request_bytes")]
    pub max_request_bytes: u64,
    /// moderation response 的聚合硬上限。
    #[serde(default = "default_llm_moderation_max_response_bytes")]
    pub max_response_bytes: u64,
    /// 依赖超时、非 2xx 或坏响应时的 `closed|open` 策略；明确 flagged 永远拒绝。
    #[serde(default)]
    pub fail_mode: LlmModerationFailModeCfg,
}

/// 外部 moderation 依赖失败策略。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmModerationFailModeCfg {
    /// 依赖不可判定时拒绝模型请求，安全优先。
    #[default]
    Closed,
    /// 仅依赖故障时继续；明确 `flagged=true` 仍拒绝。
    Open,
}

/// LLM 精确/语义两级缓存。
///
/// 缓存只接管非流式成功 JSON 响应；SSE 不会被聚合成伪流。语义查询必须配置真实 embedding
/// 服务，不使用字符串距离冒充语义相似度。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmSemanticCacheCfg {
    /// 缓存存活时间(ms)。L1 entry 自带单调时钟截止时间，L2 同时设置 Redis TTL。
    #[serde(default = "default_llm_cache_ttl_ms")]
    pub ttl_ms: u64,
    /// 单 route L1 与每个 L2 scope 的最大 entry 数。
    #[serde(default = "default_llm_cache_max_entries")]
    pub max_entries: u64,
    /// 允许缓存的模型响应最大字节数；更大的响应透明返回但不回填。
    #[serde(default = "default_llm_cache_max_response_bytes")]
    pub max_response_bytes: u64,
    /// 余弦相似度命中阈值，范围 0.0..=1.0。
    #[serde(default = "default_llm_cache_similarity_threshold")]
    pub similarity_threshold: f32,
    /// 一次语义查询最多比较的最近候选数，防止线性扫描无界。
    #[serde(default = "default_llm_cache_max_candidates")]
    pub max_candidates: usize,
    /// 是否使用 `runtime_state.http_cache` 的 Redis 作为跨节点 L2。
    #[serde(default)]
    pub l2: bool,
    /// 缓存隔离维度。默认 consumer，避免不同认证租户共享相似 prompt 的响应。
    #[serde(default)]
    pub scope: LlmCacheScopeCfg,
    /// OpenAI-compatible embedding 服务。
    pub embedding: LlmEmbeddingCfg,
}

/// LLM 语义缓存隔离维度。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmCacheScopeCfg {
    /// 整条 route 共享。只适合明确允许公共响应复用的匿名/公共知识场景。
    Route,
    /// 按已验证 consumer 隔离；匿名请求使用固定 anonymous scope。
    #[default]
    Consumer,
    /// 按已验证 API-Key 的 SHA-256 指纹隔离，原始 key 不进入缓存键。
    ApiKey,
}

/// OpenAI-compatible embedding 后端配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmEmbeddingCfg {
    /// embedding 服务地址，支持 `http(s)://` 与 `lb://service`。
    pub uri: String,
    /// 发给 embedding 服务的模型名。
    pub model: String,
    /// API path；空时使用 `/v1/embeddings`。
    #[serde(default)]
    pub path: String,
    /// provider API key SecretSource；空表示不注入凭据。
    #[serde(default)]
    pub api_key: String,
    /// 接受的最大向量维度；provider 返回更大向量时 fail-open 跳过缓存。
    #[serde(default = "default_llm_embedding_max_dimensions")]
    pub max_dimensions: usize,
}

/// 单个 AI 模型后端。route 的 `api_type` 冻结 wire 契约；只有显式支持无损转换的 Chat
/// provider adapter 会重写实体，其它 API 保持 provider 原生协议。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmModelCfg {
    /// 配置内稳定、低基数模型 id，用于 metrics/日志；不接受请求动态值。
    pub id: String,
    /// 固定 wire provider；可选值由 `LlmProviderCfg` 定义，不能由请求动态选择。
    pub provider: LlmProviderCfg,
    /// 模型后端地址，支持 `http(s)://` 与 `lb://service`。
    pub uri: String,
    /// 发给 provider 的真实模型名。
    pub model: String,
    /// provider API path；空时使用 provider 安全默认值。
    #[serde(default)]
    pub path: String,
    /// Google SSE API path；空时由 `model` 生成
    /// `/v1beta/models/{model}:streamGenerateContent?alt=sse`。其它 provider 必须留空。
    #[serde(default)]
    pub stream_path: String,
    /// provider API key SecretSource；空表示不注入凭据，适合本地 vLLM/Ollama。
    #[serde(default)]
    pub api_key: String,
    /// 远程 Secret provider 在候选构建期物化的 API key；不参与配置序列化。
    #[serde(skip, default)]
    pub resolved_api_key: Option<String>,
    /// Anthropic API 版本；OpenAI provider 必须留空。
    #[serde(default)]
    pub anthropic_version: String,
    /// Azure API 版本或其它 provider 明确版本；会进入固定 path/query，客户端不能覆盖。
    #[serde(default)]
    pub api_version: String,
    /// 云 provider 固定 region；Bedrock SigV4 scope 与 Vertex endpoint 均由此字段冻结。
    #[serde(default)]
    pub region: String,
    /// Vertex AI 固定 project；只用于构建可信 API path。
    #[serde(default)]
    pub project: String,
    /// AWS access key id SecretSource；仅 Bedrock SigV4 使用。
    #[serde(default)]
    pub aws_access_key_id: String,
    /// 远程 Secret provider 在候选构建期物化的 AWS access key id。
    #[serde(skip, default)]
    pub resolved_aws_access_key_id: Option<String>,
    /// AWS secret access key SecretSource；仅 Bedrock SigV4 使用。
    #[serde(default)]
    pub aws_secret_access_key: String,
    /// 远程 Secret provider 在候选构建期物化的 AWS secret access key。
    #[serde(skip, default)]
    pub resolved_aws_secret_access_key: Option<String>,
    /// AWS 临时 session token SecretSource；仅 Bedrock SigV4 使用，可为空。
    #[serde(default)]
    pub aws_session_token: String,
    /// 远程 Secret provider 在候选构建期物化的 AWS session token。
    #[serde(skip, default)]
    pub resolved_aws_session_token: Option<String>,
    /// 组合云凭据的最早有效截止点；reload 调度不得让其中任一项过期后继续使用旧快照。
    #[serde(skip, default)]
    pub resolved_not_after: Option<std::time::Instant>,
    /// 是否直接使用 provider 原生 request/response，不执行跨 provider 字段转换。
    #[serde(default)]
    pub native_passthrough: bool,
    /// 每百万 prompt token 的微美元成本，用于低基数成本观测；0 表示未知。
    #[serde(default)]
    pub input_cost_microusd_per_million: u64,
    /// 每百万 completion token 的微美元成本；0 表示未知。
    #[serde(default)]
    pub output_cost_microusd_per_million: u64,
    /// image/audio/video/batch/file 等非 token 计价请求的保守固定费用，单位微美元。
    #[serde(default)]
    pub fixed_cost_microusd: u64,
    /// 此模型提供的固定能力标签，如 `multimodal`、`tools`、`structured_output`、加速器、
    /// 拓扑位置、prefix-cache、队列或 LoRA 状态；只接受安全 ASCII token。
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// 冻结 catalog 中的预期首 token 延迟；joint 策略在运行样本不足时使用，单位毫秒。
    #[serde(default)]
    pub expected_first_token_latency_ms: u64,
    /// `selection.strategy=weighted` 的相对权重；0 表示不参与首选但仍可作为 fallback。
    #[serde(default = "default_llm_model_weight")]
    pub weight: u32,
}

/// 多模型选择策略。required_capabilities 在所有策略前先过滤不满足能力的模型。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct LlmSelectionCfg {
    /// `ordered` / `cost` / `latency` / `weighted` / `joint`。
    #[serde(default)]
    pub strategy: LlmSelectionStrategyCfg,
    /// route 固定要求的能力集合，最多 16 项。
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    /// joint 策略的软偏好能力；命中项越多，语义得分越高。
    #[serde(default)]
    pub preferred_capabilities: Vec<String>,
    /// joint 策略允许的首 token 延迟上界；模型声明值或运行 EWMA 超过时不作为首选。
    #[serde(default)]
    pub max_first_token_latency_ms: u64,
    /// 可选 shadow 模型 id；只接收按比例采样的副本，结果永不进入主响应或 fallback。
    #[serde(default)]
    pub shadow_model: String,
    /// shadow 采样万分比，范围 0..=10000。
    #[serde(default)]
    pub shadow_basis_points: u16,
    /// 灰度候选模型 id；命中采样时提升为首选，失败仍回落到正常模型顺序。
    #[serde(default)]
    pub rollout_model: String,
    /// 灰度请求万分比，范围 0..=10000。
    #[serde(default)]
    pub rollout_basis_points: u16,
}

/// 模型首选排序策略。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmSelectionStrategyCfg {
    /// 按配置书写顺序，首项主模型。
    #[default]
    Ordered,
    /// 按 input+output 配置单价从低到高。
    Cost,
    /// 按本进程成功响应头延迟 EWMA 从低到高；无样本时保持配置顺序。
    Latency,
    /// 按配置权重为请求稳定选择首模型，其余保持 fallback 顺序。
    Weighted,
    /// 同时按能力、SLO、估算费用和本进程语义亲和度计算首选顺序。
    Joint,
}

/// LLM token bucket 配额。与 QPS 共用  RateLimiter，但 `cost` 是本次 token 预留值。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmTokenQuotaCfg {
    /// 每个窗口回填的 token 数。
    pub tokens: u64,
    /// 配额窗口毫秒。
    pub window_ms: u64,
    /// 允许额外突发的 token 数。
    #[serde(default)]
    pub burst: u64,
    /// `route` / `consumer` / `api_key`。
    #[serde(default)]
    pub dimension: LlmQuotaDimensionCfg,
    /// 当前规则最多保留的活跃维度数。
    #[serde(default = "default_llm_quota_max_active_keys")]
    pub max_active_keys: usize,
    /// 维度表达到上限时是否 fail-open；默认 false（配额安全优先）。
    #[serde(default)]
    pub active_keys_fail_open: bool,
}

/// LLM token 配额维度。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmQuotaDimensionCfg {
    /// 每 route 共享。
    #[default]
    Route,
    /// 使用已验证的 consumer 身份；匿名请求使用固定 anonymous 桶。
    Consumer,
    /// 使用已验证 API-Key 的 SHA-256 指纹；不把原 key 放进内存 key/Redis key。
    ApiKey,
}

/// Prompt 护栏配置。这里只提供确定、可审计的字符串规则，不假装使用了不存在的 ML 分类器。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmGuardrailsCfg {
    /// 按方向与内容分类声明的有界规则；命中即拒绝，不记录命中内容。
    #[serde(default)]
    pub rules: Vec<crate::ai::guardrail::RuleCfg>,
    /// 流式输出保留的解码文本尾部；必须覆盖每条输出规则的最大匹配长度。
    #[serde(default = "crate::ai::guardrail::default_window_bytes")]
    pub stream_window_bytes: usize,
    /// 统一前置的可信 system prompt；空表示不装饰。只在 LLM 显式慢路径产生一次必要 JSON 重编码。
    #[serde(default)]
    pub system_prompt: String,
    /// ASCII 大小写不敏感的禁止子串，最多 64 条、每条最多 256 字节。
    #[serde(default)]
    pub blocked_substrings: Vec<String>,
    /// 非流式统一响应的禁止子串；命中后不把 provider body 发给下游。
    #[serde(default)]
    pub blocked_response_substrings: Vec<String>,
}

impl Default for LlmGuardrailsCfg {
    /// 业务作用：保持未声明内容策略时的透明转发，并为后续显式规则提供一致的窗口默认值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：空规则、空模板与默认流窗口；不会启动任何内容扫描。
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            stream_window_bytes: crate::ai::guardrail::default_window_bytes(),
            system_prompt: String::new(),
            blocked_substrings: Vec::new(),
            blocked_response_substrings: Vec::new(),
        }
    }
}

/// LLM 模型协议适配器。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LlmProviderCfg {
    /// OpenAI Chat Completions 兼容协议，也用于 vLLM/Ollama 的兼容入口。
    Openai,
    /// Anthropic Messages API。
    Anthropic,
    /// Google Gemini Developer API `generateContent` / `streamGenerateContent`。
    Google,
    /// Azure OpenAI / Microsoft Foundry OpenAI-compatible API。
    AzureOpenai,
    /// AWS Bedrock 原生或 OpenAI-compatible API。
    Bedrock,
    /// Google Vertex AI Gemini API。
    VertexAi,
    /// Cohere v2 native API。
    Cohere,
    /// Mistral API。
    Mistral,
    /// Hugging Face Inference Providers / Endpoint API。
    HuggingFace,
    /// xAI API。
    Xai,
    /// Alibaba Cloud Model Studio / DashScope API。
    Dashscope,
    /// DeepSeek OpenAI-compatible API。
    Deepseek,
    /// Ollama native 或 OpenAI-compatible API。
    Ollama,
    /// vLLM native/OpenAI-compatible API。
    Vllm,
}

/// 业务作用：为未显式声明的 `max_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_max_body_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `max_prompt_tokens` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_max_prompt_tokens() -> u64 {
    128 * 1024
}

/// 业务作用：为未显式声明的 `max_completion_tokens` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_max_completion_tokens() -> u64 {
    8 * 1024
}

/// 业务作用：为未显式声明的 `max_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_max_response_bytes() -> u64 {
    16 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `max_stream_frame_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_max_stream_frame_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `max_duration_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_max_duration_ms() -> u64 {
    120_000
}

/// 业务作用：为未显式声明的 `max_cost_microusd` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_max_cost_microusd() -> u64 {
    u64::MAX
}

/// 业务作用：为未显式声明的 `max_active_keys` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_quota_max_active_keys() -> usize {
    100_000
}

/// 业务作用：为未显式声明的 `ttl_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_cache_ttl_ms() -> u64 {
    300_000
}

/// 业务作用：为未显式声明的 `max_entries` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_cache_max_entries() -> u64 {
    10_000
}

/// 业务作用：为未显式声明的 `max_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_cache_max_response_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `similarity_threshold` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_cache_similarity_threshold() -> f32 {
    0.92
}

/// 业务作用：为未显式声明的 `max_candidates` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_cache_max_candidates() -> usize {
    128
}

/// 业务作用：为未显式声明的 `max_dimensions` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_embedding_max_dimensions() -> usize {
    4096
}

/// 业务作用：为未显式声明的 `weight` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_model_weight() -> u32 {
    100
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_moderation_timeout_ms() -> u64 {
    2_000
}

/// 业务作用：为未显式声明的 `max_request_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_moderation_max_request_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `max_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_llm_moderation_max_response_bytes() -> u64 {
    1024 * 1024
}
