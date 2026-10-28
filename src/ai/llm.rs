//! AI/LLM 独立 API 契约、provider 身份与模型路由。
//!
//! Chat Completions 只在声明无损 adapter 的 provider 间转换；Responses、embedding、rerank、
//! image/audio/video、batch/file 与 Realtime 保持各自原生 wire 契约。所有请求先受 route 字节、
//! 时长和费用预算约束，模型目录与凭据在快照构建期冻结，客户端不能选择 provider path 或身份。

use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cache::expiry::ExpiringCache;
use crate::control::ownership::state::{Budget, Lease};
#[cfg(feature = "ai-governance")]
use anyhow::ensure;
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use http::header::{HeaderValue, AUTHORIZATION, CONTENT_LENGTH, COOKIE, TRANSFER_ENCODING};
use http::request::Parts;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::config::model::{
    LlmApiTypeCfg, LlmCacheScopeCfg, LlmEmbeddingCfg, LlmModelCfg, LlmModerationCfg,
    LlmModerationFailModeCfg, LlmProviderCfg, LlmQuotaDimensionCfg, LlmRouteCfg,
    LlmSelectionStrategyCfg, LlmSemanticCacheCfg, LlmTokenQuotaCfg,
};

/// 单 route 最多允许的 fallback 模型数，限制一次请求最坏尝试次数与配置内存。
const MAX_LLM_MODELS: usize = 16;
/// LLM JSON 请求体硬上限；route 可以收紧，不能放大。
const MAX_LLM_BODY_BYTES: u64 = 16 * 1024 * 1024;
/// Provider 返回的非流式 JSON 最大转换体积，防错误页/恶意上游导致无界聚合。
pub(crate) const MAX_LLM_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Embedding response 单独限制为 4MiB；向量本身还有维度上限，二者共同防御异常 provider。
pub(crate) const MAX_LLM_EMBEDDING_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Redis exact response 二进制格式。固定头避免把任意 Redis 脏值当作可信 JSON body。
const LLM_CACHE_RESPONSE_MAGIC: &[u8; 4] = b"GWLR";
const LLM_CACHE_RESPONSE_VERSION: u8 = 1;

/// 已编译的 LLM route 计划。
pub struct LlmRoutePolicy {
    pub(crate) governance: Option<Arc<super::governance::Plan>>,
    /// 独立 API 契约；非 Chat 类型不进入 Chat adapter。
    pub(crate) api_type: LlmApiType,
    /// 请求体聚合硬上限。
    pub(crate) max_body_bytes: usize,
    /// Prompt 估算硬上限。
    pub(crate) max_prompt_tokens: u64,
    /// Completion 预留/注入硬上限。
    pub(crate) max_completion_tokens: u64,
    /// provider 响应累计字节门。
    pub(crate) max_response_bytes: usize,
    /// 流协议单 frame 字节门。
    pub(crate) max_stream_frame_bytes: usize,
    /// 单次调用或长连接持续时间门。
    pub(crate) max_duration: Duration,
    /// 路由允许的单请求估算费用上限。
    pub(crate) max_cost_microusd: u64,
    /// 可选 token bucket 配额。
    pub(crate) token_quota: Option<LlmTokenQuota>,
    /// 构建期校验后的注入/越权短语。
    blocked_substrings: Arc<[Arc<str>]>,
    /// 可信 system prompt 模板；当前是固定文本，不执行请求变量插值。
    system_prompt: Option<Arc<str>>,
    /// 非流式输出本地审核短语。
    blocked_response_substrings: Arc<[Arc<str>]>,
    /// 同代结构化内容策略；流式输出在交付前使用有界前瞻窗口。
    pub(crate) guardrail: Option<Arc<super::guardrail::Plan>>,
    /// 可选外部 moderation 计划；在模型 admission 前执行。
    pub(crate) moderation: Option<Arc<LlmModerationPolicy>>,
    /// 可选精确 + 语义缓存。状态随 route 快照生命周期走，换版不会串用旧策略 entry。
    pub(crate) semantic_cache: Option<Arc<LlmSemanticCache>>,
    /// 构建期编译的模型首选策略。
    pub(crate) selection: LlmSelectionStrategy,
    /// joint 策略软偏好能力。
    pub(crate) preferred_capabilities: Arc<[Arc<str>]>,
    /// joint 策略首 token SLO；None 表示不按声明延迟淘汰。
    pub(crate) max_first_token_latency: Option<Duration>,
    /// 可选 shadow 模型下标及采样万分比。
    pub(crate) shadow: Option<(usize, u16)>,
    /// 可选灰度模型下标及采样万分比。
    pub(crate) rollout: Option<(usize, u16)>,
    /// 影响响应语义的 route 配置摘要；进入 cache scope，热更 system/model 后不会命中旧 L2。
    pub(crate) cache_salt: [u8; 32],
    /// 主模型在前、fallback 在后的不可变模型 slice。
    models: Arc<[LlmModel]>,
}

/// 已解析凭据、超时和资源上限的外部 OpenAI-compatible moderation 计划。
pub struct LlmModerationPolicy {
    /// `http(s)://` 或 `lb://` 上游。
    pub(crate) upstream: Arc<str>,
    /// 固定 API path。
    pub(crate) path: Arc<str>,
    /// 固定 moderation model。
    model: Arc<str>,
    /// 已解析 bearer token。
    api_key: Option<HeaderValue>,
    /// 调用总超时。
    pub(crate) timeout: Duration,
    /// 序列化 request 硬上限。
    max_request_bytes: usize,
    /// response 聚合硬上限。
    pub(crate) max_response_bytes: usize,
    /// 依赖故障策略。
    pub(crate) fail_mode: LlmModerationFailModeCfg,
}

/// 已编译的 LLM 精确/语义缓存计划。
pub struct LlmSemanticCache {
    workspace_budget: std::sync::OnceLock<Option<Budget>>,
    /// 精确键 L1。值由 `Arc` 共享，命中不会复制响应 `Bytes`。
    exact: ExpiringCache<[u8; 32], LlmCacheEntry>,
    /// 最近语义候选仅保留弱引用，精确缓存到期或淘汰后不能由候选索引继续占住工作区名额。
    semantic: Mutex<VecDeque<std::sync::Weak<LlmCacheEntry>>>,
    ttl: Duration,
    max_entries: usize,
    pub(crate) max_response_bytes: usize,
    threshold: f32,
    max_candidates: usize,
    pub(crate) l2_enabled: bool,
    pub(crate) scope: LlmCacheScopeCfg,
    /// OpenAI-compatible embedding 后端。
    pub(crate) embedding: LlmEmbeddingModel,
}

/// 一条缓存响应及其归一化 embedding。
pub struct LlmCacheEntry {
    _workspace_lease: Option<Lease>,
    /// 原 provider 的成功 JSON；Bytes clone 只增引用计数。
    pub(crate) body: Bytes,
    /// 实际生成响应的配置模型 id，用于响应头与 cache-hit 指标。
    pub(crate) model_id: Arc<str>,
    /// embedding 已在回填时归一化，命中计算只做点积。
    vector: Arc<[f32]>,
    /// 除 prompt/model/stream 外的生成参数摘要；不同温度、工具、输出格式不能语义串缓存。
    params_digest: [u8; 32],
    /// 单调时钟截止点；避免 wall-clock 回拨让 L1 entry 意外延寿。
    expires_at: Instant,
}

/// 已解析凭据与固定请求路径的 embedding 后端。
pub struct LlmEmbeddingModel {
    /// `http(s)://` 或 `lb://` 上游。
    pub(crate) upstream: Arc<str>,
    /// OpenAI-compatible embedding model 名称。
    model: Arc<str>,
    /// Provider path。
    pub(crate) path: Arc<str>,
    /// 已解析的 bearer token。
    api_key: Option<HeaderValue>,
    /// 响应向量维度硬上限。
    pub(crate) max_dimensions: usize,
}

/// 已解析 SecretSource 与 provider 默认值的单模型计划。
pub struct LlmModel {
    /// 低基数配置 id。
    pub(crate) id: Arc<str>,
    /// Wire provider。
    pub(crate) provider: LlmProvider,
    /// 此模型参与的 route API 类型。
    pub(crate) api_type: LlmApiType,
    /// `http(s)://` 或 `lb://` 上游。
    pub(crate) upstream: Arc<str>,
    /// Provider 模型名。
    model: Arc<str>,
    /// Provider API path。
    pub(crate) path: Arc<str>,
    /// Google SSE API path；其它 provider 为 None。
    stream_path: Option<Arc<str>>,
    /// 已解析的 provider API key header 值。
    api_key: Option<HeaderValue>,
    /// Anthropic 强制版本 header。
    anthropic_version: Option<HeaderValue>,
    /// 云 provider 固定 region。
    region: Option<Arc<str>>,
    /// Bedrock SigV4 access key id。
    aws_access_key_id: Option<Arc<str>>,
    /// Bedrock SigV4 secret access key，只驻留不可变快照内存。
    aws_secret_access_key: Option<Arc<[u8]>>,
    /// Bedrock 临时 session token。
    aws_session_token: Option<HeaderValue>,
    /// 是否保持 provider 原生 request/response。
    pub(crate) native_passthrough: bool,
    /// 每百万 prompt token 的微美元价格。
    pub(crate) input_cost_microusd_per_million: u64,
    /// 每百万 completion token 的微美元价格。
    pub(crate) output_cost_microusd_per_million: u64,
    /// 非 token 请求的固定估算费用。
    pub(crate) fixed_cost_microusd: u64,
    /// 构建期冻结的能力集合。
    pub(crate) capabilities: Arc<[Arc<str>]>,
    /// catalog 声明的首 token 延迟。
    pub(crate) expected_first_token_latency: Option<Duration>,
    /// weighted 首选权重；0 只作为 fallback。
    pub(crate) weight: u32,
}

/// 已编译的 token 配额规则。
pub struct LlmTokenQuota {
    /// 每 window 回填 token 数。
    pub(crate) limit: u64,
    /// 配额窗口。
    pub(crate) window: Duration,
    /// 突发 token 容量。
    pub(crate) burst: u64,
    /// 身份维度。
    pub(crate) dimension: LlmQuotaDimensionCfg,
    /// 高基数维度硬上限。
    pub(crate) max_active_keys: usize,
    /// 维度溢出策略。
    pub(crate) active_keys_fail_open: bool,
}

/// 运行期 provider 枚举；与 serde 配置解耦，便于后续增加 Gemini adapter 而不污染热路径。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmProvider {
    /// OpenAI-compatible Chat Completions。
    Openai,
    /// Anthropic Messages。
    Anthropic,
    /// Google Gemini Developer API。
    Google,
    AzureOpenai,
    Bedrock,
    VertexAi,
    Cohere,
    Mistral,
    HuggingFace,
    Xai,
    Dashscope,
    Deepseek,
    Ollama,
    Vllm,
}

impl LlmProvider {
    /// 业务作用：为 provider 观测提供固定枚举标签，不将客户端模型参数作为协议分类。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：低基数 provider 名称。
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
            Self::AzureOpenai => "azure_openai",
            Self::Bedrock => "bedrock",
            Self::VertexAi => "vertex_ai",
            Self::Cohere => "cohere",
            Self::Mistral => "mistral",
            Self::HuggingFace => "hugging_face",
            Self::Xai => "xai",
            Self::Dashscope => "dashscope",
            Self::Deepseek => "deepseek",
            Self::Ollama => "ollama",
            Self::Vllm => "vllm",
        }
    }
}

/// 与 Chat adapter 解耦的 AI API 类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmApiType {
    ChatCompletions,
    Responses,
    Embeddings,
    Rerank,
    Image,
    Audio,
    Video,
    Batch,
    File,
    Realtime,
}

/// 与 serde 配置解耦的模型首选策略。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmSelectionStrategy {
    /// 配置顺序。
    Ordered,
    /// 配置价格从低到高。
    Cost,
    /// 进程内成功 TTFB EWMA 从低到高。
    Latency,
    /// 请求稳定哈希按权重选择首模型。
    Weighted,
    /// 能力、SLO、费用与运行延迟联合排序。
    Joint,
}

/// Provider 回传的真实 token 计数。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LlmUsage {
    /// Prompt/input token。
    pub prompt_tokens: u64,
    /// Completion/output token。
    pub completion_tokens: u64,
}

/// Redis 语义索引成员。响应 body 单独保存在 exact key，索引只携带摘要与向量，避免每次候选
/// 查询把多个完整模型响应搬过网络。
#[derive(Serialize, Deserialize)]
pub(crate) struct LlmL2Candidate {
    exact_digest: [u8; 32],
    params_digest: [u8; 32],
    vector: Vec<f32>,
}

/// 只解析一次的统一请求。`raw` 与 JSON DOM 同时保留：前者支持无改写的 Bytes 复用，后者供
/// token/护栏检查和 provider 转换复用，fallback 不重新解析下游字节。
pub struct ParsedLlmRequest {
    raw: Bytes,
    document: Value,
    /// 客户端是否请求 SSE。
    pub stream: bool,
    /// 基于 UTF-8 字节上界的保守 prompt token 预留；后续 provider usage 用于多退少补。
    pub prompt_tokens: u64,
    /// 客户端声明的 completion 上限；未声明时为 None。
    pub max_completion_tokens: Option<u64>,
    /// DOM 是否仍与 `raw` 完全一致；首次同模型 OpenAI 转发可据此零复制复用 body。
    pristine: bool,
}

impl LlmRoutePolicy {
    /// 业务作用：在候选快照构建期编译模型、内容策略、缓存隔离与 SecretSource。
    ///
    /// 参数说明：
    /// - `cfg`：是完整路由 AI 配置
    /// - `config_dir`：用于本地依赖定位
    /// - `route_id`：是固定路由身份。
    ///
    /// 返回：所有模型和策略有效时返回不可变计划；任一不兼容或超限拒绝整个候选，不产生 provider 请求。
    pub fn build(cfg: &LlmRouteCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
        let api_type = match cfg.api_type {
            LlmApiTypeCfg::ChatCompletions => LlmApiType::ChatCompletions,
            LlmApiTypeCfg::Responses => LlmApiType::Responses,
            LlmApiTypeCfg::Embeddings => LlmApiType::Embeddings,
            LlmApiTypeCfg::Rerank => LlmApiType::Rerank,
            LlmApiTypeCfg::Image => LlmApiType::Image,
            LlmApiTypeCfg::Audio => LlmApiType::Audio,
            LlmApiTypeCfg::Video => LlmApiType::Video,
            LlmApiTypeCfg::Batch => LlmApiType::Batch,
            LlmApiTypeCfg::File => LlmApiType::File,
            LlmApiTypeCfg::Realtime => LlmApiType::Realtime,
        };
        if !(1..=MAX_LLM_BODY_BYTES).contains(&cfg.max_body_bytes) {
            bail!("route `{route_id}` llm.max_body_bytes must be within 1..={MAX_LLM_BODY_BYTES}");
        }
        if !(1..=MAX_LLM_RESPONSE_BYTES as u64).contains(&cfg.max_response_bytes) {
            bail!(
                "route `{route_id}` llm.max_response_bytes must be within 1..={MAX_LLM_RESPONSE_BYTES}"
            );
        }
        if cfg.max_stream_frame_bytes == 0
            || cfg.max_stream_frame_bytes > cfg.max_response_bytes
            || cfg.max_stream_frame_bytes > 4 * 1024 * 1024
        {
            bail!("route `{route_id}` llm.max_stream_frame_bytes must be positive, no larger than max_response_bytes, and <=4194304");
        }
        if !(1..=86_400_000).contains(&cfg.max_duration_ms) {
            bail!("route `{route_id}` llm.max_duration_ms must be within 1..=86400000");
        }
        if cfg.max_cost_microusd == 0 {
            bail!("route `{route_id}` llm.max_cost_microusd must be positive");
        }
        if api_type != LlmApiType::ChatCompletions
            && (cfg.governance.is_some()
                || cfg.moderation.is_some()
                || cfg.semantic_cache.is_some()
                || cfg.token_quota.is_some()
                || !cfg.guardrails.system_prompt.is_empty()
                || !cfg.guardrails.blocked_substrings.is_empty()
                || !cfg.guardrails.blocked_response_substrings.is_empty()
                || !cfg.guardrails.rules.is_empty())
        {
            bail!("route `{route_id}` non-Chat API cannot enable Chat-only moderation, semantic_cache, token_quota, or prompt guardrails");
        }
        if cfg.models.is_empty() || cfg.models.len() > MAX_LLM_MODELS {
            bail!("route `{route_id}` llm.models must contain 1..={MAX_LLM_MODELS} entries");
        }
        if cfg.selection.required_capabilities.len() > 16 {
            bail!("route `{route_id}` llm.selection supports at most 16 required_capabilities");
        }
        let mut required = HashSet::with_capacity(cfg.selection.required_capabilities.len());
        for capability in &cfg.selection.required_capabilities {
            validate_capability(capability, route_id)?;
            if !required.insert(capability.as_str()) {
                bail!("route `{route_id}` has duplicate required LLM capability `{capability}`");
            }
        }
        let selection = match cfg.selection.strategy {
            LlmSelectionStrategyCfg::Ordered => LlmSelectionStrategy::Ordered,
            LlmSelectionStrategyCfg::Cost => LlmSelectionStrategy::Cost,
            LlmSelectionStrategyCfg::Latency => LlmSelectionStrategy::Latency,
            LlmSelectionStrategyCfg::Weighted => LlmSelectionStrategy::Weighted,
            LlmSelectionStrategyCfg::Joint => LlmSelectionStrategy::Joint,
        };
        if cfg.selection.preferred_capabilities.len() > 16 {
            bail!("route `{route_id}` llm.selection supports at most 16 preferred_capabilities");
        }
        let mut preferred = HashSet::with_capacity(cfg.selection.preferred_capabilities.len());
        for capability in &cfg.selection.preferred_capabilities {
            validate_capability(capability, route_id)?;
            if !preferred.insert(capability.as_str()) {
                bail!("route `{route_id}` has duplicate preferred LLM capability `{capability}`");
            }
        }
        if cfg.selection.shadow_basis_points > 10_000 || cfg.selection.rollout_basis_points > 10_000
        {
            bail!("route `{route_id}` LLM shadow/rollout basis points must be <=10000");
        }
        if cfg.selection.shadow_model.is_empty() != (cfg.selection.shadow_basis_points == 0) {
            bail!("route `{route_id}` LLM shadow_model and positive shadow_basis_points must be configured together");
        }
        if cfg.selection.rollout_model.is_empty() != (cfg.selection.rollout_basis_points == 0) {
            bail!("route `{route_id}` LLM rollout_model and positive rollout_basis_points must be configured together");
        }
        if !cfg.selection.shadow_model.is_empty()
            && cfg.selection.shadow_model == cfg.selection.rollout_model
        {
            bail!("route `{route_id}` LLM shadow and rollout models must be distinct");
        }
        let mut ids = HashSet::with_capacity(cfg.models.len());
        let mut models = Vec::with_capacity(cfg.models.len());
        for model in &cfg.models {
            validate_model_id(model.id.as_str(), route_id)?;
            if !ids.insert(model.id.as_str()) {
                bail!(
                    "route `{route_id}` has duplicate llm model id `{}`",
                    model.id
                );
            }
            if model.capabilities.len() > 32 {
                bail!(
                    "route `{route_id}` llm model `{}` supports at most 32 capabilities",
                    model.id
                );
            }
            let mut capabilities = HashSet::with_capacity(model.capabilities.len());
            for capability in &model.capabilities {
                validate_capability(capability, route_id)?;
                if !capabilities.insert(capability.as_str()) {
                    bail!(
                        "route `{route_id}` llm model `{}` has duplicate capability `{capability}`",
                        model.id
                    );
                }
            }
            let built = LlmModel::build(model, config_dir, route_id, api_type)?;
            if required
                .iter()
                .all(|capability| capabilities.contains(capability))
            {
                models.push(built);
            }
        }
        if models.is_empty() {
            bail!("route `{route_id}` has no LLM model satisfying selection.required_capabilities");
        }
        if selection == LlmSelectionStrategy::Weighted
            && models.iter().all(|model| model.weight == 0)
        {
            bail!("route `{route_id}` weighted LLM selection requires at least one positive model weight");
        }
        if selection == LlmSelectionStrategy::Cost {
            // 稳定排序保留相同价格的配置顺序；价格为 0 表示未知，统一排在已知价格之后。
            models.sort_by_key(|model| {
                let total = model
                    .input_cost_microusd_per_million
                    .saturating_add(model.output_cost_microusd_per_million);
                (total == 0, total)
            });
        }
        let model_index = |id: &str, field: &str| -> Result<Option<usize>> {
            if id.is_empty() {
                return Ok(None);
            }
            models
                .iter()
                .position(|model| model.id.as_ref() == id)
                .map(Some)
                .with_context(|| {
                    format!(
                        "route `{route_id}` llm.selection.{field} references an unavailable model"
                    )
                })
        };
        let shadow = model_index(cfg.selection.shadow_model.as_str(), "shadow_model")?
            .map(|index| (index, cfg.selection.shadow_basis_points));
        let rollout = model_index(cfg.selection.rollout_model.as_str(), "rollout_model")?
            .map(|index| (index, cfg.selection.rollout_basis_points));
        if shadow.is_some() && models.len() < 2 {
            bail!("route `{route_id}` LLM shadow evaluation requires a distinct main model");
        }
        if api_type == LlmApiType::Realtime && shadow.is_some() {
            bail!("route `{route_id}` realtime API cannot duplicate a bidirectional upgrade as shadow traffic");
        }
        if cfg.max_prompt_tokens == 0 || cfg.max_prompt_tokens > 16 * 1024 * 1024 {
            bail!("route `{route_id}` llm.max_prompt_tokens must be within 1..=16777216");
        }
        if cfg.max_completion_tokens == 0 || cfg.max_completion_tokens > 16 * 1024 * 1024 {
            bail!("route `{route_id}` llm.max_completion_tokens must be within 1..=16777216");
        }
        let token_quota = cfg
            .token_quota
            .as_ref()
            .map(|quota| LlmTokenQuota::build(quota, route_id))
            .transpose()?;
        let semantic_cache = cfg
            .semantic_cache
            .as_ref()
            .map(|cache| LlmSemanticCache::build(cache, config_dir, route_id))
            .transpose()?
            .map(Arc::new);
        let governance = super::governance::build(cfg.governance.as_ref(), config_dir)?;
        anyhow::ensure!(
            governance.is_none() || cfg.semantic_cache.is_none(),
            "request_only AI governance cannot enable response caches"
        );
        anyhow::ensure!(
            governance.is_none() || shadow.is_none(),
            "request_only AI governance cannot duplicate retrieval context into shadow requests"
        );
        let blocked = compile_guardrail_patterns(
            &cfg.guardrails.blocked_substrings,
            route_id,
            "blocked_substrings",
        )?;
        let blocked_response_substrings = compile_guardrail_patterns(
            &cfg.guardrails.blocked_response_substrings,
            route_id,
            "blocked_response_substrings",
        )?;
        let moderation = cfg
            .moderation
            .as_ref()
            .map(|moderation| LlmModerationPolicy::build(moderation, config_dir, route_id))
            .transpose()?
            .map(Arc::new);
        let guardrail = super::guardrail::Plan::build(
            &cfg.guardrails.rules,
            &cfg.guardrails.blocked_response_substrings,
            cfg.guardrails.stream_window_bytes,
        )?;
        // 原生非 Chat SSE 没有统一的文本增量结构；不能把无法检查的流当成已通过输出防护。
        if governance.is_some()
            || guardrail
                .as_ref()
                .is_some_and(|plan| plan.enabled(super::guardrail::Direction::Response))
        {
            ensure_guarded_models(&models)?;
        }
        if cfg.guardrails.system_prompt.len() > 16 * 1024
            || cfg.guardrails.system_prompt.bytes().any(|byte| byte == 0)
        {
            bail!(
                "route `{route_id}` llm.guardrails.system_prompt must be <=16384 bytes without NUL"
            );
        }
        let system_prompt = (!cfg.guardrails.system_prompt.is_empty())
            .then(|| Arc::from(cfg.guardrails.system_prompt.as_str()));
        let mut cache_salt = Sha256::new();
        cache_salt.update(b"gw-llm-policy-v1\0");
        hash_digest_part(&mut cache_salt, &serde_json::to_vec(&cfg.guardrails.rules)?);
        hash_digest_part(&mut cache_salt, cfg.guardrails.system_prompt.as_bytes());
        for pattern in &cfg.guardrails.blocked_response_substrings {
            hash_digest_part(&mut cache_salt, pattern.as_bytes());
        }
        if let Some(moderation) = &moderation {
            hash_digest_part(&mut cache_salt, moderation.upstream.as_bytes());
            hash_digest_part(&mut cache_salt, moderation.path.as_bytes());
            hash_digest_part(&mut cache_salt, moderation.model.as_bytes());
            cache_salt.update(moderation.timeout.as_millis().to_be_bytes());
            cache_salt.update([moderation.fail_mode as u8]);
        }
        cache_salt.update(cfg.max_completion_tokens.to_be_bytes());
        cache_salt.update([selection as u8]);
        for model in &models {
            hash_digest_part(&mut cache_salt, model.id.as_bytes());
            hash_digest_part(&mut cache_salt, model.model.as_bytes());
            hash_digest_part(&mut cache_salt, model.upstream.as_bytes());
            hash_digest_part(&mut cache_salt, model.path.as_bytes());
            if let Some(path) = &model.stream_path {
                hash_digest_part(&mut cache_salt, path.as_bytes());
            }
            cache_salt.update([model.provider as u8]);
        }
        Ok(Self {
            api_type,
            governance,
            max_body_bytes: cfg.max_body_bytes as usize,
            max_prompt_tokens: cfg.max_prompt_tokens,
            max_completion_tokens: cfg.max_completion_tokens,
            max_response_bytes: cfg.max_response_bytes as usize,
            max_stream_frame_bytes: cfg.max_stream_frame_bytes as usize,
            max_duration: Duration::from_millis(cfg.max_duration_ms),
            max_cost_microusd: cfg.max_cost_microusd,
            token_quota,
            blocked_substrings: blocked.into(),
            system_prompt,
            blocked_response_substrings: blocked_response_substrings.into(),
            guardrail,
            moderation,
            semantic_cache,
            selection,
            preferred_capabilities: cfg
                .selection
                .preferred_capabilities
                .iter()
                .map(|value| Arc::from(value.as_str()))
                .collect::<Vec<_>>()
                .into(),
            max_first_token_latency: (cfg.selection.max_first_token_latency_ms > 0)
                .then(|| Duration::from_millis(cfg.selection.max_first_token_latency_ms)),
            shadow,
            rollout,
            cache_salt: cache_salt.finalize().into(),
            models: models.into(),
        })
    }

    /// 业务作用：返回不可变的有序模型列表；遍历顺序就是 fallback 顺序。
    pub(crate) fn models(&self) -> &[LlmModel] {
        self.models.as_ref()
    }

    /// 业务作用：返回首个命中的 prompt 护栏规则；比较过程只借用 JSON 字符串，不拼接完整 prompt。
    pub(crate) fn blocked_prompt<'a>(&'a self, request: &ParsedLlmRequest) -> Option<&'a str> {
        self.blocked_substrings
            .iter()
            .find(|pattern| request.prompt_contains(pattern.as_ref()))
            .map(AsRef::as_ref)
    }

    /// 业务作用：在注入可信模板、查询缓存和调用 provider 前检查客户端 JSON 中的结构化内容。
    ///
    /// 参数说明：
    /// - `request`：是已完成语法与体积校验的客户端请求。
    ///
    /// 返回：命中时返回固定分类；无策略或未命中时返回 None。
    pub(crate) fn classify_prompt(
        &self,
        request: &ParsedLlmRequest,
    ) -> Option<super::guardrail::Category> {
        self.guardrail
            .as_ref()?
            .inspect_json(super::guardrail::Direction::Request, &request.document)
    }

    /// 业务作用：把固定 system prompt 注入请求；不存在时保持原始 Bytes 可复用状态。
    pub(crate) fn decorate_prompt(&self, request: &mut ParsedLlmRequest) -> Result<()> {
        if let Some(prompt) = &self.system_prompt {
            request.prepend_system_prompt(prompt.as_ref())?;
        }
        Ok(())
    }

    /// 业务作用：在缓存回填和下游交付前检查非流式统一 JSON 的内容策略。
    ///
    /// 参数说明：
    /// - `body`：是已受响应字节预算约束的 provider 实体。
    ///
    /// 返回：命中任一兼容短语或结构化规则时为 true；无命中为 false；无法解析时拒绝交付。
    pub(crate) fn blocked_response(&self, body: &[u8]) -> Result<bool> {
        Ok(self.classify_response(body)?.is_some())
    }

    /// 业务作用：为非流式输出裁决保留固定内容分类，用于不含原文的观测。
    ///
    /// 参数说明：
    /// - `body`：是已经受体积约束的统一 JSON 响应。
    ///
    /// 返回：命中规则时返回分类，未命中时返回 None；无效 JSON 返回错误。
    pub(crate) fn classify_response(
        &self,
        body: &[u8],
    ) -> Result<Option<super::guardrail::Category>> {
        if self.blocked_response_substrings.is_empty() && self.guardrail.is_none() {
            return Ok(None);
        }
        let value: Value = serde_json::from_slice(body).context("LLM response is not JSON")?;
        if let Some(category) = self
            .guardrail
            .as_ref()
            .and_then(|plan| plan.inspect_json(super::guardrail::Direction::Response, &value))
        {
            return Ok(Some(category));
        }
        Ok(self
            .blocked_response_substrings
            .iter()
            .any(|pattern| value_contains(&value, pattern.as_ref()))
            .then_some(super::guardrail::Category::Content))
    }
}

/// 业务作用：拒绝无法按统一 Chat 增量语义审核的 provider 原生流。
///
/// 参数说明：
/// - `models`：是当前 route 的完整模型目录，包括备用与影子模型。
///
/// 返回：所有潜在响应均可检查时成功，否则拒绝候选配置，不允许 fallback 绕过内容策略。
fn ensure_guarded_models(models: &[LlmModel]) -> Result<()> {
    for model in models {
        anyhow::ensure!(
            !model.native_passthrough
                || !matches!(
                    model.provider,
                    LlmProvider::Anthropic
                        | LlmProvider::Google
                        | LlmProvider::VertexAi
                        | LlmProvider::Cohere
                ),
            "AI output guardrail requires a unified Chat SSE model"
        );
    }
    Ok(())
}

impl LlmSemanticCache {
    /// 业务作用：冻结语义缓存的阈值、容量和嵌入模型，拒绝无法约束成本或授权域的配置。
    fn build(cfg: &LlmSemanticCacheCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
        if !(1..=604_800_000).contains(&cfg.ttl_ms) {
            bail!("route `{route_id}` llm.semantic_cache.ttl_ms must be within 1..=604800000");
        }
        if cfg.max_entries == 0 || cfg.max_entries > 1_000_000 {
            bail!("route `{route_id}` llm.semantic_cache.max_entries must be within 1..=1000000");
        }
        if !(1..=MAX_LLM_RESPONSE_BYTES as u64).contains(&cfg.max_response_bytes) {
            bail!(
                "route `{route_id}` llm.semantic_cache.max_response_bytes must be within 1..={MAX_LLM_RESPONSE_BYTES}"
            );
        }
        if !cfg.similarity_threshold.is_finite() || !(0.0..=1.0).contains(&cfg.similarity_threshold)
        {
            bail!("route `{route_id}` llm.semantic_cache.similarity_threshold must be finite within 0.0..=1.0");
        }
        if cfg.max_candidates == 0 || cfg.max_candidates > 1024 {
            bail!("route `{route_id}` llm.semantic_cache.max_candidates must be within 1..=1024");
        }
        let embedding = LlmEmbeddingModel::build(&cfg.embedding, config_dir, route_id)?;
        // 一次请求的浮点乘加工作量也必须有上限；候选数和维度各自合法仍可能组合成 CPU 放大器。
        if cfg.max_candidates.saturating_mul(embedding.max_dimensions) > 1_048_576 {
            bail!("route `{route_id}` llm.semantic_cache max_candidates * embedding.max_dimensions must be <= 1048576");
        }
        Ok(Self {
            workspace_budget: std::sync::OnceLock::new(),
            exact: ExpiringCache::new(cfg.max_entries),
            semantic: Mutex::new(VecDeque::with_capacity(
                usize::try_from(cfg.max_entries.min(65_536)).unwrap_or(65_536),
            )),
            ttl: Duration::from_millis(cfg.ttl_ms),
            max_entries: cfg.max_entries as usize,
            max_response_bytes: cfg.max_response_bytes as usize,
            threshold: cfg.similarity_threshold,
            max_candidates: cfg.max_candidates,
            l2_enabled: cfg.l2,
            scope: cfg.scope,
            embedding,
        })
    }

    /// 业务作用：将缓存绑定到主管线已经冻结的路由归属，所有精确与语义条目共用该预算。
    ///
    /// 参数说明：
    /// - `parts`：只读取配置注入的 Budget，不读取客户端工作区头。
    ///
    /// 返回：保存预算并登记到期回收；无法登记时后续插入只返回临时响应，不驻留。
    pub(crate) fn bind_budget(&self, parts: &Parts) {
        let budget = self
            .workspace_budget
            .get_or_init(|| parts.extensions.get::<Budget>().cloned());
        self.exact.bind_budget(budget.as_ref());
    }

    /// 业务作用：提供已冻结的归属预算，供 L2 写入执行同域容量门。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：工作区预算引用；平台缓存返回 None。
    pub(crate) fn budget(&self) -> Option<&Budget> {
        self.workspace_budget.get().and_then(Option::as_ref)
    }

    /// 业务作用：查询精确 L1；过期 entry 被主动失效，返回的 `Arc` 与响应体共享底层 allocation。
    pub(crate) async fn lookup_exact(&self, key: &[u8; 32]) -> Option<Arc<LlmCacheEntry>> {
        let entry = self.exact.get(key).await?;
        if entry.expires_at > Instant::now() {
            Some(entry)
        } else {
            self.exact.invalidate(key).await;
            None
        }
    }

    /// 业务作用：在最近的有界候选中计算余弦相似度。向量已归一化，因此只做借用 slice 的点积，
    /// 不为候选构造临时 Vec；维度/生成参数不一致的 entry 会直接跳过。
    pub(crate) fn lookup_semantic(
        &self,
        params_digest: &[u8; 32],
        vector: &[f32],
    ) -> Option<Arc<LlmCacheEntry>> {
        let now = Instant::now();
        let mut entries = self.semantic.lock();
        entries.retain(|entry| entry.upgrade().is_some_and(|entry| entry.expires_at > now));
        let mut best: Option<(f32, Arc<LlmCacheEntry>)> = None;
        for entry in entries
            .iter()
            .rev()
            .take(self.max_candidates)
            .filter_map(std::sync::Weak::upgrade)
        {
            if &entry.params_digest != params_digest || entry.vector.len() != vector.len() {
                continue;
            }
            let similarity = entry
                .vector
                .iter()
                .zip(vector)
                .fold(0.0_f32, |sum, (left, right)| left.mul_add(*right, sum));
            if similarity >= self.threshold
                && best
                    .as_ref()
                    .is_none_or(|(current, _)| similarity > *current)
            {
                best = Some((similarity, entry.clone()));
            }
        }
        best.map(|(_, entry)| entry)
    }

    /// 业务作用：在工作区容量内写入精确缓存与弱引用语义索引，正文与向量不重复复制。
    ///
    /// 参数说明：
    /// - `key`：是完整授权域和生成参数摘要
    /// - `params_digest`：是完整授权域和生成参数摘要
    /// - `vector`：为受限向量
    /// - `body`：为可信 provider 响应。
    /// - `model_id`：为可信 provider 响应。
    ///
    /// 返回：共享响应；预算耗尽时只返回临时值，不创建常驻条目。
    pub(crate) async fn insert(
        &self,
        key: [u8; 32],
        params_digest: [u8; 32],
        vector: Arc<[f32]>,
        body: Bytes,
        model_id: Arc<str>,
    ) -> Arc<LlmCacheEntry> {
        let admission = if self.exact.bind_budget(self.budget()) {
            self.budget().map(Budget::acquire).transpose()
        } else {
            Err(crate::control::ownership::ReservationDenied)
        };
        let cacheable = admission.is_ok();
        let expires_at = Instant::now() + self.ttl;
        let entry = LlmCacheEntry {
            _workspace_lease: admission.ok().flatten(),
            body,
            model_id,
            vector,
            params_digest,
            expires_at,
        };
        if !cacheable {
            return Arc::new(entry);
        }
        let entry = self.exact.insert(key, entry, expires_at).await;
        if !entry.vector.is_empty() {
            let mut entries = self.semantic.lock();
            entries.retain(|entry| entry.strong_count() != 0);
            entries.push_back(Arc::downgrade(&entry));
            while entries.len() > self.max_entries {
                entries.pop_front();
            }
        }
        entry
    }

    /// 业务作用：缓存 TTL，供 Redis L2 使用同一策略。
    pub(crate) fn ttl(&self) -> Duration {
        self.ttl
    }

    /// 业务作用：单 scope 的 L2 索引最大 entry 数。
    pub(crate) fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// 业务作用：最多从 L2 拉取的最近候选数。
    pub(crate) fn max_candidates(&self) -> usize {
        self.max_candidates
    }

    /// 业务作用：语义命中阈值。
    pub(crate) fn threshold(&self) -> f32 {
        self.threshold
    }
}

impl LlmEmbeddingModel {
    /// 业务作用：编译固定嵌入模型的调用目标与凭据，使请求不能自行选择外呼地址。
    fn build(cfg: &LlmEmbeddingCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
        validate_upstream(cfg.uri.as_str(), route_id, "embedding")?;
        if cfg.model.trim().is_empty() || cfg.model.len() > 256 {
            bail!("route `{route_id}` llm.semantic_cache.embedding.model must be 1..=256 bytes");
        }
        let path = if cfg.path.is_empty() {
            "/v1/embeddings"
        } else {
            cfg.path.as_str()
        };
        validate_provider_path(path, route_id, "embedding")?;
        if cfg.max_dimensions == 0 || cfg.max_dimensions > 65_536 {
            bail!("route `{route_id}` llm.semantic_cache.embedding.max_dimensions must be within 1..=65536");
        }
        let api_key = resolve_api_key(cfg.api_key.as_str(), config_dir, route_id, "embedding")?;
        Ok(Self {
            upstream: Arc::from(cfg.uri.as_str()),
            model: Arc::from(cfg.model.as_str()),
            path: Arc::from(path),
            api_key,
            max_dimensions: cfg.max_dimensions,
        })
    }

    /// 业务作用：清除下游信任边界凭据并注入 embedding provider bearer token。
    pub(crate) fn prepare_headers(&self, parts: &mut Parts) {
        parts.headers.remove(AUTHORIZATION);
        parts.headers.remove(COOKIE);
        parts.headers.remove("x-api-key");
        parts.headers.remove("anthropic-version");
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(TRANSFER_ENCODING);
        parts.headers.remove(http::header::ACCEPT_ENCODING);
        parts.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(key) = &self.api_key {
            let mut value = Vec::with_capacity("Bearer ".len() + key.as_bytes().len());
            value.extend_from_slice(b"Bearer ");
            value.extend_from_slice(key.as_bytes());
            if let Ok(mut value) = HeaderValue::from_bytes(&value) {
                value.set_sensitive(true);
                parts.headers.insert(AUTHORIZATION, value);
            }
        }
    }
}

impl LlmModerationPolicy {
    /// 业务作用：在候选快照构建期解析 external moderation 的 endpoint、SecretSource 与资源门。
    ///
    /// 参数说明：
    /// - `cfg`：是 route moderation 配置
    /// - `config_dir`：是 SecretSource 相对目录
    /// - `route_id`：用于错误定位。
    ///
    /// 返回：所有边界合法时返回不可变调用计划；超时、体积、URI、model 或凭据非法时拒绝候选快照。
    pub(crate) fn build(cfg: &LlmModerationCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
        validate_upstream(cfg.uri.as_str(), route_id, "moderation")?;
        if cfg.model.trim().is_empty()
            || cfg.model.len() > 256
            || cfg
                .model
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            bail!("route `{route_id}` llm.moderation.model must be 1..=256 bytes without control characters");
        }
        let path = if cfg.path.is_empty() {
            "/v1/moderations"
        } else {
            cfg.path.as_str()
        };
        validate_provider_path(path, route_id, "moderation")?;
        if !(1..=60_000).contains(&cfg.timeout_ms) {
            bail!("route `{route_id}` llm.moderation.timeout_ms must be within 1..=60000");
        }
        if !(1..=MAX_LLM_BODY_BYTES).contains(&cfg.max_request_bytes) {
            bail!(
                "route `{route_id}` llm.moderation.max_request_bytes must be within 1..={MAX_LLM_BODY_BYTES}"
            );
        }
        if !(1..=4 * 1024 * 1024).contains(&cfg.max_response_bytes) {
            bail!(
                "route `{route_id}` llm.moderation.max_response_bytes must be within 1..=4194304"
            );
        }
        let api_key = resolve_api_key(cfg.api_key.as_str(), config_dir, route_id, "moderation")?;
        Ok(Self {
            upstream: Arc::from(cfg.uri.as_str()),
            path: Arc::from(path),
            model: Arc::from(cfg.model.as_str()),
            api_key,
            timeout: Duration::from_millis(cfg.timeout_ms),
            max_request_bytes: cfg.max_request_bytes as usize,
            max_response_bytes: cfg.max_response_bytes as usize,
            fail_mode: cfg.fail_mode,
        })
    }

    /// 业务作用：构造仅包含统一 prompt 文本与固定 model 的 external moderation 请求。
    ///
    /// 参数说明：
    /// - `request`：是完成可信 system prompt 注入后的统一请求。
    ///
    /// 返回：纯文本 prompt 可在 request 硬上限内序列化时返回 body；多模态块或超限时失败闭合。
    pub(crate) fn body(&self, request: &ParsedLlmRequest) -> Result<Bytes> {
        let messages = request
            .document
            .get("messages")
            .and_then(Value::as_array)
            .expect("LLM messages validated at parse");
        let mut input = String::with_capacity(
            usize::try_from(request.prompt_tokens.saturating_mul(4))
                .unwrap_or(usize::MAX)
                .min(self.max_request_bytes),
        );
        for message in messages {
            let message = message.as_object().expect("LLM message validated at parse");
            input.push_str(
                message
                    .get("role")
                    .and_then(Value::as_str)
                    .expect("LLM role validated at parse"),
            );
            input.push(':');
            input.push_str(&strict_content_text(
                message
                    .get("content")
                    .expect("LLM content validated at parse"),
            )?);
            input.push('\n');
            if input.len() > self.max_request_bytes {
                bail!("LLM moderation input exceeds request limit");
            }
        }
        let body = serde_json::to_vec(&json!({
            "model":self.model.as_ref(),
            "input":input
        }))
        .map(Bytes::from)
        .context("encode LLM moderation request")?;
        if body.len() > self.max_request_bytes {
            bail!("LLM moderation request exceeds request limit");
        }
        Ok(body)
    }

    /// 业务作用：清除下游凭据并注入 external moderation bearer token，维持独立信任边界。
    ///
    /// 参数说明：
    /// - `parts`：是将发送给 moderation endpoint 的请求头副本。
    ///
    /// 返回：无；原地清除客户端/provider 专属认证字段并设置 JSON content type。
    pub(crate) fn prepare_headers(&self, parts: &mut Parts) {
        parts.headers.remove(AUTHORIZATION);
        parts.headers.remove(COOKIE);
        parts.headers.remove("x-api-key");
        parts.headers.remove("x-goog-api-key");
        parts.headers.remove("api-key");
        parts.headers.remove("anthropic-version");
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(TRANSFER_ENCODING);
        parts.headers.remove(http::header::ACCEPT_ENCODING);
        parts.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(key) = &self.api_key {
            let mut value = Vec::with_capacity("Bearer ".len() + key.as_bytes().len());
            value.extend_from_slice(b"Bearer ");
            value.extend_from_slice(key.as_bytes());
            if let Ok(mut value) = HeaderValue::from_bytes(&value) {
                value.set_sensitive(true);
                parts.headers.insert(AUTHORIZATION, value);
            }
        }
    }
}

/// 业务作用：解析 OpenAI-compatible moderation 响应的最终 flagged 判定。
///
/// 参数说明：
/// - `body`：是经过 route response 硬上限约束的 JSON。
///
/// 返回：唯一 result 的 `flagged` 布尔值；空/多结果、坏 JSON 或字段类型错误时返回错误，由 route fail policy 决定是否继续。
pub(crate) fn moderation_flagged(body: &[u8]) -> Result<bool> {
    let value: Value = serde_json::from_slice(body).context("moderation response is not JSON")?;
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .context("moderation response requires results array")?;
    if results.len() != 1 {
        bail!("moderation response must contain exactly one result");
    }
    results[0]
        .get("flagged")
        .and_then(Value::as_bool)
        .context("moderation result requires boolean flagged")
}

impl LlmTokenQuota {
    /// 业务作用：编译模型额度维度与令牌补充策略，拒绝零容量或无法执行的配额声明。
    fn build(cfg: &LlmTokenQuotaCfg, route_id: &str) -> Result<Self> {
        if cfg.tokens == 0 {
            bail!("route `{route_id}` llm.token_quota.tokens must be positive");
        }
        if !(1..=86_400_000).contains(&cfg.window_ms) {
            bail!("route `{route_id}` llm.token_quota.window_ms must be within 1..=86400000");
        }
        if cfg.max_active_keys == 0 || cfg.max_active_keys > 1_000_000 {
            bail!("route `{route_id}` llm.token_quota.max_active_keys must be within 1..=1000000");
        }
        Ok(Self {
            limit: cfg.tokens,
            window: Duration::from_millis(cfg.window_ms),
            burst: cfg.burst,
            dimension: cfg.dimension,
            max_active_keys: cfg.max_active_keys,
            active_keys_fail_open: cfg.active_keys_fail_open,
        })
    }
}

impl LlmModel {
    /// 业务作用：在候选快照构建阶段把 provider 配置编译成不含未解析 SecretSource 的固定模型计划。
    ///
    /// 参数说明：
    /// - `cfg`：是单模型配置
    /// - `config_dir`：是 SecretSource 相对目录
    /// - `route_id`：用于错误定位
    /// - `api_type`：是 route 冻结的独立 wire 契约。
    ///
    /// 返回：配置、路径、模型名和凭据都合法时返回可发布模型；任一信任边界不满足时拒绝候选快照。
    fn build(
        cfg: &LlmModelCfg,
        config_dir: &Path,
        route_id: &str,
        api_type: LlmApiType,
    ) -> Result<Self> {
        if cfg.model.trim().is_empty() || cfg.model.len() > 256 {
            bail!(
                "route `{route_id}` llm model `{}` model name must be 1..=256 bytes",
                cfg.id
            );
        }
        if cfg.weight > 1_000_000 {
            bail!(
                "route `{route_id}` llm model `{}` weight must be <= 1000000",
                cfg.id
            );
        }
        validate_upstream(cfg.uri.as_str(), route_id, cfg.id.as_str())?;
        let provider = match cfg.provider {
            LlmProviderCfg::Openai => LlmProvider::Openai,
            LlmProviderCfg::Anthropic => LlmProvider::Anthropic,
            LlmProviderCfg::Google => LlmProvider::Google,
            LlmProviderCfg::AzureOpenai => LlmProvider::AzureOpenai,
            LlmProviderCfg::Bedrock => LlmProvider::Bedrock,
            LlmProviderCfg::VertexAi => LlmProvider::VertexAi,
            LlmProviderCfg::Cohere => LlmProvider::Cohere,
            LlmProviderCfg::Mistral => LlmProvider::Mistral,
            LlmProviderCfg::HuggingFace => LlmProvider::HuggingFace,
            LlmProviderCfg::Xai => LlmProvider::Xai,
            LlmProviderCfg::Dashscope => LlmProvider::Dashscope,
            LlmProviderCfg::Deepseek => LlmProvider::Deepseek,
            LlmProviderCfg::Ollama => LlmProvider::Ollama,
            LlmProviderCfg::Vllm => LlmProvider::Vllm,
        };
        if !provider_supports_api(provider, api_type, cfg.native_passthrough) {
            bail!(
                "route `{route_id}` llm model `{}` provider does not support the selected api_type without lossy conversion",
                cfg.id
            );
        }
        if matches!(provider, LlmProvider::Google | LlmProvider::VertexAi) {
            validate_google_model_name(cfg.model.as_str(), route_id, cfg.id.as_str())?;
        }
        validate_cloud_scope(cfg, provider, route_id)?;
        let default_path = default_provider_path(cfg, provider, api_type, route_id)?;
        let mut path = if cfg.path.is_empty() {
            default_path
        } else {
            cfg.path.clone()
        };
        if api_type == LlmApiType::Realtime {
            validate_realtime_path(path.as_str(), route_id, cfg.id.as_str())?;
        } else {
            validate_provider_path(path.as_str(), route_id, cfg.id.as_str())?;
        }
        if provider == LlmProvider::AzureOpenai && !cfg.api_version.is_empty() {
            // API 版本只从快照中的安全 scope 生成，客户端不能借 query 改写 endpoint 契约。
            let separator = if path.contains('?') {
                '&'
            } else {
                '?'
            };
            let added_len = "api-version=".len() + cfg.api_version.len() + separator.len_utf8();
            if path.len().saturating_add(added_len) > 2048 {
                bail!(
                    "route `{route_id}` Azure OpenAI model `{}` path and api_version exceed 2048 bytes",
                    cfg.id
                );
            }
            path.push(separator);
            path.push_str("api-version=");
            path.push_str(cfg.api_version.as_str());
        }
        let stream_path = match (provider, api_type) {
            (LlmProvider::Google, LlmApiType::ChatCompletions) => {
                let stream_path = if cfg.stream_path.is_empty() {
                    format!("/v1beta/models/{}:streamGenerateContent?alt=sse", cfg.model)
                } else {
                    cfg.stream_path.clone()
                };
                validate_google_stream_path(stream_path.as_str(), route_id, cfg.id.as_str())?;
                Some(Arc::from(stream_path))
            }
            (LlmProvider::VertexAi, LlmApiType::ChatCompletions) => {
                let stream_path = if cfg.stream_path.is_empty() {
                    format!(
                        "/v1/projects/{}/locations/{}/publishers/google/models/{}:streamGenerateContent?alt=sse",
                        cfg.project, cfg.region, cfg.model
                    )
                } else {
                    cfg.stream_path.clone()
                };
                validate_google_stream_path(stream_path.as_str(), route_id, cfg.id.as_str())?;
                Some(Arc::from(stream_path))
            }
            _ => {
                if !cfg.stream_path.is_empty() {
                    bail!(
                        "route `{route_id}` LLM model `{}` cannot set stream_path for this provider/api_type",
                        cfg.id
                    );
                }
                None
            }
        };
        let api_key = resolve_model_api_key(cfg, config_dir, route_id)?;
        let anthropic_version = match provider {
            LlmProvider::Anthropic => {
                let raw = if cfg.anthropic_version.is_empty() {
                    "2023-06-01"
                } else {
                    cfg.anthropic_version.as_str()
                };
                Some(HeaderValue::from_str(raw).with_context(|| {
                    format!(
                        "route `{route_id}` Anthropic model `{}` has invalid anthropic_version",
                        cfg.id
                    )
                })?)
            }
            _ => {
                if !cfg.anthropic_version.is_empty() {
                    bail!(
                        "route `{route_id}` non-Anthropic model `{}` cannot set anthropic_version",
                        cfg.id
                    );
                }
                None
            }
        };
        let aws_access_key_id = resolve_optional_secret(
            cfg.resolved_aws_access_key_id.as_deref(),
            cfg.aws_access_key_id.as_str(),
            config_dir,
            route_id,
            cfg.id.as_str(),
            "aws_access_key_id",
        )?
        .map(Arc::from);
        let aws_secret_access_key = resolve_optional_secret(
            cfg.resolved_aws_secret_access_key.as_deref(),
            cfg.aws_secret_access_key.as_str(),
            config_dir,
            route_id,
            cfg.id.as_str(),
            "aws_secret_access_key",
        )?
        .map(|value| Arc::from(value.into_bytes()));
        let aws_session_token = resolve_optional_secret(
            cfg.resolved_aws_session_token.as_deref(),
            cfg.aws_session_token.as_str(),
            config_dir,
            route_id,
            cfg.id.as_str(),
            "aws_session_token",
        )?
        .map(|value| {
            let mut value = HeaderValue::from_str(value.as_str())
                .context("Bedrock session token is not a valid header value")?;
            value.set_sensitive(true);
            Ok::<_, anyhow::Error>(value)
        })
        .transpose()?;
        if aws_access_key_id.is_some() != aws_secret_access_key.is_some() {
            bail!(
                "route `{route_id}` Bedrock model `{}` requires both AWS access and secret keys",
                cfg.id
            );
        }
        if provider == LlmProvider::Bedrock && api_key.is_some() && aws_access_key_id.is_some() {
            bail!(
                "route `{route_id}` Bedrock model `{}` cannot combine bearer API key and SigV4 credentials",
                cfg.id
            );
        }
        if provider == LlmProvider::Bedrock
            && aws_access_key_id.is_some()
            && !cfg.uri.starts_with("https://")
        {
            bail!(
                "route `{route_id}` Bedrock model `{}` SigV4 requires a fixed https origin",
                cfg.id
            );
        }
        Ok(Self {
            id: Arc::from(cfg.id.as_str()),
            provider,
            api_type,
            upstream: Arc::from(cfg.uri.as_str()),
            model: Arc::from(cfg.model.as_str()),
            path: Arc::from(path),
            stream_path,
            api_key,
            anthropic_version,
            region: (!cfg.region.is_empty()).then(|| Arc::from(cfg.region.as_str())),
            aws_access_key_id,
            aws_secret_access_key,
            aws_session_token,
            native_passthrough: cfg.native_passthrough || api_type != LlmApiType::ChatCompletions,
            input_cost_microusd_per_million: cfg.input_cost_microusd_per_million,
            output_cost_microusd_per_million: cfg.output_cost_microusd_per_million,
            fixed_cost_microusd: cfg.fixed_cost_microusd,
            capabilities: cfg
                .capabilities
                .iter()
                .map(|value| Arc::from(value.as_str()))
                .collect::<Vec<_>>()
                .into(),
            expected_first_token_latency: (cfg.expected_first_token_latency_ms > 0)
                .then(|| Duration::from_millis(cfg.expected_first_token_latency_ms)),
            weight: cfg.weight,
        })
    }

    /// 业务作用：把下游认证字段替换为 provider 凭据并设置 provider 固定 header，阻止客户端凭据越界泄漏。
    ///
    /// 参数说明：
    /// - `parts`：是即将发送给模型 provider 的独立请求头副本
    /// - `stream`：表示是否使用 SSE endpoint。
    ///
    /// 返回：无；原地清理不可信凭据并注入快照构建期解析的 provider 凭据。
    pub(crate) fn prepare_headers(&self, parts: &mut Parts, stream: bool) {
        parts.headers.remove(AUTHORIZATION);
        parts.headers.remove(COOKIE);
        parts.headers.remove("x-api-key");
        parts.headers.remove("x-goog-api-key");
        parts.headers.remove("anthropic-version");
        parts.headers.remove("x-amz-date");
        parts.headers.remove("x-amz-content-sha256");
        parts.headers.remove("x-amz-security-token");
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(TRANSFER_ENCODING);
        parts.headers.remove(http::header::ACCEPT_ENCODING);
        if !matches!(self.api_type, LlmApiType::File | LlmApiType::Realtime)
            && !parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.to_ascii_lowercase().starts_with("multipart/"))
        {
            parts.headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        match self.provider {
            LlmProvider::Openai
            | LlmProvider::Bedrock
            | LlmProvider::VertexAi
            | LlmProvider::Cohere
            | LlmProvider::Mistral
            | LlmProvider::HuggingFace
            | LlmProvider::Xai
            | LlmProvider::Dashscope
            | LlmProvider::Deepseek
            | LlmProvider::Ollama
            | LlmProvider::Vllm => {
                if let Some(key) = &self.api_key {
                    let mut value = Vec::with_capacity("Bearer ".len() + key.as_bytes().len());
                    value.extend_from_slice(b"Bearer ");
                    value.extend_from_slice(key.as_bytes());
                    if let Ok(mut value) = HeaderValue::from_bytes(&value) {
                        value.set_sensitive(true);
                        parts.headers.insert(AUTHORIZATION, value);
                    }
                }
            }
            LlmProvider::AzureOpenai => {
                if let Some(key) = &self.api_key {
                    parts.headers.insert("api-key", key.clone());
                }
            }
            LlmProvider::Anthropic => {
                if let Some(key) = &self.api_key {
                    parts.headers.insert("x-api-key", key.clone());
                }
                if let Some(version) = &self.anthropic_version {
                    parts.headers.insert("anthropic-version", version.clone());
                }
            }
            LlmProvider::Google => {
                if let Some(key) = &self.api_key {
                    parts.headers.insert("x-goog-api-key", key.clone());
                }
                if stream {
                    parts.headers.insert(
                        http::header::ACCEPT,
                        HeaderValue::from_static("text/event-stream"),
                    );
                }
            }
        }
    }

    /// 业务作用：把 Bedrock 请求的固定 origin、region、path 与精确实体绑定进 SigV4，阻止客户端
    /// 替换签名 scope、临时令牌或 payload 后仍复用授权。
    ///
    /// 参数说明：
    /// - `parts`：是已完成 provider header 清洗的上游请求头
    /// - `body`：是最终 provider 实体
    /// - `path`：是快照冻结的 path/query
    /// - `now`：是本次签名时刻。
    ///
    /// 返回：非 Bedrock 或 bearer API key 模式不改变请求；SigV4 材料完整时注入签名，否则失败。
    pub(crate) fn sign_bedrock_request(
        &self,
        parts: &mut Parts,
        body: &[u8],
        path: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.provider != LlmProvider::Bedrock || self.aws_access_key_id.is_none() {
            return Ok(());
        }
        let access_key = self
            .aws_access_key_id
            .as_deref()
            .context("Bedrock SigV4 access key is missing")?;
        let secret_key = self
            .aws_secret_access_key
            .as_deref()
            .context("Bedrock SigV4 secret key is missing")?;
        let region = self
            .region
            .as_deref()
            .context("Bedrock SigV4 region is missing")?;
        let origin: http::Uri = self
            .upstream
            .parse()
            .context("Bedrock SigV4 origin is invalid")?;
        let authority = origin
            .authority()
            .context("Bedrock SigV4 origin has no authority")?
            .as_str();
        parts.headers.insert(
            http::header::HOST,
            HeaderValue::from_str(authority).context("Bedrock authority is not a header value")?,
        );
        let payload_hash = sha256_hex(body);
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        parts.headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_str(payload_hash.as_str())?,
        );
        parts
            .headers
            .insert("x-amz-date", HeaderValue::from_str(amz_date.as_str())?);
        if let Some(token) = &self.aws_session_token {
            parts.headers.insert("x-amz-security-token", token.clone());
        }

        let target: http::Uri = path
            .parse()
            .context("Bedrock SigV4 path/query is invalid")?;
        let canonical_uri = aws_percent_encode_path(target.path());
        let canonical_query = canonical_aws_query(target.query().unwrap_or_default())?;
        let mut signed_names = vec!["content-type", "host", "x-amz-content-sha256", "x-amz-date"];
        if self.aws_session_token.is_some() {
            signed_names.push("x-amz-security-token");
        }
        if parts
            .headers
            .contains_key("x-amzn-bedrock-request-metadata")
        {
            signed_names.push("x-amzn-bedrock-request-metadata");
        }
        signed_names.sort_unstable();
        let signed_headers = signed_names.join(";");
        let mut canonical_headers = String::new();
        for name in &signed_names {
            let value = parts
                .headers
                .get(*name)
                .context("Bedrock signed header is missing")?
                .to_str()
                .context("Bedrock signed header is not ASCII")?;
            canonical_headers.push_str(name);
            canonical_headers.push(':');
            canonical_headers.push_str(normalize_aws_header_value(value).as_str());
            canonical_headers.push('\n');
        }
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            parts.method.as_str(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash
        );
        let scope = format!("{date}/{region}/bedrock/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let mut prefixed_secret = Vec::with_capacity(4 + secret_key.len());
        prefixed_secret.extend_from_slice(b"AWS4");
        prefixed_secret.extend_from_slice(secret_key);
        let date_key = hmac_sha256(&prefixed_secret, date.as_bytes());
        let region_key = hmac_sha256(&date_key, region.as_bytes());
        let service_key = hmac_sha256(&region_key, b"bedrock");
        let signing_key = hmac_sha256(&service_key, b"aws4_request");
        let signature = hex_bytes(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        );
        let mut authorization = HeaderValue::from_str(authorization.as_str())?;
        authorization.set_sensitive(true);
        parts.headers.insert(AUTHORIZATION, authorization);
        Ok(())
    }

    /// 业务作用：为当前请求选择 provider 固定的 unary 或 SSE path，避免运行期拼接不可信模型名。
    ///
    /// 参数说明：
    /// - `stream`：表示下游是否请求 SSE。
    ///
    /// 返回：Google SSE 返回构建期校验过的 `stream_path`，其它情况返回普通 `path`。
    pub(crate) fn path_for(&self, stream: bool) -> &str {
        if stream {
            if let Some(path) = &self.stream_path {
                return path.as_ref();
            }
        }
        self.path.as_ref()
    }

    /// 业务作用：复验模型 catalog 是否覆盖本次请求实际使用的 tool、structured output 与多模态能力。
    ///
    /// 参数说明：
    /// - `required`：是从已验证请求 DOM 推导的能力 token 集合。
    ///
    /// 返回：全部能力都在快照冻结 catalog 中时为 true；缺少任一项时为 false。
    pub(crate) fn supports_capabilities(&self, required: &[&'static str]) -> bool {
        required.iter().all(|required| {
            self.capabilities
                .iter()
                .any(|capability| capability.as_ref() == *required)
        })
    }

    /// 业务作用：用冻结价格计算请求的保守费用，供 provider I/O 前执行 route cost admission。
    ///
    /// 参数说明：
    /// - `prompt_tokens`：是网关保守预留；非 token API 使用固定费用。
    /// - `completion_tokens`：是网关保守预留；非 token API 使用固定费用。
    ///
    /// 返回：价格完整时返回向上取整的微美元；任一所需价格未知时返回 None。
    pub(crate) fn estimated_cost_microusd(
        &self,
        prompt_tokens: u64,
        completion_tokens: u64,
    ) -> Option<u64> {
        if self.fixed_cost_microusd > 0 {
            return Some(self.fixed_cost_microusd);
        }
        if self.input_cost_microusd_per_million == 0 || self.output_cost_microusd_per_million == 0 {
            return None;
        }
        let input = prompt_tokens
            .saturating_mul(self.input_cost_microusd_per_million)
            .saturating_add(999_999)
            / 1_000_000;
        let output = completion_tokens
            .saturating_mul(self.output_cost_microusd_per_million)
            .saturating_add(999_999)
            / 1_000_000;
        Some(input.saturating_add(output))
    }

    /// 业务作用：为独立 JSON API 固定 provider 模型，不执行 Chat 字段映射或丢弃未知原生字段。
    ///
    /// 参数说明：
    /// - `document`：是已验证 JSON object
    /// - `raw`：是原始实体，可在模型已匹配时零复制复用。
    ///
    /// 返回：Batch/File 原样返回；其它 API 只覆盖顶层 `model`，序列化超限由 route 外层复验。
    pub(crate) fn native_json_body(&self, document: &Value, raw: &Bytes) -> Result<Bytes> {
        if matches!(self.api_type, LlmApiType::Batch | LlmApiType::File) {
            return Ok(raw.clone());
        }
        let object = document
            .as_object()
            .context("native AI JSON body must be an object")?;
        if object
            .get("model")
            .and_then(Value::as_str)
            .is_some_and(|model| model == self.model.as_ref())
        {
            return Ok(raw.clone());
        }
        let mut document = document.clone();
        document
            .as_object_mut()
            .expect("object validated above")
            .insert("model".to_string(), Value::String(self.model.to_string()));
        serde_json::to_vec(&document)
            .map(Bytes::from)
            .context("serialize provider-native AI request")
    }
}

/// 业务作用：从 provider 原生 JSON 推导实际 tools、structured output 与多模态能力门，
/// 防止客户端用未声明字段绕过冻结 catalog。
///
/// 参数说明：
/// - `document`：是已通过 JSON object 与字节上限校验的请求。
///
/// 返回：返回去重的固定能力 token，供所有模型在 provider I/O 前过滤。
pub(crate) fn native_required_capabilities(document: &Value) -> Vec<&'static str> {
    let mut required = Vec::with_capacity(3);
    let object = document.as_object();
    if object
        .and_then(|value| value.get("tools"))
        .is_some_and(|value| {
            !value.is_null() && value.as_array().is_none_or(|items| !items.is_empty())
        })
    {
        required.push("tools");
    }
    if object.is_some_and(|value| {
        value.contains_key("response_format") || value.contains_key("json_schema")
    }) || document.pointer("/text/format").is_some()
    {
        required.push("structured_output");
    }
    if native_value_is_multimodal(document) {
        required.push("multimodal");
    }
    required
}

/// 业务作用：从原生请求中读取声明的输出 token 上限，供冻结价格在调用 provider 前保守估算。
///
/// 参数说明：
/// - `document`：是独立 API 的 JSON object。
///
/// 返回：返回常见 provider 字段中的最大非负值；未声明时返回 0。
pub(crate) fn native_completion_tokens(document: &Value) -> u64 {
    [
        "max_tokens",
        "max_output_tokens",
        "max_completion_tokens",
        "max_tokens_to_sample",
    ]
    .into_iter()
    .filter_map(|field| document.get(field).and_then(Value::as_u64))
    .max()
    .unwrap_or_default()
}

/// 业务作用：递归识别原生 content block 或媒体输入键，不解释或改写 provider payload。
///
/// 参数说明：
/// - `value`：是当前 JSON 节点。
///
/// 返回：出现 image/audio/video/input_file 等媒体语义时返回 true。
fn native_value_is_multimodal(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(native_value_is_multimodal),
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "image"
                    | "image_url"
                    | "input_image"
                    | "audio"
                    | "input_audio"
                    | "video"
                    | "input_video"
                    | "file"
                    | "input_file"
            ) || (key == "type"
                && value.as_str().is_some_and(|kind| {
                    kind.contains("image")
                        || kind.contains("audio")
                        || kind.contains("video")
                        || kind.contains("file")
                }))
                || native_value_is_multimodal(value)
        }),
        _ => false,
    }
}

impl ParsedLlmRequest {
    /// 业务作用：解析 OpenAI-compatible Chat Completions 请求并计算有界 token 估算。
    pub fn parse(raw: Bytes) -> Result<Self> {
        let document: Value =
            serde_json::from_slice(raw.as_ref()).context("LLM body is not JSON")?;
        let object = document
            .as_object()
            .context("LLM body must be a JSON object")?;
        let messages = object
            .get("messages")
            .and_then(Value::as_array)
            .context("LLM body requires messages array")?;
        if messages.is_empty() || messages.len() > 4096 {
            bail!("LLM messages must contain 1..=4096 entries");
        }
        let prompt_bytes = prompt_text_bytes(messages)?;
        // 不依赖 provider tokenizer 时，UTF-8 字节数是比 bytes/4 更安全的 token 上界；
        // 再加入 message framing，使空消息不能免费穿过配额。最终账单会按 usage 退款差额。
        let prompt_tokens =
            (prompt_bytes as u64).saturating_add((messages.len() as u64).saturating_mul(4));
        let stream = object
            .get("stream")
            .map(|value| value.as_bool().context("LLM stream must be boolean"))
            .transpose()?
            .unwrap_or(false);
        let max_completion_tokens = object
            .get("max_tokens")
            .or_else(|| object.get("max_completion_tokens"))
            .map(|value| {
                value
                    .as_u64()
                    .filter(|value| *value > 0)
                    .context("LLM max_tokens must be a positive integer")
            })
            .transpose()?;
        Ok(Self {
            raw,
            document,
            stream,
            prompt_tokens,
            max_completion_tokens,
            pristine: true,
        })
    }

    /// 业务作用：把统一 OpenAI Chat Completions 请求转换为选中 provider 的有界 wire body。
    ///
    /// 参数说明：
    /// - `model`：是快照构建期已校验的目标 provider 与模型计划。
    ///
    /// 返回：字段可无损映射时返回 JSON `Bytes`；存在 provider 不支持的角色、内容或参数时失败闭合。
    pub(crate) fn body_for(&mut self, model: &LlmModel) -> Result<Bytes> {
        if model.native_passthrough {
            self.document
                .as_object_mut()
                .expect("LLM object validated at parse")
                .insert("model".to_string(), Value::String(model.model.to_string()));
            self.pristine = false;
            return serde_json::to_vec(&self.document)
                .map(Bytes::from)
                .context("encode provider native request");
        }
        match model.provider {
            LlmProvider::Openai
            | LlmProvider::AzureOpenai
            | LlmProvider::Bedrock
            | LlmProvider::Mistral
            | LlmProvider::HuggingFace
            | LlmProvider::Xai
            | LlmProvider::Dashscope
            | LlmProvider::Deepseek
            | LlmProvider::Ollama
            | LlmProvider::Vllm => {
                let current_matches = self
                    .document
                    .get("model")
                    .and_then(Value::as_str)
                    .is_some_and(|current| current == model.model.as_ref());
                if self.pristine && current_matches {
                    return Ok(self.raw.clone());
                }
                self.document
                    .as_object_mut()
                    .expect("LLM object validated at parse")
                    .insert("model".to_string(), Value::String(model.model.to_string()));
                self.pristine = false;
                serde_json::to_vec(&self.document)
                    .map(Bytes::from)
                    .context("encode OpenAI model request")
            }
            LlmProvider::Anthropic => {
                let body = openai_to_anthropic(&self.document, model.model.as_ref())?;
                serde_json::to_vec(&body)
                    .map(Bytes::from)
                    .context("encode Anthropic model request")
            }
            LlmProvider::Google => {
                let body = openai_to_google(&self.document, self.stream)?;
                serde_json::to_vec(&body)
                    .map(Bytes::from)
                    .context("encode Google model request")
            }
            LlmProvider::VertexAi => {
                let body = openai_to_google(&self.document, self.stream)?;
                serde_json::to_vec(&body)
                    .map(Bytes::from)
                    .context("encode Vertex AI model request")
            }
            LlmProvider::Cohere => unreachable!("Cohere Chat requires native passthrough"),
        }
    }

    /// 业务作用：从请求实际字段推导跨 provider 必须无损保持的能力，避免 catalog 只按 route 静态标签放行。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回去重的小型静态能力列表，供每个 fallback 模型在调用前复验。
    pub(crate) fn required_capabilities(&self) -> Vec<&'static str> {
        let mut required = Vec::with_capacity(4);
        if self.document.get("tools").is_some()
            || self.document.get("tool_choice").is_some()
            || self.document.get("parallel_tool_calls").is_some()
        {
            required.push("tools");
        }
        if self.document.get("response_format").is_some()
            || self.document.get("json_schema").is_some()
        {
            required.push("structured_output");
        }
        if self
            .document
            .get("messages")
            .and_then(Value::as_array)
            .is_some_and(|messages| {
                messages.iter().any(|message| {
                    message
                        .get("content")
                        .and_then(Value::as_array)
                        .is_some_and(|blocks| {
                            blocks.iter().any(|block| {
                                !matches!(
                                    block.get("type").and_then(Value::as_str),
                                    Some("text" | "input_text" | "output_text")
                                )
                            })
                        })
                })
            })
        {
            required.push("multimodal");
        }
        required
    }

    /// 业务作用：校验 completion 上限；请求未声明时把安全默认值写入 DOM。返回本次配额预留成本。
    pub(crate) fn reserve_tokens(&mut self, max_completion_tokens: u64) -> Result<u64> {
        let completion = self.max_completion_tokens.unwrap_or(max_completion_tokens);
        if completion > max_completion_tokens {
            bail!("LLM max_tokens exceeds route completion limit");
        }
        if self.max_completion_tokens.is_none() {
            self.document
                .as_object_mut()
                .expect("LLM object validated at parse")
                .insert("max_tokens".to_string(), Value::Number(completion.into()));
            self.max_completion_tokens = Some(completion);
            self.pristine = false;
        }
        if self.stream {
            // OpenAI-compatible providers只有显式 include_usage 才会在最终 SSE chunk 给出真实
            // token。统一入口强制打开它；Anthropic adapter 会忽略此 OpenAI 专属字段。
            let object = self
                .document
                .as_object_mut()
                .expect("LLM object validated at parse");
            let options = object
                .entry("stream_options")
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .context("LLM stream_options must be an object")?;
            if options.get("include_usage") != Some(&Value::Bool(true)) {
                options.insert("include_usage".to_string(), Value::Bool(true));
                self.pristine = false;
            }
        }
        self.prompt_tokens
            .checked_add(completion)
            .context("LLM reserved token cost overflow")
    }

    /// 业务作用：生成按缓存 scope 隔离的精确键。直接增量摘要原始 `Bytes`，不创建 body 副本；同一逻辑
    /// JSON 使用不同空白可能精确 miss，但会继续走真正 embedding 语义层，正确性不受影响。
    pub(crate) fn exact_cache_digest(&self, scope: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"gw-llm-exact-v1\0");
        digest.update((scope.len() as u64).to_be_bytes());
        digest.update(scope);
        digest.update(self.raw.as_ref());
        digest.finalize().into()
    }

    /// 业务作用：摘要除 messages/model/stream 外的全部生成参数。语义相近 prompt 只有在 temperature、tools、
    /// response_format 等参数也一致时才能复用响应。字段名排序使 JSON 对象书写顺序不影响结果。
    pub(crate) fn semantic_params_digest(&self, scope: &[u8; 32]) -> Result<[u8; 32]> {
        let object = self
            .document
            .as_object()
            .expect("LLM object validated at parse");
        let mut keys = object
            .keys()
            .filter(|key| !matches!(key.as_str(), "messages" | "model" | "stream"))
            .collect::<Vec<_>>();
        keys.sort_unstable();
        let mut digest = Sha256::new();
        digest.update(b"gw-llm-params-v1\0");
        // L1 语义索引在同一路由内共享，scope 必须进入比较摘要；否则不同 consumer 的相近
        // prompt 会在本机索引中串租户。L2 虽按 scope 分 key，也保持同一摘要协议。
        digest.update(scope);
        for key in keys {
            digest.update((key.len() as u64).to_be_bytes());
            digest.update(key.as_bytes());
            let mut writer = DigestWriter(&mut digest);
            serde_json::to_writer(&mut writer, &object[key])
                .context("hash LLM semantic parameters")?;
        }
        Ok(digest.finalize().into())
    }

    /// 业务作用：构造一次 OpenAI-compatible embedding 请求。prompt 拼接是语义缓存显式慢路径唯一必要的
    /// 文本合并：包含 role 分隔符，避免 `system:a + user:b` 与 `system:ab` 被编码成同一输入。
    pub(crate) fn embedding_body(&self, model: &LlmEmbeddingModel) -> Result<Bytes> {
        let messages = self
            .document
            .get("messages")
            .and_then(Value::as_array)
            .expect("LLM messages validated at parse");
        let prompt_capacity = usize::try_from(self.prompt_tokens.saturating_mul(4))
            .unwrap_or(usize::MAX)
            .min(MAX_LLM_BODY_BYTES as usize);
        let mut prompt = String::with_capacity(prompt_capacity);
        for message in messages {
            let object = message.as_object().expect("LLM message validated at parse");
            prompt.push_str(object["role"].as_str().expect("LLM role validated"));
            prompt.push(':');
            append_content_text(&mut prompt, &object["content"])?;
            prompt.push('\n');
        }
        serde_json::to_vec(&json!({
            "model": model.model.as_ref(),
            "input": prompt
        }))
        .map(Bytes::from)
        .context("encode embedding request")
    }

    /// 业务作用：插入配置持有的可信 system prompt，并重新计算总 prompt 预算。
    ///
    /// 参数说明：
    /// - `prompt`：是同代固定文本，不能来自客户端变量。
    ///
    /// 返回：更新消息与 token 估算；容量耗尽时不继续模型调用。
    pub(crate) fn prepend_system_prompt(&mut self, prompt: &str) -> Result<()> {
        let messages = self
            .document
            .get_mut("messages")
            .and_then(Value::as_array_mut)
            .expect("LLM messages validated at parse");
        if messages.len() >= 4096 {
            bail!("LLM system prompt would exceed 4096 messages");
        }
        messages.insert(
            0,
            json!({
                "role":"system",
                "content":prompt
            }),
        );
        let prompt_bytes = prompt_text_bytes(messages)?;
        self.prompt_tokens =
            (prompt_bytes as u64).saturating_add((messages.len() as u64).saturating_mul(4));
        self.pristine = false;
        Ok(())
    }

    /// 业务作用：提取最后一条用户文本作为固定检索服务的查询，不把系统提示或工具参数用作检索指令。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界纯文本查询；多模态或缺少用户消息时拒绝。
    #[cfg(feature = "ai-governance")]
    pub(crate) fn retrieval_query(&self) -> Result<String> {
        let message = self.document["messages"]
            .as_array()
            .context("LLM messages missing")?
            .iter()
            .rev()
            .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
            .context("RAG requires a user message")?;
        let text = strict_content_text(&message["content"])?;
        ensure!(
            !text.is_empty() && text.len() <= 128 * 1024,
            "RAG query exceeds limit"
        );
        Ok(text)
    }

    /// 业务作用：把已校验 provenance 的检索文档作为低信任 user 内容附加，而不是提升为 system 指令。
    ///
    /// 参数说明：
    /// - `text`：是已受上下文容量门限制的文档 JSON。
    ///
    /// 返回：更新请求与 token 估算；消息数量超限时拒绝。
    #[cfg(feature = "ai-governance")]
    pub(crate) fn append_retrieval_context(&mut self, text: &str) -> Result<()> {
        let messages = self.document["messages"]
            .as_array_mut()
            .expect("LLM messages validated");
        ensure!(
            messages.len() < 4096,
            "RAG context exceeds message capacity"
        );
        messages.push(json!({
            "role":"user",
            "content":text
        }));
        self.prompt_tokens = prompt_text_bytes(messages)? as u64 + messages.len() as u64 * 4;
        self.pristine = false;
        Ok(())
    }

    /// 业务作用：在受支持的提示字段中查找禁止内容，避免扫描无关协议字段改变规则语义。
    fn prompt_contains(&self, pattern: &str) -> bool {
        self.document
            .get("messages")
            .and_then(Value::as_array)
            .is_some_and(|messages| {
                messages.iter().any(|message| {
                    message
                        .get("content")
                        .is_some_and(|content| content_contains(content, pattern))
                })
            })
    }
}

/// 业务作用：解析 OpenAI-compatible embedding 响应并原地归一化向量。只保留第一个 embedding；空、NaN、
/// infinite、零范数或维度超限都视为缓存后端失败，调用方应 fail-open 继续模型请求。
pub(crate) fn parse_embedding(body: &[u8], max_dimensions: usize) -> Result<Arc<[f32]>> {
    let value: Value = serde_json::from_slice(body).context("embedding response is not JSON")?;
    let values = value
        .pointer("/data/0/embedding")
        .and_then(Value::as_array)
        .context("embedding response requires data[0].embedding")?;
    if values.is_empty() || values.len() > max_dimensions {
        bail!("embedding dimensions must be within 1..={max_dimensions}");
    }
    let mut vector = Vec::with_capacity(values.len());
    let mut squared_norm = 0.0_f64;
    for value in values {
        let component = value
            .as_f64()
            .filter(|component| component.is_finite())
            .context("embedding component must be finite")?;
        squared_norm = component.mul_add(component, squared_norm);
        vector.push(component as f32);
    }
    if !squared_norm.is_finite() || squared_norm <= f64::EPSILON {
        bail!("embedding vector must have a finite non-zero norm");
    }
    let inverse_norm = squared_norm.sqrt().recip() as f32;
    for component in &mut vector {
        *component *= inverse_norm;
    }
    Ok(vector.into())
}

/// 业务作用：编码 Redis exact response。body 已是 provider 校验过的有界 JSON `Bytes`；L2 Redis string
/// 必须连续，因此这里只做一次不可避免的顺序复制，不经 base64/JSON 二次膨胀。
pub(crate) fn encode_l2_response(model_id: &str, body: &[u8]) -> Result<Bytes> {
    let model_len = u16::try_from(model_id.len()).context("LLM cache model id too long")?;
    let body_len = u32::try_from(body.len()).context("LLM cache response too long")?;
    let mut encoded = Vec::with_capacity(11 + model_id.len() + body.len());
    encoded.extend_from_slice(LLM_CACHE_RESPONSE_MAGIC);
    encoded.push(LLM_CACHE_RESPONSE_VERSION);
    encoded.extend_from_slice(&model_len.to_be_bytes());
    encoded.extend_from_slice(&body_len.to_be_bytes());
    encoded.extend_from_slice(model_id.as_bytes());
    encoded.extend_from_slice(body);
    Ok(Bytes::from(encoded))
}

/// 业务作用：解码 Redis exact response，先验证固定头与所有长度再建立 `Bytes::slice`。body slice 与下载的
/// Redis allocation 共享内存，不再复制完整 JSON。
pub(crate) fn decode_l2_response(
    encoded: Bytes,
    max_response_bytes: usize,
) -> Result<(Arc<str>, Bytes)> {
    if encoded.len() < 11
        || &encoded[..4] != LLM_CACHE_RESPONSE_MAGIC
        || encoded[4] != LLM_CACHE_RESPONSE_VERSION
    {
        bail!("invalid LLM cache response header");
    }
    let model_len = u16::from_be_bytes([encoded[5], encoded[6]]) as usize;
    let body_len = u32::from_be_bytes([encoded[7], encoded[8], encoded[9], encoded[10]]) as usize;
    if body_len > max_response_bytes || 11 + model_len + body_len != encoded.len() {
        bail!("invalid LLM cache response length");
    }
    let model = std::str::from_utf8(&encoded[11..11 + model_len])
        .context("LLM cache model id is not UTF-8")?;
    validate_model_id(model, "cached")?;
    Ok((Arc::from(model), encoded.slice(11 + model_len..)))
}

/// 业务作用：序列化小型 L2 语义索引成员；不包含响应 body。
pub(crate) fn encode_l2_candidate(
    exact_digest: [u8; 32],
    params_digest: [u8; 32],
    vector: &[f32],
) -> Result<String> {
    serde_json::to_string(&LlmL2Candidate {
        exact_digest,
        params_digest,
        vector: vector.to_vec(),
    })
    .context("encode LLM semantic L2 candidate")
}

/// 业务作用：从有界 Redis 列表选最高相似度候选。每个成员都重新校验维度/有限值；单个脏成员跳过，
/// 不使整条 route 缓存失效。
pub(crate) fn best_l2_candidate(
    candidates: &[Vec<u8>],
    params_digest: &[u8; 32],
    vector: &[f32],
    threshold: f32,
) -> Option<([u8; 32], Arc<[f32]>)> {
    let mut best: Option<(f32, [u8; 32], Arc<[f32]>)> = None;
    for raw in candidates {
        let Ok(candidate) = serde_json::from_slice::<LlmL2Candidate>(raw) else {
            continue;
        };
        if &candidate.params_digest != params_digest || candidate.vector.len() != vector.len() {
            continue;
        }
        let mut similarity = 0.0_f32;
        let mut squared_norm = 0.0_f32;
        let mut valid = true;
        for (left, right) in candidate.vector.iter().zip(vector) {
            if !left.is_finite() {
                valid = false;
                break;
            }
            similarity = left.mul_add(*right, similarity);
            squared_norm = left.mul_add(*left, squared_norm);
        }
        // Redis 是共享外部事实源，不能信任其中的“已归一化”声明；否则恶意放大向量能让
        // 任意低相似 prompt 越过阈值。允许少量 f32/JSON round-trip 误差。
        valid &= (squared_norm - 1.0).abs() <= 0.01;
        if valid
            && similarity >= threshold
            && best
                .as_ref()
                .is_none_or(|(current, _, _)| similarity > *current)
        {
            best = Some((similarity, candidate.exact_digest, candidate.vector.into()));
        }
    }
    best.map(|(_, digest, vector)| (digest, vector))
}

/// 业务作用：将 32 字节摘要写成固定 64 字节小写十六进制 key 片段。
pub(crate) fn digest_hex(digest: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing digest hex to String cannot fail");
    }
    encoded
}

/// 让 serde_json 直接把参数 JSON 字节喂给 SHA-256，避免先构造临时 Vec。
struct DigestWriter<'a>(&'a mut Sha256);

impl std::io::Write for DigestWriter<'_> {
    /// 业务作用：向有界 JSON 编码缓冲写入字节，在超过容量前中止编码。
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    /// 业务作用：完成内存编码器的刷新合同，不触发外部文件或网络副作用。
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 业务作用：把非流式 Anthropic Messages 响应映射回 OpenAI Chat Completions。
///
/// 参数说明：
/// - `body`：受响应大小限制的原始 provider JSON。
///
/// 返回：统一响应与可选最终用量；缺失用量保持未知，畸形字段和数值溢出拒绝响应。
pub(crate) fn anthropic_response_to_openai(body: &[u8]) -> Result<(Bytes, Option<LlmUsage>)> {
    let source: Value = serde_json::from_slice(body).context("Anthropic response is not JSON")?;
    let object = source
        .as_object()
        .context("Anthropic response must be a JSON object")?;
    let blocks = object
        .get("content")
        .and_then(Value::as_array)
        .context("Anthropic response requires content array")?;
    if blocks.iter().any(|block| {
        block.get("type").and_then(Value::as_str) != Some("text")
            || block.get("text").and_then(Value::as_str).is_none()
    }) {
        bail!("Anthropic adapter cannot losslessly represent non-text response blocks");
    }
    let content = blocks
        .iter()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect::<String>();
    let usage = source
        .get("usage")
        .map(|usage| {
            let prompt_tokens = anthropic_input_usage(usage)?
                .context("Anthropic usage.input_tokens is required")?;
            let completion_tokens = usage
                .get("output_tokens")
                .and_then(Value::as_u64)
                .context("Anthropic usage.output_tokens must be an unsigned integer")?;
            prompt_tokens
                .checked_add(completion_tokens)
                .context("Anthropic usage total overflows")?;
            Ok::<_, anyhow::Error>(LlmUsage {
                prompt_tokens,
                completion_tokens,
            })
        })
        .transpose()?;
    let finish_reason = match object.get("stop_reason").and_then(Value::as_str) {
        Some("max_tokens") => "length",
        Some("tool_use") => {
            bail!("Anthropic adapter cannot losslessly represent tool_use response")
        }
        _ => "stop",
    };
    let mut converted = json!({
        "id": object.get("id").cloned().unwrap_or_else(|| Value::String("anthropic".to_string())),
        "object": "chat.completion",
        "created": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "model": object.get("model").cloned().unwrap_or(Value::Null),
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": finish_reason
        }]
    });
    if let Some(usage) = usage {
        converted["usage"] = json!({
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.prompt_tokens + usage.completion_tokens
        });
    }
    let encoded = serde_json::to_vec(&converted)
        .map(Bytes::from)
        .context("encode unified OpenAI response")?;
    Ok((encoded, usage))
}

/// 业务作用：合并 Anthropic 三种互不重叠的输入 token，缓存读取和创建同样占用处理额度。
///
/// 参数说明：
/// - `usage`：已经解析的原生 usage 对象。
///
/// 返回：完整输入总数；主要字段缺失保持未知，可选缓存计数为空视为没有该类别，错误类型或溢出拒绝。
pub(crate) fn anthropic_input_usage(usage: &Value) -> Result<Option<u64>> {
    anyhow::ensure!(usage.is_object(), "Anthropic usage must be an object");
    let Some(input) = usage.get("input_tokens") else {
        return Ok(None);
    };
    let mut total = input
        .as_u64()
        .context("Anthropic input_tokens must be unsigned")?;
    for field in ["cache_creation_input_tokens", "cache_read_input_tokens"] {
        if let Some(value) = usage.get(field).filter(|value| !value.is_null()) {
            total = total
                .checked_add(
                    value
                        .as_u64()
                        .context("Anthropic cache input tokens must be unsigned")?,
                )
                .context("Anthropic input usage overflows")?;
        }
    }
    Ok(Some(total))
}

/// 业务作用：把 Google `GenerateContentResponse` 映射回统一 OpenAI Chat Completions 响应，并提取账单事实。
///
/// 参数说明：
/// - `body`：是经过响应体硬上限约束的 Google unary JSON。
///
/// 返回：候选与 text part 合法时返回统一响应和可选 usage；prompt 被安全策略拦截、候选缺失或含非文本 part 时失败闭合。
pub(crate) fn google_response_to_openai(body: &[u8]) -> Result<(Bytes, Option<LlmUsage>)> {
    let source: Value = serde_json::from_slice(body).context("Google response is not JSON")?;
    let object = source
        .as_object()
        .context("Google response must be a JSON object")?;
    if let Some(reason) = source
        .pointer("/promptFeedback/blockReason")
        .and_then(Value::as_str)
    {
        bail!("Google blocked prompt with reason `{reason}`");
    }
    let candidates = object
        .get("candidates")
        .and_then(Value::as_array)
        .context("Google response requires candidates array")?;
    if candidates.is_empty() || candidates.len() > 8 {
        bail!("Google response candidates must contain 1..=8 entries");
    }
    let mut choices = Vec::with_capacity(candidates.len());
    for (position, candidate) in candidates.iter().enumerate() {
        let candidate = candidate
            .as_object()
            .context("Google candidate must be an object")?;
        let parts = candidate
            .get("content")
            .and_then(Value::as_object)
            .and_then(|content| content.get("parts"))
            .and_then(Value::as_array)
            .context("Google candidate requires content.parts array")?;
        let mut content = String::new();
        for part in parts {
            let part = part
                .as_object()
                .context("Google candidate part must be an object")?;
            if part.len() != 1 || !part.contains_key("text") {
                bail!("Google adapter received a non-text candidate part");
            }
            content.push_str(
                part.get("text")
                    .and_then(Value::as_str)
                    .context("Google text part requires string text")?,
            );
        }
        let index = candidate
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or(position as u64);
        choices.push(json!({
            "index": index,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": google_finish_reason(
                candidate.get("finishReason").and_then(Value::as_str)
            )
        }));
    }
    let usage = google_usage(&source)?;
    let mut converted = Map::new();
    converted.insert(
        "id".to_string(),
        object
            .get("responseId")
            .cloned()
            .unwrap_or_else(|| Value::String("google".to_string())),
    );
    converted.insert(
        "object".to_string(),
        Value::String("chat.completion".to_string()),
    );
    converted.insert(
        "created".to_string(),
        Value::Number(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .into(),
        ),
    );
    converted.insert(
        "model".to_string(),
        object.get("modelVersion").cloned().unwrap_or(Value::Null),
    );
    converted.insert("choices".to_string(), Value::Array(choices));
    if let Some(usage) = usage {
        converted.insert(
            "usage".to_string(),
            json!({
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.prompt_tokens.saturating_add(usage.completion_tokens)
            }),
        );
    }
    let encoded = serde_json::to_vec(&Value::Object(converted))
        .map(Bytes::from)
        .context("encode unified Google response")?;
    Ok((encoded, usage))
}

/// 业务作用：从 Google `usageMetadata` 提取 provider 最终 token 事实，不用网关估算冒充账单值。
///
/// 参数说明：
/// - `source`：是已解析且受体积上限保护的 Google response。
///
/// 返回：usage 完整时返回 prompt/completion 计数；缺失或流式中间字段不完整时保持未知，错误类型或溢出拒绝响应。
pub(crate) fn google_usage(source: &Value) -> Result<Option<LlmUsage>> {
    let Some(usage) = source.get("usageMetadata") else {
        return Ok(None);
    };
    anyhow::ensure!(usage.is_object(), "Google usageMetadata must be an object");
    let prompt_tokens = match usage.get("promptTokenCount") {
        Some(value) => value
            .as_u64()
            .context("Google usageMetadata.promptTokenCount must be an unsigned integer")?,
        None => return Ok(None),
    };
    let completion_tokens = match usage.get("candidatesTokenCount") {
        Some(value) => value
            .as_u64()
            .context("Google usageMetadata.candidatesTokenCount must be an unsigned integer")?,
        // 流式中间 event 可只携带 promptTokenCount；只有最终完整 usage 才能结算，
        // 半字段不能用零值猜测，否则会错误退款 completion 预留。
        None => return Ok(None),
    };
    let extra = |field: &str| -> Result<u64> {
        usage
            .get(field)
            .map(|value| {
                value
                    .as_u64()
                    .context("Google extra usage must be unsigned")
            })
            .transpose()
            .map(|value| value.unwrap_or(0))
    };
    let prompt_tokens = prompt_tokens
        .checked_add(extra("toolUsePromptTokenCount")?)
        .context("Google prompt usage overflows")?;
    let completion_tokens = completion_tokens
        .checked_add(extra("thoughtsTokenCount")?)
        .context("Google completion usage overflows")?;
    let total = prompt_tokens
        .checked_add(completion_tokens)
        .context("Google usage total overflows")?;
    if let Some(value) = usage.get("totalTokenCount") {
        anyhow::ensure!(
            value.as_u64() == Some(total),
            "Google usage total disagrees with components"
        );
    }
    Ok(Some(LlmUsage {
        prompt_tokens,
        completion_tokens,
    }))
}

/// 业务作用：从 OpenAI-compatible 非流式响应读取 usage；缺失 usage 返回 None，不用估算值冒充账单事实。
///
/// 参数说明：
/// - `body`：已经过实体容量门的原始 provider JSON。
///
/// 返回：完整无符号 token 事实；缺失保持未知，错误类型或加法溢出拒绝响应。
pub(crate) fn openai_usage(body: &[u8]) -> Result<Option<LlmUsage>> {
    let value: Value = serde_json::from_slice(body).context("OpenAI response is not JSON")?;
    openai_usage_value(&value)
}

/// 业务作用：统一复用非流式与 SSE 已解析用量，防止字段缺失或矛盾总数触发错误退款。
///
/// 参数说明：
/// - `value`：已经通过容量门解析的 provider 对象。
///
/// 返回：完整 token 事实；空 usage 保持未知，不合法字段和总数矛盾拒绝。
pub(crate) fn openai_usage_value(value: &Value) -> Result<Option<LlmUsage>> {
    let Some(usage) = value.get("usage").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let prompt_tokens = usage
        .get("prompt_tokens")
        .and_then(Value::as_u64)
        .context("OpenAI usage.prompt_tokens must be an unsigned integer")?;
    let completion_tokens = usage
        .get("completion_tokens")
        .and_then(Value::as_u64)
        .context("OpenAI usage.completion_tokens must be an unsigned integer")?;
    let total = prompt_tokens
        .checked_add(completion_tokens)
        .context("OpenAI usage total overflows")?;
    if let Some(value) = usage.get("total_tokens") {
        anyhow::ensure!(
            value.as_u64() == Some(total),
            "OpenAI usage total disagrees with components"
        );
    }
    Ok(Some(LlmUsage {
        prompt_tokens,
        completion_tokens,
    }))
}

/// 业务作用：把统一聊天请求转换为 Anthropic 协议，保留消息角色、工具调用和生成参数的明确映射。
///
/// 参数说明：
/// - `source`：已验证的统一聊天请求。
/// - `model`：固定上游模型名。
///
/// 返回：受支持文本请求的原生协议实体；未知字段拒绝，用量观测选项不透传到 Anthropic。
fn openai_to_anthropic(source: &Value, model: &str) -> Result<Value> {
    let object = source
        .as_object()
        .context("LLM request must be an object")?;
    const ALLOWED_KEYS: &[&str] = &[
        "messages",
        "model",
        "stream",
        "stream_options",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "stop",
    ];
    if let Some(field) = object
        .keys()
        .find(|field| !ALLOWED_KEYS.contains(&field.as_str()))
    {
        bail!("Anthropic adapter does not support request field `{field}`");
    }
    if let Some(options) = object.get("stream_options") {
        let options = options
            .as_object()
            .context("LLM stream_options must be an object")?;
        // Anthropic 自带 usage 事件；统一入口的观测要求由原生事件满足，不能作为未知生成参数发送。
        anyhow::ensure!(
            options
                .iter()
                .all(|(key, value)| key == "include_usage" && value == &Value::Bool(true)),
            "Anthropic adapter only accepts stream_options.include_usage=true"
        );
    }
    let messages = object
        .get("messages")
        .and_then(Value::as_array)
        .context("LLM body requires messages array")?;
    let mut system = Vec::new();
    let mut converted = Vec::with_capacity(messages.len());
    for message in messages {
        let message = message
            .as_object()
            .context("LLM message must be an object")?;
        if message
            .keys()
            .any(|key| !matches!(key.as_str(), "role" | "content"))
        {
            bail!("Anthropic adapter only supports message role and content fields");
        }
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .context("LLM message requires string role")?;
        let content = message
            .get("content")
            .context("LLM message requires content")?;
        if role == "system" {
            system.push(strict_content_text(content)?);
            continue;
        }
        if !matches!(role, "user" | "assistant") {
            bail!("Anthropic adapter only supports system/user/assistant roles");
        }
        converted.push(json!({
            "role": role,
            "content": strict_content_text(content)?
        }));
    }
    if converted.is_empty() {
        bail!("Anthropic adapter requires at least one user/assistant message");
    }
    let mut target = Map::new();
    target.insert("model".to_string(), Value::String(model.to_string()));
    target.insert("messages".to_string(), Value::Array(converted));
    target.insert(
        "max_tokens".to_string(),
        Value::Number(
            object
                .get("max_tokens")
                .or_else(|| object.get("max_completion_tokens"))
                .and_then(Value::as_u64)
                .unwrap_or(1024)
                .into(),
        ),
    );
    if !system.is_empty() {
        target.insert("system".to_string(), Value::String(system.join("\n")));
    }
    for key in ["stream", "temperature", "top_p", "stop"] {
        if let Some(value) = object.get(key) {
            target.insert(key.to_string(), value.clone());
        }
    }
    Ok(Value::Object(target))
}

/// 业务作用：把统一 text-only Chat Completions 请求转换成 Google `GenerateContentRequest`，并拒绝无法证明等价的字段。
///
/// 参数说明：
/// - `source`：是已解析的统一请求
/// - `stream`：表示将使用 Google SSE endpoint。
///
/// 返回：角色、内容块和生成参数可无损映射时返回 Google JSON；工具、多模态、未知参数或多候选流式请求失败闭合。
fn openai_to_google(source: &Value, stream: bool) -> Result<Value> {
    let object = source
        .as_object()
        .context("LLM request must be an object")?;
    const ALLOWED_KEYS: &[&str] = &[
        "messages",
        "model",
        "stream",
        "stream_options",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "stop",
        "n",
        "seed",
        "frequency_penalty",
        "presence_penalty",
    ];
    if let Some(field) = object
        .keys()
        .find(|field| !ALLOWED_KEYS.contains(&field.as_str()))
    {
        bail!("Google adapter does not support request field `{field}`");
    }
    if let Some(options) = object.get("stream_options") {
        let options = options
            .as_object()
            .context("LLM stream_options must be an object")?;
        if options
            .iter()
            .any(|(key, value)| key != "include_usage" || value != &Value::Bool(true))
        {
            bail!("Google adapter only accepts stream_options.include_usage=true");
        }
    }
    let messages = object
        .get("messages")
        .and_then(Value::as_array)
        .context("LLM body requires messages array")?;
    let mut system = Vec::new();
    let mut contents = Vec::with_capacity(messages.len());
    for message in messages {
        let message = message
            .as_object()
            .context("LLM message must be an object")?;
        if message
            .keys()
            .any(|key| !matches!(key.as_str(), "role" | "content"))
        {
            bail!("Google adapter only supports message role and content fields");
        }
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .context("LLM message requires string role")?;
        let text = strict_content_text(
            message
                .get("content")
                .context("LLM message requires content")?,
        )?;
        match role {
            "system" => system.push(text),
            "user" => contents.push(json!({
                "role":"user",
                "parts":[{
                    "text":text
                }]
            })),
            "assistant" => contents.push(json!({
                "role":"model",
                "parts":[{
                    "text":text
                }]
            })),
            _ => bail!("Google adapter only supports system/user/assistant roles"),
        }
    }
    if contents.is_empty() {
        bail!("Google adapter requires at least one user/assistant message");
    }
    let mut generation = Map::new();
    if let Some(value) = object
        .get("max_tokens")
        .or_else(|| object.get("max_completion_tokens"))
    {
        generation.insert("maxOutputTokens".to_string(), value.clone());
    }
    for (source_key, target_key) in [
        ("temperature", "temperature"),
        ("top_p", "topP"),
        ("seed", "seed"),
        ("frequency_penalty", "frequencyPenalty"),
        ("presence_penalty", "presencePenalty"),
    ] {
        if let Some(value) = object.get(source_key) {
            generation.insert(target_key.to_string(), value.clone());
        }
    }
    if let Some(stop) = object.get("stop") {
        let stop = if let Some(stop) = stop.as_str() {
            vec![Value::String(stop.to_string())]
        } else {
            stop.as_array()
                .filter(|values| {
                    !values.is_empty() && values.len() <= 64 && values.iter().all(Value::is_string)
                })
                .cloned()
                .context("LLM stop must be a string or 1..=64 strings")?
        };
        generation.insert("stopSequences".to_string(), Value::Array(stop));
    }
    if let Some(count) = object.get("n") {
        let count = count
            .as_u64()
            .filter(|count| (1..=8).contains(count))
            .context("LLM n must be within 1..=8 for Google")?;
        if stream && count != 1 {
            bail!("Google streaming adapter only supports n=1");
        }
        generation.insert("candidateCount".to_string(), Value::Number(count.into()));
    }
    let mut target = Map::new();
    target.insert("contents".to_string(), Value::Array(contents));
    if !system.is_empty() {
        target.insert(
            "systemInstruction".to_string(),
            json!({
                "parts":[{
                    "text":system.join("\n")
                }]
            }),
        );
    }
    if !generation.is_empty() {
        target.insert("generationConfig".to_string(), Value::Object(generation));
    }
    Ok(Value::Object(target))
}

/// 业务作用：把统一消息内容收窄为 Google 当前适配器支持的纯文本，阻止多模态块被静默丢弃。
///
/// 参数说明：
/// - `content`：是单条 Chat Completions message 的 content。
///
/// 返回：字符串或全部为 text 的 block 数组被拼接返回；空数组、非 text block 与畸形字段失败闭合。
fn strict_content_text(content: &Value) -> Result<String> {
    if let Some(text) = content.as_str() {
        return Ok(text.to_string());
    }
    let blocks = content
        .as_array()
        .filter(|blocks| !blocks.is_empty())
        .context("Google message content must be string or non-empty text array")?;
    let mut text = String::new();
    for block in blocks {
        let block = block
            .as_object()
            .context("Google message content block must be an object")?;
        if block.len() != 2
            || block.get("type").and_then(Value::as_str) != Some("text")
            || !block.contains_key("text")
        {
            bail!("Google adapter only supports OpenAI text content blocks");
        }
        text.push_str(
            block
                .get("text")
                .and_then(Value::as_str)
                .context("Google text content block requires string text")?,
        );
    }
    Ok(text)
}

/// 业务作用：把 Google 的固定完成原因收敛为 OpenAI 下游可理解的低基数 finish reason。
///
/// 参数说明：
/// - `reason`：是候选的可选 Google `finishReason`。
///
/// 返回：token 上限映射为 `length`，安全类终止映射为 `content_filter`，其它完成态映射为 `stop`。
pub(crate) fn google_finish_reason(reason: Option<&str>) -> &'static str {
    match reason {
        Some("MAX_TOKENS") => "length",
        Some("SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII") => {
            "content_filter"
        }
        _ => "stop",
    }
}

/// 业务作用：计算提示文本的字节预算，供输入容量与保守成本估算使用。
fn prompt_text_bytes(messages: &[Value]) -> Result<usize> {
    let mut bytes = 0_usize;
    for message in messages {
        let object = message
            .as_object()
            .context("LLM message must be an object")?;
        object
            .get("role")
            .and_then(Value::as_str)
            .context("LLM message requires string role")?;
        let content = object
            .get("content")
            .context("LLM message requires content")?;
        bytes = bytes
            .checked_add(content_text_bytes(content)?)
            .context("LLM prompt byte count overflow")?;
    }
    Ok(bytes)
}

/// 业务作用：把 message 的文字片段追加到已有 prompt buffer；调用方统一控制分隔符和总 allocation。
fn append_content_text(target: &mut String, content: &Value) -> Result<()> {
    if let Some(text) = content.as_str() {
        target.push_str(text);
        return Ok(());
    }
    let blocks = content
        .as_array()
        .context("LLM message content must be string or array")?;
    for block in blocks {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            let value = block
                .get("text")
                .and_then(Value::as_str)
                .context("LLM text content block requires text")?;
            target.push_str(value);
        }
    }
    Ok(())
}

/// 业务作用：只借用 JSON 字符串计算 prompt 大小；token 预估热路径不构造临时拼接字符串。
fn content_text_bytes(content: &Value) -> Result<usize> {
    if let Some(text) = content.as_str() {
        return Ok(text.len());
    }
    let blocks = content
        .as_array()
        .context("LLM message content must be string or array")?;
    let mut bytes = 0_usize;
    for block in blocks {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            let value = block
                .get("text")
                .and_then(Value::as_str)
                .context("LLM text content block requires text")?;
            bytes = bytes
                .checked_add(value.len())
                .context("LLM content byte count overflow")?;
        }
    }
    Ok(bytes)
}

/// 业务作用：检查模型内容字段中的目标文本，不把结构元数据误当成提示内容。
fn content_contains(content: &Value, pattern: &str) -> bool {
    if let Some(text) = content.as_str() {
        return contains_ascii_case_insensitive(text.as_bytes(), pattern.as_bytes());
    }
    content.as_array().is_some_and(|blocks| {
        blocks.iter().any(|block| {
            block
                .get("text")
                .and_then(Value::as_str)
                .is_some_and(|text| {
                    contains_ascii_case_insensitive(text.as_bytes(), pattern.as_bytes())
                })
        })
    })
}

/// 业务作用：递归检查受支持 JSON 内容值，供提示与输出规则共享文本判定。
fn value_contains(value: &Value, pattern: &str) -> bool {
    match value {
        Value::String(text) => contains_ascii_case_insensitive(text.as_bytes(), pattern.as_bytes()),
        Value::Array(values) => values.iter().any(|value| value_contains(value, pattern)),
        Value::Object(values) => values.values().any(|value| value_contains(value, pattern)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// 业务作用：ASCII 护栏无分配扫描；pattern 在构建期已限制为 ASCII，UTF-8 prompt 的非 ASCII 字节
/// 只会比较失败，不会被错误地逐字节改写或产生临时 lowercase String。
fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

/// 业务作用：限制模型标识的长度与字符集，防止不可信配置污染路径和观测维度。
fn validate_model_id(id: &str, route_id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("route `{route_id}` llm model id `{id}` must be 1..=64 ASCII [A-Za-z0-9._-]");
    }
    Ok(())
}

/// 业务作用：校验模型能力名称，使路由能力筛选只接受明确的有限声明。
fn validate_capability(capability: &str, route_id: &str) -> Result<()> {
    if capability.is_empty()
        || capability.len() > 64
        || !capability
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "route `{route_id}` LLM capability `{capability}` must be 1..=64 ASCII [A-Za-z0-9._-]"
        );
    }
    Ok(())
}

/// 业务作用：在构建期编译输入输出规则，避免请求线程重复解析或执行失效规则。
fn compile_guardrail_patterns(
    patterns: &[String],
    route_id: &str,
    field: &str,
) -> Result<Vec<Arc<str>>> {
    if patterns.len() > 64 {
        bail!("route `{route_id}` llm.guardrails.{field} supports at most 64 entries");
    }
    let mut compiled = Vec::with_capacity(patterns.len());
    let mut unique = HashSet::with_capacity(patterns.len());
    for pattern in patterns {
        if pattern.is_empty()
            || pattern.len() > 256
            || !pattern.is_ascii()
            || pattern.bytes().any(|byte| byte.is_ascii_control())
        {
            bail!("route `{route_id}` llm.guardrails.{field} entry must be 1..=256 printable ASCII bytes");
        }
        let normalized = pattern.to_ascii_lowercase();
        if !unique.insert(normalized) {
            bail!("route `{route_id}` has duplicate LLM guardrail {field} entry");
        }
        compiled.push(Arc::from(pattern.as_str()));
    }
    Ok(compiled)
}

/// 业务作用：给缓存摘要中的字段加入边界，避免不同字段拼接产生相同身份。
fn hash_digest_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

/// 业务作用：冻结 provider/API 兼容矩阵，避免运行期用 Chat adapter 猜测其它协议。
///
/// 参数说明：
/// - `provider`：是候选模型声明
/// - `api_type`：是候选模型声明
/// - `native_passthrough`：表示 Chat 是否保持原生 wire。
///
/// 返回：存在明确、无损的 wire 契约时为 true；未知组合为 false 并在构建期拒绝。
fn provider_supports_api(
    provider: LlmProvider,
    api_type: LlmApiType,
    native_passthrough: bool,
) -> bool {
    match api_type {
        LlmApiType::ChatCompletions => provider != LlmProvider::Cohere || native_passthrough,
        LlmApiType::Responses => matches!(
            provider,
            LlmProvider::Openai
                | LlmProvider::AzureOpenai
                | LlmProvider::Bedrock
                | LlmProvider::Xai
        ),
        LlmApiType::Embeddings => matches!(
            provider,
            LlmProvider::Openai
                | LlmProvider::AzureOpenai
                | LlmProvider::Bedrock
                | LlmProvider::VertexAi
                | LlmProvider::Cohere
                | LlmProvider::Mistral
                | LlmProvider::HuggingFace
                | LlmProvider::Dashscope
                | LlmProvider::Ollama
                | LlmProvider::Vllm
        ),
        LlmApiType::Rerank => matches!(
            provider,
            LlmProvider::Cohere
                | LlmProvider::Mistral
                | LlmProvider::HuggingFace
                | LlmProvider::Dashscope
        ),
        LlmApiType::Image => matches!(
            provider,
            LlmProvider::Openai
                | LlmProvider::AzureOpenai
                | LlmProvider::Bedrock
                | LlmProvider::VertexAi
                | LlmProvider::HuggingFace
                | LlmProvider::Xai
                | LlmProvider::Dashscope
        ),
        LlmApiType::Audio => matches!(
            provider,
            LlmProvider::Openai
                | LlmProvider::AzureOpenai
                | LlmProvider::Mistral
                | LlmProvider::HuggingFace
                | LlmProvider::Dashscope
        ),
        LlmApiType::Video => matches!(
            provider,
            LlmProvider::Openai
                | LlmProvider::AzureOpenai
                | LlmProvider::VertexAi
                | LlmProvider::Dashscope
        ),
        LlmApiType::Batch | LlmApiType::File => matches!(
            provider,
            LlmProvider::Openai
                | LlmProvider::AzureOpenai
                | LlmProvider::Mistral
                | LlmProvider::Xai
                | LlmProvider::Dashscope
        ),
        LlmApiType::Realtime => {
            matches!(provider, LlmProvider::Openai | LlmProvider::AzureOpenai)
        }
    }
}

/// 业务作用：验证区域、project 与云签名材料只进入对应 provider，并确保 endpoint scope 不由请求决定。
///
/// 参数说明：
/// - `cfg`：是模型声明
/// - `provider`：是已编译 provider
/// - `route_id`：用于低敏错误定位。
///
/// 返回：云身份字段闭合且字符安全时成功；缺失 scope、半套签名材料或跨 provider 字段污染时失败。
fn validate_cloud_scope(cfg: &LlmModelCfg, provider: LlmProvider, route_id: &str) -> Result<()> {
    let safe_scope = |value: &str| {
        value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    if !cfg.region.is_empty() && !safe_scope(cfg.region.as_str()) {
        bail!(
            "route `{route_id}` llm model `{}` has invalid region",
            cfg.id
        );
    }
    if !cfg.project.is_empty() && !safe_scope(cfg.project.as_str()) {
        bail!(
            "route `{route_id}` llm model `{}` has invalid project",
            cfg.id
        );
    }
    if !cfg.api_version.is_empty() && !safe_scope(cfg.api_version.as_str()) {
        bail!(
            "route `{route_id}` llm model `{}` has invalid api_version",
            cfg.id
        );
    }
    match provider {
        LlmProvider::Bedrock => {
            if cfg.region.is_empty() {
                bail!(
                    "route `{route_id}` Bedrock model `{}` requires region",
                    cfg.id
                );
            }
            if !cfg.project.is_empty() || !cfg.api_version.is_empty() {
                bail!(
                    "route `{route_id}` Bedrock model `{}` cannot set project/api_version",
                    cfg.id
                );
            }
        }
        LlmProvider::VertexAi => {
            if cfg.region.is_empty() || cfg.project.is_empty() {
                bail!(
                    "route `{route_id}` Vertex AI model `{}` requires region and project",
                    cfg.id
                );
            }
            if !cfg.api_version.is_empty()
                || !cfg.aws_access_key_id.is_empty()
                || !cfg.aws_secret_access_key.is_empty()
                || !cfg.aws_session_token.is_empty()
            {
                bail!("route `{route_id}` Vertex AI model `{}` has incompatible cloud identity fields", cfg.id);
            }
        }
        LlmProvider::AzureOpenai => {
            if !cfg.region.is_empty()
                || !cfg.project.is_empty()
                || !cfg.aws_access_key_id.is_empty()
                || !cfg.aws_secret_access_key.is_empty()
                || !cfg.aws_session_token.is_empty()
            {
                bail!("route `{route_id}` Azure OpenAI model `{}` has incompatible cloud identity fields", cfg.id);
            }
        }
        _ => {
            if !cfg.api_version.is_empty()
                || !cfg.region.is_empty()
                || !cfg.project.is_empty()
                || !cfg.aws_access_key_id.is_empty()
                || !cfg.aws_secret_access_key.is_empty()
                || !cfg.aws_session_token.is_empty()
            {
                bail!(
                    "route `{route_id}` llm model `{}` sets cloud fields for a non-cloud provider",
                    cfg.id
                );
            }
        }
    }
    Ok(())
}

/// 业务作用：按 provider 与独立 API 类型生成可信默认 path，模型、region 与 project 只来自当前快照。
///
/// 参数说明：
/// - `cfg`：提供已校验模型 scope
/// - `provider`：是兼容矩阵已接受的组合
/// - `api_type`：是兼容矩阵已接受的组合
/// - `route_id`：仅用于配置错误定位。
///
/// 返回：返回固定绝对 path；需要用户选择具体原生 operation 而未提供 path 时拒绝候选。
fn default_provider_path(
    cfg: &LlmModelCfg,
    provider: LlmProvider,
    api_type: LlmApiType,
    route_id: &str,
) -> Result<String> {
    if provider == LlmProvider::Google {
        return Ok(format!("/v1beta/models/{}:generateContent", cfg.model));
    }
    if provider == LlmProvider::VertexAi && api_type == LlmApiType::ChatCompletions {
        return Ok(format!(
            "/v1/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
            cfg.project, cfg.region, cfg.model
        ));
    }
    if provider == LlmProvider::Anthropic {
        return Ok("/v1/messages".to_string());
    }
    if provider == LlmProvider::Cohere {
        return Ok(match api_type {
            LlmApiType::ChatCompletions => "/v2/chat",
            LlmApiType::Embeddings => "/v2/embed",
            LlmApiType::Rerank => "/v2/rerank",
            _ => unreachable!("Cohere compatibility checked before default path"),
        }
        .to_string());
    }
    if provider == LlmProvider::Ollama && cfg.native_passthrough {
        return Ok(match api_type {
            LlmApiType::ChatCompletions => "/api/chat",
            LlmApiType::Embeddings => "/api/embed",
            _ => unreachable!("Ollama compatibility checked before default path"),
        }
        .to_string());
    }
    if provider == LlmProvider::Mistral && api_type == LlmApiType::Batch {
        return Ok("/v1/batch/jobs".to_string());
    }
    if matches!(provider, LlmProvider::Bedrock | LlmProvider::VertexAi)
        && !matches!(
            api_type,
            LlmApiType::ChatCompletions | LlmApiType::Responses
        )
    {
        bail!(
            "route `{route_id}` llm model `{}` requires an explicit native path for this cloud API",
            cfg.id
        );
    }
    let openai_path = match api_type {
        LlmApiType::ChatCompletions => "/v1/chat/completions".to_string(),
        LlmApiType::Responses => "/v1/responses".to_string(),
        LlmApiType::Embeddings => "/v1/embeddings".to_string(),
        LlmApiType::Rerank => "/v1/rerank".to_string(),
        LlmApiType::Image => "/v1/images/generations".to_string(),
        LlmApiType::Audio => "/v1/audio/speech".to_string(),
        LlmApiType::Video => "/v1/videos".to_string(),
        LlmApiType::Batch => "/v1/batches".to_string(),
        LlmApiType::File => "/v1/files".to_string(),
        LlmApiType::Realtime => {
            let model = percent_encoding::utf8_percent_encode(
                cfg.model.as_str(),
                percent_encoding::NON_ALPHANUMERIC,
            );
            format!("/v1/realtime?model={model}")
        }
    };
    if provider == LlmProvider::AzureOpenai {
        return Ok(format!("/openai{openai_path}"));
    }
    Ok(openai_path)
}

/// 业务作用：校验 Realtime 固定升级 path，允许模型 query 但拒绝 fragment、控制字节与相对目标。
///
/// 参数说明：
/// - `path`：是候选升级目标
/// - `route_id`：只用于错误定位。
/// - `model_id`：只用于错误定位。
///
/// 返回：合法绝对 URI path/query 时成功，否则拒绝候选快照。
fn validate_realtime_path(path: &str, route_id: &str, model_id: &str) -> Result<()> {
    let uri: http::Uri = path.parse().with_context(|| {
        format!("route `{route_id}` realtime model `{model_id}` path is invalid")
    })?;
    if !uri.path().starts_with('/')
        || uri.path().len() > 2048
        || path.contains('#')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("route `{route_id}` realtime model `{model_id}` path must be a bounded absolute path without fragment/control bytes");
    }
    Ok(())
}

/// 业务作用：在候选构建阶段解析可选云凭据 SecretSource，禁止请求路径访问外部事实源。
///
/// 参数说明：
/// - `resolved`：本轮构建已预先物化的可选 Secret 值。
/// - `source`：声明式 SecretSource。
/// - `config_dir`：相对路径解析根。
/// - `route_id`：用于低敏错误定位的 route 标识。
/// - `model_id`：用于低敏错误定位的模型标识。
/// - `field`：用于低敏错误定位的配置字段名。
///
/// 返回：空来源返回 None；合法来源返回已物化文本，读取或语法失败时拒绝候选。
fn resolve_optional_secret(
    resolved: Option<&str>,
    source: &str,
    config_dir: &Path,
    route_id: &str,
    model_id: &str,
    field: &str,
) -> Result<Option<String>> {
    if let Some(value) = resolved {
        return Ok(Some(value.to_owned()));
    }
    if source.is_empty() {
        return Ok(None);
    }
    if crate::security::remote_secret::is_remote_reference(source) {
        bail!("route `{route_id}` llm model `{model_id}` {field} remote value was not prepared");
    }
    crate::security::secret::resolve_text(
        source,
        config_dir,
        &format!("route `{route_id}` llm model `{model_id}` {field}"),
    )
    .map(Some)
}

/// 业务作用：读取模型 API key，优先使用本轮远程 Secret provider 的内存结果，并冻结为敏感 header。
///
/// 参数说明：
/// - `cfg`：是当前模型声明
/// - `config_dir`：是本地 SecretSource 根
/// - `route_id`：仅用于错误定位。
///
/// 返回：空来源返回 None；远程或本地来源有效时返回敏感值，未物化远程引用与非法 header 失败。
fn resolve_model_api_key(
    cfg: &LlmModelCfg,
    config_dir: &Path,
    route_id: &str,
) -> Result<Option<HeaderValue>> {
    let value = if let Some(value) = cfg.resolved_api_key.as_deref() {
        Some(value.to_owned())
    } else if cfg.api_key.is_empty() {
        None
    } else {
        if crate::security::remote_secret::is_remote_reference(cfg.api_key.as_str()) {
            bail!(
                "route `{route_id}` llm model `{}` api_key remote value was not prepared",
                cfg.id
            );
        }
        Some(crate::security::secret::resolve_text(
            cfg.api_key.as_str(),
            config_dir,
            &format!("route `{route_id}` llm model `{}` api_key", cfg.id),
        )?)
    };
    let Some(value) = value else {
        return Ok(None);
    };
    let mut value = HeaderValue::from_str(value.as_str()).with_context(|| {
        format!(
            "route `{route_id}` llm model `{}` api_key is not a header value",
            cfg.id
        )
    })?;
    value.set_sensitive(true);
    Ok(Some(value))
}

/// 业务作用：约束模型 API 路径，使固定 provider 配置不能退化为任意外呼。
fn validate_provider_path(path: &str, route_id: &str, model_id: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > 2048
        || path.contains('?')
        || path.contains('#')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!(
            "route `{route_id}` llm model `{model_id}` path must be an absolute path without query/fragment/control bytes"
        );
    }
    Ok(())
}

/// 业务作用：验证 Google model 名可安全进入构建期生成的 URI path，阻止 path/query 注入。
///
/// 参数说明：
/// - `model`：是 provider 模型名
/// - `route_id`：只用于配置错误定位。
/// - `model_id`：只用于配置错误定位。
///
/// 返回：1..=256 字节安全 ASCII segment 返回成功，其它输入拒绝候选快照。
fn validate_google_model_name(model: &str, route_id: &str, model_id: &str) -> Result<()> {
    if model.is_empty()
        || model.len() > 256
        || !model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "route `{route_id}` Google model `{model_id}` model name must be 1..=256 ASCII [A-Za-z0-9._-]"
        );
    }
    Ok(())
}

/// 业务作用：验证 Google SSE endpoint 只携带固定 `alt=sse` query，避免自定义 path 注入任意参数。
///
/// 参数说明：
/// - `path`：是待发布的 stream path
/// - `route_id`：用于配置错误定位。
/// - `model_id`：用于配置错误定位。
///
/// 返回：安全绝对路径加精确 `?alt=sse` 时成功，否则拒绝候选快照。
fn validate_google_stream_path(path: &str, route_id: &str, model_id: &str) -> Result<()> {
    let Some(base) = path.strip_suffix("?alt=sse") else {
        bail!("route `{route_id}` Google model `{model_id}` stream_path must end with `?alt=sse`");
    };
    validate_provider_path(base, route_id, model_id)?;
    if !base.contains(":streamGenerateContent") {
        bail!(
            "route `{route_id}` Google model `{model_id}` stream_path must target `:streamGenerateContent`"
        );
    }
    Ok(())
}

/// 业务作用：在配置构建期解析 provider 凭据，数据面只使用冻结的认证值。
fn resolve_api_key(
    source: &str,
    config_dir: &Path,
    route_id: &str,
    model_id: &str,
) -> Result<Option<HeaderValue>> {
    if source.is_empty() {
        return Ok(None);
    }
    let value = crate::security::secret::resolve_text(
        source,
        config_dir,
        &format!("route `{route_id}` llm model `{model_id}` api_key"),
    )?;
    let mut value = HeaderValue::from_str(value.as_str()).with_context(|| {
        format!("route `{route_id}` llm model `{model_id}` api_key is not a header value")
    })?;
    value.set_sensitive(true);
    Ok(Some(value))
}

/// 业务作用：计算 SigV4 所需 SHA-256 小写十六进制摘要，不保留原始实体副本。
///
/// 参数说明：
/// - `input`：是 canonical request 或最终 provider 实体。
///
/// 返回：返回固定 64 字符摘要。
fn sha256_hex(input: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(input).into();
    hex_bytes(&digest)
}

/// 业务作用：执行 SigV4 密钥派生和最终签名使用的 HMAC-SHA256。
///
/// 参数说明：
/// - `key`：是当前派生级密钥
/// - `message`：是下一层 scope 或待签名文本。
///
/// 返回：返回固定 32 字节 MAC；HMAC-SHA256 接受任意长度密钥。
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// 业务作用：把二进制签名编码为 canonical 小写十六进制，避免日志或错误路径接触原始密钥。
///
/// 参数说明：
/// - `input`：是摘要或 MAC 字节。
///
/// 返回：返回两倍输入长度的 ASCII 字符串。
fn hex_bytes(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// 业务作用：按 AWS unreserved 规则编码 canonical URI path，并保留层级分隔符。
///
/// 参数说明：
/// - `path`：是快照冻结的绝对 URI path。
///
/// 返回：返回可进入 SigV4 canonical request 的 ASCII path。
fn aws_percent_encode_path(path: &str) -> String {
    aws_percent_encode(path.as_bytes(), true)
}

/// 业务作用：规范化固定 query 的编码和排序，使签名绑定的参数顺序不依赖配置书写顺序。
///
/// 参数说明：
/// - `query`：是不含问号的原始 query。
///
/// 返回：参数可按百分号语法解码时返回 key/value 分别编码并排序的 canonical query。
fn canonical_aws_query(query: &str) -> Result<String> {
    if query.is_empty() {
        return Ok(String::new());
    }
    let mut pairs = Vec::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_encoding::percent_decode_str(key).collect::<Vec<_>>();
        let value = percent_encoding::percent_decode_str(value).collect::<Vec<_>>();
        pairs.push((
            aws_percent_encode(key.as_slice(), false),
            aws_percent_encode(value.as_slice(), false),
        ));
    }
    pairs.sort_unstable();
    Ok(pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&"))
}

/// 业务作用：执行 AWS URI 编码，路径模式仅保留 `/`，其余非 unreserved 字节使用大写十六进制。
///
/// 参数说明：
/// - `input`：是 UTF-8 或已解码 query 字节
/// - `preserve_slash`：仅供 canonical path 使用。
///
/// 返回：返回不含歧义空格、加号或小写 escape 的 ASCII 字符串。
fn aws_percent_encode(input: &[u8], preserve_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(input.len());
    for byte in input {
        if byte.is_ascii_alphanumeric()
            || matches!(*byte, b'-' | b'.' | b'_' | b'~')
            || (preserve_slash && *byte == b'/')
        {
            output.push(*byte as char);
        } else {
            output.push('%');
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    output
}

/// 业务作用：折叠 SigV4 header 值的首尾与连续空白，确保签名与 HTTP 语义规范值一致。
///
/// 参数说明：
/// - `value`：是已验证 ASCII header 值。
///
/// 返回：返回单空格连接的 canonical 值。
fn normalize_aws_header_value(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

/// 业务作用：验证模型后端目标的 URI 和协议边界，阻止无法执行的配置进入快照。
fn validate_upstream(uri: &str, route_id: &str, model_id: &str) -> Result<()> {
    let parsed: http::Uri = uri
        .parse()
        .with_context(|| format!("route `{route_id}` llm model `{model_id}` has invalid uri"))?;
    match parsed.scheme_str() {
        Some("http" | "https") if parsed.authority().is_some() => Ok(()),
        Some("lb")
            if parsed.authority().is_some() || !parsed.path().trim_matches('/').is_empty() =>
        {
            Ok(())
        }
        _ => bail!(
            "route `{route_id}` llm model `{model_id}` uri must be absolute http(s):// or lb://"
        ),
    }
}
