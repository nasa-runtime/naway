//! V6 AI/LLM 统一协议与模型路由。
//!
//! 下游固定使用 OpenAI Chat Completions JSON 契约；模型列表在快照构建期编译为有序计划。
//! 请求 JSON 是显式慢路径：只有配置了 `routes[].llm` 的 route 才读取 body，并且先执行硬上限。
//! 单 frame 直接保留 Hyper 交付的 [`Bytes`]；OpenAI 模型名已经匹配时，上游请求继续复用同一
//! allocation。只有 provider/模型字段确实需要转换时才重新序列化一次。

use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::header::{HeaderValue, AUTHORIZATION, CONTENT_LENGTH, COOKIE, TRANSFER_ENCODING};
use http::request::Parts;
use nasa::cache::local_cache::BoundedLocalCache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::config::model::{
    LlmCacheScopeCfg, LlmEmbeddingCfg, LlmModelCfg, LlmModerationCfg, LlmModerationFailModeCfg,
    LlmProviderCfg, LlmQuotaDimensionCfg, LlmRouteCfg, LlmSelectionStrategyCfg,
    LlmSemanticCacheCfg, LlmTokenQuotaCfg,
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
    /// 请求体聚合硬上限。
    pub(crate) max_body_bytes: usize,
    /// Prompt 估算硬上限。
    pub(crate) max_prompt_tokens: u64,
    /// Completion 预留/注入硬上限。
    pub(crate) max_completion_tokens: u64,
    /// 可选 token bucket 配额。
    pub(crate) token_quota: Option<LlmTokenQuota>,
    /// 构建期校验后的注入/越权短语。
    blocked_substrings: Arc<[Arc<str>]>,
    /// 可信 system prompt 模板；当前是固定文本，不执行请求变量插值。
    system_prompt: Option<Arc<str>>,
    /// 非流式输出本地审核短语。
    blocked_response_substrings: Arc<[Arc<str>]>,
    /// 可选外部 moderation 计划；在模型 admission 前执行。
    pub(crate) moderation: Option<Arc<LlmModerationPolicy>>,
    /// 可选精确 + 语义缓存。状态随 route 快照生命周期走，换版不会串用旧策略 entry。
    pub(crate) semantic_cache: Option<Arc<LlmSemanticCache>>,
    /// 构建期编译的模型首选策略。
    pub(crate) selection: LlmSelectionStrategy,
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
    /// 精确键 L1。值由 `Arc` 共享，命中不会复制响应 `Bytes`。
    exact: BoundedLocalCache<[u8; 32], LlmCacheEntry>,
    /// 最近语义候选。`BoundedLocalCache` 没有暴露全量迭代，因此单独维护有硬上限的小索引；
    /// entry 本体仍与 exact L1 共用同一 `Arc`，不会再复制 response/vector。
    semantic: Mutex<VecDeque<Arc<LlmCacheEntry>>>,
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
    /// 每百万 prompt token 的微美元价格。
    pub(crate) input_cost_microusd_per_million: u64,
    /// 每百万 completion token 的微美元价格。
    pub(crate) output_cost_microusd_per_million: u64,
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
    /// 在 build-then-swap 阶段编译并校验模型列表与 SecretSource。
    pub fn build(cfg: &LlmRouteCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
        if !(1..=MAX_LLM_BODY_BYTES).contains(&cfg.max_body_bytes) {
            bail!("route `{route_id}` llm.max_body_bytes must be within 1..={MAX_LLM_BODY_BYTES}");
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
        };
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
            let built = LlmModel::build(model, config_dir, route_id)?;
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
            // Stable sort preserves config order for equal/unknown price; price=0 means unknown and sorts last.
            models.sort_by_key(|model| {
                let total = model
                    .input_cost_microusd_per_million
                    .saturating_add(model.output_cost_microusd_per_million);
                (total == 0, total)
            });
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
            max_body_bytes: cfg.max_body_bytes as usize,
            max_prompt_tokens: cfg.max_prompt_tokens,
            max_completion_tokens: cfg.max_completion_tokens,
            token_quota,
            blocked_substrings: blocked.into(),
            system_prompt,
            blocked_response_substrings: blocked_response_substrings.into(),
            moderation,
            semantic_cache,
            selection,
            cache_salt: cache_salt.finalize().into(),
            models: models.into(),
        })
    }

    /// 返回不可变的有序模型列表；遍历顺序就是 fallback 顺序。
    pub(crate) fn models(&self) -> &[LlmModel] {
        self.models.as_ref()
    }

    /// 返回首个命中的 prompt 护栏规则；比较过程只借用 JSON 字符串，不拼接完整 prompt。
    pub(crate) fn blocked_prompt<'a>(&'a self, request: &ParsedLlmRequest) -> Option<&'a str> {
        self.blocked_substrings
            .iter()
            .find(|pattern| request.prompt_contains(pattern.as_ref()))
            .map(AsRef::as_ref)
    }

    /// 把固定 system prompt 注入请求；不存在时保持原始 Bytes 可复用状态。
    pub(crate) fn decorate_prompt(&self, request: &mut ParsedLlmRequest) -> Result<()> {
        if let Some(prompt) = &self.system_prompt {
            request.prepend_system_prompt(prompt.as_ref())?;
        }
        Ok(())
    }

    /// 对非流式统一 JSON 响应执行本地输出审核。解析只借用 response body，字符串扫描不分配。
    pub(crate) fn blocked_response(&self, body: &[u8]) -> Result<bool> {
        if self.blocked_response_substrings.is_empty() {
            return Ok(false);
        }
        let value: Value = serde_json::from_slice(body).context("LLM response is not JSON")?;
        Ok(self
            .blocked_response_substrings
            .iter()
            .any(|pattern| value_contains(&value, pattern.as_ref())))
    }
}

impl LlmSemanticCache {
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
            exact: BoundedLocalCache::new(cfg.max_entries),
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

    /// 查询精确 L1；过期 entry 被主动失效，返回的 `Arc` 与响应体共享底层 allocation。
    pub(crate) async fn lookup_exact(&self, key: &[u8; 32]) -> Option<Arc<LlmCacheEntry>> {
        let entry = self.exact.get(key).await?;
        if entry.expires_at > Instant::now() {
            Some(entry)
        } else {
            self.exact.invalidate(key).await;
            None
        }
    }

    /// 在最近的有界候选中计算余弦相似度。向量已归一化，因此只做借用 slice 的点积，
    /// 不为候选构造临时 Vec；维度/生成参数不一致的 entry 会直接跳过。
    pub(crate) fn lookup_semantic(
        &self,
        params_digest: &[u8; 32],
        vector: &[f32],
    ) -> Option<Arc<LlmCacheEntry>> {
        let now = Instant::now();
        let mut entries = self.semantic.lock();
        entries.retain(|entry| entry.expires_at > now);
        let mut best: Option<(f32, Arc<LlmCacheEntry>)> = None;
        for entry in entries.iter().rev().take(self.max_candidates) {
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

    /// 写入精确 L1 与语义候选索引。`body`/`vector` 各只被接管一次，两个索引共享同一 entry。
    pub(crate) async fn insert(
        &self,
        key: [u8; 32],
        params_digest: [u8; 32],
        vector: Arc<[f32]>,
        body: Bytes,
        model_id: Arc<str>,
    ) -> Arc<LlmCacheEntry> {
        let entry = self
            .exact
            .insert(
                key,
                LlmCacheEntry {
                    body,
                    model_id,
                    vector,
                    params_digest,
                    expires_at: Instant::now() + self.ttl,
                },
            )
            .await;
        if !entry.vector.is_empty() {
            let mut entries = self.semantic.lock();
            entries.push_back(entry.clone());
            while entries.len() > self.max_entries {
                entries.pop_front();
            }
        }
        entry
    }

    /// 缓存 TTL，供 Redis L2 使用同一策略。
    pub(crate) fn ttl(&self) -> Duration {
        self.ttl
    }

    /// 单 scope 的 L2 索引最大 entry 数。
    pub(crate) fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// 最多从 L2 拉取的最近候选数。
    pub(crate) fn max_candidates(&self) -> usize {
        self.max_candidates
    }

    /// 语义命中阈值。
    pub(crate) fn threshold(&self) -> f32 {
        self.threshold
    }
}

impl LlmEmbeddingModel {
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

    /// 清除下游信任边界凭据并注入 embedding provider bearer token。
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
    /// 参数说明：`cfg` 是 route moderation 配置，`config_dir` 是 SecretSource 相对目录，`route_id` 用于错误定位。
    ///
    /// 返回：所有边界合法时返回不可变调用计划；超时、体积、URI、model 或凭据非法时拒绝候选快照。
    fn build(cfg: &LlmModerationCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
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
    /// 参数说明：`request` 是完成可信 system prompt 注入后的统一请求。
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
        let body = serde_json::to_vec(&json!({"model":self.model.as_ref(),"input":input}))
            .map(Bytes::from)
            .context("encode LLM moderation request")?;
        if body.len() > self.max_request_bytes {
            bail!("LLM moderation request exceeds request limit");
        }
        Ok(body)
    }

    /// 业务作用：清除下游凭据并注入 external moderation bearer token，维持独立信任边界。
    ///
    /// 参数说明：`parts` 是将发送给 moderation endpoint 的请求头副本。
    ///
    /// 返回：无；原地清除客户端/provider 专属认证字段并设置 JSON content type。
    pub(crate) fn prepare_headers(&self, parts: &mut Parts) {
        parts.headers.remove(AUTHORIZATION);
        parts.headers.remove(COOKIE);
        parts.headers.remove("x-api-key");
        parts.headers.remove("x-goog-api-key");
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
/// 参数说明：`body` 是经过 route response 硬上限约束的 JSON。
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
    /// 参数说明：`cfg` 是单模型配置，`config_dir` 是 SecretSource 相对目录，`route_id` 用于错误定位。
    ///
    /// 返回：配置、路径、模型名和凭据都合法时返回可发布模型；任一信任边界不满足时拒绝候选快照。
    fn build(cfg: &LlmModelCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
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
        };
        if provider == LlmProvider::Google {
            validate_google_model_name(cfg.model.as_str(), route_id, cfg.id.as_str())?;
        }
        let default_path = match provider {
            LlmProvider::Openai => "/v1/chat/completions".to_string(),
            LlmProvider::Anthropic => "/v1/messages".to_string(),
            LlmProvider::Google => {
                format!("/v1beta/models/{}:generateContent", cfg.model)
            }
        };
        let path = if cfg.path.is_empty() {
            default_path
        } else {
            cfg.path.clone()
        };
        validate_provider_path(path.as_str(), route_id, cfg.id.as_str())?;
        let stream_path = match provider {
            LlmProvider::Google => {
                let stream_path = if cfg.stream_path.is_empty() {
                    format!("/v1beta/models/{}:streamGenerateContent?alt=sse", cfg.model)
                } else {
                    cfg.stream_path.clone()
                };
                validate_google_stream_path(stream_path.as_str(), route_id, cfg.id.as_str())?;
                Some(Arc::from(stream_path))
            }
            LlmProvider::Openai | LlmProvider::Anthropic => {
                if !cfg.stream_path.is_empty() {
                    bail!(
                        "route `{route_id}` non-Google LLM model `{}` cannot set stream_path",
                        cfg.id
                    );
                }
                None
            }
        };
        let api_key = resolve_api_key(cfg.api_key.as_str(), config_dir, route_id, cfg.id.as_str())?;
        let anthropic_version = match provider {
            LlmProvider::Openai | LlmProvider::Google => {
                if !cfg.anthropic_version.is_empty() {
                    bail!(
                        "route `{route_id}` non-Anthropic model `{}` cannot set anthropic_version",
                        cfg.id
                    );
                }
                None
            }
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
        };
        Ok(Self {
            id: Arc::from(cfg.id.as_str()),
            provider,
            upstream: Arc::from(cfg.uri.as_str()),
            model: Arc::from(cfg.model.as_str()),
            path: Arc::from(path),
            stream_path,
            api_key,
            anthropic_version,
            input_cost_microusd_per_million: cfg.input_cost_microusd_per_million,
            output_cost_microusd_per_million: cfg.output_cost_microusd_per_million,
            weight: cfg.weight,
        })
    }

    /// 业务作用：把下游认证字段替换为 provider 凭据并设置 provider 固定 header，阻止客户端凭据越界泄漏。
    ///
    /// 参数说明：`parts` 是即将发送给模型 provider 的独立请求头副本；`stream` 表示是否使用 SSE endpoint。
    ///
    /// 返回：无；原地清理不可信凭据并注入快照构建期解析的 provider 凭据。
    pub(crate) fn prepare_headers(&self, parts: &mut Parts, stream: bool) {
        parts.headers.remove(AUTHORIZATION);
        parts.headers.remove(COOKIE);
        parts.headers.remove("x-api-key");
        parts.headers.remove("x-goog-api-key");
        parts.headers.remove("anthropic-version");
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(TRANSFER_ENCODING);
        parts.headers.remove(http::header::ACCEPT_ENCODING);
        parts.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        match self.provider {
            LlmProvider::Openai => {
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

    /// 业务作用：为当前请求选择 provider 固定的 unary 或 SSE path，避免运行期拼接不可信模型名。
    ///
    /// 参数说明：`stream` 表示下游是否请求 SSE。
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
}

impl ParsedLlmRequest {
    /// 解析 OpenAI-compatible Chat Completions 请求并计算有界 token 估算。
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
    /// 参数说明：`model` 是快照构建期已校验的目标 provider 与模型计划。
    ///
    /// 返回：字段可无损映射时返回 JSON `Bytes`；存在 provider 不支持的角色、内容或参数时失败闭合。
    pub(crate) fn body_for(&mut self, model: &LlmModel) -> Result<Bytes> {
        match model.provider {
            LlmProvider::Openai => {
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
        }
    }

    /// 校验 completion 上限；请求未声明时把安全默认值写入 DOM。返回本次配额预留成本。
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

    /// 生成按缓存 scope 隔离的精确键。直接增量摘要原始 `Bytes`，不创建 body 副本；同一逻辑
    /// JSON 使用不同空白可能精确 miss，但会继续走真正 embedding 语义层，正确性不受影响。
    pub(crate) fn exact_cache_digest(&self, scope: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"gw-llm-exact-v1\0");
        digest.update((scope.len() as u64).to_be_bytes());
        digest.update(scope);
        digest.update(self.raw.as_ref());
        digest.finalize().into()
    }

    /// 摘要除 messages/model/stream 外的全部生成参数。语义相近 prompt 只有在 temperature、tools、
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
        // L1 semantic index is route-wide, so scope 必须进入比较摘要；否则不同 consumer 的相近
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

    /// 构造一次 OpenAI-compatible embedding 请求。prompt 拼接是语义缓存显式慢路径唯一必要的
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
        serde_json::to_vec(&json!({"model": model.model.as_ref(), "input": prompt}))
            .map(Bytes::from)
            .context("encode embedding request")
    }

    /// 在 messages 首位插入可信固定 system prompt，并重新计算保守 prompt token 估算。只有配置
    /// 该能力才修改 DOM/重编码；普通 OpenAI 同模型请求仍保留原 `Bytes` 零复制路径。
    fn prepend_system_prompt(&mut self, prompt: &str) -> Result<()> {
        let messages = self
            .document
            .get_mut("messages")
            .and_then(Value::as_array_mut)
            .expect("LLM messages validated at parse");
        if messages.len() >= 4096 {
            bail!("LLM system prompt would exceed 4096 messages");
        }
        messages.insert(0, json!({"role":"system","content":prompt}));
        let prompt_bytes = prompt_text_bytes(messages)?;
        self.prompt_tokens =
            (prompt_bytes as u64).saturating_add((messages.len() as u64).saturating_mul(4));
        self.pristine = false;
        Ok(())
    }

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

/// 解析 OpenAI-compatible embedding 响应并原地归一化向量。只保留第一个 embedding；空、NaN、
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

/// 编码 Redis exact response。body 已是 provider 校验过的有界 JSON `Bytes`；L2 Redis string
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

/// 解码 Redis exact response，先验证固定头与所有长度再建立 `Bytes::slice`。body slice 与下载的
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

/// 序列化小型 L2 语义索引成员；不包含响应 body。
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

/// 从有界 Redis 列表选最高相似度候选。每个成员都重新校验维度/有限值；单个脏成员跳过，
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

/// 将 32 字节摘要写成固定 64 字节小写十六进制 key 片段。
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
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 把非流式 Anthropic Messages 响应映射回 OpenAI Chat Completions。
pub(crate) fn anthropic_response_to_openai(body: &[u8]) -> Result<(Bytes, LlmUsage)> {
    let source: Value = serde_json::from_slice(body).context("Anthropic response is not JSON")?;
    let object = source
        .as_object()
        .context("Anthropic response must be a JSON object")?;
    let content = object
        .get("content")
        .and_then(Value::as_array)
        .context("Anthropic response requires content array")?
        .iter()
        .filter_map(|block| {
            (block.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| block.get("text").and_then(Value::as_str))
                .flatten()
        })
        .collect::<String>();
    let input_tokens = source
        .pointer("/usage/input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = source
        .pointer("/usage/output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let finish_reason = match object.get("stop_reason").and_then(Value::as_str) {
        Some("max_tokens") => "length",
        Some("tool_use") => "tool_calls",
        _ => "stop",
    };
    let converted = json!({
        "id": object.get("id").cloned().unwrap_or_else(|| Value::String("anthropic".to_string())),
        "object": "chat.completion",
        "created": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "model": object.get("model").cloned().unwrap_or(Value::Null),
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": finish_reason
        }],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens.saturating_add(output_tokens)
        }
    });
    let encoded = serde_json::to_vec(&converted)
        .map(Bytes::from)
        .context("encode unified OpenAI response")?;
    Ok((
        encoded,
        LlmUsage {
            prompt_tokens: input_tokens,
            completion_tokens: output_tokens,
        },
    ))
}

/// 业务作用：把 Google `GenerateContentResponse` 映射回统一 OpenAI Chat Completions 响应，并提取账单事实。
///
/// 参数说明：`body` 是经过响应体硬上限约束的 Google unary JSON。
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
            "message": {"role": "assistant", "content": content},
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
/// 参数说明：`source` 是已解析且受体积上限保护的 Google response。
///
/// 返回：usage 完整时返回 prompt/completion 计数，整体缺失时返回 None，字段半缺或类型错误时拒绝响应。
pub(crate) fn google_usage(source: &Value) -> Result<Option<LlmUsage>> {
    let Some(usage) = source.get("usageMetadata") else {
        return Ok(None);
    };
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
    Ok(Some(LlmUsage {
        prompt_tokens,
        completion_tokens,
    }))
}

/// 从 OpenAI-compatible 非流式响应读取 usage；缺失 usage 返回 None，不用估算值冒充账单事实。
pub(crate) fn openai_usage(body: &[u8]) -> Result<Option<LlmUsage>> {
    let value: Value = serde_json::from_slice(body).context("OpenAI response is not JSON")?;
    let Some(usage) = value.get("usage") else {
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
    Ok(Some(LlmUsage {
        prompt_tokens,
        completion_tokens,
    }))
}

fn openai_to_anthropic(source: &Value, model: &str) -> Result<Value> {
    let object = source
        .as_object()
        .context("LLM request must be an object")?;
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
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .context("LLM message requires string role")?;
        let content = message
            .get("content")
            .cloned()
            .context("LLM message requires content")?;
        if role == "system" {
            system.push(content_text(&content)?);
            continue;
        }
        if !matches!(role, "user" | "assistant") {
            bail!("Anthropic adapter only supports system/user/assistant roles");
        }
        converted.push(json!({ "role": role, "content": content }));
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
/// 参数说明：`source` 是已解析的统一请求，`stream` 表示将使用 Google SSE endpoint。
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
            "user" => contents.push(json!({"role":"user","parts":[{"text":text}]})),
            "assistant" => contents.push(json!({"role":"model","parts":[{"text":text}]})),
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
            json!({"parts":[{"text":system.join("\n")}]}),
        );
    }
    if !generation.is_empty() {
        target.insert("generationConfig".to_string(), Value::Object(generation));
    }
    Ok(Value::Object(target))
}

/// 业务作用：把统一消息内容收窄为 Google 当前适配器支持的纯文本，阻止多模态块被静默丢弃。
///
/// 参数说明：`content` 是单条 Chat Completions message 的 content。
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
/// 参数说明：`reason` 是候选的可选 Google `finishReason`。
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

fn content_text(content: &Value) -> Result<String> {
    if let Some(text) = content.as_str() {
        return Ok(text.to_string());
    }
    let blocks = content
        .as_array()
        .context("LLM message content must be string or array")?;
    let mut text = String::new();
    for block in blocks {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            let value = block
                .get("text")
                .and_then(Value::as_str)
                .context("LLM text content block requires text")?;
            text.push_str(value);
        }
    }
    Ok(text)
}

/// 把 message 的文字片段追加到已有 prompt buffer；调用方统一控制分隔符和总 allocation。
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

/// 只借用 JSON 字符串计算 prompt 大小；token 预估热路径不构造临时拼接字符串。
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

fn value_contains(value: &Value, pattern: &str) -> bool {
    match value {
        Value::String(text) => contains_ascii_case_insensitive(text.as_bytes(), pattern.as_bytes()),
        Value::Array(values) => values.iter().any(|value| value_contains(value, pattern)),
        Value::Object(values) => values.values().any(|value| value_contains(value, pattern)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// ASCII 护栏无分配扫描；pattern 在构建期已限制为 ASCII，UTF-8 prompt 的非 ASCII 字节
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

fn hash_digest_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

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
/// 参数说明：`model` 是 provider 模型名，`route_id` 与 `model_id` 只用于配置错误定位。
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
/// 参数说明：`path` 是待发布的 stream path，`route_id` 与 `model_id` 用于配置错误定位。
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

fn resolve_api_key(
    source: &str,
    config_dir: &Path,
    route_id: &str,
    model_id: &str,
) -> Result<Option<HeaderValue>> {
    if source.is_empty() {
        return Ok(None);
    }
    let value = crate::secret::resolve_text(
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

#[path = "../../tests/unit/llm.rs"]
#[cfg(test)]
mod tests;
