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
    LlmCacheScopeCfg, LlmEmbeddingCfg, LlmModelCfg, LlmProviderCfg, LlmQuotaDimensionCfg,
    LlmRouteCfg, LlmSelectionStrategyCfg, LlmSemanticCacheCfg, LlmTokenQuotaCfg,
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
    /// 可选精确 + 语义缓存。状态随 route 快照生命周期走，换版不会串用旧策略 entry。
    pub(crate) semantic_cache: Option<Arc<LlmSemanticCache>>,
    /// 构建期编译的模型首选策略。
    pub(crate) selection: LlmSelectionStrategy,
    /// 影响响应语义的 route 配置摘要；进入 cache scope，热更 system/model 后不会命中旧 L2。
    pub(crate) cache_salt: [u8; 32],
    /// 主模型在前、fallback 在后的不可变模型 slice。
    models: Arc<[LlmModel]>,
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
    /// 基于 UTF-8 字节数的保守 prompt token 估算；后续 provider usage 会覆盖观测值。
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
        cache_salt.update(cfg.max_completion_tokens.to_be_bytes());
        cache_salt.update([selection as u8]);
        for model in &models {
            hash_digest_part(&mut cache_salt, model.id.as_bytes());
            hash_digest_part(&mut cache_salt, model.model.as_bytes());
            hash_digest_part(&mut cache_salt, model.upstream.as_bytes());
            hash_digest_part(&mut cache_salt, model.path.as_bytes());
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
        };
        let default_path = match provider {
            LlmProvider::Openai => "/v1/chat/completions",
            LlmProvider::Anthropic => "/v1/messages",
        };
        let path = if cfg.path.is_empty() {
            default_path
        } else {
            cfg.path.as_str()
        };
        validate_provider_path(path, route_id, cfg.id.as_str())?;
        let api_key = resolve_api_key(cfg.api_key.as_str(), config_dir, route_id, cfg.id.as_str())?;
        let anthropic_version = match provider {
            LlmProvider::Openai => {
                if !cfg.anthropic_version.is_empty() {
                    bail!(
                        "route `{route_id}` OpenAI model `{}` cannot set anthropic_version",
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
            api_key,
            anthropic_version,
            input_cost_microusd_per_million: cfg.input_cost_microusd_per_million,
            output_cost_microusd_per_million: cfg.output_cost_microusd_per_million,
            weight: cfg.weight,
        })
    }

    /// 把下游认证字段替换为 provider 凭据并设置 provider 固定 header。
    ///
    /// 下游 Authorization/Cookie/API-Key 属客户端到 gateway 的信任边界，绝不能因默认透传泄漏
    /// 给外部模型。HeaderValue 在快照中已解析；clone 只复制小 header 元数据/内部字节。
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
        }
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
        // 4 UTF-8 bytes/token is an intentionally conservative tokenizer-independent estimate;
        // add a small per-message framing cost so many empty messages cannot appear free.
        let prompt_tokens = (prompt_bytes as u64)
            .div_ceil(4)
            .saturating_add((messages.len() as u64).saturating_mul(4));
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

    /// 为一个模型生成上游 body。返回 `Bytes`，fallback 只增加引用计数或拥有一次转换结果。
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
        self.prompt_tokens = (prompt_bytes as u64)
            .div_ceil(4)
            .saturating_add((messages.len() as u64).saturating_mul(4));
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
