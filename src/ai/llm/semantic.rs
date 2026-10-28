//! 模型策略比较只读取冻结参数，语义缓存的条目、锁和工作区占用不参与配置身份。

use super::{LlmCacheScopeCfg, LlmEmbeddingModel, LlmSemanticCache};
use std::time::Duration;

#[derive(PartialEq)]
struct CacheIdentity<'a> {
    ttl: Duration,
    max_entries: usize,
    max_response_bytes: usize,
    threshold: f32,
    max_candidates: usize,
    l2_enabled: bool,
    scope: LlmCacheScopeCfg,
    embedding: &'a LlmEmbeddingModel,
}

impl LlmSemanticCache {
    /// 业务作用：穷尽区分语义缓存的固定容量与运行条目，使管理比较无需等待请求持有的锁。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用同次构建的 embedding 目标与实际凭据，保留有限阈值和全部固定缓存预算。
    fn semantic_identity(&self) -> CacheIdentity<'_> {
        let Self {
            workspace_budget: _,
            exact: _,
            semantic: _,
            ttl,
            max_entries,
            max_response_bytes,
            threshold,
            max_candidates,
            l2_enabled,
            scope,
            embedding,
        } = self;
        CacheIdentity {
            ttl: *ttl,
            max_entries: *max_entries,
            max_response_bytes: *max_response_bytes,
            threshold: *threshold,
            max_candidates: *max_candidates,
            l2_enabled: *l2_enabled,
            scope: *scope,
            embedding,
        }
    }
}

impl PartialEq for LlmSemanticCache {
    /// 业务作用：识别语义缓存策略变更，避免活动条目或许可占用被当作配置变化。
    ///
    /// 参数说明：
    /// - `other`：已校验阈值有限且预算合法的候选缓存。
    ///
    /// 返回：全部固定参数一致时为真；不读取条目、不获取锁、不分配或编码凭据。
    fn eq(&self, other: &Self) -> bool {
        self.semantic_identity() == other.semantic_identity()
    }
}

// 构建器拒绝非有限阈值，缓存身份保持自反性；正负零使用相同的余弦阈值语义。
impl Eq for LlmSemanticCache {}
