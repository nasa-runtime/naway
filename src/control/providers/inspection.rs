//! 已授权来源的低敏读面与纯候选输入；不返回传输地址、凭据引用、模板正文或派生路由。

use super::{
    model::{Declaration, Reference},
    registry::State,
    state::{Observation, Snapshot},
};
use crate::control::ownership::Owner;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

impl Snapshot {
    /// 业务作用：为管理入口提供有限的本地来源身份与不可伪造归属，先筛权限再生成详情。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最多三十二项身份与 owner 借用，不含传输配置。
    pub(crate) fn owners(&self) -> impl Iterator<Item = (&str, &Owner)> {
        self.plan
            .sources
            .iter()
            .map(|(id, source)| (id.as_str(), &source.authority.owner))
    }

    /// 业务作用：绑定某来源的完整已发布事实，作为管理分页、候选和导出的前置条件。
    ///
    /// 参数说明：
    /// - `id`：为已授权来源。
    ///
    /// 返回：本来源声明与本域合并语义摘要；成功续期不会改变该值，不使用其它域的对象序列。
    pub(crate) fn etag(&self, id: &str) -> Option<String> {
        use sha2::{Digest, Sha256};
        let source = self.plan.sources.get(id)?;
        let mut hash = Sha256::new();
        hash.update(serde_json::to_vec(&source.config).ok()?);
        hash.update(serde_json::to_vec(&source.authority.owner).ok()?);
        hash.update(serde_json::to_vec(&self.registry.metadata(id)).ok()?);
        for (key, value) in &self.view.objects {
            if key.namespace == source.authority.namespace {
                hash.update(serde_json::to_vec(&(key, &value.authority.source, value.state)).ok()?);
                hash.update(value.object.digest);
            }
        }
        Some(format!("\"sha256-{:x}\"", hash.finalize()))
    }

    /// 业务作用：在收集管理候选正文前取得该来源的本地预算。
    ///
    /// 参数说明：
    /// - `id`：为已授权来源。
    ///
    /// 返回：有限字节上限，未知来源为空。
    pub(crate) fn body_limit(&self, id: &str) -> Option<usize> {
        Some(self.plan.sources.get(id)?.config.max_body_bytes)
    }

    /// 业务作用：为平台聚合读面提供整个配置联邦的语义摘要，不向工作区读取者交付全局序列。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已发布合并视图的固定长度 SHA-256 文本。
    pub(crate) fn federation_digest(&self) -> String {
        self.view
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// 业务作用：输出仅已发布证据支持的状态，最近失败与最大陈旧期分别展示。
    ///
    /// 参数说明：
    /// - `id`：是已授权来源。
    ///
    /// 返回：有限低敏摘要；无来源返回空，不包含错误原文或远端正文。
    pub(crate) fn summary(&self, id: &str) -> Option<Value> {
        let source = self.plan.sources.get(id)?;
        let now = Instant::now();
        let refreshed = self.registry.refreshed(id);
        let document = self.registry.metadata(id);
        let age = refreshed.map(|time| now.saturating_duration_since(time).as_millis() as u64);
        let health = source.health.lock();
        let phase = if document.is_none() {
            "warming"
        } else if age.is_none_or(|age| age >= source.config.max_stale_ms) {
            "stale"
        } else if health
            .last
            .is_some_and(|outcome| outcome != super::metrics::Outcome::Published)
        {
            "degraded"
        } else {
            "current"
        };
        Some(json!({
            "id":id,
            "namespace":source.authority.namespace,
            "owner":source.authority.owner,
            "priority":source.authority.priority,
            "revision":document.map(|value|value.0),
            "objects":document.map_or(0,|value|value.1),
            "phase":phase,
            "age_ms":age,
            "max_stale_ms":source.config.max_stale_ms,
            "last_outcome":health.last,
            "consecutive_failures":health.failures,
            "last_attempt_age_ms":health.attempted.map(|time|now.saturating_duration_since(time).as_millis() as u64)
        }))
    }

    /// 业务作用：解释选中来源、冲突、删除、过期与依赖未齐，不展示其它 owner 的对象存在性。
    ///
    /// 参数说明：
    /// - `id`：为已授权来源
    /// - `offset`：为同一摘要下的有界页。
    /// - `limit`：为同一摘要下的有界页。
    ///
    /// 返回：本 namespace 的可见合并状态，不包含规则正文、上游地址或凭据。
    pub(crate) fn explain(&self, id: &str, offset: usize, limit: usize) -> Option<Value> {
        let source = self.plan.sources.get(id)?;
        let now = Instant::now();
        let mut objects:Vec<_>=self.view.objects.iter().filter(|(key,value)|key.namespace==source.authority.namespace&&value.authority.owner==source.authority.owner).skip(offset).take(limit+1).map(|(key,value)|{
            let state=if value.state==State::Active&&value.valid_until.is_some_and(|deadline|deadline<=now){
                State::Expired
            }else{
                value.state
            };
            json!({
                "identity":key,
                "selected_source":value.authority.source,
                "generation":value.object.declaration.generation,
                "state":state,
                "compiled":state==State::Active&&self.report.active.contains(key),
                "waiting_dependencies":state==State::Active&&self.report.withdrawn.contains(key),
                "selected_from_requested_source":value.authority.source==id
            })
        }).collect();
        let next = (objects.len() > limit).then_some(offset + limit);
        objects.truncate(limit);
        Some(json!({
            "source":self.summary(id)?,
            "objects":objects,
            "next_offset":next
        }))
    }

    /// 业务作用：生成可供独立写入方 CAS 重放的来源中立声明，不包含传输秘密或运行时派生状态。
    ///
    /// 参数说明：
    /// - `id`：为已经授权的固定来源。
    ///
    /// 返回：当前归属与提升版本的重放候选；未观察、版本或预算耗尽时拒绝，不写回事实源。
    pub(crate) fn export(&self, id: &str) -> Result<Value> {
        let source = self.plan.sources.get(id).context("source missing")?;
        Ok(json!({
            "schema_version":1,
            "source":id,
            "namespace":source.authority.namespace,
            "owner":source.authority.owner,
            "priority":source.authority.priority,
            "declaration":self.registry.replay(id)?
        }))
    }

    /// 业务作用：把管理候选绑定到同代本地来源权威，交给完整构建器，不刷新运行中来源时间。
    ///
    /// 参数说明：
    /// - `id`：为已授权来源
    /// - `bytes`：是受上限约束的 JSON/YAML 声明。
    ///
    /// 返回：私有候选观测；解析失败不回显原始载荷。
    pub(crate) fn candidate(&self, id: &str, bytes: &[u8]) -> Result<Observation> {
        let source = self.plan.sources.get(id).context("source missing")?;
        let document: Declaration =
            crate::config::document::decode(bytes, source.config.max_body_bytes)
                .map_err(|_| anyhow::anyhow!("source declaration rejected"))?;
        Ok(Observation {
            signature: self.plan.signature,
            incarnation: self.plan.incarnation,
            source: id.into(),
            document,
            workload: None,
            observed: Instant::now(),
        })
    }

    /// 业务作用：对完整构建后的两个来源声明比较真实语义，不把仅 revision/generation 变化伪装成业务变化。
    ///
    /// 参数说明：
    /// - `next`：是同代完整候选
    /// - `id`：为获授权来源。
    ///
    /// 返回：按稳定身份列出的语义增删改，不返回完整 spec 或其它 owner 对象。
    pub(crate) fn diff(&self, next: &Self, id: &str) -> Value {
        let index = |snapshot: &Self| {
            snapshot
                .registry
                .document(id)
                .map(|document| {
                    document
                        .objects
                        .into_iter()
                        .filter(|object| object.spec.is_some())
                        .map(|object| ((object.kind, object.name), object.spec))
                        .collect::<BTreeMap<_, _>>()
                })
                .unwrap_or_default()
        };
        let before = index(self);
        let after = index(next);
        let keys: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
        let namespace = self
            .plan
            .sources
            .get(id)
            .map(|source| source.authority.namespace.as_str())
            .unwrap_or("");
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        for (kind, name) in keys {
            let key = (kind, name.clone());
            let target = match (before.get(&key), after.get(&key)) {
                (None, Some(_)) => &mut added,
                (Some(_), None) => &mut removed,
                (Some(left), Some(right)) if left != right => &mut changed,
                _ => continue,
            };
            target.push(Reference {
                namespace: namespace.into(),
                kind,
                name,
            });
        }
        json!({
            "added":added,
            "removed":removed,
            "changed":changed
        })
    }
}
