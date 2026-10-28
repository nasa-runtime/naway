//! 确定性来源合并与候选水位；完整网关发布失败时不刷新来源健康或退休旧声明。

use super::model::*;
use anyhow::{ensure, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
struct Watermark {
    generation: u64,
    digest: [u8; 32],
    present: bool,
}

#[derive(Clone)]
struct Source {
    authority: Authority,
    document: Option<Arc<Prepared>>,
    watermarks: BTreeMap<(Kind, String), Watermark>,
    refreshed: Option<Instant>,
}

#[derive(Clone)]
pub(super) struct Registry {
    serial: u64,
    sources: BTreeMap<String, Source>,
}

/// 仅用于完整 build 的中间候选；不含自行替换 GatewaySnapshot 的能力。
pub(super) struct Candidate {
    base_serial: u64,
    pub(super) valid_until: Option<Instant>,
    sources: BTreeMap<String, Source>,
    pub view: View,
}

pub(super) struct Commit<'a> {
    registry: &'a mut Registry,
    sources: BTreeMap<String, Source>,
    serial: u64,
}

#[derive(Clone)]
pub(super) struct View {
    pub objects: BTreeMap<Reference, Resolved>,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    Active,
    Tombstone,
    Expired,
    Conflict,
}

#[derive(Clone)]
pub(super) struct Resolved {
    pub authority: Authority,
    pub object: Arc<PreparedObject>,
    pub state: State,
    pub valid_until: Option<Instant>,
}

impl Registry {
    /// 业务作用：直接读取已准备声明的规模，目录查询不复制完整正文。
    ///
    /// 参数说明：
    /// - `id`：为固定来源。
    ///
    /// 返回：已发布 revision、对象数和内容摘要；未观察时为空。
    pub(super) fn metadata(&self, id: &str) -> Option<(u64, usize, [u8; 32])> {
        let document = self.sources.get(id)?.document.as_ref()?;
        Some((document.revision, document.objects.len(), document.digest))
    }

    /// 业务作用：给管理读面提供已提交声明的新鲜度，不把失败尝试当作刷新。
    ///
    /// 参数说明：
    /// - `id`：是已授权固定来源。
    ///
    /// 返回：最近发布观测时间；未知来源或未发布时为空。
    pub(super) fn refreshed(&self, id: &str) -> Option<Instant> {
        self.sources.get(id)?.refreshed
    }

    /// 业务作用：导出当前期望声明并将省略删除转成可重放 tombstone，避免新目录复活低优先级对象。
    ///
    /// 参数说明：
    /// - `id`：为已授权固定来源。
    ///
    /// 返回：提升声明 revision 的独立重放候选；不改变活动水位，容量或版本耗尽拒绝。
    pub(super) fn replay(&self, id: &str) -> Result<Declaration> {
        let source = self
            .sources
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("unknown source"))?;
        let mut document = self
            .document(id)
            .ok_or_else(|| anyhow::anyhow!("source not observed"))?;
        document.revision = document
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("source revision exhausted"))?;
        for ((kind, name), mark) in source.watermarks.iter().filter(|(_, mark)| !mark.present) {
            document.objects.push(Object {
                kind: *kind,
                name: name.clone(),
                generation: mark
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("object generation exhausted"))?,
                spec: None,
            });
        }
        document
            .objects
            .sort_by(|left, right| (left.kind, &left.name).cmp(&(right.kind, &right.name)));
        document.clone().prepare()?;
        Ok(document)
    }

    /// 业务作用：为条件读取重建上一份已发布全文，304 不能确认未通过完整构建的载荷。
    ///
    /// 参数说明：
    /// - `id`：为固定来源身份。
    ///
    /// 返回：上次已发布的完整声明；尚无成功观测时为 None，不合成空文档或删除。
    pub(super) fn document(&self, id: &str) -> Option<Declaration> {
        self.sources
            .get(id)?
            .document
            .as_ref()
            .map(|document| Declaration {
                schema_version: 1,
                revision: document.revision,
                objects: document
                    .objects
                    .values()
                    .map(|object| object.declaration.clone())
                    .collect(),
            })
    }

    /// 业务作用：建立有限来源目录并冻结归属，同一命名空间不能被不同 owner 竞争。
    ///
    /// 参数说明：
    /// - `authorities`：是本地 bootstrap 已授权来源，不接受远端对象建立新来源。
    ///
    /// 返回：空水位目录；重复来源、跨 owner 命名空间或超限时拒绝。
    pub(super) fn new(authorities: Vec<Authority>) -> Result<Self> {
        ensure!(
            authorities.len() <= MAX_SOURCES,
            "provider source capacity reached"
        );
        let mut sources = BTreeMap::new();
        let mut owners = BTreeMap::new();
        for authority in authorities {
            authority.validate()?;
            if let Some(owner) = owners.insert(authority.namespace.clone(), authority.owner.clone())
            {
                ensure!(
                    owner == authority.owner,
                    "provider namespace owner conflict"
                );
            }
            let id = authority.source.clone();
            ensure!(
                sources
                    .insert(
                        id,
                        Source {
                            authority,
                            document: None,
                            watermarks: BTreeMap::new(),
                            refreshed: None
                        }
                    )
                    .is_none(),
                "duplicate provider source"
            );
        }
        Ok(Self {
            serial: 0,
            sources,
        })
    }

    /// 业务作用：校验单个来源的完整观测，生成不修改活动水位的事务候选。
    ///
    /// 参数说明：
    /// - `id`：是固定来源
    /// - `document`：为已完整读取的声明
    /// - `now`：是本轮观测单调时间。
    ///
    /// 返回：可交给完整网关构建器的候选；重复版本只允许相同内容，拒绝乱序和删除后旧值复活。
    pub(super) fn stage(&self, id: &str, document: Declaration, now: Instant) -> Result<Candidate> {
        let document = Arc::new(document.prepare()?);
        let mut sources = self.sources.clone();
        let source = sources
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown provider source"))?;
        if let Some(previous) = &source.document {
            // 低水位或同版异内容不刷新新鲜度；否则坏来源可以无限延长旧路由的存活。
            ensure!(
                document.revision >= previous.revision,
                "provider revision regressed"
            );
            ensure!(
                document.revision != previous.revision || document.digest == previous.digest,
                "provider revision content conflict"
            );
        }
        for (key, object) in &document.objects {
            if let Some(previous) = source.watermarks.get(key) {
                ensure!(
                    object.declaration.generation >= previous.generation,
                    "provider object generation regressed"
                );
                ensure!(
                    object.declaration.generation != previous.generation
                        || (previous.present && object.digest == previous.digest),
                    "provider object generation content conflict"
                );
            }
        }
        for (key, watermark) in &mut source.watermarks {
            watermark.present = document.objects.contains_key(key);
        }
        for (key, object) in &document.objects {
            source.watermarks.insert(
                key.clone(),
                Watermark {
                    generation: object.declaration.generation,
                    digest: object.digest,
                    present: true,
                },
            );
        }
        source.document = Some(document);
        source.refreshed = Some(now);
        Self::candidate(self.serial, sources, now)
    }

    /// 业务作用：按单调时间计算陈旧撤回候选，不能把高优先级来源失联误当成允许低优先级旧值复活。
    ///
    /// 参数说明：
    /// - `now`：是当前单调时间。
    ///
    /// 返回：过期对象保留不可用占位及来源归属，后续编译器必须连同依赖路由失败闭合。
    pub(super) fn expire(&self, now: Instant) -> Result<Candidate> {
        Self::candidate(self.serial, self.sources.clone(), now)
    }

    /// 业务作用：在数据面发布前取得对应来源水位的唯一提交凭证，提前完成全部可失败检查。
    ///
    /// 参数说明：
    /// - `candidate`：是已经完成网关构建与资源准备的同一候选。
    ///
    /// 返回：独占目录的不可失败提交凭证；过期候选或序号耗尽拒绝，未提交即丢弃不改变活动目录。
    pub(super) fn authorize(&mut self, candidate: Candidate) -> Result<Commit<'_>> {
        ensure!(
            candidate.base_serial == self.serial,
            "provider candidate authority changed"
        );
        // 构建、资源准备和审计等待都可能跨过陈旧期限；过期前算出的活动图不得迟到发布。
        ensure!(
            candidate
                .valid_until
                .is_none_or(|deadline| Instant::now() < deadline),
            "provider candidate freshness expired"
        );
        let next = self
            .serial
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("provider serial exhausted"))?;
        Ok(Commit {
            registry: self,
            sources: candidate.sources,
            serial: next,
        })
    }

    /// 业务作用：限制活动声明与历史删除水位的总体空间，再执行与事件顺序无关的合并。
    ///
    /// 参数说明：
    /// - `serial`：绑定当前发布者
    /// - `sources`：为候选目录
    /// - `now`：决定统一新鲜度边界。
    ///
    /// 返回：有限中间视图；超预算拒绝整个候选，同优先级异文身份保持不可用。
    fn candidate(
        serial: u64,
        sources: BTreeMap<String, Source>,
        now: Instant,
    ) -> Result<Candidate> {
        ensure!(
            sources
                .values()
                .map(|source| source.watermarks.len())
                .sum::<usize>()
                <= MAX_OBJECTS,
            "provider historical identity capacity reached"
        );
        ensure!(
            sources
                .values()
                .filter_map(|source| source.document.as_ref())
                .map(|document| document.bytes)
                .sum::<usize>()
                <= MAX_TOTAL_BYTES,
            "provider resident byte capacity reached"
        );
        let view = merge(&sources, now)?;
        let valid_until = sources
            .values()
            .filter(|source| source.document.is_some())
            .filter_map(|source| {
                source
                    .refreshed
                    .and_then(|time| time.checked_add(source.authority.max_stale))
            })
            .filter(|deadline| *deadline > now)
            .min();
        Ok(Candidate {
            base_serial: serial,
            valid_until,
            sources,
            view,
        })
    }
}

impl Commit<'_> {
    /// 业务作用：在快照发布的同一串行提交段切换来源水位，不再执行 I/O 或可失败校验。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：候选成为唯一活动目录；最后释放独占借用，后续来源事件才能产生新候选。
    pub(super) fn commit(self) {
        self.registry.sources = self.sources;
        self.registry.serial = self.serial;
    }
}

/// 业务作用：按 namespace/种类/名称和本地优先级裁决声明，保留显式删除与过期拒绝占位。
///
/// 参数说明：
/// - `sources`：是有限固定目录
/// - `now`：是本轮统一单调时间。
///
/// 返回：确定性对象图；最高优先级异文对象不可用；等价同级来源优先采用仍新鲜的声明。
fn merge(sources: &BTreeMap<String, Source>, now: Instant) -> Result<View> {
    let mut groups: BTreeMap<Reference, Vec<Resolved>> = BTreeMap::new();
    for source in sources.values() {
        let Some(document) = &source.document else {
            continue;
        };
        let expired = source.refreshed.is_none_or(|refreshed| {
            now.saturating_duration_since(refreshed) >= source.authority.max_stale
        });
        // 全文省略也是删除证据，保留有界删除占位；否则移除高优先级对象会意外复活低优先级旧路由。
        let retired = source
            .watermarks
            .iter()
            .filter(|(_, watermark)| !watermark.present)
            .map(|((kind, name), watermark)| {
                let declaration = Object {
                    kind: *kind,
                    name: name.clone(),
                    generation: watermark.generation,
                    spec: None,
                };
                let digest = Sha256::digest(serde_json::to_vec(&declaration)?).into();
                Ok(Arc::new(PreparedObject {
                    declaration,
                    digest,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        for object in document.objects.values().cloned().chain(retired) {
            let key = Reference {
                namespace: source.authority.namespace.clone(),
                kind: object.declaration.kind,
                name: object.declaration.name.clone(),
            };
            let state = if expired {
                State::Expired
            } else if object.declaration.spec.is_none() {
                State::Tombstone
            } else {
                State::Active
            };
            let resolved = Resolved {
                authority: source.authority.clone(),
                object,
                state,
                valid_until: (state == State::Active)
                    .then(|| {
                        source
                            .refreshed
                            .and_then(|time| time.checked_add(source.authority.max_stale))
                    })
                    .flatten(),
            };
            groups.entry(key).or_default().push(resolved);
        }
    }
    let mut objects = BTreeMap::new();
    for (key, mut candidates) in groups {
        let priority = candidates
            .iter()
            .map(|value| value.authority.priority)
            .max()
            .expect("nonempty source group");
        candidates.retain(|value| value.authority.priority == priority);
        if candidates
            .iter()
            .any(|value| value.object.declaration.spec != candidates[0].object.declaration.spec)
        {
            // 冲突必须随完整事实集合收敛，不能把最早到达者永久当赢家；相关入口在同一次发布中撤回。
            let mut conflict = candidates.remove(0);
            conflict.state = State::Conflict;
            conflict.valid_until = None;
            objects.insert(key, conflict);
            continue;
        }
        // 只有最高优先级的等价声明可互为新鲜证据；高优先级失联不能启用低优先级旧策略。
        let selected = candidates
            .iter()
            .position(|value| value.state != State::Expired)
            .unwrap_or(0);
        objects.insert(key, candidates.swap_remove(selected));
    }
    let mut digest = Sha256::new();
    for (key, resolved) in &objects {
        let encoded = serde_json::to_vec(&(
            key,
            &resolved.authority.source,
            &resolved.authority.owner,
            resolved.authority.priority,
            resolved.object.declaration.generation,
            resolved.state,
            &resolved.object.declaration.spec,
        ))?;
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(encoded);
    }
    Ok(View {
        objects,
        digest: digest.finalize().into(),
    })
}
