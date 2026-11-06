//! 原任务共享一份来源树，候选只在准备时认证一次并受实际持有者容量约束。

use super::{
    authority::Authority,
    frozen::Frozen,
    source::{Authenticated, Original, Secret},
};
use crate::admin::{
    management::material_actions::Content,
    operations::{connection::Reading, model::Error, Store},
};
use std::{collections::BTreeMap, sync::Arc};

pub(in crate::admin::operations) struct Cache {
    entries: parking_lot::Mutex<BTreeMap<String, Arc<Entry>>>,
    loading: tokio::sync::Mutex<()>,
    candidates: Arc<tokio::sync::Semaphore>,
}

pub(in crate::admin::operations) struct Entry {
    pub frozen: Arc<Frozen>,
    pub(super) secret: Arc<Secret>,
    candidate: tokio::sync::Mutex<Option<Authenticated>>,
}

impl Default for Cache {
    /// 业务作用：给同一共享owner提供有限任务缓存和真实候选帧许可，退出缓存不提前归还仍被投递持有的名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：空缓存及十六份候选容量，不读取数据库或解密材料。
    fn default() -> Self {
        Self {
            entries: parking_lot::Mutex::new(BTreeMap::new()),
            loading: tokio::sync::Mutex::new(()),
            candidates: Arc::new(tokio::sync::Semaphore::new(16)),
        }
    }
}

impl Cache {
    /// 业务作用：从原父材料准备新任务，认证解密必须在共享事务之外完成，已有执行只恢复原候选摘要。
    ///
    /// 参数说明：
    /// - `authority`：当前请求的精确快照与本机初始基线。
    /// - `store`：原共享存储。
    /// - `scope`：请求已经授权的范围。
    /// - `proposal`：原材料提案身份。
    /// - `principal`：实际认证执行请求者。
    ///
    /// 返回：尚未缓存或创建节点责任的完整原任务；任何权限、密文或身份失败不触发节点动作。
    pub(in crate::admin::operations) async fn prepare(
        &self,
        authority: &Authority<'_>,
        store: &Store,
        scope: &str,
        proposal: &str,
        principal: &str,
    ) -> Result<Arc<Entry>, Error> {
        if let Some(entry) = self
            .entries
            .lock()
            .values()
            .find(|entry| {
                entry.secret.context.scope == scope && entry.secret.context.id == proposal
            })
            .cloned()
        {
            authority.check(store, &entry.frozen, false, Some(principal))?;
            return Ok(entry);
        }
        let original = Original::proposal(store, scope, proposal).await?;
        original.authorize(authority, store, Some(principal))?;
        let candidate = if original.candidate().is_some() {
            // 已有任务的重放不需要重新读取已不再使用的候选，旧钥退休不能抹去释放和结果查询责任。
            None
        } else {
            let permit = self
                .candidates
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Capacity)?;
            Some(
                original
                    .secret
                    .open(authority.state, &authority.snapshot, store, permit, &|| {
                        original.authorize(authority, store, Some(principal))
                    })
                    .await?,
            )
        };
        let digest = original
            .candidate()
            .or_else(|| candidate.as_ref().map(|candidate| candidate.content.digest))
            .ok_or(Error::Unavailable)?;
        let (frozen, secret) = original.freeze(digest)?;
        authority.check(store, &frozen, false, Some(principal))?;
        Ok(Arc::new(Entry {
            frozen,
            secret,
            candidate: tokio::sync::Mutex::new(candidate),
        }))
    }

    /// 业务作用：复用原任务树或串行冷加载同一完整批准，释放与投递不会各自重建一份大来源关系。
    ///
    /// 参数说明：
    /// - `authority`：当前后台发行快照。
    /// - `store`：原集群存储owner。
    /// - `operation`：已证Outbox或释放扫描中的原任务。
    ///
    /// 返回：当前仍获权的原任务缓存；不存在、容量、完整批准或权限失败不缓存。
    pub(in crate::admin::operations) async fn get(
        &self,
        authority: &Authority<'_>,
        store: &Store,
        operation: &str,
    ) -> Result<Arc<Entry>, Error> {
        if let Some(entry) = self.entries.lock().get(operation).cloned() {
            authority.check(store, &entry.frozen, false, None)?;
            return Ok(entry);
        }
        let _loading = self.loading.lock().await;
        if let Some(entry) = self.entries.lock().get(operation).cloned() {
            authority.check(store, &entry.frozen, false, None)?;
            return Ok(entry);
        }
        if self.entries.lock().len() >= 16 {
            return Err(Error::Capacity);
        }
        let original = Original::task(store, operation).await?;
        original.authorize(authority, store, None)?;
        let digest = original.candidate().ok_or(Error::Conflict)?;
        let (frozen, secret) = original.freeze(digest)?;
        authority.check(store, &frozen, false, None)?;
        self.retain(Arc::new(Entry {
            frozen,
            secret,
            candidate: tokio::sync::Mutex::new(None),
        }))
    }

    /// 业务作用：只在原任务已提交后保留其共享树，重复请求优先沿用同一原owner及已认证帧。
    ///
    /// 参数说明：
    /// - `entry`：由原批准装载并已确认持久任务身份的完整对象。
    ///
    /// 返回：已缓存的同一对象或新条目；达到十六份上限时拒绝缓存但不删除已提交任务。
    pub(in crate::admin::operations) fn retain(
        &self,
        entry: Arc<Entry>,
    ) -> Result<Arc<Entry>, Error> {
        let id = &entry
            .frozen
            .nodes
            .first()
            .ok_or(Error::Conflict)?
            .operation_id;
        let mut entries = self.entries.lock();
        if let Some(existing) = entries.get(id) {
            return Ok(existing.clone());
        }
        if entries.len() >= 16 {
            return Err(Error::Capacity);
        }
        entries.insert(id.clone(), entry.clone());
        Ok(entry)
    }

    /// 业务作用：以持久生命周期淘汰完成或保护任务的缓存，不以审批期限回收仍在运行的来源责任。
    ///
    /// 参数说明：
    /// - `store`：已经确认的独立材料结构及集群。
    ///
    /// 返回：最多十六个当前可自动推进的原身份；数据库失败不推测任务结束，不提前释放持久节点。
    pub(in crate::admin::operations) async fn refresh(
        &self,
        store: &Store,
    ) -> Result<Vec<String>, Error> {
        let active = store.read_query(async {
            let mut connection = Reading::acquire(&store.pool).await?;
            let active = sqlx::query_scalar::<_, String>("SELECT operation_id FROM naway_material_execution_tasks WHERE cluster_id=$1 AND state IN ('running','releasing') ORDER BY operation_id LIMIT 17")
                .bind(&store.plan.config.cluster_id).fetch_all(connection.as_mut()).await?;
            connection.release().await;
            Ok(active)
        }).await?;
        if active.len() > 16 {
            return Err(Error::Unavailable);
        }
        self.entries
            .lock()
            .retain(|id, _| active.binary_search(id).is_ok());
        Ok(active)
    }

    /// 业务作用：运行权关闭或停机时丢弃缓存持有，实际网络与阻塞工作仍自行保留许可直到最后结束。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不再由缓存保留原来源和候选，不删除任何数据库、节点秘密槽或恢复事实。
    pub(in crate::admin::operations) fn clear(&self) {
        self.entries.lock().clear();
    }
}

impl Entry {
    /// 业务作用：原准备重投共享同一认证帧，补偿与释放不需要调用候选读取，也不依赖旧钥仍存在。
    ///
    /// 参数说明：
    /// - `cache`：同一owner的固定候选容量。
    /// - `authority`：本轮实际发行权及四主体复验器。
    /// - `store`：原材料与工作流共享存储。
    ///
    /// 返回：当前原钥与候选摘要仍成立时共享唯一帧；并发冷加载串行，撤钥或容量不足不交付正文。
    pub(in crate::admin::operations) async fn content(
        &self,
        cache: &Cache,
        authority: &Authority<'_>,
        store: &Store,
    ) -> Result<Arc<Content>, Error> {
        let authorize = || authority.check(store, &self.frozen, false, None);
        authorize()?;
        let mut candidate = self.candidate.lock().await;
        authorize()?;
        if candidate
            .as_ref()
            .is_some_and(|candidate| !candidate.available(&self.secret, &authority.snapshot))
        {
            // 删除缓存自己的旧钥和明文持有；不能以已经解密过为由绕过当前钥环撤权。
            *candidate = None;
            return Err(Error::Unavailable);
        }
        if candidate.is_none() {
            let permit = cache
                .candidates
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Capacity)?;
            let opened = self
                .secret
                .open(
                    authority.state,
                    &authority.snapshot,
                    store,
                    permit,
                    &authorize,
                )
                .await?;
            if opened.content.digest != self.frozen.nodes[0].candidate_sha256 {
                return Err(Error::Conflict);
            }
            *candidate = Some(opened);
        }
        authorize()?;
        Ok(candidate
            .as_ref()
            .expect("material candidate authenticated")
            .content
            .clone())
    }
}
