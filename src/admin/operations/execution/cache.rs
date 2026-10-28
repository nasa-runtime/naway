//! 活动执行只保留一份共享原文，缓存容量不能绕过共享数据库的执行上限。

use super::frozen::Frozen;
use crate::admin::operations::{connection::Reading, model::Error, Store};
use sqlx::Row;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Default)]
pub(in crate::admin::operations) struct Cache {
    entries: parking_lot::Mutex<BTreeMap<String, Arc<Frozen>>>,
    loading: tokio::sync::Mutex<()>,
}

impl Cache {
    /// 业务作用：按不可变操作身份共享原审批正文和目标，网络重投不重复读取或编码整个候选。
    ///
    /// 参数说明：
    /// - store：唯一集群存储 owner。
    /// - id：由已验证 Outbox 派生的原操作身份。
    ///
    /// 返回：最多十六份活动冻结记录之一；缺失、容量耗尽或持久身份不一致时不缓存。
    pub(in crate::admin::operations) async fn get(
        &self,
        store: &Store,
        id: &str,
    ) -> Result<Arc<Frozen>, Error> {
        if let Some(value) = self.entries.lock().get(id).cloned() {
            return Ok(value);
        }
        // 派发与释放可能同时首次读取同一候选，串行冷加载避免重复分配整份原文，命中仍只克隆 Arc。
        let _loading = self.loading.lock().await;
        if let Some(value) = self.entries.lock().get(id).cloned() {
            return Ok(value);
        }
        let value = store.load_execution(id).await?;
        let mut entries = self.entries.lock();
        if let Some(existing) = entries.get(id) {
            return Ok(existing.clone());
        }
        if entries.len() >= 16 {
            return Err(Error::Capacity);
        }
        entries.insert(id.to_owned(), value.clone());
        Ok(value)
    }

    /// 业务作用：只保留共享库仍未释放的执行，历史数量不能让候选缓存无限增长。
    ///
    /// 参数说明：
    /// - store：本轮运行权已经验证的共享存储。
    ///
    /// 返回：清除已完整释放记录的内存引用，并返回有序活动身份供有限轮转；读取失败保留缓存并停止本轮。
    pub(in crate::admin::operations) async fn refresh(
        &self,
        store: &Store,
    ) -> Result<Vec<String>, Error> {
        let active: Vec<String> = store.read_query(async {
            let mut connection = Reading::acquire(&store.pool).await?;
            let ids = sqlx::query_scalar("SELECT operation_id FROM naway_delivery_executions WHERE cluster_id=$1 AND state<>'complete' ORDER BY operation_id LIMIT 17")
                .bind(&store.plan.config.cluster_id).fetch_all(connection.as_mut()).await?;
            connection.release().await;
            Ok(ids)
        }).await?;
        if active.len() > 16 {
            return Err(Error::Unavailable);
        }
        self.entries
            .lock()
            .retain(|id, _| active.binary_search(id).is_ok());
        Ok(active)
    }
}

impl Store {
    /// 业务作用：从同一已提交查询取得原冻结执行和被外键保留的正文，不按当前节点目录重建候选。
    ///
    /// 参数说明：
    /// - id：当前集群内精确操作身份。
    ///
    /// 返回：复验摘要、定义和全部原目标后的单份共享正文；已释放或不完整记录不获得新的交付资格。
    async fn load_execution(&self, id: &str) -> Result<Arc<Frozen>, Error> {
        let row = self.read_query(async {
            let mut connection = Reading::acquire(&self.pool).await?;
            let row = sqlx::query(
                "SELECT e.operation_id AS id,e.admission_epoch,e.scope,e.domain,e.creator,e.reviewer,e.authority,\
                e.candidate_digest,e.targets,e.target_count,e.definition_digest,e.candidate_bytes,p.candidate \
                FROM naway_delivery_executions e JOIN naway_operation_proposals p ON p.cluster_id=e.cluster_id AND p.id=e.operation_id \
                WHERE e.cluster_id=$1 AND e.operation_id=$2 AND e.state<>'complete'"
            ).bind(&self.plan.config.cluster_id).bind(id).fetch_optional(connection.as_mut()).await?;
            connection.release().await;
            Ok(row)
        }).await?.ok_or(Error::Missing)?;
        let frozen = Frozen::from_row(&row, &self.plan.config.cluster_id)?;
        let count: i16 = row
            .try_get("target_count")
            .map_err(|_| Error::Unavailable)?;
        let bytes: i32 = row
            .try_get("candidate_bytes")
            .map_err(|_| Error::Unavailable)?;
        let definition: &str = row
            .try_get("definition_digest")
            .map_err(|_| Error::Unavailable)?;
        // 缓存不把损坏字段当作新的意图；定义、目标数和字节数仍必须与创建时的原记录一致。
        if count as usize != frozen.targets.len()
            || bytes as usize != frozen.body.len()
            || definition != frozen.definition.digest()
        {
            return Err(Error::Unavailable);
        }
        Ok(Arc::new(frozen))
    }
}
