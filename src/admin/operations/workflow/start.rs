//! 已批准意图、节点占位与 NASA 首步在同一事务创建，重试不重新选择目标。

use super::super::{
    execution::frozen::Frozen,
    model::{Domain, Error},
    store::DATASOURCE,
    Store,
};
use nasa::saga::{BusinessKey, SagaId, TenantId, TriggerKind};
use nasaga_runtime_core::{StartOutcome, StartSagaRequest};
use sqlx::Row;
use std::sync::Arc;

pub(in crate::admin::operations) struct Request<'a> {
    pub(in crate::admin::operations) id: &'a str,
    pub(in crate::admin::operations) scope: &'a str,
    pub(in crate::admin::operations) domain: Domain,
    pub(in crate::admin::operations) digest: &'a [u8; 32],
}

pub(in crate::admin::operations) struct Started {
    pub(in crate::admin::operations) frozen: Arc<Frozen>,
    pub(in crate::admin::operations) created: bool,
}

impl Store {
    /// 业务作用：原子保存原审批的全部执行引用和 NASA 首步，任何节点冲突都不留下半创建工作流。
    ///
    /// 参数说明：
    /// - `request`：已通过当前请求权限的精确提案、范围、领域和确认 SHA。
    /// - `authorize`：复验同一快照、双人权限和原权限摘要；第二参数为真时还须复验全部原目标的当前基线。
    ///
    /// 返回：明确提交的新执行或同意图重放；旧提案过期、目标已被占用、撤权和未知 COMMIT 各自保持失败语义。
    pub(in crate::admin::operations) async fn start_execution(
        &self,
        request: &Request<'_>,
        authorize: &(dyn Fn(&Frozen, bool) -> Result<(), Error> + Send + Sync),
    ) -> Result<Started, Error> {
        let workflow = self.workflow.get().ok_or(Error::Unavailable)?;
        self.workflow_transaction(Box::pin(async {
            let (frozen, existing, started, state, expires, now) = {
                let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
                let row = sqlx::query(concat!(
                    "SELECT p.id,p.admission_epoch,p.scope,p.domain,p.creator,p.reviewer,p.authority,p.candidate_digest,p.candidate,p.targets,",
                    "p.state,p.expires_at_ms,p.execution_started,e.definition_digest AS existing_definition,",
                    "(e.operation_id IS NULL OR ROW(e.admission_epoch,e.scope,e.domain,e.creator,e.reviewer,e.authority,e.candidate_digest,e.candidate_bytes,e.targets) ",
                    "= ROW(p.admission_epoch,p.scope,p.domain,p.creator,p.reviewer,p.authority,p.candidate_digest,octet_length(p.candidate),p.targets)) AS execution_matches,",
                    "floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now_ms ",
                    "FROM naway_operation_proposals p LEFT JOIN naway_delivery_executions e ON e.cluster_id=p.cluster_id AND e.operation_id=p.id ",
                    "WHERE p.cluster_id=$1 AND p.scope=$2 AND p.domain=$3 AND p.id=$4 FOR UPDATE OF p"
                )).bind(&self.plan.config.cluster_id).bind(request.scope).bind(request.domain.identity().0).bind(request.id)
                    .fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Missing)?;
                let frozen = Frozen::from_row(&row, &self.plan.config.cluster_id)?;
                if !row.try_get::<bool, _>("execution_matches").map_err(|_| Error::Unavailable)? {
                    return Err(Error::Unavailable);
                }
                let existing: Option<String> = row.try_get("existing_definition").map_err(|_| Error::Unavailable)?;
                let started: bool = row.try_get("execution_started").map_err(|_| Error::Unavailable)?;
                let state: String = row.try_get("state").map_err(|_| Error::Unavailable)?;
                let expires: i64 = row.try_get("expires_at_ms").map_err(|_| Error::Unavailable)?;
                let now: i64 = row.try_get("now_ms").map_err(|_| Error::Unavailable)?;
                (Arc::new(frozen), existing, started, state, expires, now)
            };
            if frozen.targets[0].candidate_sha256 != *request.digest {
                return Err(Error::Conflict);
            }
            authorize(&frozen, false)?;
            let saga = SagaId::new(request.id).map_err(|_| Error::Invalid)?;
            let tenant = TenantId::new(&self.plan.config.cluster_id).map_err(|_| Error::Unavailable)?;
            if let Some(digest) = existing {
                // 重放只复核持久身份，不按当前在线集合重启旧操作，也不让审批 TTL 抹去已提交的执行。
                let instance = workflow.engine.load_instance(&tenant, &saga).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Unavailable)?;
                if !started || digest != frozen.definition.digest() || instance.definition_digest != digest
                    || instance.workflow != *frozen.definition.name() || instance.definition_version != frozen.definition.version()
                    || instance.business_key.as_str() != request.id
                {
                    return Err(Error::Unavailable);
                }
                authorize(&frozen, false)?;
                return Ok(Started {
                    frozen,
                    created: false
                });
            }
            if started || state != "approved" {
                return Err(Error::Conflict);
            }
            if now >= expires {
                return Err(Error::Expired);
            }
            // 全部冻结目标必须在持久创建之前仍具原基线；这里不下发 Prepare 或等待任何网络动作。
            authorize(&frozen, true)?;
            reserve(self, &frozen).await?;
            let business_key = BusinessKey::new(request.id).map_err(|_| Error::Invalid)?;
            let authorization = || authorize(&frozen, true).map_err(|_| anyhow::anyhow!("execution authority changed"));
            let outcome = workflow.engine.start_saga_authorized_traced(&StartSagaRequest {
                saga_id: &saga,
                    tenant: &tenant,
                    workflow: frozen.definition.name(),
                    version: frozen.definition.version(),
                business_key: &business_key,
                    deadline_at_ms: None,
                    trigger_kind: TriggerKind::Admin,
                trigger_id: request.id,
                    first_command_payload: None,
                    first_command_raw_payload: None,
                    now_ms: now,
            }, None, &authorization).await.map_err(|_| Error::Unavailable)?;
            // 没有业务执行却已有同名 Saga 属于权威不一致，不能把它收养为刚批准的另一个操作。
            if !matches!(outcome, StartOutcome::Started(_)) {
                return Err(Error::Conflict);
            }
            authorize(&frozen, true)?;
            Ok(Started {
                frozen,
                created: true
            })
        })).await
    }
}

/// 业务作用：在持有原提案和推进锁的事务中保留完整执行及目标槽，禁止运行到半途才争抢节点。
///
/// 参数说明：
/// - `store`：原集群的命名事务 owner。
/// - `frozen`：已通过完整身份与当前节点基线门的原审批内容。
///
/// 返回：全部引用和 execution_started 已写入当前未提交事务；容量或任一目标冲突使外层整体回滚。
async fn reserve(store: &Store, frozen: &Frozen) -> Result<(), Error> {
    let first = &frozen.targets[0];
    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
        .await
        .map_err(|_| Error::Unavailable)?;
    sqlx::query(concat!(
        "INSERT INTO naway_delivery_executions(cluster_id,operation_id,admission_epoch,scope,domain,creator,reviewer,authority,candidate_digest,candidate_bytes,targets,target_count,definition_digest,state,created_at_ms,updated_at_ms) ",
        "SELECT cluster_id,id,admission_epoch,scope,domain,creator,reviewer,authority,candidate_digest,octet_length(candidate),targets,$3,$4,'running',n.ms,n.ms ",
        "FROM naway_operation_proposals CROSS JOIN (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS ms) n WHERE cluster_id=$1 AND id=$2"
    )).bind(&store.plan.config.cluster_id).bind(&first.operation_id).bind(frozen.targets.len() as i16).bind(frozen.definition.digest())
        .execute(connection.as_mut()).await.map_err(storage_error)?;
    let digests = frozen
        .targets
        .iter()
        .map(|intent| intent.fingerprint().map_err(|_| Error::Unavailable))
        .collect::<Result<Vec<_>, _>>()?;
    let mut query = sqlx::QueryBuilder::new("INSERT INTO naway_delivery_targets(cluster_id,operation_id,node_id,target_index,intent_digest,store_id,node_epoch) ");
    query.push_values(
        frozen.targets.iter().zip(&digests),
        |mut row, (intent, digest)| {
            row.push_bind(&store.plan.config.cluster_id)
                .push_bind(&intent.operation_id)
                .push_bind(&intent.node_id)
                .push_bind(intent.target_index as i16)
                .push_bind(digest.as_slice())
                .push_bind(&intent.baseline.store_id)
                .push_bind(&intent.baseline.node_admission_epoch)
                .push_unseparated("::numeric");
        },
    );
    query
        .build()
        .execute(connection.as_mut())
        .await
        .map_err(storage_error)?;
    sqlx::query("INSERT INTO naway_delivery_slots(cluster_id,node_id,operation_id) SELECT cluster_id,node_id,operation_id FROM naway_delivery_targets WHERE cluster_id=$1 AND operation_id=$2")
        .bind(&store.plan.config.cluster_id).bind(&first.operation_id).execute(connection.as_mut()).await.map_err(storage_error)?;
    // 引用与标志先在同一事务建立，后续 NASA 创建失败会共同回滚，保留清理不能看到半完成执行。
    sqlx::query("UPDATE naway_operation_proposals SET execution_started=TRUE,updated_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE cluster_id=$1 AND id=$2")
        .bind(&store.plan.config.cluster_id).bind(&first.operation_id).execute(connection.as_mut()).await.map_err(storage_error)?;
    Ok(())
}

/// 业务作用：把执行创建的确定容量和节点竞争保留为封闭错误，数据库明细不进入管理响应。
///
/// 参数说明：
/// - `error`：同一事务中的数据库写入错误。
///
/// 返回：已知容量或冲突分类，其它基础设施错误保持不可用，不推测提交结果。
fn storage_error(error: sqlx::Error) -> Error {
    match error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
    {
        Some("PN007") => Error::Capacity,
        Some("PN006" | "23505") => Error::Conflict,
        _ => Error::Unavailable,
    }
}
