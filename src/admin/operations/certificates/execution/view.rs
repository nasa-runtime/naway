//! 原批准、全部节点报告与NASA步骤在一个只读快照内投影，查询不依赖执行开关或候选钥。

mod response;
pub(super) use response::encode;

use super::{frozen::Frozen, release::evidence, source::Original};
use crate::{
    admin::operations::{
        certificates::{authorization, model::Target},
        model::Error,
        store::DATASOURCE,
        workflow::completion,
        Store,
    },
    config::GatewaySnapshot,
    control::material::execution::{release::Terminal, report::Report},
};
use nasa::saga::SagaId;
use nasaga_backend::{SagaBackend, SagaInstanceRow, SagaStepRow};
use sqlx::Row;
use std::sync::Arc;

pub(super) struct View {
    cluster: String,
    scope: String,
    proposal: String,
    operation: Option<Operation>,
}

struct Operation {
    frozen: Arc<Frozen>,
    lifecycle: String,
    terminal: Option<String>,
    instance: SagaInstanceRow,
    steps: Vec<SagaStepRow>,
    nodes: Vec<Node>,
    created: i64,
    updated: i64,
}

struct Node {
    report: Option<Report>,
    released: bool,
}

impl Store {
    /// 业务作用：从同一数据库快照读取完整原任务及节点事实，关闭执行或退休旧钥后仍保留可读恢复入口。
    ///
    /// 参数说明：
    /// - `scope`：本次请求已经取得读取权的精确范围。
    /// - `proposal`：原材料身份，不能由当前节点目录替换。
    /// - `snapshot`：当前归属快照，用于完整逻辑目标和共享来源读取门。
    ///
    /// 返回：未启动或完整一致的低敏视图；缺节点、跨范围、定义漂移和矛盾终态拒绝整份响应。
    pub(super) async fn material_execution_view(
        &self,
        scope: &authorization::Scope,
        proposal: &str,
        snapshot: &GatewaySnapshot,
    ) -> Result<View, Error> {
        self.transaction(Box::pin(async {
            let original = {
                let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                    .await.map_err(|_| Error::Unavailable)?;
                // 原分母、节点报告和NASA状态必须同代读取，不能把并发推进拼成完整成功。
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                    .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                let row = sqlx::query("SELECT execution_started,targets FROM naway_certificate_proposals WHERE cluster_id=$1 AND scope=$2 AND id=$3")
                    .bind(&self.plan.config.cluster_id).bind(&scope.key).bind(proposal)
                    .fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Missing)?;
                let raw: &[u8] = row.try_get("targets").map_err(|_| Error::Unavailable)?;
                if !(2..=65536).contains(&raw.len()) {
                    return Err(Error::Unavailable);
                }
                let targets: Vec<Target> = serde_json::from_slice(raw).map_err(|_| Error::Unavailable)?;
                if !Target::valid_set(&targets, &self.plan.config.cluster_id) {
                    return Err(Error::Unavailable);
                }
                authorization::targets(scope, snapshot, &targets)?;
                if !row.try_get::<bool, _>("execution_started").map_err(|_| Error::Unavailable)? {
                    return Ok(View {
                        cluster: self.plan.config.cluster_id.clone(),
                        scope: scope.key.clone(),
                        proposal: proposal.into(),
                        operation: None,
                    });
                }
                if !self.material_execution_installed || self.workflow.get().is_none() {
                    return Err(Error::Unavailable);
                }
                let row = sqlx::query(concat!(include_str!("sql/source.sql"), include_str!("../impact/sql/reading.sql"), include_str!("sql/source_join.sql"),
                    " WHERE original.cluster_id=$1 AND original.scope=$2 AND original.proposal_id=$3"))
                    .bind(&self.plan.config.cluster_id).bind(&scope.key).bind(proposal)
                    .fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Unavailable)?;
                Original::parse(row)?
            };
            // 普通查询不要求历史创建者继续有写权，但当前读者必须能够读取全部原共享影响。
            original.record.proof.authority(&scope.key, snapshot).ok_or(Error::Denied)?;
            let digest = original.candidate().ok_or(Error::Unavailable)?;
            let (frozen, _) = original.freeze(digest)?;
            let operation = load(self, frozen).await?;
            Ok(View {
                cluster: self.plan.config.cluster_id.clone(),
                scope: scope.key.clone(),
                proposal: proposal.into(),
                operation: Some(operation),
            })
        })).await
    }
}

/// 业务作用：沿同一只读事务装载原定义和全部物理节点，缺席报告保持未知并核对释放事实。
///
/// 参数说明：
/// - `store`：已经持有同源只读事务的原owner。
/// - `frozen`：原批准一次冻结的完整节点树。
///
/// 返回：不含候选正文的一致任务；身份、原槽或完整终态不成立时拒绝。
async fn load(store: &Store, frozen: Arc<Frozen>) -> Result<Operation, Error> {
    let first = frozen.nodes.first().ok_or(Error::Unavailable)?;
    let saga = SagaId::new(&first.operation_id).map_err(|_| Error::Unavailable)?;
    let backend = nasa::saga::pgsql::PgSagaBackend::with_datasource(DATASOURCE)
        .map_err(|_| Error::Unavailable)?;
    let instance = backend
        .store()
        .load_instance(&saga)
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Unavailable)?;
    let steps = backend
        .store()
        .load_steps(&saga)
        .await
        .map_err(|_| Error::Unavailable)?;
    let terminal = completion::terminal(
        &frozen.definition,
        &first.operation_id,
        &store.plan.config.cluster_id,
        &instance,
        &steps,
    )?;
    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
        .await
        .map_err(|_| Error::Unavailable)?;
    let task = sqlx::query("SELECT state,terminal,created_at_ms,updated_at_ms FROM naway_material_execution_tasks WHERE cluster_id=$1 AND operation_id=$2")
        .bind(&store.plan.config.cluster_id).bind(&first.operation_id).fetch_one(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
    let lifecycle: String = task.try_get("state").map_err(|_| Error::Unavailable)?;
    let saved_terminal: Option<String> =
        task.try_get("terminal").map_err(|_| Error::Unavailable)?;
    let terminal = terminal.map(|value| match value {
        completion::Terminal::Completed => Terminal::Completed,
        completion::Terminal::Compensated => Terminal::Compensated,
    });
    if !matches!(
        lifecycle.as_str(),
        "running" | "releasing" | "halted" | "complete"
    ) || (matches!(lifecycle.as_str(), "running" | "halted") && saved_terminal.is_some())
        || (matches!(lifecycle.as_str(), "releasing" | "complete")
            && (terminal.is_none()
                || saved_terminal.as_deref() != terminal.map(super::release::name)))
    {
        return Err(Error::Unavailable);
    }
    let rows = sqlx::query(concat!(
        "SELECT n.node_id,n.node_index,n.intent_digest,n.store_id,n.node_epoch::text AS epoch,",
        "n.report,n.report_revision::text AS revision,n.released,s.operation_id AS slot_operation ",
        "FROM naway_material_execution_nodes n LEFT JOIN naway_material_execution_slots s ",
        "ON s.cluster_id=n.cluster_id AND s.operation_id=n.operation_id AND s.node_id=n.node_id ",
        "WHERE n.cluster_id=$1 AND n.operation_id=$2 ORDER BY n.node_index LIMIT 129"
    ))
    .bind(&store.plan.config.cluster_id)
    .bind(&first.operation_id)
    .fetch_all(connection.as_mut())
    .await
    .map_err(|_| Error::Unavailable)?;
    if rows.len() != frozen.nodes.len() {
        return Err(Error::Unavailable);
    }
    let mut nodes = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let (intent, position) = frozen.node(index)?;
        if row
            .try_get::<&str, _>("node_id")
            .map_err(|_| Error::Unavailable)?
            != intent.node_id
            || row
                .try_get::<i16, _>("node_index")
                .map_err(|_| Error::Unavailable)? as usize
                != index
            || row
                .try_get::<&[u8], _>("intent_digest")
                .map_err(|_| Error::Unavailable)?
                != position
                    .fingerprint(intent)
                    .map_err(|_| Error::Unavailable)?
            || row
                .try_get::<&str, _>("store_id")
                .map_err(|_| Error::Unavailable)?
                != intent.baseline.store_id
            || row
                .try_get::<&str, _>("epoch")
                .map_err(|_| Error::Unavailable)?
                != intent.baseline.node_admission_epoch
        {
            return Err(Error::Unavailable);
        }
        let report = row
            .try_get::<Option<&[u8]>, _>("report")
            .map_err(|_| Error::Unavailable)?
            .map(|bytes| {
                if bytes.is_empty() || bytes.len() > 128 * 1024 {
                    return Err(Error::Unavailable);
                }
                let report: Report =
                    serde_json::from_slice(bytes).map_err(|_| Error::Unavailable)?;
                report
                    .validate(intent, position)
                    .map_err(|_| Error::Unavailable)?;
                Ok(report)
            })
            .transpose()?;
        if row
            .try_get::<Option<String>, _>("revision")
            .map_err(|_| Error::Unavailable)?
            != report.as_ref().map(|report| report.revision.to_string())
        {
            return Err(Error::Unavailable);
        }
        if let Some(terminal) = terminal {
            evidence::validate(
                intent,
                position,
                terminal,
                report.as_ref(),
                &steps[index],
                &steps[frozen.nodes.len() + index],
            )?;
        }
        let released = row
            .try_get::<bool, _>("released")
            .map_err(|_| Error::Unavailable)?;
        let slot: Option<&str> = row
            .try_get("slot_operation")
            .map_err(|_| Error::Unavailable)?;
        // 没有原报告不等于已释放，终态前丢失原占位或终态后仍占位都不能显示为安全完成。
        if released == slot.is_some()
            || (!released && slot != Some(first.operation_id.as_str()))
            || (released && !matches!(lifecycle.as_str(), "releasing" | "complete"))
            || (!released && lifecycle == "complete")
        {
            return Err(Error::Unavailable);
        }
        nodes.push(Node {
            report,
            released,
        });
    }
    Ok(Operation {
        frozen,
        lifecycle,
        terminal: saved_terminal,
        instance,
        steps,
        nodes,
        created: task
            .try_get("created_at_ms")
            .map_err(|_| Error::Unavailable)?,
        updated: task
            .try_get("updated_at_ms")
            .map_err(|_| Error::Unavailable)?,
    })
}
