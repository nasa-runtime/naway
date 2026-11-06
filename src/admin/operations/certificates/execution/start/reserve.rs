//! 全部原物理节点在同一事务预留，不能在已经修改部分来源后才争抢其它节点。

use super::*;

/// 业务作用：保存两份原批准的完整引用和所有节点占位，随后标记父记录保留责任以阻止提前回收。
///
/// 参数说明：
/// - `store`：当前原集群共享事务owner。
/// - `frozen`：认证候选与完整原影响冻结的任务。
///
/// 返回：当前尚未提交事务中全部责任成立；容量或任一节点冲突使外层整体回滚，不产生部分任务。
pub(super) async fn all(store: &Store, frozen: &Frozen) -> Result<(), Error> {
    let first = &frozen.nodes[0];
    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
        .await
        .map_err(|_| Error::Unavailable)?;
    sqlx::query(concat!(
        "INSERT INTO naway_material_execution_tasks(cluster_id,operation_id,execution_store,proposal_id,impact_id,material_store,impact_store,",
        "material_epoch,impact_epoch,scope,material_creator,material_reviewer,impact_creator,impact_reviewer,material_intent,impact_digest,",
        "authority,impact_authority,candidate_digest,candidate_bytes,target_count,node_count,definition_digest,state,created_at_ms,updated_at_ms) ",
        "SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,'running',ms,ms ",
        "FROM (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint ms) n"
    )).bind(&store.plan.config.cluster_id).bind(&first.operation_id).bind(&first.execution_store).bind(&first.proposal_id).bind(&first.impact_id)
        .bind(&first.material_store).bind(&first.impact_store).bind(first.material_epoch as i64).bind(first.impact_epoch as i64).bind(&first.scope)
        .bind(&first.material_creator).bind(&first.material_reviewer).bind(&first.impact_creator).bind(&first.impact_reviewer)
        .bind(first.material_intent_sha256.as_slice()).bind(first.impact_sha256.as_slice()).bind(first.authority_sha256.as_slice())
        .bind(first.impact_authority_sha256.as_slice()).bind(first.candidate_sha256.as_slice()).bind(first.candidate_bytes as i32)
        .bind(first.target_count as i16).bind(frozen.nodes.len() as i16).bind(frozen.definition.digest())
        .execute(connection.as_mut()).await.map_err(database_error)?;
    let digests = (0..frozen.nodes.len())
        .map(|index| {
            let (intent, position) = frozen.node(index)?;
            position.fingerprint(intent).map_err(|_| Error::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut query = sqlx::QueryBuilder::new("INSERT INTO naway_material_execution_nodes(cluster_id,operation_id,node_id,node_index,intent_digest,store_id,node_epoch) ");
    query.push_values(
        frozen.nodes.iter().zip(&digests).enumerate(),
        |mut row, (index, (intent, digest))| {
            row.push_bind(&store.plan.config.cluster_id)
                .push_bind(&intent.operation_id)
                .push_bind(&intent.node_id)
                .push_bind(index as i16)
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
        .map_err(database_error)?;
    // 数据库共同节点门还会检查配置任务占位，租约过期也不能把另一种未释放责任当作空闲。
    sqlx::query("INSERT INTO naway_material_execution_slots(cluster_id,node_id,operation_id) SELECT cluster_id,node_id,operation_id FROM naway_material_execution_nodes WHERE cluster_id=$1 AND operation_id=$2 ORDER BY node_index")
        .bind(&store.plan.config.cluster_id).bind(&first.operation_id).execute(connection.as_mut()).await.map_err(database_error)?;
    for (query, id) in [
        ("UPDATE naway_certificate_proposals SET execution_started=TRUE,updated_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE cluster_id=$1 AND id=$2 AND NOT execution_started", &first.proposal_id),
        ("UPDATE naway_material_impact_proposals SET execution_started=TRUE,updated_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE cluster_id=$1 AND id=$2 AND NOT execution_started", &first.impact_id),
    ] {
        // 任务引用先建立，父保留标志随后写入同一事务；NASA首步失败时二者必须共同撤回。
        if sqlx::query(query).bind(&store.plan.config.cluster_id).bind(id).execute(connection.as_mut()).await.map_err(database_error)?.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

/// 业务作用：将独立材料容量和原节点竞争映射成稳定业务错误，不把数据库明细送到管理响应。
///
/// 参数说明：
/// - `error`：当前共享创建事务的SQL失败。
///
/// 返回：已知容量、身份或节点冲突分类；其它基础设施失败保留不可用，不推测提交结果。
fn database_error(error: sqlx::Error) -> Error {
    match error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
    {
        Some("PN011") => Error::Capacity,
        Some("PN010" | "PN012" | "23505") => Error::Conflict,
        _ => Error::Unavailable,
    }
}
