//! 原材料与完整影响从同一快照装载，任务创建之后不以审批到期抹去原恢复责任。

mod secret;

use super::{
    authority::{self, Authority},
    frozen::{Approved, Frozen},
};
use crate::{
    admin::operations::{
        certificates::{
            crypto,
            impact::model::{self, Record},
        },
        connection::Reading,
        model::Error,
        Store,
    },
    control::{
        material::{authorization, impact::Context},
        ownership::config::Action,
    },
};
pub(super) use secret::{Authenticated, Secret};
use sqlx::{postgres::PgRow, Row};
use std::sync::Arc;

pub(super) struct Original {
    pub record: Record,
    pub secret: Arc<Secret>,
    pub execution_store: String,
    pub task: Option<Task>,
}

pub(super) struct Task {
    pub id: String,
    pub state: String,
    candidate_digest: [u8; 32],
    definition: String,
    targets: usize,
    nodes: usize,
}

impl Original {
    /// 业务作用：按原父材料身份读取完整批准及可选原执行，不读取密文正文或借当前目录重建目标。
    ///
    /// 参数说明：
    /// - `store`：已验证独立执行结构的共享owner。
    /// - `scope`：请求已授权的精确范围。
    /// - `proposal`：原材料提案身份。
    ///
    /// 返回：同一快照中的完整原批准和可选任务；缺失、非法证明或跨父子身份拒绝。
    pub(super) async fn proposal(
        store: &Store,
        scope: &str,
        proposal: &str,
    ) -> Result<Self, Error> {
        let row = store.read_query(async {
            let mut connection = Reading::acquire(&store.pool).await?;
            let row = sqlx::query(concat!(include_str!("sql/source.sql"), include_str!("../impact/sql/reading.sql"), include_str!("sql/source_join.sql"),
                " WHERE original.cluster_id=$1 AND original.scope=$2 AND original.proposal_id=$3"))
                .bind(&store.plan.config.cluster_id).bind(scope).bind(proposal).fetch_optional(connection.as_mut()).await?;
            connection.release().await;
            Ok(row)
        }).await?.ok_or(Error::Missing)?;
        Self::parse(row)
    }

    /// 业务作用：从已证Outbox的原任务身份恢复完整批准，审批TTL不参与已提交执行的恢复资格。
    ///
    /// 参数说明：
    /// - `store`：永久绑定原集群的共享owner。
    /// - `operation`：已验证消息或释放扫描得到的原任务身份。
    ///
    /// 返回：只包含原running/releasing责任的完整记录；不存在、完成、保护或不一致时不借新提案替代。
    pub(super) async fn task(store: &Store, operation: &str) -> Result<Self, Error> {
        let row = store.read_query(async {
            let mut connection = Reading::acquire(&store.pool).await?;
            let row = sqlx::query(concat!(include_str!("sql/source.sql"), include_str!("../impact/sql/reading.sql"), include_str!("sql/source_join.sql"),
                " WHERE original.cluster_id=$1 AND t.operation_id=$2 AND t.state IN ('running','releasing')"))
                .bind(&store.plan.config.cluster_id).bind(operation).fetch_optional(connection.as_mut()).await?;
            connection.release().await;
            Ok(row)
        }).await?.ok_or(Error::Missing)?;
        Self::parse(row)
    }

    /// 业务作用：限制原批准元数据预算并校验共享任务与父记录的不可变关联，异常持久内容不进入KDF。
    ///
    /// 参数说明：
    /// - `row`：单次共享查询中的原两份批准、永久owner、材料摘要及可选任务。
    ///
    /// 返回：完整合法的原生元数据；审批、任务标志、分母或固定字段不一致拒绝。
    pub(super) fn parse(row: PgRow) -> Result<Self, Error> {
        let read = || -> Result<_, sqlx::Error> {
            let task = row
                .try_get::<Option<String>, _>("task_id")?
                .map(|id| {
                    Ok::<_, sqlx::Error>(Task {
                        id,
                        state: row.try_get("task_state")?,
                        candidate_digest: fixed(&row, "candidate_digest")?,
                        definition: row.try_get("definition_digest")?,
                        targets: row.try_get::<i16, _>("target_count")? as usize,
                        nodes: row.try_get::<i16, _>("node_count")? as usize,
                    })
                })
                .transpose()?;
            Ok((
                Secret {
                    context: crypto::Context {
                        cluster: row.try_get("cluster_id")?,
                        store_id: row.try_get("original_store")?,
                        epoch: row.try_get("original_epoch")?,
                        id: row.try_get("proposal_id")?,
                        key_id: row.try_get("key_id")?,
                        creator: row.try_get("original_creator")?,
                        scope: row.try_get("original_scope")?,
                        intent: fixed(&row, "original_intent")?,
                        created: row.try_get("material_created")?,
                        expires: row.try_get("original_expires")?,
                    },
                    authority: fixed(&row, "original_authority")?,
                    targets: row.try_get("original_targets")?,
                    summary: row.try_get("original_summary")?,
                    material_bytes: row.try_get("material_bytes")?,
                    ciphertext_bytes: row.try_get("ciphertext_bytes")?,
                    ciphertext_sha256: fixed(&row, "ciphertext_sha256")?,
                    reviewer: row
                        .try_get::<Option<String>, _>("material_reviewer")?
                        .unwrap_or_default(),
                },
                row.try_get::<String, _>("execution_store")?,
                task,
                row.try_get::<bool, _>("task_matches")?,
            ))
        };
        let (secret, execution_store, task, matches) = read().map_err(|_| Error::Unavailable)?;
        secret.validate()?;
        let record = if task.is_some() {
            model::parse_execution(row)?
        } else {
            model::parse(row)?
        };
        // 原任务持续保留两份父批准；任一孤立标志或错任务都不能借TTL转换为新执行。
        if !matches
            || record.status != "approved"
            || record.material_status != "approved"
            || record.execution_started != record.material_execution_started
            || record.execution_started != task.is_some()
            || !crate::control::material::node::hexadecimal(&execution_store, 64)
            || task.as_ref().is_some_and(|task| {
                !matches!(
                    task.state.as_str(),
                    "running" | "releasing" | "halted" | "complete"
                ) || task.targets != record.proof.targets.len()
                    || task.nodes != record.proof.nodes.len()
            })
        {
            return Err(Error::Conflict);
        }
        Ok(Self {
            record,
            secret: Arc::new(secret),
            execution_store,
            task,
        })
    }

    /// 业务作用：认证解密之前复验两份原批准的四主体与全批对象权威，读取权限不能触发材料工作。
    ///
    /// 参数说明：
    /// - `authority`：当前精确管理快照及真实owner。
    /// - `store`：本次原共享存储。
    /// - `principal`：实际请求者；后台恢复没有新增请求主体。
    ///
    /// 返回：完整原权限与当前读取/写入/审阅资格一致才成功；撤权或归属变化不进入秘密读取。
    pub(super) fn authorize(
        &self,
        authority: &Authority<'_>,
        store: &Store,
        principal: Option<&str>,
    ) -> Result<(), Error> {
        authority::running(authority.state, store, &authority.snapshot)?;
        let record = &self.record;
        let reviewer = record.reviewer.as_deref().ok_or(Error::Conflict)?;
        for (subject, action) in [
            (record.material_creator.as_str(), Action::Write),
            (self.secret.reviewer.as_str(), Action::Review),
            (record.creator.as_str(), Action::Write),
            (reviewer, Action::Review),
        ]
        .into_iter()
        .chain(principal.map(|principal| (principal, Action::Write)))
        {
            authorization::check(&record.scope, &authority.snapshot, subject, Action::Read)
                .ok_or(Error::Denied)?;
            authorization::check(&record.scope, &authority.snapshot, subject, action)
                .ok_or(Error::Denied)?;
        }
        if authorization::authority(&record.scope, &authority.snapshot, &record.proof.targets)
            != Some(record.authority)
            || record.proof.authority(&record.scope, &authority.snapshot)
                != Some(record.impact_authority)
        {
            return Err(Error::Denied);
        }
        Ok(())
    }

    /// 业务作用：消费完整原影响为唯一冻结节点树，新任务使用认证候选摘要，恢复使用原任务保存的同一摘要。
    ///
    /// 参数说明：
    /// - `candidate`：新任务唯一认证候选摘要；已有任务必须与其原持久摘要完全相同。
    ///
    /// 返回：原冻结任务及可共享密文标记；原节点树移动一次，定义或候选漂移拒绝。
    pub(super) fn freeze(self, candidate: [u8; 32]) -> Result<(Arc<Frozen>, Arc<Secret>), Error> {
        if self
            .task
            .as_ref()
            .is_some_and(|task| task.candidate_digest != candidate)
        {
            return Err(Error::Conflict);
        }
        let record = self.record;
        let operation = self
            .task
            .as_ref()
            .map_or(record.id.as_str(), |task| task.id.as_str());
        let frozen = Frozen::build(Approved {
            proof: record.proof,
            context: Context {
                cluster: &record.cluster_id,
                material_store: &record.material_store,
                impact_store: &record.impact_store,
                proposal: &record.proposal_id,
                scope: &record.scope,
                material_creator: &record.material_creator,
                material_epoch: self.secret.context.epoch,
                material_intent: &record.material_intent,
                authority: &record.authority,
                impact_authority: &record.impact_authority,
                issued: record.issued_at_ms,
                observed_until: record.observed_until_ms,
            },
            operation,
            execution_store: &self.execution_store,
            impact_id: &record.id,
            impact_epoch: record
                .admission_epoch
                .parse()
                .map_err(|_| Error::Unavailable)?,
            material_reviewer: &self.secret.reviewer,
            impact_creator: &record.creator,
            impact_reviewer: record.reviewer.as_deref().ok_or(Error::Conflict)?,
            impact_digest: record.impact_digest,
            candidate_bytes: self.secret.material_bytes as u32,
            candidate_digest: candidate,
        })?;
        if self
            .task
            .as_ref()
            .is_some_and(|task| task.definition != frozen.definition.digest())
        {
            return Err(Error::Conflict);
        }
        Ok((Arc::new(frozen), self.secret))
    }

    /// 业务作用：恢复任务时借用首次认证后持久保存的候选摘要，释放与补偿无需重新解密不再使用的候选。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：存在原任务时的固定摘要；尚未创建任务时为空，不能用占位值构造可执行意图。
    pub(super) fn candidate(&self) -> Option<[u8; 32]> {
        self.task.as_ref().map(|task| task.candidate_digest)
    }
}

/// 业务作用：拒绝截断或扩大的数据库摘要，避免异常元数据进入原批准与候选身份。
///
/// 参数说明：
/// - `row`：原共享查询行。
/// - `name`：源码固定的摘要列名。
///
/// 返回：精确三十二字节摘要；类型或长度不同按存储异常拒绝。
fn fixed(row: &PgRow, name: &str) -> Result<[u8; 32], sqlx::Error> {
    row.try_get::<Vec<u8>, _>(name)?
        .try_into()
        .map_err(|_| sqlx::Error::Protocol("material execution digest differs".into()))
}
