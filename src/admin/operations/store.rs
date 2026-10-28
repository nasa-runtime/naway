//! 同事务保存候选和幂等收据；跨 Admin 容量由数据库行锁裁决。

use super::model::{hex, Candidate, Decision, Error, Record, Review};
use crate::config::operations::Plan;
use nasa::idempotency::{
    pgsql::{PgIdempotencyStore, PgIdempotencyTransactionError},
    ExecutionLease, IdempotencyKey, IdempotencyOutcome, IdempotencyStore, RequestFingerprint,
    StoredResponse,
};
use nasa::tx::pgsql::TxDecision;
use sqlx::{postgres::PgRow, Row};
use std::{future::Future, sync::Arc, time::Duration};

pub(super) const DATASOURCE: &str = "naway_admin_operations";

/// 专用池和命名事务的唯一进程 owner；API只借用它，清理仅有一个有界周期任务。
pub struct Store {
    pub(super) plan: Arc<Plan>,
    pub(super) pool: sqlx::PgPool,
    pub(super) workflow_installed: bool,
    pub(super) delivery_installed: bool,
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(super) workflow: std::sync::OnceLock<super::workflow::Workflow>,
    #[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
    pub(super) executor:
        std::sync::OnceLock<tokio::sync::Mutex<Option<super::execution::runtime::Runtime>>>,
    idempotency: PgIdempotencyStore,
    pub(super) admission: tokio::sync::Semaphore,
    pub(super) stopping: tokio_util::sync::CancellationToken,
    pub(super) cleaner:
        std::sync::OnceLock<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl Store {
    /// 业务作用：验证持久权威后装配命名事务与幂等句柄，阻止未初始化的节点开放写入口。
    ///
    /// 参数说明：
    /// - `plan`：启动时已冻结的资源声明。
    ///
    /// 返回：只读结构门和容量合同均一致的存储；失败关闭所建池。
    pub async fn open(plan: Arc<Plan>) -> anyhow::Result<Arc<Self>> {
        let store = Self::connect(plan).await?;
        // 绑定后的 schema 永久属于一个集群；先拒绝错误身份，注册触发器再覆盖等待中的竞争。
        if !store
            .execution_namespace()
            .await
            .is_ok_and(|binding| binding.permits(&store.plan.config.cluster_id))
        {
            store.close().await;
            anyhow::bail!("operations execution namespace unavailable or differs");
        }
        #[cfg(feature = "admin-operations-workflow-pgsql")]
        if store.plan.config.workflow.enabled {
            match super::workflow::Workflow::open(&store).await {
                Ok(workflow) => {
                    let _ = store.workflow.set(workflow);
                }
                Err(error) => {
                    store.close().await;
                    return Err(error);
                }
            }
        }
        if store.register_capacity().await.is_err() {
            store.close().await;
            anyhow::bail!("operations capacity authority unavailable or differs");
        }
        if store.prepare_retention().await.is_err() {
            store.close().await;
            anyhow::bail!("operations retention authority unavailable or differs");
        }
        Ok(store)
    }

    /// 业务作用：只装配通过结构门的存储资源，供启动登记或显式维护各自执行授权步骤。
    ///
    /// 参数说明：
    /// - `plan`：完整配置已经验证的数据库身份和目标预算。
    ///
    /// 返回：已绑定 NASA 命名事务且尚未登记容量、保留或启动后台任务的 owner。
    pub(super) async fn connect(plan: Arc<Plan>) -> anyhow::Result<Arc<Self>> {
        let pool = super::schema::connect(&plan).await?;
        let installed = match super::schema::gate(&pool, &plan, false, false).await {
            Ok(installed) => installed,
            Err(error) => {
                pool.close().await;
                return Err(error);
            }
        };
        if nasa::tx::pgsql::try_init_datasource(DATASOURCE, pool.clone()).is_err() {
            pool.close().await;
            anyhow::bail!("operations datasource already owned or unavailable");
        }
        let idempotency = PgIdempotencyStore::with_datasource(DATASOURCE)?;
        Ok(Arc::new(Self {
            plan,
            pool,
            workflow_installed: installed.workflow,
            delivery_installed: installed.delivery,
            #[cfg(feature = "admin-operations-workflow-pgsql")]
            workflow: std::sync::OnceLock::new(),
            #[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
            executor: std::sync::OnceLock::new(),
            idempotency,
            admission: tokio::sync::Semaphore::new(8),
            stopping: tokio_util::sync::CancellationToken::new(),
            cleaner: std::sync::OnceLock::new(),
        }))
    }

    /// 业务作用：在进程停机时停止新连接并有界等待正在结束的管理事务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：池关闭或等待上限过去；未知提交必须由下一入口按原键回读。
    pub async fn close(&self) {
        // 先停止轮次并等待当前事务结束，随后关池；未知提交只能由下一进程回读收敛。
        self.stopping.cancel();
        #[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
        if let Some(executor) = self.executor.get() {
            if let Some(mut runtime) = executor.lock().await.take() {
                runtime.close().await;
            }
        }
        if let Some(cleaner) = self.cleaner.get() {
            if let Some(mut worker) = cleaner.lock().await.take() {
                if tokio::time::timeout(Duration::from_secs(11), &mut worker)
                    .await
                    .is_err()
                {
                    worker.abort();
                    let _ = worker.await;
                }
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), self.pool.close()).await;
    }

    /// 业务作用：保存固定意图并原子完成幂等收据，使另一 Admin 能返回同一提案身份。
    ///
    /// 参数说明：
    /// - `scope`：已授权的平台或工作区域。
    /// - `creator`：认证得到的稳定主体。
    /// - `client_key`：有界幂等键。
    /// - `authority`：当前域权限的冻结摘要。
    /// - `candidate`：只通过语法校验的完整候选意图。
    ///
    /// 返回：已提交或重放的 id；容量、冲突和未知提交各自保留分类。
    pub(super) async fn submit(
        &self,
        scope: &str,
        creator: &str,
        client_key: &str,
        authority: &[u8; 32],
        candidate: &Candidate,
    ) -> Result<String, Error> {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
        let id = hex(&random);
        let key = IdempotencyKey {
            tenant: self.plan.config.cluster_id.clone(),
            subject: creator.into(),
            route_id: super::retention::route(scope, candidate.admission_epoch),
            client_key: client_key.into(),
        };
        let fingerprint = RequestFingerprint(candidate.fingerprint(authority));
        let lease = ExecutionLease(random);
        let body = async {
            match self
                .idempotency
                .begin(&key, fingerprint, lease)
                .await
                .map_err(|_| Error::Unavailable)?
            {
                IdempotencyOutcome::Replay(response) => {
                    let id = String::from_utf8(response.body).map_err(|_| Error::Unavailable)?;
                    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return Err(Error::Unavailable);
                    }
                    return Ok(id);
                }
                IdempotencyOutcome::FirstExecution => {}
                _ => return Err(Error::Conflict),
            }
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                .await
                .map_err(|_| Error::Unavailable)?;
            // 所有入口锁同一 cluster 行后再计数；并发 Admin 不能各自看到空余后共同突破预算。
            let admission =
                super::retention::Authority::lock(connection.as_mut(), &key.tenant).await?;
            admission.admit(candidate.admission_epoch)?;
            // 资源合同已改变的入口只能回放原收据；新建须先更新配置，数据库仍约束未升级 writer。
            if !admission.capacity.matches(&self.plan.config) {
                return Err(Error::Unavailable);
            }
            // 容量统计仅由 INSERT 触发器在同一锁内执行，避免应用层再次扫描相同保留集合。
            sqlx::query("WITH now AS (SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS ms) INSERT INTO naway_operation_proposals(cluster_id, id, scope, domain, creator, client_key, authority, candidate, candidate_digest, targets, state, created_at_ms, expires_at_ms, updated_at_ms, admission_epoch) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'awaiting_approval',ms,ms + $11,ms,$12 FROM now")
                .bind(&key.tenant).bind(&id).bind(scope).bind(candidate.domain.identity().0).bind(creator).bind(client_key)
                .bind(authority.as_slice()).bind(candidate.bytes.as_ref()).bind(candidate.digest.as_slice()).bind(&candidate.target_bytes)
                .bind(i64::from(candidate.ttl_seconds) * 1000)
                .bind(candidate.admission_epoch)
                .execute(connection.as_mut()).await.map_err(|error| match error.as_database_error().and_then(|error| error.code()).as_deref() {
                    Some("23505") => Error::Conflict,
                    Some("23514") => Error::Expired,
                    Some("PN001") => Error::Capacity,
                    _ => Error::Unavailable,
                })?;
            // 释放 ambient 连接借用后再交给 NASA 幂等组件；两次访问仍属于同一物理事务。
            drop(connection);
            if !self
                .idempotency
                .complete(
                    &key,
                    fingerprint,
                    lease,
                    StoredResponse {
                        status: 201,
                        body: id.as_bytes().to_vec(),
                        headers: Vec::new(),
                    },
                )
                .await
                .map_err(|_| Error::Unavailable)?
            {
                return Err(Error::Conflict);
            }
            Ok(id)
        };
        // 幂等和 SQL 组合的状态只属于这次有界管理事务，不占用通用请求栈的内联空间。
        self.transaction(Box::pin(body)).await
    }

    /// 业务作用：按精确授权范围读取单个低敏提案，不加载候选正文。
    ///
    /// 参数说明：
    /// - `scope`：当前请求允许的域。
    /// - `id`：固定长度提案身份。
    ///
    /// 返回：当前记录或不存在；超期依据数据库时钟投影，不伪造目标结果。
    pub(super) async fn read(&self, scope: &str, id: &str) -> Result<Record, Error> {
        let query = async {
            let mut connection = super::connection::Reading::acquire(&self.pool).await?;
            let row = sqlx::query(concat!(
            "SELECT admission_epoch, id, scope, domain, creator, reviewer, state, execution_started, candidate_digest, octet_length(candidate) AS candidate_bytes, targets, created_at_ms, expires_at_ms, updated_at_ms, ",
            "floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_operation_proposals WHERE cluster_id = $1 AND scope = $2 AND id = $3"
        )).bind(&self.plan.config.cluster_id).bind(scope).bind(id)
                .fetch_optional(connection.as_mut()).await?;
            connection.release().await;
            Ok(row)
        };
        let row = self.read_query(query).await?.ok_or(Error::Missing)?;
        record(row)
    }

    /// 业务作用：使用稳定身份游标读取一个已授权域的有界列表，避免全表正文装载。
    ///
    /// 参数说明：
    /// - `scope`：精确授权范围。
    /// - `domain`：当前主体可读的唯一领域。
    /// - `after`：上页最后一个 id，空字符串表示首屏。
    /// - `limit`：调用入口限制后的最大条数。
    ///
    /// 返回：最多指定条数的低敏投影；随机 id 排序只用于游标，不承诺时间顺序。
    pub(super) async fn list(
        &self,
        scope: &str,
        domain: &str,
        after: &str,
        limit: i64,
    ) -> Result<Vec<Record>, Error> {
        let query = async {
            let mut connection = super::connection::Reading::acquire(&self.pool).await?;
            let rows = sqlx::query(concat!(
            "SELECT admission_epoch, id, scope, domain, creator, reviewer, state, execution_started, candidate_digest, octet_length(candidate) AS candidate_bytes, targets, created_at_ms, expires_at_ms, updated_at_ms, ",
            "floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_operation_proposals WHERE cluster_id = $1 AND scope = $2 AND id > $3 AND domain = $5 ORDER BY id LIMIT $4"
        )).bind(&self.plan.config.cluster_id).bind(scope).bind(after).bind(limit).bind(domain)
                .fetch_all(connection.as_mut()).await?;
            connection.release().await;
            Ok(rows)
        };
        let rows = self.read_query(query).await?;
        rows.into_iter().map(record).collect()
    }

    /// 业务作用：为读取数据库事实设置覆盖连接获取和网络回包的绝对期限，避免静默连接永久占用管理名额。
    ///
    /// 参数说明：
    /// - `query`：只读取本数据库事实的有限查询。
    ///
    /// 返回：六秒内完整取得的事实；超时或数据库错误均不交付部分结果。
    pub(super) async fn read_query<T>(
        &self,
        query: impl Future<Output = Result<T, sqlx::Error>>,
    ) -> Result<T, Error> {
        tokio::time::timeout(Duration::from_secs(6), Box::pin(query))
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)
    }

    /// 业务作用：在同一记录锁内复验摘要、权限和期限，只允许一次确定的审阅状态迁移。
    ///
    /// 参数说明：
    /// - `scope`：已授权的范围。
    /// - `id`：被审阅的提案身份。
    /// - `principal`：当前审阅主体。
    /// - `authority`：按创建者和当前权限重新构建的摘要。
    /// - `review`：批准、拒绝或创建者取消以及明确确认的候选摘要。
    ///
    /// 返回：审阅已提交时成功；超期、重复审阅、越权或未知提交保持独立失败。
    pub(super) async fn review(
        &self,
        scope: &str,
        id: &str,
        principal: &str,
        authority: &[u8; 32],
        review: &Review,
    ) -> Result<(), Error> {
        self.transaction(Box::pin(async {
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
            let row = sqlx::query("SELECT creator, authority, candidate_digest, state, expires_at_ms, floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_operation_proposals WHERE cluster_id = $1 AND scope = $2 AND id = $3 FOR UPDATE")
                .bind(&self.plan.config.cluster_id).bind(scope).bind(id).fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Missing)?;
            let creator: String = row.try_get("creator").map_err(|_| Error::Unavailable)?;
            let stored_authority: Vec<u8> = row.try_get("authority").map_err(|_| Error::Unavailable)?;
            let candidate_digest: Vec<u8> = row.try_get("candidate_digest").map_err(|_| Error::Unavailable)?;
            let state: String = row.try_get("state").map_err(|_| Error::Unavailable)?;
            let expires: i64 = row.try_get("expires_at_ms").map_err(|_| Error::Unavailable)?;
            let now: i64 = row.try_get("now_ms").map_err(|_| Error::Unavailable)?;
            // 已批准或过期的事实不能被覆盖；取消也必须指向原候选，避免盲目终结另一项工作。
            if state != "awaiting_approval" || now >= expires || stored_authority != authority || hex(&candidate_digest) != review.candidate_sha256 {
                return Err(Error::Conflict);
            }
            let next = match review.decision {
                Decision::Cancel if principal == creator => "cancelled",
                Decision::Approve if principal != creator => "approved",
                Decision::Reject if principal != creator => "rejected",
                _ => return Err(Error::Denied),
            };
            // 获取锁可能等待；服务端更新条件再次读取时钟，不能使用等待前的过期判断续期批准。
            let changed = sqlx::query("UPDATE naway_operation_proposals SET state = $4, reviewer = $5, updated_at_ms = floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint WHERE cluster_id = $1 AND scope = $2 AND id = $3 AND expires_at_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
                .bind(&self.plan.config.cluster_id).bind(scope).bind(id).bind(next).bind(principal)
                .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
            if changed.rows_affected() != 1 {
                return Err(Error::Conflict);
            }
            Ok(())
        })).await
    }

    /// 业务作用：保留 NASA 对 COMMIT 未知的分类，并为整个事务设绝对等待上限。
    ///
    /// 参数说明：
    /// - `body`：只能保存本数据库事实的业务步骤。
    ///
    /// 返回：明确提交的值或封闭失败；超时后不得声称回滚或重新生成操作身份。
    pub(super) async fn transaction<T>(
        &self,
        body: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let decision = async {
            match body.await {
                Ok(value) => TxDecision::Commit(value),
                Err(error) => TxDecision::Rollback(error),
            }
        };
        match tokio::time::timeout(
            Duration::from_secs(10),
            self.idempotency.run_decided(decision),
        )
        .await
        {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(PgIdempotencyTransactionError::Business(error))) => Err(error),
            Ok(Err(
                PgIdempotencyTransactionError::OutcomeUnknown
                | PgIdempotencyTransactionError::RollbackFailed,
            ))
            | Err(_) => Err(Error::OutcomeUnknown),
            _ => Err(Error::Unavailable),
        }
    }
}

/// 业务作用：把受数据库约束的行转换成低敏 API 记录，并按当前数据库时钟标记过期。
///
/// 参数说明：
/// - `row`：查询已排除候选原文和秘密的持久记录。
///
/// 返回：类型完整的有限投影；持久数据不符合协议时不交付部分记录。
pub(super) fn record(row: PgRow) -> Result<Record, Error> {
    let parse = || -> Result<Record, sqlx::Error> {
        let expires_at_ms: i64 = row.try_get("expires_at_ms")?;
        let now: i64 = row.try_get("now_ms")?;
        let mut status: String = row.try_get("state")?;
        let execution_started: bool = row.try_get("execution_started")?;
        // 审批期限只限制首次创建；已提交的执行必须继续呈现原批准事实和持久进度。
        if !execution_started
            && now >= expires_at_ms
            && matches!(status.as_str(), "awaiting_approval" | "approved")
        {
            status = "expired".into();
        }
        let targets: Vec<u8> = row.try_get("targets")?;
        let targets = serde_json::from_slice(&targets)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
        Ok(Record {
            admission_epoch: row.try_get("admission_epoch")?,
            id: row.try_get("id")?,
            scope: row.try_get("scope")?,
            domain: row.try_get("domain")?,
            creator: row.try_get("creator")?,
            reviewer: row.try_get("reviewer")?,
            status,
            execution_started,
            candidate_sha256: hex(&row.try_get::<Vec<u8>, _>("candidate_digest")?),
            candidate_bytes: row.try_get("candidate_bytes")?,
            targets,
            created_at_ms: row.try_get("created_at_ms")?,
            expires_at_ms,
            updated_at_ms: row.try_get("updated_at_ms")?,
        })
    };
    parse().map_err(|_| Error::Unavailable)
}
