//! 与提案同源的 NASA 工作流运行态；存储就绪和节点执行资格分别判定。

mod definition;
#[cfg(feature = "node-actions")]
pub(super) mod dispatch;
#[cfg(feature = "node-actions")]
mod results;
#[cfg(feature = "node-actions")]
pub(super) mod start;
#[cfg(feature = "node-actions")]
mod timers;
#[cfg(feature = "node-actions")]
mod transaction;

use super::{store::DATASOURCE, Store};
use crate::config::operations::Plan;
use nasa::saga::pgsql::{OrchestratorConfig, PgOrchestrator};
use std::{sync::Arc, time::Duration};

pub(super) struct Workflow {
    engine: PgOrchestrator,
    #[cfg(feature = "node-actions")]
    timer_tokens: nasaga_backend::TimerFencingTokenIssuer,
    pub(super) summary: definition::Summary,
}

impl Workflow {
    /// 业务作用：在开放管理入口前确认冻结定义、共享配额和历史在途实例仍属于同一持久权威。
    ///
    /// 参数说明：
    /// - `store`：已通过实际结构门且已安装 NASA 命名 datasource 的存储 owner。
    ///
    /// 返回：完成六秒内启动预检的引擎；未初始化、未绑定或历史定义不一致时拒绝就绪。
    pub(super) async fn open(store: &Store) -> anyhow::Result<Self> {
        anyhow::ensure!(
            store.workflow_installed,
            "operations workflow schema is not initialized"
        );
        require_binding(store).await?;
        verify_tenants(store).await?;
        let (registry, summary) = definition::registry()?;
        let config = OrchestratorConfig {
            inbox_consumer: "naway-operation-results".into(),
            cancel_max_attempts: 3,
            compensate_max_attempts: 3,
            resolve_max_attempts: 5,
            timer_claim_limit: 8,
            startup_scan_limit: 128,
            tenant_quotas: [(store.plan.config.cluster_id.clone(), 16)].into(),
            ..OrchestratorConfig::default()
        };
        let workflow = Self {
            #[cfg(feature = "node-actions")]
            timer_tokens: nasaga_backend::TimerFencingTokenIssuer::new(),
            engine: PgOrchestrator::with_datasource(registry, config, DATASOURCE)
                .map_err(|_| anyhow::anyhow!("operations workflow construction failed"))?,
            summary,
        };
        // 在途实例必须能由原定义继续裁决；缺失或漂移时不得以新的定义静默宣告就绪。
        let verification = async {
            nasa::outbox::pgsql::verify_outbox_tenant_quota_schema_for(DATASOURCE).await?;
            workflow.engine.verify_startup().await
        };
        tokio::time::timeout(Duration::from_secs(6), Box::pin(verification))
            .await
            .map_err(|_| anyhow::anyhow!("operations workflow startup verification timed out"))?
            .map_err(|_| anyhow::anyhow!("operations workflow startup verification failed"))?;
        Ok(workflow)
    }
}

/// 业务作用：执行显式工作流迁移或只读启动验证，不安装后台调度器、不开放命令入口。
///
/// 参数说明：
/// - `plan`：当前完整配置选定的数据库与永久集群身份。
/// - `migrate`：显式初始化为真，只读状态为假。
///
/// 返回：已提交结构或实际验证后的定义摘要；失败关闭资源，提交不确定须原身份复查。
pub(super) async fn maintain(plan: Arc<Plan>, migrate: bool) -> anyhow::Result<serde_json::Value> {
    let store = Store::connect(plan).await?;
    let result = async {
        require_binding(&store).await?;
        if migrate {
            // 已有永久绑定先于 DDL，迁移事务原子建立全部结构和零配额事实。
            super::schema::gate(&store.pool, &store.plan, true, true).await.map_err(|_| {
                anyhow::anyhow!("workflow initialization did not confirm completion; inspect the original cluster and schema before retrying")
            })?;
            return Ok(serde_json::json!({
                "cluster_id": store.plan.config.cluster_id,
                "workflow_schema_installed": true,
                "delivery_schema_installed": true,
                "execution_available": false,
            }));
        }
        let workflow = Workflow::open(&store).await?;
        Ok(serde_json::json!({
            "cluster_id": store.plan.config.cluster_id,
            "workflow_schema_installed": true,
            "delivery_schema_installed": store.delivery_installed,
            "workflow_storage_ready": true,
            "workflow": workflow.summary,
            "execution_available": false,
        }))
    }
    .await;
    store.close().await;
    result
}

/// 业务作用：要求工作流 schema 已永久绑定当前集群，未绑定的多集群提案库不能启用共享命令扫描。
///
/// 参数说明：
/// - `store`：当前唯一数据库与集群计划。
///
/// 返回：精确匹配时成功；未绑定、异集群、保护行缺席和读取异常均阻止后续动作。
async fn require_binding(store: &Store) -> anyhow::Result<()> {
    let binding = store
        .execution_namespace()
        .await
        .map_err(|_| anyhow::anyhow!("operations execution namespace unavailable"))?;
    anyhow::ensure!(
        binding.bound_to(&store.plan.config.cluster_id),
        "operations workflow requires the matching bound cluster"
    );
    Ok(())
}

/// 业务作用：复验共享命令和实例只属于永久集群，且两个配额账本已经明确初始化。
///
/// 参数说明：
/// - `store`：持有固定集群身份和六秒只读期限的存储 owner。
///
/// 返回：无异集群事实且两个唯一账本可用时成功；缺失、未初始化或其它生产者内容均拒绝就绪。
async fn verify_tenants(store: &Store) -> anyhow::Result<()> {
    let valid = store.read_query(async {
        let mut connection = super::connection::Reading::acquire(&store.pool).await?;
        let valid: bool = sqlx::query_scalar(
            "SELECT (SELECT count(*) = 1 AND coalesce(bool_and(tenant_id = $1 AND initialized), FALSE) FROM saga_tenant_quota) \
             AND (SELECT count(*) = 1 AND coalesce(bool_and(tenant_id = $1 AND initialized), FALSE) FROM outbox_tenant_quota) \
             AND NOT EXISTS (SELECT 1 FROM saga_instance WHERE tenant_id <> $1) \
             AND NOT EXISTS (SELECT 1 FROM outbox_event WHERE tenant <> $1 OR aggregate_type <> $2)"
        ).bind(&store.plan.config.cluster_id).bind(nasa::saga::pgsql::SAGA_AGGREGATE_TYPE)
            .fetch_one(connection.as_mut()).await?;
        connection.release().await;
        Ok(valid)
    }).await.map_err(|_| anyhow::anyhow!("operations workflow ownership inspection unavailable"))?;
    anyhow::ensure!(
        valid,
        "operations workflow tenant or quota authority differs"
    );
    Ok(())
}
