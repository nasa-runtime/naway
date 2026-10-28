//! 显式迁移与只读结构复验；同一连接的锁和迁移生命周期由 NASA 管理。

use crate::config::operations::Plan;
use nasa::migration::pgsql::{MigrationMode, MigrationSettings, Migrator};
use sqlx::{postgres::PgPoolOptions, ConnectOptions, PgPool, SqlSafeStr};
use std::{str::FromStr, time::Duration};

mod delivery;
mod workflow;

pub(super) struct Installed {
    pub workflow: bool,
    pub delivery: bool,
}

const MIGRATION: &str = concat!(
    include_str!("sql/proposals.sql"),
    "\nINSERT INTO naway_operation_schema(name, shape) SELECT 'proposals', shape FROM (\n",
    include_str!("sql/shape.sql"),
    "\n) AS initial_shape;\n"
);

// 追加结构前在迁移持有的 session 锁和事务内复验旧基线，不能将已有漂移登记为新权威。
const EPOCH_MIGRATION: &str = concat!(
    "DO $$ BEGIN IF (SELECT shape FROM naway_operation_schema WHERE name = 'proposals') IS DISTINCT FROM (SELECT shape FROM (",
    include_str!("sql/shape.sql"),
    ") AS previous_shape) THEN RAISE EXCEPTION 'operations schema structure differs from migration evidence'; END IF; END $$;\n",
    include_str!("sql/proposal_admission_epochs.sql"),
    "\nUPDATE naway_operation_schema SET shape = (SELECT base.shape || jsonb_build_object('protocol', protocol.shape) FROM (",
    include_str!("sql/shape.sql"),
    ") AS base CROSS JOIN (",
    include_str!("sql/epoch_shape.sql"),
    ") AS protocol) WHERE name = 'proposals';\n"
);

// 已交付迁移的输入保持不变；新合同先验证旧证据，再把容量函数纳入同一实际结构基线。
const CAPACITY_MIGRATION: &str = concat!(
    "DO $$ BEGIN IF (SELECT shape FROM naway_operation_schema WHERE name = 'proposals') IS DISTINCT FROM (SELECT base.shape || jsonb_build_object('protocol', protocol.shape) FROM (",
    include_str!("sql/shape.sql"),
    ") AS base CROSS JOIN (",
    include_str!("sql/epoch_shape.sql"),
    ") AS protocol) THEN RAISE EXCEPTION 'operations schema structure differs from migration evidence'; END IF; END $$;\n",
    include_str!("sql/proposal_capacity_contract.sql"),
    "\nUPDATE naway_operation_schema SET shape = (SELECT base.shape || jsonb_build_object('protocol', protocol.shape, 'capacity', capacity.shape) FROM (",
    include_str!("sql/shape.sql"),
    ") AS base CROSS JOIN (",
    include_str!("sql/epoch_shape.sql"),
    ") AS protocol CROSS JOIN (",
    include_str!("sql/capacity_shape.sql"),
    ") AS capacity) WHERE name = 'proposals';\n"
);

// 集群注册触发器与单行身份属于执行边界；先复验原合同，不能将任意旧结构纳入新证据。
const NAMESPACE_MIGRATION: &str = concat!(
    "DO $$ BEGIN IF (SELECT shape FROM naway_operation_schema WHERE name = 'proposals') IS DISTINCT FROM (SELECT base.shape || jsonb_build_object('protocol', protocol.shape, 'capacity', capacity.shape) FROM (",
    include_str!("sql/shape.sql"),
    ") AS base CROSS JOIN (",
    include_str!("sql/epoch_shape.sql"),
    ") AS protocol CROSS JOIN (",
    include_str!("sql/capacity_shape.sql"),
    ") AS capacity) THEN RAISE EXCEPTION 'operations schema structure differs from migration evidence'; END IF; END $$;\n",
    include_str!("sql/execution_namespace.sql"),
    "\nUPDATE naway_operation_schema SET shape = (SELECT base.shape || jsonb_build_object('protocol', protocol.shape, 'capacity', capacity.shape, 'namespace', namespace.shape) FROM (",
    include_str!("sql/shape.sql"),
    ") AS base CROSS JOIN (",
    include_str!("sql/epoch_shape.sql"),
    ") AS protocol CROSS JOIN (",
    include_str!("sql/capacity_shape.sql"),
    ") AS capacity CROSS JOIN (",
    include_str!("sql/namespace_shape.sql"),
    ") AS namespace) WHERE name = 'proposals';\n"
);

/// 业务作用：建立只承载持久管理操作的有界连接池，不使用全局数据面连接资源。
///
/// 参数说明：
/// - `plan`：已验证并冻结的数据库身份。
///
/// 返回：最多四条连接且获取、SQL和空闲事务均有限期的池；错误不包含 DSN。
pub(super) async fn connect(plan: &Plan) -> anyhow::Result<PgPool> {
    let options = sqlx::postgres::PgConnectOptions::from_str(&plan.database_url)
        .map_err(|_| anyhow::anyhow!("invalid operations database URL"))?
        .disable_statement_logging()
        .options([
            ("search_path", plan.config.schema.as_str()),
            ("statement_timeout", "3000"),
            ("lock_timeout", "2000"),
            ("idle_in_transaction_session_timeout", "5000"),
        ]);
    PgPoolOptions::new()
        .max_connections(4)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(2))
        .idle_timeout(Duration::from_secs(60))
        .max_lifetime(Duration::from_secs(300))
        .connect_with(options)
        .await
        .map_err(|_| anyhow::anyhow!("operations database connection unavailable"))
}

/// 业务作用：在开放管理请求前核对迁移摘要和实际数据库对象，显式初始化才允许 DDL。
///
/// 参数说明：
/// - `pool`：专用直连或 session pooling 连接池。
/// - `plan`：指定受管 schema 的冻结声明。
/// - `apply`：仅命令行显式初始化可置真。
/// - `with_workflow`：显式工作流初始化时包含工作流和交付合同；否则只验证已经提交的尾部。
///
/// 返回：所有已安装结构匹配时返回工作流及交付合同是否已初始化；漂移或缺失阻断启动。
pub(super) async fn gate(
    pool: &PgPool,
    plan: &Plan,
    apply: bool,
    with_workflow: bool,
) -> anyhow::Result<Installed> {
    let installed = installed_tail(pool).await?;
    let with_delivery = installed >= 6 || (apply && with_workflow);
    let with_workflow = with_workflow || installed >= 5;
    let mut migrations = vec![
        sqlx::migrate::Migration::new(
            1,
            "persistent operation proposals".into(),
            sqlx::migrate::MigrationType::Simple,
            MIGRATION.into_sql_str(),
            false,
        ),
        sqlx::migrate::Migration::new(
            2,
            "proposal admission epochs".into(),
            sqlx::migrate::MigrationType::Simple,
            EPOCH_MIGRATION.into_sql_str(),
            false,
        ),
        sqlx::migrate::Migration::new(
            3,
            "proposal capacity contract".into(),
            sqlx::migrate::MigrationType::Simple,
            CAPACITY_MIGRATION.into_sql_str(),
            false,
        ),
        sqlx::migrate::Migration::new(
            4,
            "execution cluster namespace".into(),
            sqlx::migrate::MigrationType::Simple,
            NAMESPACE_MIGRATION.into_sql_str(),
            false,
        ),
    ];
    if with_workflow {
        migrations.push(sqlx::migrate::Migration::new(
            5,
            "persistent operation workflow".into(),
            sqlx::migrate::MigrationType::Simple,
            workflow::MIGRATION.into_sql_str(),
            false,
        ));
    }
    if with_delivery {
        migrations.push(sqlx::migrate::Migration::new(
            6,
            "persistent target delivery".into(),
            sqlx::migrate::MigrationType::Simple,
            delivery::MIGRATION.into_sql_str(),
            false,
        ));
    }
    let migrator = Migrator::with_migrations(migrations);
    let settings = MigrationSettings {
        mode: if apply {
            MigrationMode::Apply
        } else {
            MigrationMode::Validate
        },
        lock_timeout_ms: 5000,
        allow_dirty: false,
    };
    if let Err(error) =
        nasa::migration::pgsql::run_gate(pool, &plan.config.schema, &migrator, &settings).await
    {
        // 等待迁移锁期间另一入口可能已提交工作流尾部；只允许按该已存在事实重选一次完整合同。
        let selected = if with_delivery {
            6
        } else if with_workflow {
            5
        } else {
            4
        };
        let committed = installed_tail(pool).await?;
        if committed > selected && committed <= 6 {
            return Box::pin(gate(pool, plan, apply, false)).await;
        }
        return Err(error.into());
    }
    // 迁移账本只证明曾应用的 SQL；结构基线还必须与当前 catalog 一致，避免丢失约束后继续受理。
    verify_shape(pool, "SELECT shape::text FROM naway_operation_schema WHERE name = 'proposals'", concat!(
        "SELECT (base.shape || jsonb_build_object('protocol', protocol.shape, 'capacity', capacity.shape, 'namespace', namespace.shape))::text FROM (",
        include_str!("sql/shape.sql"),
        ") AS base CROSS JOIN (",
        include_str!("sql/epoch_shape.sql"),
        ") AS protocol CROSS JOIN (",
        include_str!("sql/capacity_shape.sql"),
        ") AS capacity CROSS JOIN (",
        include_str!("sql/namespace_shape.sql"),
        ") AS namespace"
    )).await?;
    if with_workflow {
        verify_shape(
            pool,
            "SELECT shape::text FROM naway_operation_workflow_schema WHERE singleton",
            workflow::SHAPE,
        )
        .await?;
    }
    if with_delivery {
        verify_shape(
            pool,
            "SELECT shape::text FROM naway_delivery_schema WHERE singleton",
            delivery::SHAPE,
        )
        .await?;
    }
    Ok(Installed {
        workflow: with_workflow,
        delivery: with_delivery,
    })
}

/// 业务作用：只按已提交迁移账本选择需要验证的合同尾部，关闭运行开关不能回退数据库保护。
///
/// 参数说明：
/// - `pool`：已经固定 search_path 的独立管理连接池。
///
/// 返回：账本当前最大迁移编号；空库为零，未知尾部交给迁移器拒绝，读取失败不继续。
async fn installed_tail(pool: &PgPool) -> anyhow::Result<i64> {
    let read = async {
        let mut connection = super::connection::Reading::acquire(pool).await?;
        let exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(connection.as_mut())
            .await?;
        let installed = if exists {
            sqlx::query_scalar("SELECT coalesce(max(version), 0) FROM _sqlx_migrations")
                .fetch_one(connection.as_mut())
                .await?
        } else {
            0
        };
        connection.release().await;
        Ok::<_, sqlx::Error>(installed)
    };
    tokio::time::timeout(Duration::from_secs(6), read)
        .await
        .map_err(|_| anyhow::anyhow!("operations migration inspection timed out"))?
        .map_err(|_| anyhow::anyhow!("operations migration inspection unavailable"))
}

/// 业务作用：在同一有界物理连接中比对迁移证据与实际结构，取消时不遗留占池探测。
///
/// 参数说明：
/// - `pool`：当前持久权威的专用连接池。
/// - `expected`：读取唯一合同证据的编译期语句，不接受请求内容。
/// - `actual`：只查询 PostgreSQL catalog 的编译期语句。
///
/// 返回：两份结构完全相同才成功；缺证据、漂移、超时或传输异常都拒绝就绪。
async fn verify_shape(
    pool: &PgPool,
    expected: &'static str,
    actual: &'static str,
) -> anyhow::Result<()> {
    let read = async {
        let mut connection = super::connection::Reading::acquire(pool).await?;
        let expected: String = sqlx::query_scalar(expected)
            .fetch_one(connection.as_mut())
            .await?;
        let actual: String = sqlx::query_scalar(actual)
            .fetch_one(connection.as_mut())
            .await?;
        connection.release().await;
        Ok::<_, sqlx::Error>(expected == actual)
    };
    let same = tokio::time::timeout(Duration::from_secs(6), read)
        .await
        .map_err(|_| anyhow::anyhow!("operations schema inspection timed out"))?
        .map_err(|_| anyhow::anyhow!("operations schema evidence unavailable"))?;
    anyhow::ensure!(
        same,
        "operations schema structure differs from migration evidence"
    );
    Ok(())
}
