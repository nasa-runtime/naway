//! 定时器先独立领取，再在方向保护事务中裁决，节点网络不能占用推进锁。

use super::{
    super::{connection::Reading, model::Error, store::DATASOURCE, Store},
    results::database_now,
};
use nasaga_backend::{SagaBackend, SagaTimerRow, TimerClaimBatch, TimerFencingToken};
use nasaga_runtime_core::TimerOutcome;
use std::time::Duration;

impl Store {
    /// 业务作用：复用 NASA 的有限批次和消费能力，分别控制领取租约与业务裁决的事务边界。
    ///
    /// 参数说明：
    /// - owner：本进程固定随机运行身份，不能取自客户端输入。
    /// - authorize：验证当前控制面快照、执行开关和停止权。
    ///
    /// 返回：明确提交的裁决数量；失败保留已提交领取，原 token 不重建，后续可按租约接管。
    pub(in crate::admin::operations) async fn advance_timers(
        &self,
        owner: &str,
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<u32, Error> {
        let batch = self.claim_execution_timers(owner, authorize).await?;
        let backend = nasa::saga::pgsql::PgSagaBackend::with_datasource(DATASOURCE)
            .map_err(|_| Error::Unavailable)?;
        let mut applied = 0;
        for timer in batch.timers() {
            match self
                .fire_execution_timer(timer, batch.token(), authorize)
                .await?
            {
                TimerOutcome::Applied {
                    ..
                } => applied += 1,
                TimerOutcome::SkippedPaused => {
                    // 交还只能独立提交；它不改变业务截止或结果，暂停期间按 NASA 租约规则退避。
                    let now = self.timer_clock().await?;
                    let available = now.checked_add(30_000).ok_or(Error::Unavailable)?;
                    tokio::time::timeout(
                        Duration::from_secs(6),
                        backend.store().release_timer(
                            &timer.timer_id,
                            batch.token(),
                            now,
                            available,
                        ),
                    )
                    .await
                    .map_err(|_| Error::OutcomeUnknown)?
                    .map_err(|_| Error::Unavailable)?;
                }
                TimerOutcome::SkippedFencingLost | TimerOutcome::SkippedStale => {}
            }
        }
        Ok(applied)
    }

    /// 业务作用：在业务事务外独立提交 NASA timer 租约，未确认领取绝不取得消费权。
    ///
    /// 参数说明：
    /// - owner：同进程固定随机 owner。
    /// - authorize：本轮当前运行权的同步复验。
    ///
    /// 返回：最多八条且由不可复制 token 绑定的已确认批次；未知提交只等待自然过期，不重造 token。
    pub(in crate::admin::operations) async fn claim_execution_timers(
        &self,
        owner: &str,
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<TimerClaimBatch, Error> {
        if self.stopping.is_cancelled() || !self.delivery_installed {
            return Err(Error::Unavailable);
        }
        let workflow = self.workflow.get().ok_or(Error::Unavailable)?;
        authorize()?;
        let now = self.timer_clock().await?;
        let backend = nasa::saga::pgsql::PgSagaBackend::with_datasource(DATASOURCE)
            .map_err(|_| Error::Unavailable)?;
        // NASA 领取必须独立提交，不能为了方向保护而把尚未可见的租约包在外层事务里。
        let batch = tokio::time::timeout(
            Duration::from_secs(6),
            backend.store().claim_due_timers(
                owner,
                workflow.timer_tokens.issue(owner, now),
                now,
                60_000,
                8,
            ),
        )
        .await
        .map_err(|_| Error::OutcomeUnknown)?
        .map_err(|_| Error::Unavailable)?;
        authorize()?;
        Ok(batch)
    }

    /// 业务作用：在同一方向保护锁内消费已确认 timer 并提交 NASA 状态，领取与业务事务各自保持原合同。
    ///
    /// 参数说明：
    /// - timer：原已确认批次的单个有限任务。
    /// - token：同批次持有的不可复制消费能力。
    /// - authorize：提交前后当前控制面运行权的同步检查。
    ///
    /// 返回：明确提交的 NASA 裁决；回滚时 timer 仍属于原租约，可用同一批次重试或等待到期接管。
    pub(in crate::admin::operations) async fn fire_execution_timer(
        &self,
        timer: &SagaTimerRow,
        token: &TimerFencingToken,
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<TimerOutcome, Error> {
        let workflow = self.workflow.get().ok_or(Error::Unavailable)?;
        self.workflow_transaction(Box::pin(async {
            authorize()?;
            let now = database_now().await?;
            // 只在此事务消费和推进状态；文件动作、外部发送及租约领取不得进入该锁域。
            let result = workflow
                .engine
                .fire_timer(timer, token, now)
                .await
                .map_err(|_| Error::Unavailable)?;
            authorize()?;
            Ok(result)
        }))
        .await
    }

    /// 业务作用：在没有业务事务的领取和交还边界读取当前数据库时钟，不能复用上轮扫描时间。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界读取的正毫秒时间；失败不发行新的领取 token。
    async fn timer_clock(&self) -> Result<i64, Error> {
        let now: i64 = self
            .read_query(async {
                let mut connection = Reading::acquire(&self.pool).await?;
                let now = sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                )
                .fetch_one(connection.as_mut())
                .await?;
                connection.release().await;
                Ok(now)
            })
            .await?;
        if now <= 0 {
            return Err(Error::Unavailable);
        }
        Ok(now)
    }
}
