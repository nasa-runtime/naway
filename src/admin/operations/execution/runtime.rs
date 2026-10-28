//! 固定三个任务独立推进命令、定时器和终态释放，关闭开关不读取或改变共享工作流。

use super::{authority, cache::Cache, publisher::Publisher, release::Cursor};
use crate::admin::{
    operations::{model::Error, store::DATASOURCE, Store},
    AdminState,
};
use anyhow::{ensure, Context, Result};
use std::{
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub(in crate::admin::operations) struct Runtime {
    tasks: [JoinHandle<()>; 3],
}

#[derive(Clone, Copy, Debug)]
enum Task {
    Dispatch,
    Timers,
    Release,
}

impl Store {
    /// 业务作用：在唯一管理 owner 挂接后建立固定运行任务，数据库和工作流关闭时不创建派发器。
    ///
    /// 参数说明：
    /// - state：同一完整控制面实例，任务只保留弱引用避免资源循环持有。
    ///
    /// 返回：已装配独立的派发、timer 和释放 owner；执行关闭时全部休眠，启用缺少结构或发行身份则启动失败。
    pub(in crate::admin::operations) fn start_executor(
        self: &Arc<Self>,
        state: &Arc<AdminState>,
    ) -> Result<()> {
        if self.workflow.get().is_none() {
            return Ok(());
        }
        if self.plan.config.execution.enabled {
            authority::running(state, self, &state.snap.load_full())
                .map_err(|_| anyhow::anyhow!("operations execution authority unavailable"))?;
        }
        ensure!(
            self.executor.get().is_none(),
            "operations executor already installed"
        );
        let mut owner = [0; 16];
        getrandom::getrandom(&mut owner).context("execution owner entropy unavailable")?;
        let cache = Arc::new(Cache::default());
        let tasks = [Task::Dispatch, Task::Timers, Task::Release].map(|task| {
            tokio::spawn(drive(
                Arc::downgrade(state),
                Arc::downgrade(self),
                self.stopping.clone(),
                owner,
                task,
                cache.clone(),
            ))
        });
        self.executor
            .set(tokio::sync::Mutex::new(Some(Runtime {
                tasks,
            })))
            .map_err(|_| anyhow::anyhow!("operations executor owner changed"))?;
        Ok(())
    }
}

impl Runtime {
    /// 业务作用：停机撤权之后有界等待三个任务退出，随后才允许关闭共享数据库池。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：任务均已结束或取消；未知事务由原持久身份重试，不删除节点资格。
    pub(in crate::admin::operations) async fn close(&mut self) {
        for task in &mut self.tasks {
            if tokio::time::timeout(Duration::from_secs(5), &mut *task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

impl Drop for Runtime {
    /// 业务作用：非正常 owner 释放也取消后台等待，避免任务脱离唯一管理生命周期。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只取消本实例三个任务，已经交给阻塞节点工作的许可由原工作单元保持。
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// 业务作用：按当前快照决定本轮是否推进，慢网络与 timer 分别使用固定任务和有界数据库资源。
///
/// 参数说明：
/// - state：管理实例的弱引用，退出后不重建 owner。
/// - store：共享存储的弱引用，避免任务与资源互相保持存活。
/// - stopping：停机前首先撤销的运行权。
/// - owner：本进程独立随机身份，兼作节点租约 owner。
/// - task：固定任务用途，分别推进有限 timer 批次、单条 Outbox 或单个释放目标。
/// - cache：三个 owner 共享的最多十六份原候选缓存，timer 不读取候选。
///
/// 返回：停止或 owner 消失时结束；失败保留原持久工作，日志按状态变化及一分钟间隔限制。
async fn drive(
    state: Weak<AdminState>,
    store: Weak<Store>,
    stopping: CancellationToken,
    owner: [u8; 16],
    task: Task,
    cache: Arc<Cache>,
) {
    let mut cursor = Cursor::default();
    let name = crate::admin::operations::model::hex(&owner);
    let mut last: Option<(Error, Instant)> = None;
    loop {
        tokio::select! {
            biased;
            _ = stopping.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
        let (Some(state), Some(store)) = (state.upgrade(), store.upgrade()) else {
            break;
        };
        let snapshot = state.snap.load_full();
        if authority::running(&state, &store, &snapshot).is_err() {
            continue;
        }
        let run = async {
            match task {
                Task::Timers => store
                    .advance_timers(&name, &|| {
                        authority::running(&state, &store, &snapshot).map(|_| ())
                    })
                    .await
                    .map(|_| ()),
                Task::Release => cursor.advance(&state, &store, &owner, &cache).await,
                Task::Dispatch => {
                    cache.refresh(&store).await?;
                    authority::running(&state, &store, &snapshot)?;
                    let outbox = nasa::outbox::pgsql::PgOutbox::with_datasource(DATASOURCE)
                        .map_err(|_| Error::Unavailable)?;
                    let report = outbox
                        .dispatch_batch(
                            &Publisher {
                                state: &state,
                                store: &store,
                                owner: &owner,
                                cache: &cache,
                            },
                            1,
                        )
                        .await
                        .map_err(|_| Error::Unavailable)?;
                    if report.first_error.is_some() {
                        return Err(Error::Unavailable);
                    }
                    Ok(())
                }
            }
        };
        // 停机先撤销所有授权，再取消网络和数据库等待；未知 COMMIT 不能被当作未发生。
        let result = tokio::select! {
            biased;
            _ = stopping.cancelled() => break,
            result = tokio::time::timeout(Duration::from_secs(60), Box::pin(run)) => result.unwrap_or(Err(Error::OutcomeUnknown)),
        };
        match result {
            Ok(()) => {
                if last.take().is_some() {
                    tracing::info!(?task, "operations execution polling resumed");
                }
            }
            Err(error) => {
                if last.is_none_or(|(previous, at)| {
                    previous != error || at.elapsed() >= Duration::from_secs(60)
                }) {
                    tracing::warn!(?task, ?error, "operations execution polling not confirmed");
                    last = Some((error, Instant::now()));
                }
            }
        }
    }
}
