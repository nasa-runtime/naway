//! 有限保留与单调受理代际；删除事实之前先持久封闭原请求的新建能力。

use super::{
    model::Error,
    store::{Store, DATASOURCE},
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::{sync::Arc, time::Duration};

pub(super) struct Authority {
    pub capacity: super::capacity::Contract,
    pub epoch: i64,
    pub expires: i64,
    pub required: bool,
    now: i64,
    window: i64,
    contract: Option<Vec<u8>>,
}

impl Authority {
    /// 业务作用：锁定唯一集群权威后读取数据库时钟，使等待锁的时间不会延长准入期限。
    ///
    /// 参数说明：
    /// - `connection`：当前同源事务的物理连接。
    /// - `cluster`：已验证的集群身份。
    ///
    /// 返回：持锁的当前代际和保留合同；缺失或数据库失败时封闭本次操作。
    pub(super) async fn lock(connection: &mut PgConnection, cluster: &str) -> Result<Self, Error> {
        let row = sqlx::query("SELECT current_epoch, epoch_expires_at_ms, epoch_required, epoch_window_ms, retention_contract, capacity_revision, capacity_digest, capacity_previous_digest, max_records, max_records_per_scope, max_candidate_bytes, max_total_candidate_bytes FROM naway_operation_clusters WHERE cluster_id = $1 FOR UPDATE")
            .bind(cluster).fetch_one(&mut *connection).await.map_err(|_| Error::Unavailable)?;
        let now = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(connection)
        .await
        .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            capacity: super::capacity::Contract::from_row(&row)?,
            epoch: row
                .try_get("current_epoch")
                .map_err(|_| Error::Unavailable)?,
            expires: row
                .try_get("epoch_expires_at_ms")
                .map_err(|_| Error::Unavailable)?,
            required: row
                .try_get("epoch_required")
                .map_err(|_| Error::Unavailable)?,
            window: row
                .try_get("epoch_window_ms")
                .map_err(|_| Error::Unavailable)?,
            contract: row
                .try_get("retention_contract")
                .map_err(|_| Error::Unavailable)?,
            now,
        })
    }

    /// 业务作用：只允许当前未过期代际首次写入，兼容协议关闭后永久拒绝无代际新建。
    ///
    /// 参数说明：
    /// - `epoch`：请求最初取得且必须在重试时保留的受理代际。
    ///
    /// 返回：当前协议允许新建时成功；老代际、未来代际及已关闭兼容入口返回过期。
    pub(super) fn admit(&self, epoch: i64) -> Result<(), Error> {
        if epoch == 0 && !self.required
            || epoch > 0 && epoch == self.epoch && self.now < self.expires
        {
            Ok(())
        } else {
            Err(Error::Expired)
        }
    }

    /// 业务作用：在持锁状态下单调推进已到期窗口，数据库时间回拨不会重新激活已关闭代际。
    ///
    /// 参数说明：
    /// - `connection`：持有集群行锁的事务连接。
    /// - `cluster`：需要推进的唯一集群。
    ///
    /// 返回：更新当前事务中的代际事实；整数耗尽或数据库失败时拒绝发布新窗口。
    async fn refresh(&mut self, connection: &mut PgConnection, cluster: &str) -> Result<(), Error> {
        if self.epoch > 0 && self.now < self.expires {
            return Ok(());
        }
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Unavailable)?;
        self.expires = self
            .now
            .checked_add(self.window)
            .ok_or(Error::Unavailable)?;
        sqlx::query("UPDATE naway_operation_clusters SET current_epoch = $2, epoch_expires_at_ms = $3 WHERE cluster_id = $1")
            .bind(cluster).bind(self.epoch).bind(self.expires).execute(connection).await.map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}

impl Store {
    /// 业务作用：在任何清理启动前持久登记不可倒退的协议门和共享保留合同。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：关闭时不修改持久权威；开启时合同必须一致，未知提交阻断本次启动。
    pub(super) async fn prepare_retention(&self) -> Result<(), Error> {
        let policy = &self.plan.config.retention;
        if !policy.enabled {
            return Ok(());
        }
        let digest = contract(policy);
        self.transaction(Box::pin(async {
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
            let cluster = &self.plan.config.cluster_id;
            let authority = Authority::lock(connection.as_mut(), cluster).await?;
            if let Some(stored) = authority.contract {
                // 同一集群不能让不同 Admin 以不同期限删除事实；已登记合同只能精确恢复。
                if stored.as_slice() != digest || !authority.required {
                    return Err(Error::Conflict);
                }
                return Ok(());
            }
            let window = i64::from(policy.epoch_window_seconds) * 1000;
            let epoch = authority.epoch.checked_add(1).ok_or(Error::Unavailable)?;
            let expires = authority.now.checked_add(window).ok_or(Error::Unavailable)?;
            // 强制门、合同与新窗口同事务发布；清理任务必须等明确提交后才能启动。
            sqlx::query("UPDATE naway_operation_clusters SET epoch_required = TRUE, retention_contract = $2, epoch_window_ms = $3, current_epoch = $4, epoch_expires_at_ms = $5 WHERE cluster_id = $1")
                .bind(cluster).bind(digest.as_slice()).bind(window).bind(epoch).bind(expires)
                .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
            Ok(())
        })).await
    }

    /// 业务作用：为已授权请求取得跨 Admin 一致的有限受理窗口，不创建提案或执行权限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：明确提交的当前代际；数据库不可用或提交未知时不交付猜测窗口。
    pub(super) async fn context(&self) -> Result<Authority, Error> {
        self.transaction(Box::pin(async {
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                .await
                .map_err(|_| Error::Unavailable)?;
            let cluster = &self.plan.config.cluster_id;
            let mut authority = Authority::lock(connection.as_mut(), cluster).await?;
            authority.refresh(connection.as_mut(), cluster).await?;
            Ok(authority)
        }))
        .await
    }

    /// 业务作用：每轮仅删除有限个从未执行且超过保留期限的提案及其精确完成收据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：明确提交的删除数量；任何收据不一致、引用阻断或未知提交都不提前释放容量。
    pub(super) async fn collect_expired(&self) -> Result<usize, Error> {
        let policy = &self.plan.config.retention;
        if !policy.enabled {
            return Ok(0);
        }
        self.transaction(Box::pin(async {
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
            let cluster = &self.plan.config.cluster_id;
            let mut authority = Authority::lock(connection.as_mut(), cluster).await?;
            // 先证实旧协议永久关闭，再选择可删除事实；配置开关本身不能充当持久证据。
            if !authority.required || authority.contract.as_deref() != Some(contract(policy).as_slice()) {
                return Err(Error::Conflict);
            }
            authority.refresh(connection.as_mut(), cluster).await?;
            let cutoff = authority.now.checked_sub(i64::from(policy.retain_seconds) * 1000).ok_or(Error::Unavailable)?;
            let rows = sqlx::query("SELECT id, scope, creator, client_key, admission_epoch FROM naway_operation_proposals WHERE cluster_id = $1 AND NOT execution_started AND admission_epoch < $2 AND (CASE WHEN state IN ('rejected', 'cancelled') THEN updated_at_ms ELSE expires_at_ms END) <= $3 ORDER BY id LIMIT $4 FOR UPDATE")
                .bind(cluster).bind(authority.epoch).bind(cutoff).bind(i64::from(policy.batch_size))
                .fetch_all(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
            for row in &rows {
                let id: String = row.try_get("id").map_err(|_| Error::Unavailable)?;
                let scope: String = row.try_get("scope").map_err(|_| Error::Unavailable)?;
                let creator: String = row.try_get("creator").map_err(|_| Error::Unavailable)?;
                let key: String = row.try_get("client_key").map_err(|_| Error::Unavailable)?;
                let epoch: i64 = row.try_get("admission_epoch").map_err(|_| Error::Unavailable)?;
                // 不删除在途或不匹配收据；任何执行引用应以外键拒绝后续提案删除，整批保持原子性。
                let receipt = sqlx::query("DELETE FROM idempotency_record_v2 WHERE tenant = $1 AND subject = $2 AND route_id = $3 AND client_key = $4 AND state = 1 AND status = 201 AND body = $5 AND headers = $6")
                    .bind(cluster).bind(creator).bind(route(&scope, epoch)).bind(key).bind(id.as_bytes()).bind(b"[]".as_slice())
                    .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                if receipt.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                let proposal = sqlx::query("DELETE FROM naway_operation_proposals WHERE cluster_id = $1 AND id = $2 AND NOT execution_started")
                    .bind(cluster).bind(id).execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                if proposal.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
            }
            Ok(rows.len())
        })).await
    }

    /// 业务作用：装配唯一有限清理循环，多个 Admin 通过共享数据库行锁裁决每批删除。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：开启且 owner 已就绪时安装一次任务；关闭时不创建任务或周期数据库访问。
    pub(super) fn start_retention(self: &Arc<Self>) {
        if !self.plan.config.retention.enabled {
            return;
        }
        self.cleaner.get_or_init(|| {
            let owner = Arc::downgrade(self);
            let stopping = self.stopping.clone();
            let interval =
                Duration::from_secs(u64::from(self.plan.config.retention.interval_seconds));
            tokio::sync::Mutex::new(Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = stopping.cancelled() => break,
                        _ = tokio::time::sleep(interval) => {}
                    }
                    let Some(store) = owner.upgrade() else {
                        break;
                    };
                    // 停机不再开始新轮次；已经开始的事务有绝对期限，close 会等其结束再关池。
                    if stopping.is_cancelled() {
                        break;
                    }
                    match store.collect_expired().await {
                        Ok(deleted) if deleted > 0 => {
                            tracing::info!(deleted, "operations retention batch committed")
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(?error, "operations retention batch not confirmed")
                        }
                    }
                }
            })))
        });
    }
}

impl Drop for Store {
    /// 业务作用：owner 释放时停止周期唤醒，避免失去管理运行态后继续触发清理。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同步发出取消信号；正常停机由 close 等待已有事务结束。
    fn drop(&mut self) {
        self.stopping.cancel();
    }
}

/// 业务作用：将持久受理代际纳入幂等命名空间，同时保持旧提案收据可读。
///
/// 参数说明：
/// - `scope`：经过长度和字符校验的精确权限域。
/// - `epoch`：原请求的代际，零表示兼容协议。
///
/// 返回：最长一百五十七字节的稳定 NASA route 键。
pub(super) fn route(scope: &str, epoch: i64) -> String {
    if epoch == 0 {
        format!("proposal:{scope}")
    } else {
        format!("proposal:{scope}:{epoch}")
    }
}

/// 业务作用：冻结跨 Admin 的删除预算和时钟窗口，阻止不同启动声明共享同一清理权威。
///
/// 参数说明：
/// - `policy`：已通过边界验证且显式启用的保留声明。
///
/// 返回：固定字段顺序的 SHA-256，不包含节点身份或连接秘密。
fn contract(policy: &crate::config::operations::Retention) -> [u8; 32] {
    let mut digest = Sha256::new();
    for value in [
        policy.epoch_window_seconds,
        policy.retain_seconds,
        policy.interval_seconds,
        policy.batch_size,
    ] {
        digest.update(value.to_be_bytes());
    }
    digest.finalize().into()
}
