//! 材料投递消费独立持久水位，只复用数据库与本机双时钟的有限期限算法。

use crate::{
    admin::operations::{
        execution::lease::clock::{Proof, Stamp},
        model::Error,
        store::DATASOURCE,
        Store,
    },
    control::{
        actions::command::Delivery,
        material::{execution::position::Position, node::Intent},
    },
};
use sqlx::Row;

pub(in crate::admin::operations) struct Lease {
    intent: [u8; 32],
    fence: u64,
    clock: Proof,
}

impl Store {
    /// 业务作用：取得原材料节点的独立共享租约，并在明确提交后才授予一次有限签发资格。
    ///
    /// 参数说明：
    /// - `intent`：包含原两份批准、完整来源和独立执行域的冻结意图。
    /// - `position`：工作流原物理节点位置，与逻辑目标分母分别校验。
    /// - `owner`：本次发行进程的独立随机身份。
    /// - `authorize`：当前快照、四主体和完整原影响权威的同步复验。
    ///
    /// 返回：只可消费一次的已提交租约；竞争、错域、提交不确定、撤权和时钟分歧均不签发。
    pub(in crate::admin::operations) async fn acquire_material_lease(
        &self,
        intent: &Intent,
        position: Position,
        owner: &[u8; 16],
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<Lease, Error> {
        if !self.material_execution_installed || self.stopping.is_cancelled() {
            return Err(Error::Unavailable);
        }
        let digest = position.fingerprint(intent).map_err(|_| Error::Invalid)?;
        if intent.baseline.cluster_id != self.plan.config.cluster_id {
            return Err(Error::Conflict);
        }
        let started = Stamp::now()?;
        let (fence, observed, expires) = self.transaction(Box::pin(async {
            authorize()?;
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                .await.map_err(|_| Error::Unavailable)?;
            // 节点占位必须随原任务明确提交；取得租约只推进材料域，不新建节点也不借配置计数签发。
            let row = sqlx::query("SELECT fence,now_ms,expires_at_ms FROM naway_material_execution_acquire($1,$2,$3,$4,$5,$6)")
                .bind(&self.plan.config.cluster_id).bind(&intent.execution_store)
                .bind(&intent.operation_id).bind(&intent.node_id).bind(digest.as_slice())
                .bind(owner.as_slice()).fetch_one(connection.as_mut()).await
                .map_err(|error| match error.as_database_error().and_then(|error| error.code()).as_deref() {
                    Some("PN010" | "PN012") => Error::Conflict,
                    Some("PN011") => Error::Capacity,
                    _ => Error::Unavailable,
                })?;
            let fence: i64 = row.try_get("fence").map_err(|_| Error::Unavailable)?;
            let observed: i64 = row.try_get("now_ms").map_err(|_| Error::Unavailable)?;
            let expires: i64 = row.try_get("expires_at_ms").map_err(|_| Error::Unavailable)?;
            authorize()?;
            Ok((fence, observed, expires))
        })).await?;
        // COMMIT 未知绝不产生外部权威；等待中撤权即放弃签发，已提交租约保持原期限自然失效。
        authorize()?;
        let clock = Proof::confirmed(started, Stamp::now()?, observed, expires)?;
        let fence = u64::try_from(fence)
            .ok()
            .filter(|fence| *fence > 0)
            .ok_or(Error::Unavailable)?;
        Ok(Lease {
            intent: digest,
            fence,
            clock,
        })
    }
}

impl Lease {
    /// 业务作用：将已提交材料租约消费为精确接收会话的一次投递，不能转给别的节点位置或存储域。
    ///
    /// 参数说明：
    /// - `intent`：即将签发的原完整材料意图。
    /// - `position`：原定义中的物理节点位置。
    /// - `issuer`：当前发行节点身份。
    /// - `boot`：当前新鲜管理报告中的接收启动身份。
    /// - `session`：当前已认证管理会话。
    ///
    /// 返回：不超过数据库和原单调期限的投递；错意图、错位置或剩余预算不足拒绝。
    pub(in crate::admin::operations) fn into_delivery(
        self,
        intent: &Intent,
        position: Position,
        issuer: String,
        boot: String,
        session: [u8; 32],
    ) -> Result<Delivery, Error> {
        if position.fingerprint(intent).map_err(|_| Error::Invalid)? != self.intent {
            return Err(Error::Conflict);
        }
        let (issued_at_ms, expires_at_ms) = self.clock.window(Stamp::now()?)?;
        Ok(Delivery {
            resolve_compensation: false,
            issuer_node_id: issuer,
            receiving_boot_id: boot,
            fence: self.fence,
            session,
            issued_at_ms,
            expires_at_ms,
        })
    }
}
