//! 数据库确认和单调期限共同授予一次投递权，未知 COMMIT 或时钟分歧不产生签名。

mod clock;

use crate::{
    admin::operations::{model::Error, store::DATASOURCE, Store},
    control::actions::command::{Delivery, Intent},
};
use clock::{Proof, Stamp};
use sqlx::Row;

pub(in crate::admin::operations) struct Lease {
    intent: [u8; 32],
    fence: u64,
    clock: Proof,
}

impl Store {
    /// 业务作用：以共享事务取得原目标的新 fence，等待 COMMIT 和当前权限复验后才交付一次签发证明。
    ///
    /// 参数说明：
    /// - `intent`：已冻结审批、原文和完整目标基线的同一业务意图。
    /// - `owner`：本进程启动时生成且不跨进程复用的随机身份。
    /// - `authorize`：对原快照实例和当前创建、审阅权限的同步复验。
    ///
    /// 返回：只能消费一次的投递证明；错目标、活跃其它 owner、未知提交或时钟不可信拒绝签发。
    pub(in crate::admin::operations) async fn acquire_target_lease(
        &self,
        intent: &Intent,
        owner: &[u8; 16],
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<Lease, Error> {
        if !self.delivery_installed || self.stopping.is_cancelled() {
            return Err(Error::Unavailable);
        }
        let digest = intent.fingerprint().map_err(|_| Error::Invalid)?;
        let started = Stamp::now()?;
        let (fence, observed, expires) = self.transaction(Box::pin(async {
            authorize()?;
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
            // 原目标占位必须已随工作流创建提交；过期租约只能接管同一意图，不能在这里新建或换操作。
            let row = sqlx::query("SELECT fence, now_ms, expires_at_ms FROM naway_delivery_acquire($1,$2,$3,$4,$5)")
                .bind(&self.plan.config.cluster_id).bind(&intent.operation_id).bind(&intent.node_id)
                .bind(digest.as_slice()).bind(owner.as_slice()).fetch_one(connection.as_mut()).await.map_err(|error| match error.as_database_error().and_then(|error| error.code()).as_deref() {
                    Some("PN006" | "PN008") => Error::Conflict,
                    Some("PN007") => Error::Capacity,
                    _ => Error::Unavailable,
                })?;
            let fence: i64 = row.try_get("fence").map_err(|_| Error::Unavailable)?;
            let observed: i64 = row.try_get("now_ms").map_err(|_| Error::Unavailable)?;
            let expires: i64 = row.try_get("expires_at_ms").map_err(|_| Error::Unavailable)?;
            authorize()?;
            Ok((fence, observed, expires))
        })).await?;
        // 事务返回之前的租约都没有外部签发权；提交后再检查快照，撤权期间取得的占位只等待过期。
        authorize()?;
        let clock = Proof::confirmed(started, Stamp::now()?, observed, expires)?;
        let fence = u64::try_from(fence)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(Error::Unavailable)?;
        Ok(Lease {
            intent: digest,
            fence,
            clock,
        })
    }
}

impl Lease {
    /// 业务作用：消费已确认租约并绑定实际接收会话，后续重投必须重新取得数据库证明。
    ///
    /// 参数说明：
    /// - `intent`：即将进入签名的完整原意图。
    /// - `issuer`：当前发布的发行节点身份。
    /// - `boot`：新鲜管理报告中实际接收方启动身份。
    /// - `session`：该接收端当前会话，不来自提案自报。
    ///
    /// 返回：同时受数据库期限、首次单调期限和当前时钟约束的投递；错意图或剩余预算不足拒绝。
    pub(in crate::admin::operations) fn into_delivery(
        self,
        intent: &Intent,
        issuer: String,
        boot: String,
        session: [u8; 32],
    ) -> Result<Delivery, Error> {
        if intent.fingerprint().map_err(|_| Error::Invalid)? != self.intent {
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
