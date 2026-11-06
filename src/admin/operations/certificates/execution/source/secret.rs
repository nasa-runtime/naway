//! 只有原准备步骤需要候选明文，有限许可覆盖实际KDF及最后一个共享帧持有者。

use crate::{
    admin::{
        management::material_actions::Content,
        operations::{certificates::crypto, connection::Reading, model::Error, Store},
        AdminState,
    },
    config::GatewaySnapshot,
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::sync::OwnedSemaphorePermit;
use zeroize::Zeroizing;

pub(in crate::admin::operations::certificates::execution) struct Secret {
    pub context: crypto::Context,
    pub authority: [u8; 32],
    pub targets: Vec<u8>,
    pub summary: Vec<u8>,
    pub material_bytes: i32,
    pub ciphertext_bytes: i32,
    pub ciphertext_sha256: [u8; 32],
    pub reviewer: String,
}

pub(in crate::admin::operations::certificates::execution) struct Authenticated {
    pub content: Arc<Content>,
    key: Arc<Zeroizing<String>>,
}

impl Secret {
    /// 业务作用：在创建任务的同源事务内锁定最初认证的原材料，密文或审批变化不能被早到KDF结果覆盖。
    ///
    /// 参数说明：
    /// - `connection`：已经持有工作流推进权的共享事务连接。
    ///
    /// 返回：原完整材料标记、审阅者与期限仍成立时持锁成功；已有执行或任何记录变化都拒绝首次创建。
    pub(in crate::admin::operations::certificates::execution) async fn lock_for_start(
        &self,
        connection: &mut sqlx::PgConnection,
    ) -> Result<(), Error> {
        let id = sqlx::query_scalar::<_, String>(concat!(
            "SELECT p.id FROM naway_certificate_proposals p JOIN naway_certificate_owners o ON o.cluster_id=p.cluster_id ",
            "WHERE p.cluster_id=$1 AND p.id=$2 AND p.scope=$3 AND o.store_id=$4 AND p.admission_epoch=$5 ",
            "AND p.creator=$6 AND p.reviewer=$7 AND p.key_id=$8 AND p.authority=$9 AND p.intent_digest=$10 ",
            "AND p.targets=$11 AND p.summary=$12 AND p.created_at_ms=$13 AND p.expires_at_ms=$14 ",
            "AND p.material_bytes=$15 AND sha256(convert_to(p.ciphertext,'UTF8'))=$16 ",
            "AND octet_length(p.ciphertext)=$17 AND p.state='approved' AND NOT p.execution_started ",
            "AND p.expires_at_ms > floor(extract(epoch FROM clock_timestamp())*1000)::bigint FOR UPDATE OF p"
        )).bind(&self.context.cluster).bind(&self.context.id).bind(&self.context.scope).bind(&self.context.store_id)
            .bind(self.context.epoch).bind(&self.context.creator).bind(&self.reviewer).bind(&self.context.key_id)
            .bind(self.authority.as_slice()).bind(self.context.intent.as_slice()).bind(&self.targets).bind(&self.summary)
            .bind(self.context.created).bind(self.context.expires).bind(self.material_bytes).bind(self.ciphertext_sha256.as_slice())
            .bind(self.ciphertext_bytes).fetch_optional(connection).await.map_err(|_| Error::Unavailable)?;
        if id.is_none() {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// 业务作用：在任何秘密读取之前约束原材料元数据与预算，持久行不能扩大KDF或候选帧容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原身份与固定长度预算均合法时成功；异常元数据不进入密文读取。
    pub(super) fn validate(&self) -> Result<(), Error> {
        use crate::{config::operations::token, control::material::node::hexadecimal};
        if !(18..=1_048_592).contains(&self.material_bytes)
            || !(64..=self.material_bytes * 2 + 256).contains(&self.ciphertext_bytes)
            || !(2..=65536).contains(&self.targets.len())
            || !(2..=1024).contains(&self.summary.len())
            || self.context.epoch <= 0
            || self.context.created < 0
            || self.context.expires <= self.context.created
            || !hexadecimal(&self.context.id, 32)
            || !hexadecimal(&self.context.store_id, 64)
            || !token(&self.context.cluster, 128)
            || !token(&self.context.key_id, 64)
            || !token(&self.context.creator, 128)
            || !token(&self.reviewer, 128)
            || self.context.creator == self.reviewer
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    /// 业务作用：认证原持久候选一次并转移唯一明文帧，许可和发布锁由实际阻塞任务持有到算法结束。
    ///
    /// 参数说明：
    /// - `state`：当前真实管理发布owner。
    /// - `snapshot`：当前完整权限与有限钥环快照。
    /// - `store`：提供原记录和两个实际算法名额的存储。
    /// - `permit`：秘密读取之前取得的候选容量，随最后一个帧持有者释放。
    /// - `authorize`：两份完整原批准、四主体和精确快照的同步复验。
    ///
    /// 返回：唯一已认证候选及其原钥身份；过期新请求、撤权、换记录或密码学失败均不交付正文。
    pub(in crate::admin::operations::certificates::execution) async fn open(
        self: &Arc<Self>,
        state: &AdminState,
        snapshot: &Arc<GatewaySnapshot>,
        store: &Store,
        permit: OwnedSemaphorePermit,
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<Authenticated, Error> {
        authorize()?;
        let ciphertext = store.read_query(async {
            let mut connection = Reading::acquire(&store.pool).await?;
            let ciphertext = sqlx::query_scalar::<_, String>(concat!(
                "SELECT p.ciphertext FROM naway_certificate_proposals p JOIN naway_certificate_owners o ON o.cluster_id=p.cluster_id ",
                "WHERE p.cluster_id=$1 AND p.id=$2 AND p.scope=$3 AND o.store_id=$4 AND p.admission_epoch=$5 ",
                "AND p.creator=$6 AND p.reviewer=$7 AND p.key_id=$8 AND p.authority=$9 AND p.intent_digest=$10 ",
                "AND p.targets=$11 AND p.summary=$12 AND p.created_at_ms=$13 AND p.expires_at_ms=$14 ",
                "AND p.material_bytes=$15 AND sha256(convert_to(p.ciphertext,'UTF8'))=$16 AND p.state='approved' ",
                "AND (p.execution_started OR p.expires_at_ms > floor(extract(epoch FROM clock_timestamp())*1000)::bigint)"
            )).bind(&self.context.cluster).bind(&self.context.id).bind(&self.context.scope).bind(&self.context.store_id)
                .bind(self.context.epoch).bind(&self.context.creator).bind(&self.reviewer).bind(&self.context.key_id)
                .bind(self.authority.as_slice()).bind(self.context.intent.as_slice()).bind(&self.targets).bind(&self.summary)
                .bind(self.context.created).bind(self.context.expires).bind(self.material_bytes).bind(self.ciphertext_sha256.as_slice())
                .fetch_optional(connection.as_mut()).await?;
            connection.release().await;
            Ok(ciphertext)
        }).await?.ok_or(Error::Conflict)?;
        if ciphertext.len() != self.ciphertext_bytes as usize
            || Sha256::digest(ciphertext.as_bytes()).as_slice() != self.ciphertext_sha256
        {
            return Err(Error::Unavailable);
        }
        let publication = Arc::new(
            tokio::time::timeout(Duration::from_secs(2), state.apply_coordinator.lock_owned())
                .await
                .map_err(|_| Error::Capacity)?,
        );
        // 数据库等待与发布权排队都可能跨越撤权，KDF开始前重新核对，取消不能提前归还仍占用的实际许可。
        authorize()?;
        let key = self.key(snapshot)?;
        let original = self.clone();
        let original_key = key.clone();
        let content = crypto::run(
            store
                .certificate_workers
                .as_ref()
                .ok_or(Error::Unavailable)?,
            publication.clone(),
            move || {
                let opened = crypto::open(
                    &ciphertext,
                    &original_key,
                    &original.context,
                    &original.targets,
                    &original.authority,
                    &original.summary,
                )?;
                if opened.material.0.len() != original.material_bytes as usize {
                    return Err(Error::Unavailable);
                }
                Ok(Arc::new(Content::admitted(opened.material, permit)))
            },
        )
        .await?;
        authorize()?;
        // 文件准备会自行取得同一发布权；秘密缓存只能保留材料，不能持锁等待节点执行。
        drop(publication);
        Ok(Authenticated {
            content,
            key,
        })
    }

    /// 业务作用：按原key id取得当前解密权，缺旧钥时不能退回新写钥继续共享旧秘密。
    ///
    /// 参数说明：
    /// - `snapshot`：本轮完整活动钥环。
    ///
    /// 返回：原钥仍可用时共享清零容器；移除或缺失原标识时拒绝。
    fn key(&self, snapshot: &GatewaySnapshot) -> Result<Arc<Zeroizing<String>>, Error> {
        snapshot
            .admin_operations
            .as_ref()
            .and_then(|plan| plan.certificate_keys.as_ref())
            .and_then(|keys| keys.get(&self.context.key_id))
            .ok_or(Error::Unavailable)
    }
}

impl Authenticated {
    /// 业务作用：复用已认证帧之前确认原钥仍在当前钥环，轮换或撤销不能被缓存绕过。
    ///
    /// 参数说明：
    /// - `secret`：该帧原持久密文标记。
    /// - `snapshot`：本轮实际授权快照。
    ///
    /// 返回：同一原钥内容仍明确可用才为真；身份删除或同名换钥均要求停止使用旧帧。
    pub(in crate::admin::operations::certificates::execution) fn available(
        &self,
        secret: &Secret,
        snapshot: &GatewaySnapshot,
    ) -> bool {
        secret.key(snapshot).is_ok_and(|current| {
            crate::security::auth::constant_time_eq(current.as_bytes(), self.key.as_bytes())
        })
    }
}
