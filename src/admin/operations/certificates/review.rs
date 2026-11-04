//! 材料审阅只推进共享提案状态，批准不会向节点发送安装命令。

pub(super) use super::super::model::Decision;
use super::{crypto, Error, Store};
use crate::config::operations::certificates::Keyring;
use serde::Deserialize;
use sqlx::Row;
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Review {
    pub decision: Decision,
    pub certificate_sha256: String,
}

pub(super) struct Request<'a> {
    pub scope: &'a str,
    pub id: &'a str,
    pub principal: &'a str,
    pub authority: [u8; 32],
    pub review: Review,
    pub keyring: Arc<Keyring>,
    pub publication: Arc<OwnedMutexGuard<()>>,
}

/// 业务作用：同一行锁中复验原意图、期限与双主体关系，批准前认证密文，拒绝和取消仍能处置缺钥材料。
///
/// 参数说明：
/// - `store`：已经就绪的独立材料存储。
/// - `request`：当前创建者及审阅者权限已复验的冻结审阅意图。
///
/// 返回：确定审阅提交才成功；缺钥、篡改、撤权、重复或过期均不能批准。
pub(super) async fn apply(store: &Store, request: Request<'_>) -> Result<(), Error> {
    store.transaction(Box::pin(async {
        let mut connection = nasa::tx::pgsql::mandatory_conn_for(super::super::store::DATASOURCE)
            .await.map_err(|_| Error::Unavailable)?;
        let cluster = &store.plan.config.cluster_id;
        // 统一先集群后提案的锁序，避免审阅与有限回收分别反向持锁。
        super::super::retention::Authority::lock(connection.as_mut(), cluster).await?;
        let store_id = super::capacity::owner(connection.as_mut(), store).await?;
        let row = sqlx::query("SELECT creator,authority,intent_digest,key_id,ciphertext,targets,summary,admission_epoch,state,created_at_ms,expires_at_ms,floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_certificate_proposals WHERE cluster_id=$1 AND scope=$2 AND id=$3 FOR UPDATE")
            .bind(cluster)
            .bind(request.scope)
            .bind(request.id).fetch_optional(connection.as_mut())
            .await
            .map_err(super::database_error)?.ok_or(Error::Missing)?;
        let creator: String = row.try_get("creator").map_err(|_| Error::Unavailable)?;
        let authority: Vec<u8> = row.try_get("authority").map_err(|_| Error::Unavailable)?;
        let summary: Vec<u8> = row.try_get("summary").map_err(|_| Error::Unavailable)?;
        let state: String = row.try_get("state").map_err(|_| Error::Unavailable)?;
        let expires: i64 = row.try_get("expires_at_ms").map_err(|_| Error::Unavailable)?;
        let now: i64 = row.try_get("now_ms").map_err(|_| Error::Unavailable)?;
        let certificate: super::model::Summary = serde_json::from_slice(&summary).map_err(|_| Error::Unavailable)?;
        // 原授权摘要与原公开证书必须一起确认；等待期间过期不得用旧检查结果继续批准。
        if authority != request.authority || state != "awaiting_approval" || now >= expires
            || request.review.certificate_sha256 != certificate.certificate_sha256
        {
            return Err(Error::Conflict);
        }
        let next = match request.review.decision {
            Decision::Cancel if request.principal == creator => "cancelled",
            Decision::Approve if request.principal != creator => "approved",
            Decision::Reject if request.principal != creator => "rejected",
            _ => return Err(Error::Denied),
        };
        if matches!(request.review.decision, Decision::Approve) {
            let intent: Vec<u8> = row.try_get("intent_digest").map_err(|_| Error::Unavailable)?;
            let context = crypto::Context {
                cluster: cluster.clone(),
                store_id,
                epoch: row.try_get("admission_epoch").map_err(|_| Error::Unavailable)?,
                id: request.id.into(),
                key_id: row.try_get("key_id").map_err(|_| Error::Unavailable)?,
                creator,
                scope: request.scope.into(),
                intent: intent.try_into().map_err(|_| Error::Unavailable)?,
                created: row.try_get("created_at_ms").map_err(|_| Error::Unavailable)?,
                expires,
            };
            let secret = request.keyring.get(&context.key_id).ok_or(Error::Unavailable)?;
            let ciphertext: String = row.try_get("ciphertext").map_err(|_| Error::Unavailable)?;
            let targets: Vec<u8> = row.try_get("targets").map_err(|_| Error::Unavailable)?;
            let authority = request.authority;
            crypto::run(store.certificate_workers.as_ref().ok_or(Error::Unavailable)?, request.publication.clone(), move || {
                crypto::verify(&ciphertext, &secret, &context, &targets, &authority, &summary)
            }).await?;
        }
        let changed = sqlx::query("UPDATE naway_certificate_proposals SET state=$4,reviewer=$5,updated_at_ms=floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint WHERE cluster_id=$1 AND scope=$2 AND id=$3 AND expires_at_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .bind(cluster)
            .bind(request.scope)
            .bind(request.id)
            .bind(next)
            .bind(request.principal)
            .execute(connection.as_mut()).await.map_err(|error| {
                // 审阅门中的时钟或状态冲突属于原提案失效，不能误报为首次受理代已经关闭。
                match super::database_error(error) {
                    Error::Expired => Error::Conflict,
                    other => other,
                }
            })?;
        if changed.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
        Ok(())
    })).await
}
