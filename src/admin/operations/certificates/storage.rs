//! 材料与 NASA 幂等收据共用一份事务，未知提交保留原请求查询身份。

use super::{crypto, model::Candidate, Error, Store};
use crate::config::operations::certificates::Keyring;
use nasa::idempotency::{
    ExecutionLease, IdempotencyKey, IdempotencyOutcome, IdempotencyStore, RequestFingerprint,
    StoredResponse,
};
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;

pub(super) struct Submission<'a> {
    pub scope: &'a str,
    pub creator: &'a str,
    pub client_key: &'a str,
    pub authority: [u8; 32],
    pub candidate: Candidate,
    pub keyring: Arc<Keyring>,
    pub publication: Arc<OwnedMutexGuard<()>>,
}

/// 业务作用：在原授权和共享容量锁内保存加密材料，同原请求只回放既有提案，不重复加密或另建身份。
///
/// 参数说明：
/// - `store`：已登记材料 owner 的共享数据库资源。
/// - `input`：已授权的固定意图、当前钥环和配置发布权。
///
/// 返回：同事务提交的提案 id；超时或提交未知必须用原代际与原幂等键回读。
pub(super) async fn submit(store: &Store, input: Submission<'_>) -> Result<String, Error> {
    let workers = store
        .certificate_workers
        .as_ref()
        .ok_or(Error::Unavailable)?;
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
    let id = super::super::model::hex(&random);
    let key = IdempotencyKey {
        tenant: store.plan.config.cluster_id.clone(),
        subject: input.creator.into(),
        route_id: super::route(input.scope, input.candidate.epoch),
        client_key: input.client_key.into(),
    };
    let fingerprint = RequestFingerprint(input.candidate.fingerprint(&input.authority));
    let lease = ExecutionLease(random);
    store.transaction(Box::pin(async move {
        match store.idempotency.begin(&key, fingerprint, lease).await.map_err(|_| Error::Unavailable)? {
            IdempotencyOutcome::Replay(response) => {
                let id = String::from_utf8(response.body).map_err(|_| Error::Unavailable)?;
                if response.status != 201 || !super::model::valid_hex(&id, 32) {
                    return Err(Error::Unavailable);
                }
                return Ok(id);
            }
            IdempotencyOutcome::FirstExecution => {}
            _ => return Err(Error::Conflict),
        }
        let mut connection = nasa::tx::pgsql::mandatory_conn_for(super::super::store::DATASOURCE)
            .await.map_err(|_| Error::Unavailable)?;
        // 配置发布权先于数据库集群锁，锁内先预留容量再运行 KDF；阻塞算法没有数据库提交权，取消不能让它脱离原事务提交。
        let admission = super::super::retention::Authority::lock(connection.as_mut(), &key.tenant).await?;
        if !admission.required {
            return Err(Error::Unavailable);
        }
        admission.admit(input.candidate.epoch)?;
        let store_id = super::capacity::owner(connection.as_mut(), store).await?;
        let material_bytes = input.candidate.material.0.len() as i32;
        let reservation = input.candidate.reservation() as i64;
        sqlx::query("SELECT naway_certificate_capacity($1,$2,$3,$4)")
            .bind(&key.tenant)
            .bind(input.scope)
            .bind(reservation)
            .bind(material_bytes)
            .execute(connection.as_mut()).await.map_err(super::database_error)?;
        let created: i64 = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(connection.as_mut()).await.map_err(super::database_error)?;
        let expires = created.checked_add(i64::from(input.candidate.ttl_seconds) * 1000).ok_or(Error::Unavailable)?;
        let key_id = input.keyring.write_key_id.clone();
        let secret = input.keyring.get(&key_id).ok_or(Error::Unavailable)?;
        let context = crypto::Context {
            cluster: key.tenant.clone(),
            store_id,
            epoch: input.candidate.epoch,
            id: id.clone(),
            key_id: key_id.clone(),
            creator: input.creator.into(),
            scope: input.scope.into(),
            intent: fingerprint.0,
            created,
            expires,
        };
        let material = input.candidate.material;
        let sealed = crypto::run(workers, input.publication, move || crypto::seal(material, &secret, &context)).await?;
        // 密文和低敏投影才进入 SQL；触发器复验当前代际与容量，KDF 等待不能延长已关闭受理窗口。
        sqlx::query("INSERT INTO naway_certificate_proposals(cluster_id,id,scope,creator,client_key,admission_epoch,authority,intent_digest,key_id,ciphertext,material_bytes,reserved_bytes,targets,summary,state,created_at_ms,expires_at_ms,updated_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'awaiting_approval',$15,$16,$15)")
            .bind(&key.tenant)
            .bind(&id)
            .bind(input.scope)
            .bind(input.creator)
            .bind(input.client_key)
            .bind(input.candidate.epoch)
            .bind(input.authority.as_slice())
            .bind(fingerprint.0.as_slice())
            .bind(key_id)
            .bind(sealed.ciphertext)
            .bind(material_bytes)
            .bind(reservation)
            .bind(input.candidate.target_bytes)
            .bind(sealed.summary)
            .bind(created)
            .bind(expires)
            .execute(connection.as_mut())
            .await
            .map_err(super::database_error)?;
        // NASA 幂等组件需要重新借用同一 ambient 连接，先归还借用而不结束事务。
        drop(connection);
        if !store.idempotency.complete(&key, fingerprint, lease, StoredResponse {
            status: 201,
            body: id.as_bytes().to_vec(),
            headers: Vec::new(),
        }).await.map_err(|_| Error::Unavailable)? {
            return Err(Error::Conflict);
        }
        Ok(id)
    })).await
}
