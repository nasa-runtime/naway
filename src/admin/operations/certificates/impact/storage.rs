//! 服务端完整观察与独立幂等收据同事务登记，旧材料批准不参与新影响状态迁移。

use super::{capacity, Error, Store};
use crate::admin::operations::certificates::preview::{Observation, Stamp};
use crate::control::material::impact::{Context, Node, Proof};
use nasa::idempotency::{
    ExecutionLease, IdempotencyKey, IdempotencyOutcome, IdempotencyStore, RequestFingerprint,
    StoredResponse,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) struct Request<'a> {
    pub scope: &'a str,
    pub creator: &'a str,
    pub key: &'a str,
    pub epoch: i64,
    pub proposal: &'a str,
}

pub(super) struct Candidate {
    pub stamp: Arc<Stamp>,
    pub proof: Proof,
    pub issued: u64,
    pub expires: u64,
    pub window: crate::admin::management::material::RequestWindow,
}

impl Candidate {
    /// 业务作用：只移动全部成功的原生节点证明进入持久候选，任一失败不能缩小原目标分母。
    ///
    /// 参数说明：
    /// - `observation`：服务端已复验原记录和完整原节点的实际结果。
    ///
    /// 返回：不含私钥或网络命令的完整影响；失败结果整批拒绝并释放材料持有者。
    pub(super) fn from_observation(observation: Observation) -> Result<Self, Error> {
        let mut nodes = Vec::with_capacity(observation.observed.len());
        for item in observation.observed {
            let completed = item.result.map_err(|_| Error::Conflict)?;
            nodes.push(Node {
                node_id: item.intent.node.clone(),
                target_indices: item.intent.indices.clone(),
                impact_sha256: crate::admin::operations::model::hex(&completed.proof.impact),
                conditions: completed.proof.conditions,
            });
        }
        let proof = Proof {
            schema: 1,
            targets: observation.source.targets,
            certificate: observation.source.certificate,
            nodes,
        };
        if !proof.valid(&observation.source.stamp.context.cluster) {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            stamp: observation.source.stamp,
            proof,
            issued: observation.issued,
            expires: observation.expires,
            window: observation.window,
        })
    }
}

/// 业务作用：昂贵预检前检查当前共享受理和独立预算，已满存储不能继续消耗材料解密与节点工作。
///
/// 参数说明：
/// - `store`：已注册影响 owner 的管理存储。
/// - `request`：原主体、范围及受理代，不接受客户端证明。
///
/// 返回：当前仍可能容纳记录时成功；最终实际字节仍由登记事务触发器裁决，不预占无限责任。
pub(super) async fn preflight(store: &Store, request: Request<'_>) -> Result<(), Error> {
    store
        .transaction(Box::pin(async {
            let mut connection =
                nasa::tx::pgsql::mandatory_conn_for(crate::admin::operations::store::DATASOURCE)
                    .await
                    .map_err(|_| Error::Unavailable)?;
            let authority = crate::admin::operations::retention::Authority::lock(
                connection.as_mut(),
                &store.plan.config.cluster_id,
            )
            .await?;
            if !authority.required {
                return Err(Error::Unavailable);
            }
            authority.admit(request.epoch)?;
            capacity::owner(connection.as_mut(), store).await?;
            sqlx::query("SELECT naway_material_impact_capacity($1,$2,$3)")
                .bind(&store.plan.config.cluster_id)
                .bind(request.scope)
                .bind(4098_i64)
                .execute(connection.as_mut())
                .await
                .map_err(super::super::database_error)?;
            Ok(())
        }))
        .await
}

/// 业务作用：在固定锁序中复验完整原标记并保存唯一影响及收据，提交未知不能重新生成批准对象。
///
/// 参数说明：
/// - `context`：持有配置发布权的原请求身份及当前共享影响存储。
/// - `request`：与最初确认相同的主体、提案和幂等身份。
/// - `candidate`：全部目标成功的原生影响及原记录标记。
/// - `impact_authority`：持有配置发布锁后复验的全部共享对象权威。
///
/// 返回：明确提交或同请求回放的影响身份；容量、原状态或期限改变不产生部分影响记录。
pub(super) async fn submit(
    context: &crate::admin::operations::certificates::preview::Context<'_>,
    request: Request<'_>,
    candidate: &Candidate,
    impact_authority: &[u8; 32],
) -> Result<String, Error> {
    let store = context.store;
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
    let id = crate::admin::operations::model::hex(&random);
    let key = IdempotencyKey {
        tenant: store.plan.config.cluster_id.clone(),
        subject: request.creator.into(),
        route_id: super::route(request.scope, request.epoch),
        client_key: request.key.into(),
    };
    let mut fingerprint = Sha256::new();
    fingerprint.update(b"naway-material-impact-request\0");
    for value in [
        &key.tenant,
        request.scope,
        request.creator,
        request.proposal,
    ] {
        fingerprint.update((value.len() as u64).to_be_bytes());
        fingerprint.update(value.as_bytes());
    }
    fingerprint.update(request.epoch.to_be_bytes());
    let fingerprint = RequestFingerprint(fingerprint.finalize().into());
    let lease = ExecutionLease(random);
    store.transaction(Box::pin(async {
        match store.idempotency.begin(&key, fingerprint, lease).await.map_err(|_| Error::Unavailable)? {
            IdempotencyOutcome::Replay(response) => {
                let id = String::from_utf8(response.body).map_err(|_| Error::Unavailable)?;
                if response.status != 201 || !super::super::model::valid_hex(&id, 32) {
                    return Err(Error::Unavailable);
                }
                return Ok(id);
            }
            IdempotencyOutcome::FirstExecution => {}
            _ => return Err(Error::Conflict),
        }
        let mut connection = nasa::tx::pgsql::mandatory_conn_for(crate::admin::operations::store::DATASOURCE).await.map_err(|_| Error::Unavailable)?;
        // 配置发布权由调用者持有，数据库依次取得集群、影响 owner 和原材料，不能在等待后沿用旧观察。
        let admission = crate::admin::operations::retention::Authority::lock(connection.as_mut(), &key.tenant).await?;
        admission.admit(request.epoch)?;
        let impact_store = capacity::owner(connection.as_mut(), store).await?;
        candidate.stamp.lock(connection.as_mut()).await?;
        let original = &candidate.stamp.context;
        if original.id != request.proposal || original.scope != request.scope || original.cluster != key.tenant {
            return Err(Error::Conflict);
        }
        let digest = candidate.proof.digest(&Context {
            cluster: &key.tenant,
            material_store: &original.store_id,
            impact_store: &impact_store,
            proposal: &original.id,
            scope: &original.scope,
            material_creator: &original.creator,
            material_epoch: original.epoch,
            material_intent: &original.intent,
            authority: &candidate.stamp.authority,
            impact_authority,
            issued: candidate.issued,
            observed_until: candidate.expires,
        }).ok_or(Error::Unavailable)?;
        // 只在真实持久边界编码一次；容量写入器在增长前拒绝超量，SQL预算按实际字节和固定元数据计算。
        let encoded = super::encoding::bytes(&candidate.proof, crate::config::operations::certificates::impact::MAX_PROOF_BYTES)?;
        let reserved = encoded.len() as i64 + crate::config::operations::certificates::impact::RECORD_OVERHEAD as i64;
        let issued = i64::try_from(candidate.issued).map_err(|_| Error::Conflict)?;
        let expires = i64::try_from(candidate.expires).map_err(|_| Error::Conflict)?;
        // 沿用最初签发时的单调窗口，编码和数据库排队不能靠重新采样墙钟延长登记资格。
        candidate.window.check().map_err(|_| Error::Conflict)?;
        // 发布锁只冻结配置，不延长原凭据；锁等待和编码后重新认证，避免自然到期的身份仍可登记。
        if super::api::authorize_candidate(context, candidate)? != *impact_authority {
            return Err(Error::Denied);
        }
        sqlx::query("WITH now AS (SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS ms) INSERT INTO naway_material_impact_proposals(cluster_id,id,proposal_id,scope,creator,material_creator,client_key,admission_epoch,material_admission_epoch,material_store_id,authority,impact_authority,material_intent,impact_digest,proof,reserved_bytes,issued_at_ms,observed_until_ms,state,created_at_ms,expires_at_ms,updated_at_ms) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'awaiting_approval',ms,$19,ms FROM now")
            .bind(&key.tenant).bind(&id).bind(request.proposal).bind(request.scope).bind(request.creator).bind(&original.creator)
            .bind(request.key).bind(request.epoch).bind(original.epoch).bind(&original.store_id).bind(candidate.stamp.authority.as_slice())
            .bind(impact_authority.as_slice()).bind(original.intent.as_slice()).bind(digest.as_slice()).bind(encoded)
            .bind(reserved).bind(issued).bind(expires).bind(original.expires)
            .execute(connection.as_mut()).await.map_err(|error| {
                // 约束同时保护父材料和短期观察，不能把这些失效误报为已经明确检查过的受理代过期。
                match super::super::database_error(error) {
                    Error::Expired => Error::Conflict,
                    other => other,
                }
            })?;
        // 先释放连接借用，再让 NASA 在同一个 ambient 事务保存完成收据，二者不能分别提交。
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
