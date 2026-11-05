//! 影响批准公开投影与隐藏权威分开，材料内容和秘密摘要不进入 HTTP 输出。

use super::Error;
use crate::control::material::impact::{Context, Proof};
use serde::Serialize;
use sqlx::{postgres::PgRow, Row};

#[derive(Serialize)]
pub(super) struct Record {
    pub id: String,
    pub proposal_id: String,
    pub cluster_id: String,
    pub scope: String,
    pub admission_epoch: String,
    pub material_admission_epoch: String,
    pub creator: String,
    pub material_creator: String,
    pub reviewer: Option<String>,
    pub status: String,
    pub material_status: String,
    pub parent_active: bool,
    pub execution_supported: bool,
    pub validation: &'static str,
    pub impact_sha256: String,
    pub proof: Proof,
    pub issued_at_ms: u64,
    pub observed_until_ms: u64,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(skip_serializing)]
    pub material_store: String,
    #[serde(skip_serializing)]
    pub impact_store: String,
    #[serde(skip_serializing)]
    pub authority: [u8; 32],
    #[serde(skip_serializing)]
    pub impact_authority: [u8; 32],
    #[serde(skip_serializing)]
    pub material_intent: [u8; 32],
}

/// 业务作用：从完整父子同一快照构造只读投影，不能把终止父材料下的批准显示为可继续审阅。
///
/// 参数说明：
/// - `row`：固定查询取得的有限公开证明及原材料元数据，不含密文。
///
/// 返回：完整分母、摘要、原材料和身份一致的记录；异常持久内容不交付半份事实。
pub(super) fn parse(row: PgRow) -> Result<Record, Error> {
    let read = || -> Result<Record, sqlx::Error> {
        let failure = || sqlx::Error::Protocol("material impact evidence differs".into());
        let fixed = |name| -> Result<[u8; 32], sqlx::Error> {
            row.try_get::<Vec<u8>, _>(name)?
                .try_into()
                .map_err(|_| failure())
        };
        let bytes: Vec<u8> = row.try_get("proof")?;
        if bytes.len() > crate::config::operations::certificates::impact::MAX_PROOF_BYTES {
            return Err(failure());
        }
        let proof: Proof = serde_json::from_slice(&bytes).map_err(|_| failure())?;
        let targets: Vec<crate::control::material::Target> =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("original_targets")?)
                .map_err(|_| failure())?;
        let certificate: crate::control::material::Summary =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("original_summary")?)
                .map_err(|_| failure())?;
        let epoch: i64 = row.try_get("material_admission_epoch")?;
        let mut record = Record {
            id: row.try_get("id")?,
            proposal_id: row.try_get("proposal_id")?,
            cluster_id: row.try_get("cluster_id")?,
            scope: row.try_get("scope")?,
            admission_epoch: row.try_get::<i64, _>("admission_epoch")?.to_string(),
            material_admission_epoch: epoch.to_string(),
            creator: row.try_get("creator")?,
            material_creator: row.try_get("material_creator")?,
            reviewer: row.try_get("reviewer")?,
            status: row.try_get("state")?,
            material_status: row.try_get("material_state")?,
            parent_active: false,
            execution_supported: false,
            validation: "original_target_tls_policy",
            impact_sha256: super::super::super::model::hex(&fixed("impact_digest")?),
            proof,
            issued_at_ms: row
                .try_get::<i64, _>("issued_at_ms")?
                .try_into()
                .map_err(|_| failure())?,
            observed_until_ms: row
                .try_get::<i64, _>("observed_until_ms")?
                .try_into()
                .map_err(|_| failure())?,
            created_at_ms: row.try_get("created_at_ms")?,
            expires_at_ms: row.try_get("expires_at_ms")?,
            updated_at_ms: row.try_get("updated_at_ms")?,
            material_store: row.try_get("material_store_id")?,
            impact_store: row.try_get("impact_store_id")?,
            authority: fixed("authority")?,
            impact_authority: fixed("impact_authority")?,
            material_intent: fixed("material_intent")?,
        };
        // 父记录的原身份与公开材料必须和证明一起成立，单独伪造一份来源 JSON 不构成有效批准。
        if record.proof.targets.as_ref() != targets
            || record.proof.certificate != certificate
            || record.material_creator != row.try_get::<String, _>("original_creator")?
            || record.scope != row.try_get::<String, _>("original_scope")?
            || record.material_store != row.try_get::<String, _>("original_store")?
            || epoch != row.try_get::<i64, _>("original_epoch")?
            || record.authority != fixed("original_authority")?
            || record.material_intent != fixed("original_intent")?
            || record.expires_at_ms != row.try_get::<i64, _>("original_expires")?
        {
            return Err(failure());
        }
        let digest = record
            .proof
            .digest(&Context {
                cluster: &record.cluster_id,
                material_store: &record.material_store,
                impact_store: &record.impact_store,
                proposal: &record.proposal_id,
                scope: &record.scope,
                material_creator: &record.material_creator,
                material_epoch: epoch,
                material_intent: &record.material_intent,
                authority: &record.authority,
                impact_authority: &record.impact_authority,
                issued: record.issued_at_ms,
                observed_until: record.observed_until_ms,
            })
            .ok_or_else(failure)?;
        if super::super::super::model::hex(&digest) != record.impact_sha256 {
            return Err(failure());
        }
        let now: i64 = row.try_get("now_ms")?;
        if now >= record.expires_at_ms {
            if matches!(record.status.as_str(), "awaiting_approval" | "approved") {
                record.status = "expired".into();
            }
            if matches!(
                record.material_status.as_str(),
                "awaiting_approval" | "approved"
            ) {
                record.material_status = "expired".into();
            }
        }
        record.parent_active = matches!(
            record.material_status.as_str(),
            "awaiting_approval" | "approved"
        ) && !row.try_get::<bool, _>("execution_started")?
            && !row.try_get::<bool, _>("material_execution_started")?;
        Ok(record)
    };
    read().map_err(|_| Error::Unavailable)
}
