//! 原材料预检只读取同一持久记录，开始与交付前精确核对状态和认证上下文。

use super::{Context, current};
use crate::admin::{
    management::material_preview::Content,
    operations::{
        certificates::{Error, authorization, crypto, model::Target},
        connection::Reading,
    },
};
use crate::control::ownership::config::Action;
use sha2::{Digest, Sha256};
use sqlx::{Row, postgres::PgRow};
use std::{sync::Arc, time::Duration};
use tokio::sync::OwnedSemaphorePermit;

pub(in crate::admin::operations::certificates) struct Source {
    pub targets: Arc<[Target]>,
    pub content: Arc<Content>,
    pub certificate: crate::control::material::Summary,
    pub remaining_ms: u64,
    pub stamp: Arc<Stamp>,
}

#[derive(PartialEq, Eq)]
pub(in crate::admin::operations::certificates) struct Stamp {
    pub context: crypto::Context,
    pub authority: [u8; 32],
    targets: Vec<u8>,
    summary: Vec<u8>,
    ciphertext_sha256: [u8; 32],
    ciphertext_bytes: i32,
    material_bytes: i32,
    state: String,
    reviewer: Option<String>,
    updated: i64,
}

impl Stamp {
    /// 业务作用：最终登记在父材料行锁内精确复验最初观察标记，取消、审阅或密文变化优先于早到证明。
    ///
    /// 参数说明：
    /// - `connection`：已依次锁定集群和影响 owner 的同源事务。
    ///
    /// 返回：原完整记录仍有效才持锁成功；任何字段变化、过期或存储换代都拒绝本次登记。
    pub(in crate::admin::operations::certificates) async fn lock(
        &self,
        connection: &mut sqlx::PgConnection,
    ) -> Result<(), Error> {
        let row: Option<String> = sqlx::query_scalar("SELECT p.id FROM naway_certificate_proposals p JOIN naway_certificate_owners o ON o.cluster_id=p.cluster_id WHERE p.cluster_id=$1 AND p.scope=$2 AND p.id=$3 AND o.store_id=$4 AND p.admission_epoch=$5 AND p.creator=$6 AND p.intent_digest=$7 AND p.authority=$8 AND p.key_id=$9 AND p.targets=$10 AND p.summary=$11 AND p.material_bytes=$12 AND octet_length(p.ciphertext)=$13 AND pg_catalog.sha256(pg_catalog.convert_to(p.ciphertext,'UTF8'))=$14 AND p.state=$15 AND p.reviewer IS NOT DISTINCT FROM $16 AND p.created_at_ms=$17 AND p.expires_at_ms=$18 AND p.updated_at_ms=$19 AND NOT p.execution_started AND p.expires_at_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint FOR UPDATE OF p")
            .bind(&self.context.cluster).bind(&self.context.scope).bind(&self.context.id)
            .bind(&self.context.store_id).bind(self.context.epoch).bind(&self.context.creator)
            .bind(self.context.intent.as_slice()).bind(self.authority.as_slice()).bind(&self.context.key_id)
            .bind(&self.targets).bind(&self.summary).bind(self.material_bytes).bind(self.ciphertext_bytes)
            .bind(self.ciphertext_sha256.as_slice()).bind(&self.state).bind(&self.reviewer)
            .bind(self.context.created).bind(self.context.expires).bind(self.updated)
            .fetch_optional(connection).await.map_err(|_| Error::Unavailable)?;
        if row.is_none() {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

/// 业务作用：只装载原提案的有限元数据和密文摘要，尚未授权原目标时不把密文送入解密任务。
///
/// 参数说明：
/// - `context`：当前真实请求者、精确范围及共享存储 owner。
/// - `id`：唯一原提案身份，不接受替代目标或候选。
///
/// 返回：同一 SQL 快照的比较标记和数据库剩余期限；不存在、终止、过期或异常记录拒绝。
async fn metadata(context: &Context<'_>, id: &str) -> Result<(Stamp, u64), Error> {
    let query = async {
        let mut connection = Reading::acquire(&context.store.pool).await?;
        let row = sqlx::query("SELECT p.admission_epoch,p.creator,p.authority,p.intent_digest,p.key_id,p.targets,p.summary,p.material_bytes,p.state,p.reviewer,p.created_at_ms,p.expires_at_ms,p.updated_at_ms,o.store_id,octet_length(p.ciphertext) AS ciphertext_bytes,pg_catalog.sha256(pg_catalog.convert_to(p.ciphertext,'UTF8')) AS ciphertext_sha256,floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_certificate_proposals p JOIN naway_certificate_owners o ON o.cluster_id=p.cluster_id WHERE p.cluster_id=$1 AND p.scope=$2 AND p.id=$3")
            .bind(&context.store.plan.config.cluster_id)
            .bind(&context.scope.key)
            .bind(id)
            .fetch_optional(connection.as_mut())
            .await?;
        connection.release().await;
        Ok(row)
    };
    let row = context
        .store
        .read_query(query)
        .await?
        .ok_or(Error::Missing)?;
    parse(context, id, row)
}

/// 业务作用：在反序列化原目标之前确认固定预算和原时间窗口，持久数据异常不能扩大秘密工作容量。
///
/// 参数说明：
/// - `context`：绑定当前共享预算及发行集群的请求。
/// - `id`：原记录身份。
/// - `row`：同一快照取得的元数据、存储身份和数据库时间。
///
/// 返回：规范原记录和剩余毫秒数；缺受理代、错误长度或不可预检状态均明确拒绝。
fn parse(context: &Context<'_>, id: &str, row: PgRow) -> Result<(Stamp, u64), Error> {
    let read = || -> Result<_, sqlx::Error> {
        let fixed = |name| -> Result<[u8; 32], sqlx::Error> {
            row.try_get::<Vec<u8>, _>(name)?
                .try_into()
                .map_err(|_| sqlx::Error::Protocol("material digest length differs".into()))
        };
        Ok((
            Stamp {
                context: crypto::Context {
                    cluster: context.store.plan.config.cluster_id.clone(),
                    store_id: row.try_get("store_id")?,
                    epoch: row.try_get("admission_epoch")?,
                    id: id.into(),
                    key_id: row.try_get("key_id")?,
                    creator: row.try_get("creator")?,
                    scope: context.scope.key.clone(),
                    intent: fixed("intent_digest")?,
                    created: row.try_get("created_at_ms")?,
                    expires: row.try_get("expires_at_ms")?,
                },
                authority: fixed("authority")?,
                targets: row.try_get("targets")?,
                summary: row.try_get("summary")?,
                ciphertext_sha256: fixed("ciphertext_sha256")?,
                ciphertext_bytes: row.try_get("ciphertext_bytes")?,
                material_bytes: row.try_get("material_bytes")?,
                state: row.try_get("state")?,
                reviewer: row.try_get("reviewer")?,
                updated: row.try_get("updated_at_ms")?,
            },
            row.try_get::<i64, _>("now_ms")?,
        ))
    };
    let (stamp, now) = read().map_err(|_| Error::Unavailable)?;
    // 原受理窗口轮换不撤销已保存提案，但原记录自己的期限和审阅状态必须仍允许观察。
    if stamp.context.epoch <= 0 || !matches!(stamp.state.as_str(), "awaiting_approval" | "approved")
    {
        return Err(Error::Conflict);
    }
    let remaining = stamp
        .context
        .expires
        .checked_sub(now)
        .filter(|left| *left > 1000)
        .ok_or(Error::Conflict)? as u64;
    let limit = context.store.plan.config.certificates.max_material_bytes as usize + 16;
    if !(17..=limit).contains(&(stamp.material_bytes as usize))
        || !(1..=2 * limit + 256).contains(&(stamp.ciphertext_bytes as usize))
        || stamp.targets.is_empty()
        || stamp.targets.len() > 65536
        || stamp.summary.is_empty()
        || stamp.summary.len() > 1024
        || !super::super::model::valid_hex(&stamp.context.store_id, 64)
        || !crate::config::operations::token(&stamp.context.creator, 128)
        || !crate::config::operations::token(&stamp.context.key_id, 128)
    {
        return Err(Error::Unavailable);
    }
    Ok((stamp, remaining))
}

/// 业务作用：复验当前请求者、原创建者和全部原目标的写入资格，不能用读取权触发材料下载或 TLS 构建。
///
/// 参数说明：
/// - `context`：本次实际认证和完整配置快照。
/// - `stamp`：从原记录取得的创建者与冻结权威。
/// - `targets`：原记录的完整规范目标集合。
///
/// 返回：当前权限和原全部目标权威完全一致才成功；失权或归属变化立即拒绝。
fn authorize(context: &Context<'_>, stamp: &Stamp, targets: &[Target]) -> Result<(), Error> {
    current(context)?;
    authorization::check(
        context.scope,
        context.snapshot,
        context.principal,
        Action::Write,
    )?;
    authorization::check(
        context.scope,
        context.snapshot,
        &stamp.context.creator,
        Action::Write,
    )?;
    authorization::targets(context.scope, context.snapshot, targets)?;
    // 全部原目标的授权冻结在持久意图内，不能用当前可见的局部批次替换它。
    if authorization::authority(context.scope, context.snapshot, targets)? != stamp.authority {
        return Err(Error::Denied);
    }
    Ok(())
}

impl Source {
    /// 业务作用：认证解密原提案一次并共享唯一明文帧，调用者不能替换持久候选或绕过原创建者权限。
    ///
    /// 参数说明：
    /// - `context`：当前真实权限与发行存储。
    /// - `id`：本次唯一原提案身份。
    /// - `permit`：在读取元数据之前取得的整请求名额，随最后一个材料持有者释放。
    ///
    /// 返回：完整原目标及认证后的共享材料；任何等待中撤权、记录变化或密文失败都不交付候选。
    pub(super) async fn load(
        context: &Context<'_>,
        id: &str,
        permit: OwnedSemaphorePermit,
    ) -> Result<Self, Error> {
        let (stamp, remaining_ms) = metadata(context, id).await?;
        let targets: Vec<Target> =
            serde_json::from_slice(&stamp.targets).map_err(|_| Error::Unavailable)?;
        if !Target::valid_set(&targets, &context.store.plan.config.cluster_id) {
            return Err(Error::Unavailable);
        }
        authorize(context, &stamp, &targets)?;
        let query = async {
            let mut connection = Reading::acquire(&context.store.pool).await?;
            let ciphertext: Option<String> = sqlx::query_scalar("SELECT ciphertext FROM naway_certificate_proposals WHERE cluster_id=$1 AND scope=$2 AND id=$3 AND admission_epoch=$4 AND state=$5 AND updated_at_ms=$6 AND pg_catalog.sha256(pg_catalog.convert_to(ciphertext,'UTF8'))=$7 AND intent_digest=$8 AND authority=$9 AND targets=$10 AND summary=$11 AND key_id=$12 AND expires_at_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
                .bind(&stamp.context.cluster)
                .bind(&stamp.context.scope)
                .bind(id)
                .bind(stamp.context.epoch)
                .bind(&stamp.state)
                .bind(stamp.updated)
                .bind(stamp.ciphertext_sha256.as_slice())
                .bind(stamp.context.intent.as_slice())
                .bind(stamp.authority.as_slice())
                .bind(&stamp.targets)
                .bind(&stamp.summary)
                .bind(&stamp.context.key_id)
                .fetch_optional(connection.as_mut()).await?;
            connection.release().await;
            Ok(ciphertext)
        };
        let ciphertext = context
            .store
            .read_query(query)
            .await?
            .ok_or(Error::Conflict)?;
        if ciphertext.len() != stamp.ciphertext_bytes as usize
            || Sha256::digest(ciphertext.as_bytes()).as_slice() != stamp.ciphertext_sha256
        {
            return Err(Error::Unavailable);
        }
        let publication = Arc::new(
            tokio::time::timeout(
                Duration::from_secs(2),
                context.state.apply_coordinator.lock_owned(),
            )
            .await
            .map_err(|_| Error::Capacity)?,
        );
        // 密文读取和发布锁排队都可能跨越撤权；先重新授权，再把实际名额交给不可提前取消的 KDF。
        authorize(context, &stamp, &targets)?;
        let keyring = context
            .snapshot
            .admin_operations
            .as_ref()
            .and_then(|plan| plan.certificate_keys.as_ref())
            .ok_or(Error::Unavailable)?;
        let secret = keyring
            .get(&stamp.context.key_id)
            .ok_or(Error::Unavailable)?;
        let stamp = Arc::new(stamp);
        let original = stamp.clone();
        let (content, certificate) = crypto::run(
            context
                .store
                .certificate_workers
                .as_ref()
                .ok_or(Error::Unavailable)?,
            publication.clone(),
            move || {
                let opened = crypto::open(
                    &ciphertext,
                    &secret,
                    &original.context,
                    &original.targets,
                    &original.authority,
                    &original.summary,
                )?;
                if opened.material.0.len() != original.material_bytes as usize {
                    return Err(Error::Unavailable);
                }
                Ok((
                    Arc::new(Content::admitted(opened.material, permit)),
                    opened.summary,
                ))
            },
        )
        .await?;
        authorize(context, &stamp, &targets)?;
        // 本机目标还要取得同一配置发布锁；只保留材料和名额，不持锁等待自身预检。
        drop(publication);
        let source = Self {
            certificate,
            targets: targets.into(),
            content,
            remaining_ms,
            stamp,
        };
        source.recheck(context, id).await?;
        Ok(source)
    }

    /// 业务作用：交付前重新比较完整原记录，审阅、取消、密文变化或存储换代均撤下已完成结果。
    ///
    /// 参数说明：
    /// - `context`：本次仍冻结的当前权限与存储 owner。
    /// - `id`：最初认证的原提案身份。
    ///
    /// 返回：完整标记及当前权限一致时成功；不重新装载密文或解密材料。
    pub(super) async fn recheck(&self, context: &Context<'_>, id: &str) -> Result<(), Error> {
        let (stamp, _) = metadata(context, id).await?;
        // 审阅、取消或密文变化优先于早到节点结果，不能用已有成功掩盖原记录已经改变。
        if self.stamp.as_ref() != &stamp {
            return Err(Error::Conflict);
        }
        authorize(context, &stamp, &self.targets)
    }
}
