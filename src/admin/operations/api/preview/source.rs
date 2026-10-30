//! 预览从共享原提案读取一次正文，开始和交付前分别复验持久状态。

use super::{super::execution::Context, Error};
use crate::admin::operations::{connection::Reading, model::Target};
use crate::control::ownership::config::Action;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, Row};

pub(super) struct Source {
    pub epoch: u64,
    pub creator: String,
    pub authority: [u8; 32],
    pub digest: [u8; 32],
    pub targets: Vec<Target>,
    pub body: Bytes,
    pub remaining_ms: u64,
    stamp: Stamp,
}

#[derive(PartialEq, Eq)]
struct Stamp {
    epoch: i64,
    creator: String,
    authority: Vec<u8>,
    digest: Vec<u8>,
    targets: Vec<u8>,
    candidate_bytes: i32,
    state: String,
    updated: i64,
    expires: i64,
}

/// 业务作用：读取原提案低敏状态并以数据库时钟证明它仍可用于预览，尚不装载候选正文。
///
/// 参数说明：
/// - `context`：精确范围及实际持久 owner。
/// - `id`：原提案身份。
///
/// 返回：合法原记录和剩余期限；终止、执行中、过期或异常记录均不提供构建输入。
async fn metadata(context: &Context<'_>, id: &str) -> Result<(Stamp, u64), Error> {
    let query = async {
        let mut connection = Reading::acquire(&context.store.pool).await?;
        let row = sqlx::query("SELECT admission_epoch,creator,authority,candidate_digest,targets,octet_length(candidate) AS candidate_bytes,state,execution_started,updated_at_ms,expires_at_ms,floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_operation_proposals WHERE cluster_id=$1 AND scope=$2 AND domain=$3 AND id=$4")
            .bind(&context.store.plan.config.cluster_id).bind(&context.query.scope.key)
            .bind(context.query.domain.identity().0).bind(id)
            .fetch_optional(connection.as_mut()).await?;
        connection.release().await;
        Ok(row)
    };
    let row = context
        .store
        .read_query(query)
        .await?
        .ok_or(Error::Missing)?;
    parse(row)
}

/// 业务作用：在解析持久原目标之前施加状态、字节和时间边界，异常记录不扩大内存或构建权限。
///
/// 参数说明：
/// - `row`：同一 SQL 快照取得的原提案与数据库时间。
///
/// 返回：可预览的不可变比较标记和数据库剩余毫秒数；无代际旧记录拒绝预览。
fn parse(row: PgRow) -> Result<(Stamp, u64), Error> {
    let read = || -> Result<_, sqlx::Error> {
        Ok((
            Stamp {
                epoch: row.try_get("admission_epoch")?,
                creator: row.try_get("creator")?,
                authority: row.try_get("authority")?,
                digest: row.try_get("candidate_digest")?,
                targets: row.try_get("targets")?,
                candidate_bytes: row.try_get("candidate_bytes")?,
                state: row.try_get("state")?,
                updated: row.try_get("updated_at_ms")?,
                expires: row.try_get("expires_at_ms")?,
            },
            row.try_get::<bool, _>("execution_started")?,
            row.try_get::<i64, _>("now_ms")?,
        ))
    };
    let (stamp, started, now) = read().map_err(|_| Error::Unavailable)?;
    // 受理代际限制原请求的新建；窗口轮换不撤销已经保存且仍在自身期限内的原提案。
    if stamp.epoch <= 0
        || started
        || !matches!(stamp.state.as_str(), "awaiting_approval" | "approved")
    {
        return Err(Error::Conflict);
    }
    let remaining = stamp
        .expires
        .checked_sub(now)
        .filter(|left| *left > 1000)
        .ok_or(Error::Expired)? as u64;
    if stamp.authority.len() != 32
        || stamp.digest.len() != 32
        || !(1..=1024 * 1024).contains(&stamp.candidate_bytes)
        || stamp.targets.len() > 65536
        || !crate::config::operations::token(&stamp.creator, 128)
    {
        return Err(Error::Unavailable);
    }
    Ok((stamp, remaining))
}

/// 业务作用：在任何候选正文装载前复验请求者构建资格、原创建者写资格及冻结范围权威。
///
/// 参数说明：
/// - `context`：本次实际认证主体和完整快照。
/// - `stamp`：原提案冻结的创建者及授权摘要。
///
/// 返回：全部当前资格一致才允许读取；凭据或归属变化不借旧提案继续构建。
fn authorize(context: &Context<'_>, stamp: &Stamp) -> Result<(), Error> {
    super::current(context.state, context.store, context.snapshot)?;
    if !super::allows(context.snapshot, context.query, context.principal)
        || context.query.scope.authority(context.snapshot)?.as_slice() != stamp.authority
    {
        return Err(Error::Denied);
    }
    context.query.scope.check(
        context.snapshot,
        &stamp.creator,
        context.query.domain,
        Action::Write,
    )
}

impl Source {
    /// 业务作用：取得一份共享候选及完整原目标，先授权再读取原文，不接受客户端替换输入。
    ///
    /// 参数说明：
    /// - `context`：已持有整请求预览名额的当前请求。
    /// - `id`：唯一原提案身份。
    ///
    /// 返回：摘要一致的共享 Bytes 和全部原目标；读取期间提案变化则拒绝整次预览。
    pub(super) async fn load(context: &Context<'_>, id: &str) -> Result<Self, Error> {
        let (stamp, remaining_ms) = metadata(context, id).await?;
        authorize(context, &stamp)?;
        let targets: Vec<Target> =
            serde_json::from_slice(&stamp.targets).map_err(|_| Error::Unavailable)?;
        if targets.is_empty() || targets.len() > crate::config::operations::MAX_TARGETS {
            return Err(Error::Unavailable);
        }
        for (index, target) in targets.iter().enumerate() {
            if !crate::config::operations::token(&target.node_id, 128)
                || !crate::config::operations::token(&target.boot_id, 128)
                || target.base_version == 0
                || target.base_fingerprint.len() != 16
                || !target
                    .base_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                || index > 0 && targets[index - 1].node_id >= target.node_id
                || target
                    .node_baseline
                    .as_ref()
                    .is_some_and(|baseline| !baseline.valid())
            {
                return Err(Error::Unavailable);
            }
        }
        let query = async {
            let mut connection = Reading::acquire(&context.store.pool).await?;
            let bytes: Option<Vec<u8>> = sqlx::query_scalar("SELECT candidate FROM naway_operation_proposals WHERE cluster_id=$1 AND scope=$2 AND domain=$3 AND id=$4 AND admission_epoch=$5 AND state=$6 AND updated_at_ms=$7 AND candidate_digest=$8 AND authority=$9 AND targets=$10 AND NOT execution_started AND expires_at_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
                .bind(&context.store.plan.config.cluster_id).bind(&context.query.scope.key)
                .bind(context.query.domain.identity().0).bind(id).bind(stamp.epoch).bind(&stamp.state)
                .bind(stamp.updated).bind(&stamp.digest).bind(&stamp.authority).bind(&stamp.targets)
                .fetch_optional(connection.as_mut()).await?;
            connection.release().await;
            Ok(bytes)
        };
        let bytes = context
            .store
            .read_query(query)
            .await?
            .ok_or(Error::Conflict)?;
        authorize(context, &stamp)?;
        if bytes.len() != stamp.candidate_bytes as usize
            || Sha256::digest(&bytes).as_slice() != stamp.digest
        {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            epoch: stamp.epoch as u64,
            creator: stamp.creator.clone(),
            authority: stamp
                .authority
                .as_slice()
                .try_into()
                .map_err(|_| Error::Unavailable)?,
            digest: stamp
                .digest
                .as_slice()
                .try_into()
                .map_err(|_| Error::Unavailable)?,
            targets,
            body: bytes.into(),
            remaining_ms,
            stamp,
        })
    }

    /// 业务作用：交付差异前再次读取原持久事实，撤销或过期的源提案不能产生迟到审阅结果。
    ///
    /// 参数说明：
    /// - `context`：本次仍冻结的权限及共享存储。
    /// - `id`：最初使用的原提案身份。
    ///
    /// 返回：原内容、全部目标、审批状态及当前权限仍一致时成功；不重新装载候选正文。
    pub(super) async fn recheck(&self, context: &Context<'_>, id: &str) -> Result<(), Error> {
        let (stamp, _) = metadata(context, id).await?;
        if self.stamp != stamp {
            return Err(Error::Conflict);
        }
        authorize(context, &stamp)
    }
}
