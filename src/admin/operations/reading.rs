//! 候选原文的精确授权读取；低敏目录与可能含秘密的原文使用不同读取资格。

use super::{
    authorization::Scope,
    model::{hex, Domain, Error, Record},
    Store,
};
use crate::{config::GatewaySnapshot, full_body, BoxBody};
use bytes::Bytes;
use http::{Response, StatusCode};
use sha2::{Digest, Sha256};
use sqlx::Row;

/// 业务作用：按原请求身份恢复未知提交的低敏记录，不要求客户端重新发送候选原文。
///
/// 参数说明：
/// - `store`：当前集群的共享数据库权威。
/// - `scope`：已授权的精确读取范围。
/// - `domain`：原请求所属领域。
/// - `principal`：当前已认证且只能查自己请求的主体。
/// - `request`：携带原幂等键和代际的请求头，身份不得来自其它主体声明。
///
/// 返回：单次查询取得的原低敏记录；缺失仅表示本次未找到，不证明其它事务已经回滚。
pub(super) async fn resolve(
    store: &Store,
    scope: &Scope,
    domain: Domain,
    principal: &str,
    request: &http::request::Parts,
) -> Result<Record, Error> {
    let key = unique_header(request, "idempotency-key")?;
    if !crate::config::operations::token(key, 128) {
        return Err(Error::Invalid);
    }
    let epoch = unique_header(request, "naway-admission-epoch")?;
    if epoch.is_empty() || epoch.len() > 19 || !epoch.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Invalid);
    }
    let epoch: i64 = epoch.parse().map_err(|_| Error::Invalid)?;
    let query = async {
        let mut connection = super::connection::Reading::acquire(&store.pool).await?;
        let row = sqlx::query(concat!(
            "SELECT admission_epoch, id, scope, domain, creator, reviewer, state, execution_started, candidate_digest, octet_length(candidate) AS candidate_bytes, targets, created_at_ms, expires_at_ms, updated_at_ms, ",
            "floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_operation_proposals WHERE cluster_id = $1 AND scope = $2 AND domain = $3 AND creator = $4 AND admission_epoch = $5 AND client_key = $6"
        ))
        .bind(&store.plan.config.cluster_id).bind(&scope.key).bind(domain.identity().0).bind(principal).bind(epoch).bind(key)
            .fetch_optional(connection.as_mut()).await?;
        connection.release().await;
        Ok(row)
    };
    let row = store.read_query(query).await?.ok_or(Error::Missing)?;
    super::store::record(row)
}

/// 业务作用：拒绝请求恢复身份中的重复头与非文本值，避免代理合并产生另一请求身份。
///
/// 参数说明：
/// - `request`：当前请求的元数据。
/// - `name`：代码指定的唯一身份头。
///
/// 返回：唯一合法文本借用；缺失或重复时不查询持久记录。
fn unique_header<'a>(request: &'a http::request::Parts, name: &str) -> Result<&'a str, Error> {
    let mut values = request.headers.get_all(name).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Invalid)?;
    if values.next().is_some() {
        return Err(Error::Invalid);
    }
    Ok(value)
}

/// 业务作用：只向仍有资格的创建者或审阅者交付原始候选，不重编码或解析秘密来源。
///
/// 参数说明：
/// - `store`：当前集群共享的持久权威。
/// - `scope`：已经通过读取授权的精确平台或工作区域。
/// - `domain`：当前选定且必须匹配持久记录的领域。
/// - `id`：经过固定格式校验的提案身份。
/// - `principal`：当前已认证主体。
/// - `snapshot`：用于核对写入和审阅资格的当前权限快照。
///
/// 返回：借用数据库返回分配的有限原文响应；越权、内容异常或记录缺失时不交付正文。
pub(super) async fn candidate(
    store: &Store,
    scope: &Scope,
    domain: Domain,
    id: &str,
    principal: &str,
    snapshot: &GatewaySnapshot,
) -> Result<Response<BoxBody>, Error> {
    let access = scope.access(snapshot, principal, domain);
    // 元数据读权限不能扩大为原文读取；普通观察者不会触发数据库候选装载。
    if !access.read || !access.write && !access.review {
        return Err(Error::Denied);
    }
    let query = async {
        let mut connection = super::connection::Reading::acquire(&store.pool).await?;
        let row = sqlx::query("SELECT CASE WHEN (creator = $5 AND $6) OR $7 THEN candidate ELSE NULL END AS candidate, candidate_digest FROM naway_operation_proposals WHERE cluster_id = $1 AND scope = $2 AND domain = $3 AND id = $4")
        .bind(&store.plan.config.cluster_id).bind(&scope.key).bind(domain.identity().0).bind(id)
        .bind(principal).bind(access.write).bind(access.review)
            .fetch_optional(connection.as_mut()).await?;
        connection.release().await;
        Ok(row)
    };
    let row = store.read_query(query).await?.ok_or(Error::Missing)?;
    // 创建者身份与正文由同一行裁决；其它操作员不能通过自己的写权限读取别人的候选。
    let bytes: Option<Vec<u8>> = row.try_get("candidate").map_err(|_| Error::Unavailable)?;
    let bytes = bytes.ok_or(Error::Denied)?;
    let digest: Vec<u8> = row
        .try_get("candidate_digest")
        .map_err(|_| Error::Unavailable)?;
    if bytes.is_empty()
        || bytes.len() > store.plan.config.max_candidate_bytes as usize
        || Sha256::digest(&bytes).as_slice() != digest
    {
        return Err(Error::Unavailable);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(
            http::header::CONTENT_TYPE,
            "application/yaml; charset=utf-8",
        )
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header(http::header::ETAG, format!("\"sha256-{}\"", hex(&digest)))
        .body(full_body(Bytes::from(bytes)))
        .map_err(|_| Error::Unavailable)
}
