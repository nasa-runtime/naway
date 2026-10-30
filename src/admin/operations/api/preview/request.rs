//! 全原目标有界聚合；结果只供本次审阅，不登记执行或改变原提案。

use super::{super::execution::Context, source::Source, Error};
use crate::admin::{
    self,
    diff::model::Summary,
    management::preview::{self, command::Intent, Reason},
    operations::model::{hex, Target},
    AdminState, BoxBody,
};
use futures::{stream::FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    Succeeded {
        diff: Box<Summary>,
    },
    Failed {
        reason: Reason,
    },
}

#[derive(Serialize)]
struct Row<'a> {
    target: &'a Target,
    #[serde(skip)]
    session: Option<[u8; 32]>,
    #[serde(flatten)]
    outcome: Outcome,
}

#[derive(Serialize)]
struct Response<'a> {
    scope: &'static str,
    cluster_id: &'a str,
    proposal_id: &'a str,
    admission_epoch: String,
    proposal_scope: &'a str,
    domain: &'static str,
    candidate_sha256: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    target_count: usize,
    targets: Vec<Row<'a>>,
}

/// 业务作用：从共享原文并发取得全部原目标的真实差异，缺席或失败仍保留其原目标结果槽。
///
/// 参数说明：
/// - `state`：实际管理 owner，候选工作可持有到清理结束。
/// - `context`：当前认证主体、范围和持久提案源。
/// - `id`：已验证的原提案身份。
/// - `bytes`：只能为 JSON 空对象的有限正文。
///
/// 返回：当前源与全部证明仍有效时直接编码一次完整响应；取消不产生持久动作。
pub(super) async fn inspect(
    state: &Arc<AdminState>,
    context: &Context<'_>,
    id: &str,
    bytes: &[u8],
) -> Result<http::Response<BoxBody>, Error> {
    if !admin::request_content_type(context.request, "application/json") || bytes.len() > 256 {
        return Err(Error::Invalid);
    }
    let _: Confirmation = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    super::current(state, context.store, context.snapshot)?;
    if !super::allows(context.snapshot, context.query, context.principal) {
        return Err(Error::Denied);
    }
    // 整请求名额先于任何共享正文读取，慢节点不能让八个通用提案入口全部持有构建输入。
    let _permit = state
        .management
        .admit_preview()
        .map_err(|_| Error::Capacity)?;
    let started = Instant::now();
    let source = Source::load(context, id).await?;
    let elapsed = u64::try_from(started.elapsed().as_millis()).map_err(|_| Error::Expired)?;
    let span = source.remaining_ms.saturating_sub(elapsed).min(20_000);
    // 为最终数据库复验预留完整查询期限，节点超时保留失败行而不吞掉全部原目标分母。
    if span <= 9_000 {
        return Err(Error::Expired);
    }
    let issued_at_ms = millis()?;
    let expires_at_ms = issued_at_ms.checked_add(span).ok_or(Error::Expired)?;
    let issued = Instant::now();
    let work = FuturesUnordered::new();
    for (index, target) in source.targets.iter().enumerate() {
        let command = intent(context, id, &source, index, target);
        let body = source.body.clone();
        let state = state.clone();
        let snapshot = context.snapshot.clone();
        work.push(async move {
            let result = match command {
                Ok(command) => tokio::time::timeout(
                    Duration::from_millis(span - 8_000),
                    preview::inspect(state, snapshot, command, body, issued_at_ms, expires_at_ms),
                )
                .await
                .unwrap_or(Err(Reason::Expired)),
                Err(reason) => Err(reason),
            };
            (
                index,
                Row {
                    target,
                    session: result.as_ref().ok().and_then(|completed| completed.session),
                    outcome: outcome(result),
                },
            )
        });
    }
    let mut rows = work.collect::<Vec<_>>().await;
    rows.sort_unstable_by_key(|(index, _)| *index);
    for (index, row) in &mut rows {
        if matches!(row.outcome, Outcome::Succeeded { .. }) {
            if let Ok(intent) = intent(context, id, &source, *index, row.target) {
                if let Err(reason) =
                    preview::recheck(state, context.snapshot, &intent, row.session).await
                {
                    row.outcome = Outcome::Failed {
                        reason,
                    };
                }
            }
        }
    }
    // 返回前重新证明原提案未终止且当前权限未换代；节点成功不能覆盖源提案的撤销。
    source.recheck(context, id).await?;
    let response = Response {
        scope: "original_targets",
        cluster_id: &context.store.plan.config.cluster_id,
        proposal_id: id,
        admission_epoch: source.epoch.to_string(),
        proposal_scope: &context.query.scope.key,
        domain: context.query.domain.identity().0,
        candidate_sha256: hex(&source.digest),
        issued_at_ms,
        expires_at_ms,
        target_count: source.targets.len(),
        targets: rows.into_iter().map(|(_, row)| row).collect(),
    };
    let bytes = serde_json::to_vec(&response).map_err(|_| Error::Unavailable)?;
    let now = millis()?;
    let elapsed = u64::try_from(issued.elapsed().as_millis()).map_err(|_| Error::Expired)?;
    // 编码和等待均计入原期限；时钟跳变不能续期已完成的远端证据。
    if now >= expires_at_ms.saturating_sub(1000)
        || elapsed >= span.saturating_sub(1000)
        || now.abs_diff(issued_at_ms.saturating_add(elapsed)) > 1000
    {
        return Err(Error::Expired);
    }
    super::current(state, context.store, context.snapshot)?;
    http::Response::builder()
        .status(http::StatusCode::OK)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(admin::full_body(bytes.into()))
        .map_err(|_| Error::Unavailable)
}

/// 业务作用：把原提案的一条冻结目标映射成独立只读声明，缺少原基线时不借当前目录补写。
///
/// 参数说明：
/// - `context`：原范围、领域及实际请求者。
/// - `id`：原提案身份。
/// - `source`：经过当前权限验证的共享候选。
/// - `index`：原目标固定顺序中的位置。
/// - `target`：原始节点、启动和配置基线。
///
/// 返回：完整原目标声明；缺少持久基线或集群不一致时保留明确失败。
fn intent(
    context: &Context<'_>,
    id: &str,
    source: &Source,
    index: usize,
    target: &Target,
) -> Result<Intent, Reason> {
    let baseline = target.node_baseline.as_ref().ok_or(Reason::Unavailable)?;
    if baseline.cluster_id != context.store.plan.config.cluster_id {
        return Err(Reason::BaselineChanged);
    }
    Ok(Intent {
        proposal: id.into(),
        epoch: source.epoch,
        index: index as u32,
        count: source.targets.len() as u32,
        domain: context.query.domain,
        node: target.node_id.clone(),
        boot: target.boot_id.clone(),
        baseline: baseline.clone(),
        version: target.base_version,
        fingerprint: u64::from_str_radix(&target.base_fingerprint, 16)
            .map_err(|_| Reason::BaselineChanged)?,
        candidate_bytes: source.body.len() as u32,
        candidate_sha256: source.digest,
        scope: context.query.scope.key.clone(),
        creator: source.creator.clone(),
        principal: context.principal.into(),
        authority: source.authority,
    })
}

/// 业务作用：将节点比较映射成互斥成功或失败行，失败从不携带伪造的空差异。
///
/// 参数说明：
/// - `result`：原目标实际构建结果或有限原因。
///
/// 返回：直接消费原生差异列表，不经中间 JSON 或复制对象身份。
fn outcome(result: Result<preview::Completed, Reason>) -> Outcome {
    match result {
        Ok(completed) => Outcome::Succeeded {
            diff: Box::new(completed.summary),
        },
        Err(reason) => Outcome::Failed {
            reason,
        },
    }
}

/// 业务作用：取得预览签发和交付可共同核对的绝对时间，异常时钟不授予默认期限。
///
/// 参数说明: 无。
///
/// 返回：可表示的正 Unix 毫秒；时间回到 epoch 之前或溢出时拒绝。
fn millis() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .filter(|value| *value > 0)
        .ok_or(Error::Expired)
}
