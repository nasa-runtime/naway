//! 原提案按节点聚合但保留全部目标分母，缺席或拒绝不会变成省略的成功。

use super::{Context, current, response, source::Source};
use crate::{
    admin::{
        BoxBody,
        management::{
            material,
            material_preview::{
                self, Completed, Reason,
                command::{Intent, Pair},
            },
        },
        operations::certificates::Error,
    },
    control::material::authorization,
};
use futures::{StreamExt, stream};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(in crate::admin::operations::certificates) struct Observed {
    pub intent: Arc<Intent>,
    pub result: Result<Completed, Reason>,
}

pub(in crate::admin::operations::certificates) struct Observation {
    pub source: Source,
    pub observed: Vec<Observed>,
    pub issued: u64,
    pub expires: u64,
    pub window: material::RequestWindow,
}

/// 业务作用：只预检原持久候选和原目标，最终原记录、当前身份或窗口变化时不交付旧成功。
///
/// 参数说明：
/// - `context`：原请求凭据、唯一范围和共享存储。
/// - `id`：原提案规范身份。
/// - `bytes`：只能为空对象的有限确认正文。
/// - `permit`：正文接收前取得的真实名额，材料最后一个持有者退出前保留。
///
/// 返回：完整原分母的有限证明；不改变审批状态、持久执行或实际证书。
pub(super) async fn inspect(
    context: &Context<'_>,
    id: &str,
    bytes: &[u8],
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<http::Response<BoxBody>, Error> {
    let observation = observe(context, id, bytes, permit).await?;
    let result = response::encode(
        context,
        id,
        &observation.source,
        &observation.observed,
        observation.issued,
        observation.expires,
    )?;
    // 编码也可能跨越撤权或期限，最终返回前不能把已知失效结果留给管理页面。
    observation.window.check().map_err(|_| Error::Conflict)?;
    current(context)?;
    Ok(result)
}

/// 业务作用：共享同一原候选的完整观察流程，影响登记只消费真实节点结果而不能接受客户端证明。
///
/// 参数说明：
/// - `context`：当前原请求身份和冻结的管理权威。
/// - `id`：唯一原材料提案身份。
/// - `bytes`：只能为空对象的确认正文。
/// - `permit`：材料最后一个实际持有者释放前保留的整请求名额。
///
/// 返回：全分母原生结果及完整原记录标记；失败节点仍在结果中，登记方必须全部成功才可持久化。
pub(in crate::admin::operations::certificates) async fn observe(
    context: &Context<'_>,
    id: &str,
    bytes: &[u8],
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Observation, Error> {
    confirm(bytes)?;
    current(context)?;
    let started = Instant::now();
    let source = Source::load(context, id, permit).await?;
    let elapsed = u64::try_from(started.elapsed().as_millis()).map_err(|_| Error::Conflict)?;
    let span = source.remaining_ms.saturating_sub(elapsed).min(20_000);
    // 为最终原记录复验保留完整数据库读取预算；节点等待不能吞掉原窗口后继续返回旧证明。
    if span <= 9_000 {
        return Err(Error::Conflict);
    }
    let issued = millis()?;
    let expires = issued.checked_add(span).ok_or(Error::Conflict)?;
    let window = material::RequestWindow::preview(issued, expires).map_err(|_| Error::Conflict)?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(span - 8_000);
    let mut random = [0; 16];
    getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
    let query = hex(&random);
    let intents = intents(context, &source, &query)?;
    let mut observed = stream::iter(intents.into_iter().map(|intent| {
        let state = context.state.clone();
        let snapshot = context.snapshot.clone();
        let content = source.content.clone();
        async move {
            let result = tokio::time::timeout_at(
                deadline,
                material_preview::inspect(
                    state,
                    snapshot,
                    intent.clone(),
                    content,
                    issued,
                    expires,
                ),
            )
            .await
            .unwrap_or(Err(Reason::Expired));
            Observed {
                intent,
                result,
            }
        }
    }))
    .buffer_unordered(16)
    .collect::<Vec<_>>()
    .await;
    // 队列共用同一个绝对截止，后排节点不能从开始执行时重新取得二十秒。
    let recheck_deadline = deadline + Duration::from_millis(1000);
    for item in &mut observed {
        if let Ok(completed) = &item.result {
            let checked = tokio::time::timeout_at(
                recheck_deadline,
                material_preview::recheck(
                    context.state,
                    context.snapshot,
                    &item.intent,
                    completed.session,
                ),
            )
            .await
            .unwrap_or(Err(Reason::Expired));
            if let Err(reason) = checked {
                item.result = Err(reason);
            }
        }
    }
    source.recheck(context, id).await?;
    window.check().map_err(|_| Error::Conflict)?;
    observed.sort_unstable_by(|left, right| left.intent.node.cmp(&right.intent.node));
    current(context)?;
    Ok(Observation {
        source,
        observed,
        issued,
        expires,
        window,
    })
}

/// 业务作用：只接受空 JSON 对象的预检确认，数组和任何替代材料字段都不能触发候选分发。
///
/// 参数说明：
/// - `bytes`：已受 HTTP 体积门限制的原始正文。
///
/// 返回：正文仅包含一对对象大括号和 JSON 空白时成功；不分配对象或反射输入内容。
pub(in crate::admin::operations::certificates) fn confirm(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > 256 {
        return Err(Error::Invalid);
    }
    let mut tokens = bytes
        .iter()
        .copied()
        .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'));
    if tokens.next() != Some(b'{') || tokens.next() != Some(b'}') || tokens.next().is_some() {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// 业务作用：仅按原记录规范顺序分组，不以当前在线目录补齐成员，节点局部权威和原完整权威分别绑定。
///
/// 参数说明：
/// - `context`：当前范围与实际请求者。
/// - `source`：已经认证的原提案全部目标和唯一材料。
/// - `query`：本次不可复用的短期观察身份。
///
/// 返回：每节点一个完整声明；原基线或当前局部授权无法证明则拒绝整请求。
fn intents(context: &Context<'_>, source: &Source, query: &str) -> Result<Vec<Arc<Intent>>, Error> {
    let mut result = Vec::new();
    let mut start = 0;
    while start < source.targets.len() {
        let first = &source.targets[start];
        let end = start
            + source.targets[start..]
                .iter()
                .take_while(|target| target.node_id == first.node_id)
                .count();
        let targets: Vec<_> = source.targets[start..end]
            .iter()
            .map(|target| target.target.clone())
            .collect();
        let authority =
            authorization::logical_authority(&context.scope.key, context.snapshot, &targets)
                .ok_or(Error::Denied)?;
        result.push(Arc::new(Intent {
            original: Arc::new(material::command::Intent {
                query_kind: material::command::Query::Conditions,
                query: query.into(),
                count: source.targets.len() as u32,
                indices: (start..end).map(|index| index as u32).collect(),
                targets,
                node: first.node_id.clone(),
                boot: first.boot_id.clone(),
                baseline: first.node_baseline.clone(),
                version: first.base_version,
                fingerprint: u64::from_str_radix(&first.base_fingerprint, 16)
                    .map_err(|_| Error::Unavailable)?,
                scope: context.scope.key.clone(),
                principal: context.principal.into(),
                authority,
            }),
            proposal: source.stamp.context.id.clone(),
            store: source.stamp.context.store_id.clone(),
            epoch: source.stamp.context.epoch,
            creator: source.stamp.context.creator.clone(),
            proposal_authority: source.stamp.authority,
            proposal_intent: source.stamp.context.intent,
            pairs: source.targets[start..end]
                .iter()
                .map(|target| Pair {
                    certificate_etag: target.certificate_etag.clone(),
                    material_generation: target.material_generation.clone(),
                })
                .collect(),
            candidate_bytes: source.content.material.0.len() as u32,
            candidate_sha256: source.content.digest,
        }));
        start = end;
    }
    Ok(result)
}

/// 业务作用：给本次短期声明取得可信的正绝对时刻，不以零时间或溢出为预检续期。
///
/// 参数说明: 无。
///
/// 返回：可表达的Unix毫秒；异常墙钟拒绝本次预检。
fn millis() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .filter(|value| *value > 0)
        .ok_or(Error::Conflict)
}

/// 业务作用：编码公开观察身份或完整影响摘要，避免在内部协议引入文本材料帧。
///
/// 参数说明：
/// - `bytes`：随机观察身份或不包含秘密的固定摘要。
///
/// 返回：规范小写十六进制文本。
pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("write material observation identity");
    }
    text
}
