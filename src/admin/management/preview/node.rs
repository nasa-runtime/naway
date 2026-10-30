//! 节点预览仅在隔离工作区构建，不取得 journal 动作槽或修改活动配置。

use super::{session::Work, Reason};
use crate::{
    admin::{
        candidate::{self, BuildError, DocumentKind},
        diff::{model::Summary, snapshot},
        AdminState,
    },
    control::{actions::domain::Domain, history::ArchivedDocs},
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// 业务作用：在原节点上构建原提案候选，并在真实清理及持久基线复验后交付低敏差异。
///
/// 参数说明：
/// - `state`：实际目标的唯一管理与文件 owner。
/// - `work`：已经验签并持有节点预览容量的原工作。
/// - `body`：完整验过签名长度与摘要的原文，跨本机目标共享 Bytes。
///
/// 返回：原目标基线和权限仍有效时的有限差异；非法、过载或换代返回低敏原因，不发布配置。
pub(super) async fn inspect(
    state: Arc<AdminState>,
    work: Arc<Work>,
    body: Bytes,
) -> Result<Summary, Reason> {
    work.baseline(&state).await?;
    if body.len() != work.command.intent.candidate_bytes as usize {
        return Err(Reason::CandidateInvalid);
    }
    let kind = match work.command.intent.domain {
        Domain::Gateway => DocumentKind::Gateway,
        Domain::Sentinel => DocumentKind::Sentinel,
        Domain::InterfaceGuard => DocumentKind::InterfaceGuard,
    };
    let built = candidate::inspect_guarded(
        &state,
        work.active.clone(),
        kind,
        body,
        (state.clone(), work.clone()),
        validate,
        |(state, work), current, candidate| {
            work.authorize(state)?;
            // 依赖文件的变化可能尚未形成新快照；实际来源必须仍匹配原目标，才能交付这次比较。
            require_files(work)?;
            // 只读构建也不能接受改变本机控制权威的远程候选，否则预览与后续正式预检会给出矛盾结论。
            if crate::control::reload::remote_bootstrap_change(current, candidate).is_some() {
                return Err(Reason::CandidateInvalid);
            }
            let summary = snapshot::compare(current, candidate);
            if !within_budget(&summary) {
                return Err(Reason::Capacity);
            }
            Ok(summary)
        },
    )
    .await;
    // 节点目录或授权在构建期间变化时必须撤下结果，不能仅凭候选能够解析而声称仍适用于原目标。
    work.baseline(&state).await?;
    built.map_err(|error| match error {
        BuildError::Busy => Reason::Capacity,
        BuildError::Baseline | BuildError::Exhausted => Reason::BaselineChanged,
        BuildError::Invalid(_) => Reason::CandidateInvalid,
        BuildError::Worker | BuildError::Workspace => Reason::Unavailable,
    })?
}

/// 业务作用：在读取候选依赖之前验证归档身份，并让工作区原文只能重放已有受限对象动作。
///
/// 参数说明：
/// - `owner`：真实工作期间一直保留的当前节点和原预览许可。
/// - `docs`：从原活动版本取得的完整归档。
/// - `body`：该次签名候选的原始字节。
///
/// 返回：平台范围或合法工作区替换成功；任何基线、授权或范围不一致都在构建前拒绝。
fn validate(
    owner: &(Arc<AdminState>, Arc<Work>),
    docs: &ArchivedDocs,
    body: &[u8],
) -> Result<(), BuildError> {
    let (state, work) = owner;
    work.authorize(state).map_err(|_| BuildError::Baseline)?;
    require_files(work).map_err(|_| BuildError::Baseline)?;
    let intent = &work.command.intent;
    // 活动快照已经绑定节点的角色分帧摘要；归档逐文档核对长度与 SHA，不能拿 Nacos bundle 摘要代替。
    if !work
        .active
        .document_identity
        .as_ref()
        .is_some_and(|identity| {
            identity.matches_documents(
                [&docs.gateway, &docs.interface_guard, &docs.sentinel_rules].map(|document| {
                    (
                        document.len() as u64,
                        Sha256::digest(document.as_bytes()).into(),
                    )
                }),
            )
        })
    {
        return Err(BuildError::Baseline);
    }
    let Some(workspace) = intent.scope.strip_prefix("workspace.") else {
        return Ok(());
    };
    // 两份规则文档是全局保护资源，工作区不能通过只读构建入口读取或求值平台候选依赖。
    if intent.domain != Domain::Gateway {
        return Err(BuildError::Invalid("preview scope denied".into()));
    }
    let limit = crate::config::document::MAX_DOCUMENT_BYTES;
    let baseline = crate::config::document::parse(docs.gateway.as_bytes(), limit)
        .map_err(|_| BuildError::Baseline)?;
    let candidate = crate::config::document::parse(body, intent.candidate_bytes as usize)
        .map_err(|_| BuildError::Invalid("preview candidate invalid".into()))?;
    work.active
        .ownership
        .validate_replacement(baseline, candidate, &intent.creator, workspace)
        .map_err(|_| BuildError::Invalid("preview scope denied".into()))
}

/// 业务作用：在实际候选工作线程内复验原部署文件及声明依赖，未发布的磁盘变化不能借旧指纹构建。
///
/// 参数说明：
/// - `work`：已经验证原快照和完整基线的工作 owner。
///
/// 返回：当前有界来源指纹仍等于原意图时成功；读取失败或文件变化拒绝交付差异。
fn require_files(work: &Work) -> Result<(), Reason> {
    if crate::config::config_fingerprint(&work.active.source_config_path).ok()
        != Some(work.command.intent.fingerprint)
    {
        return Err(Reason::BaselineChanged);
    }
    Ok(())
}

/// 业务作用：将原目标差异限制为完整可传输的小结果，超量时整体拒绝而非隐藏剩余影响面。
///
/// 参数说明：
/// - `summary`：完整比较产生或收到的五领域原生摘要。
///
/// 返回：最多256个身份、原文16KiB且JSON转义24KiB以内时为真；容量不足不得显示为零差异。
pub(super) fn within_budget(summary: &Summary) -> bool {
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut escaped = 0usize;
    for changes in [
        &summary.routes,
        &summary.upstreams,
        &summary.listeners,
        &summary.sentinel,
        &summary.interface_guard,
    ] {
        let mut seen = std::collections::HashSet::new();
        for id in changes
            .added
            .iter()
            .chain(&changes.removed)
            .chain(&changes.changed)
        {
            count = count.saturating_add(1);
            bytes = bytes.saturating_add(id.len());
            // 最终 HTTP 有独立消息边界，控制字符转义不能把有界原生摘要放大到页面总预算之外。
            escaped = escaped.saturating_add(
                id.bytes()
                    .map(|byte| match byte {
                        b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 8 | 12 => 2,
                        0..=31 => 6,
                        _ => 1,
                    })
                    .sum::<usize>(),
            );
            if id.is_empty()
                || !seen.insert(id.as_str())
                || count > 256
                || bytes > 16 * 1024
                || escaped > 24 * 1024
            {
                return false;
            }
        }
    }
    true
}
