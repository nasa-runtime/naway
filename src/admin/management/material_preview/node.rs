//! 原目标、完整 pair 与候选预检共用固定发布锁序，后台任务保留实际秘密工作容量。

use super::{session::Work, Content, Reason};
use crate::{
    admin::AdminState,
    control::material::authorization,
    tls::keypair::preview::{self, Expected, Proof},
};
use std::{sync::Arc, time::Duration};

/// 业务作用：下载前或完整构建时复验原节点全部材料条件，任一共享对象越权就拒绝整批。
///
/// 参数说明：
/// - `state`：实际原节点的唯一配置、文件事务与管理 owner。
/// - `work`：已经独立验签且持有真实工作名额的原声明。
/// - `content`：已完整接收的唯一候选；为空时只验证下载前资格与完整原 pair。
///
/// 返回：全部原目标的当前完整影响证明；失败不安装候选、不创建持久执行、不发布活动监听。
pub(super) async fn inspect(
    state: Arc<AdminState>,
    work: Arc<Work>,
    content: Option<Arc<Content>>,
) -> Result<Proof, Reason> {
    work.baseline(&state).await?;
    let publication = Arc::new(
        tokio::time::timeout(Duration::from_secs(2), state.apply_coordinator.lock_owned())
            .await
            .map_err(|_| Reason::Capacity)?,
    );
    work.baseline(&state).await?;
    let owner = state.clone();
    let current = work.clone();
    let guard = publication.clone();
    let proof = tokio::task::spawn_blocking(move || {
        let _publication = guard;
        // 先冻结配置发布，再冻结部署文件和材料；取消等待也必须由真实任务完成秘密清理后释放名额。
        owner.config_history.with_stable_local_files(|| {
            current.authorize(&owner)?;
            require_files(&current)?;
            let intent = &current.command.intent;
            let expected: Vec<_> = intent
                .targets
                .iter()
                .zip(&intent.pairs)
                .map(|(target, pair)| Expected {
                    target,
                    certificate_etag: &pair.certificate_etag,
                    material_generation: &pair.material_generation,
                })
                .collect();
            let candidate = content
                .as_ref()
                .map(|content| {
                    if content.material.0.len() != intent.candidate_bytes as usize
                        || content.digest != intent.candidate_sha256
                    {
                        return Err(Reason::CandidateInvalid);
                    }
                    let (certificate, private_key) = content
                        .material
                        .parts()
                        .map_err(|_| Reason::CandidateInvalid)?;
                    crate::tls::keypair::validate_keypair(certificate, private_key)
                        .map_err(|_| Reason::CandidateInvalid)
                })
                .transpose()?;
            let proof = preview::inspect(
                &current.active,
                &expected,
                |batch| {
                    current.authorize(&owner).is_ok()
                        && authorization::logical_targets(
                            &intent.scope,
                            &current.active,
                            &intent.node,
                            batch
                                .groups
                                .iter()
                                .flat_map(|group| group.affected.iter().map(|entry| &entry.target)),
                        )
                        .is_some()
                },
                candidate.as_ref(),
            )
            .map_err(Reason::from)?;
            // 构建耗时不能保留已撤销的权威；文件被外部修改时也不把旧配置证明交付出去。
            current.authorize(&owner)?;
            require_files(&current)?;
            super::super::material::wire::validate(&proof.conditions, &intent.original)
                .map_err(Reason::from)?;
            Ok::<Proof, Reason>(proof)
        })
    })
    .await
    .map_err(|_| Reason::Unavailable)??;
    work.baseline(&state).await?;
    Ok(proof)
}

/// 业务作用：原配置文件被绕过发布器改变时撤销预检权威，不让旧快照掩盖真实部署来源。
///
/// 参数说明：
/// - `work`：冻结原配置指纹的已验签工作。
///
/// 返回：完整文件集仍与原意图一致才成功；读取失败或改变都拒绝。
fn require_files(work: &Work) -> Result<(), Reason> {
    if crate::config::config_fingerprint(&work.active.source_config_path).ok()
        != Some(work.command.intent.fingerprint)
    {
        return Err(Reason::BaselineChanged);
    }
    Ok(())
}
