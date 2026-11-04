//! 材料条件在固定锁序内读取，原请求取消不释放仍在访问文件的实际许可。

use super::{session::Work, Reason};
use crate::{
    admin::AdminState,
    control::material::authorization,
    tls::keypair::conditions::{self, Batch},
};
use std::{sync::Arc, time::Duration};

/// 业务作用：让原节点一次观察同批材料条件并复验完整共享范围，读取不授予后续安装权。
///
/// 参数说明：
/// - `state`：原实例的唯一配置与文件事务 owner。
/// - `work`：已验签且持有真实节点名额的短期工作。
///
/// 返回：原基线与当前共享归属仍有效的完整批次；无法证明时整节点拒绝且不泄露路径。
pub(super) async fn inspect(state: Arc<AdminState>, work: Arc<Work>) -> Result<Batch, Reason> {
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
    let batch = tokio::task::spawn_blocking(move || {
        let _publication = guard;
        // 文件观察前先持有配置发布权，再进入文件事务和唯一材料锁；等待取消不能提前放行新发布。
        owner.config_history.with_stable_local_files(|| {
            current.authorize(&owner)?;
            require_files(&current)?;
            let batch = conditions::read_many(&current.active, &current.command.intent.targets)
                .map_err(Reason::from)?;
            current.authorize(&owner)?;
            require_files(&current)?;
            let intent = &current.command.intent;
            // 授权一个逻辑入口不代表可以看到同文件的其它租户；完整影响任何一项越界都丢弃整批条件。
            authorization::logical_targets(
                &intent.scope,
                &current.active,
                &intent.node,
                batch
                    .groups
                    .iter()
                    .flat_map(|group| group.affected.iter().map(|affected| &affected.target)),
            )
            .ok_or(Reason::Denied)?;
            Ok::<Batch, Reason>(batch)
        })
    })
    .await
    .map_err(|_| Reason::Unavailable)??;
    // 节点目录在读取期间失去原基线时，磁盘读成功也不构成可以交付的证明。
    work.baseline(&state).await?;
    super::wire::validate(&batch, &work.command.intent)?;
    Ok(batch)
}

/// 业务作用：未发布的部署文件改变也会撤销原配置条件，不能用旧快照掩盖真实来源变化。
///
/// 参数说明：
/// - `work`：已验证原配置实例的材料工作。
///
/// 返回：完整来源指纹仍与原意图一致才成功；读取失败或改变均拒绝。
fn require_files(work: &Work) -> Result<(), Reason> {
    if crate::config::config_fingerprint(&work.active.source_config_path).ok()
        != Some(work.command.intent.fingerprint)
    {
        return Err(Reason::BaselineChanged);
    }
    Ok(())
}
