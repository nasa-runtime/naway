//! 在配置自举之前建立节点存储权威。

use super::cli::{Args, RunMode};
use anyhow::Result;

#[derive(Default)]
pub(super) struct Prepared {
    pub(super) maintenance: bool,
    #[cfg(feature = "node-journal")]
    owner: Option<std::sync::Arc<gateway::control::journal::Journal>>,
}

/// 业务作用：先处理永久节点目录，再允许任何自动配置创建、快照构建或服务资源开放。
///
/// 参数说明：
/// - `args`：固定CLI来源及显式初始化/只读检查选择。
/// - `mode`：启动角色，纯Admin不能持有本地业务动作目录。
/// - `main`：本次实际CLI主配置路径，用于绑定未决文件恢复。
///
/// 返回：维护已完成标记或唯一owner；未传目录时完全不访问存储，未编译能力时拒绝。
pub(super) fn prepare(args: &Args, mode: RunMode, main: &std::path::Path) -> Result<Prepared> {
    let Some(path) = &args.node_journal else {
        return Ok(Prepared::default());
    };
    #[cfg(not(feature = "node-journal"))]
    {
        let _ = (path, mode, main);
        anyhow::bail!("node journal requires the node-journal feature");
    }
    #[cfg(feature = "node-journal")]
    {
        use gateway::control::journal::Journal;
        if args.node_journal_status {
            println!("{}", serde_json::to_string(&Journal::status(path)?)?);
            return Ok(Prepared {
                maintenance: true,
                owner: None,
            });
        }
        // 纯Admin只协调远端节点，不能通过本地journal获取不存在的数据面动作权威。
        anyhow::ensure!(
            mode.runs_data(),
            "node journal ownership requires data, sidecar or all-in-one mode"
        );
        if args.node_journal_storage_init
            || args.node_journal_close_epoch.is_some()
            || args.node_journal_rollback_local.is_some()
        {
            let state = if let Some(expected) = &args.node_journal_rollback_local {
                Journal::rollback_local(path, main, expected)?
            } else if let Some(expected) = &args.node_journal_close_epoch {
                Journal::close_epoch(path, expected)?
            } else {
                Journal::initialize_storage(path)?
            };
            println!("{}", serde_json::to_string(&state)?);
            return Ok(Prepared {
                maintenance: true,
                owner: None,
            });
        }
        if args.node_journal_init {
            let node = args.node_journal_node.as_deref().ok_or_else(|| {
                anyhow::anyhow!("node journal initialization requires node identity")
            })?;
            let cluster = args.node_journal_cluster.as_deref().ok_or_else(|| {
                anyhow::anyhow!("node journal initialization requires cluster identity")
            })?;
            println!(
                "{}",
                serde_json::to_string(&Journal::initialize(path, node, cluster)?)?
            );
            return Ok(Prepared {
                maintenance: true,
                owner: None,
            });
        }
        Ok(Prepared {
            maintenance: false,
            owner: Some(Journal::open_bound(path, main)?),
        })
    }
}

impl Prepared {
    /// 业务作用：启动初始快照沿用正常构建器，存在持久文件方向时额外复验冻结依赖。
    ///
    /// 参数说明：
    /// - `build`：固定版本及动态来源的初始构建器，不开放业务监听。
    ///
    /// 返回：完整初始快照；动作依赖变化拒绝启动，没有动作时保持一次构建。
    pub(super) fn build(
        &self,
        mut build: impl FnMut() -> Result<gateway::config::GatewaySnapshot>,
    ) -> Result<gateway::config::GatewaySnapshot> {
        #[cfg(feature = "node-actions")]
        if let Some(owner) = &self.owner {
            return owner.build_action_candidate(build);
        }
        build()
    }

    /// 业务作用：初始快照必须与已持有的永久目录身份一致，不能先启动发现或开放监听再检查。
    ///
    /// 参数说明：
    /// - `snapshot`：刚完成语义构建的初始配置。
    ///
    /// 返回：绑定匹配或未启用时成功，漂移拒绝启动并释放owner。
    pub(super) fn validate(&self, snapshot: &gateway::config::GatewaySnapshot) -> Result<()> {
        #[cfg(feature = "node-journal")]
        if let Some(owner) = &self.owner {
            return owner.validate_snapshot(snapshot);
        }
        let _ = snapshot;
        Ok(())
    }

    /// 业务作用：向现有文件事务共享同一目录owner，使热更和管理写入沿用启动身份。
    ///
    /// 参数说明：
    /// - `history`：所有本地配置发布与回滚共用的文件事务。
    ///
    /// 返回：首次绑定成功或未启用时无副作用，重复安装拒绝。
    pub(super) fn attach(&self, history: &gateway::control::history::ConfigHistory) -> Result<()> {
        #[cfg(feature = "node-journal")]
        if let Some(owner) = &self.owner {
            return history.attach_journal(owner.clone());
        }
        let _ = history;
        Ok(())
    }
}
