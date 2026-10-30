//! 节点本地持久身份与独占目录；存储就绪不授予远程动作执行权。

#[cfg(feature = "node-actions")]
mod actions;
mod filesystem;
mod identity;
mod local;
mod observation;
mod storage;

#[cfg(feature = "node-actions")]
pub(crate) use actions::{Application, EffectState, Preparation, Stage};
pub(crate) use local::{Input as LocalInput, Receipt as LocalReceipt};
pub(crate) use observation::Observation;

use anyhow::{ensure, Context, Result};
use filesystem::{Root, IDENTITY, INITIALIZING};
use identity::Identity;
use serde::Serialize;
use std::{fs::File, path::Path, sync::Arc};

/// 跨配置换代保持的永久绑定与单进程目录owner。
pub struct Journal {
    root: Root,
    identity: Identity,
    storage: parking_lot::Mutex<Option<storage::Snapshot>>,
    observation: Arc<tokio::sync::Semaphore>,
    #[cfg(feature = "node-actions")]
    action_boot: std::sync::OnceLock<String>,
    _exclusive: File,
}

/// 只读身份状态；不包含动作受理或执行成功声明。
#[derive(Serialize)]
pub struct Status {
    schema: u32,
    node_id: String,
    cluster_id: String,
    store_id: String,
    owner_busy: bool,
    execution_supported: bool,
    storage: Option<storage::Status>,
}

impl Journal {
    /// 业务作用：在bootstrap之前取得唯一节点目录owner，未知记录或未初始化身份不得开放业务。
    ///
    /// 参数说明：
    /// - `path`：部署固定的已初始化目录。
    ///
    /// 返回：持有独占锁的共享owner；缺失、损坏、未完成初始化或其它owner存在时拒绝。
    pub fn open(path: &Path) -> Result<Arc<Self>> {
        let owner = Self::acquire(path)?;
        owner.require_idle()?;
        #[cfg(feature = "node-actions")]
        ensure!(
            owner
                .storage
                .lock()
                .as_ref()
                .and_then(storage::Snapshot::action)
                .is_none_or(|action| action.allows_local()),
            "node journal action requires bound recovery"
        );
        Ok(owner)
    }

    /// 业务作用：普通业务启动取得唯一owner后先恢复指定主配置，再允许自举或构建监听资源。
    ///
    /// 参数说明：
    /// - `path`：部署固定的已初始化journal目录。
    /// - `main`：本次实际启动的主配置位置。
    ///
    /// 返回：文件方向已补齐的共享owner；未决记录仍待正常候选与资源准备确认后结束。
    pub fn open_bound(path: &Path, main: &Path) -> Result<Arc<Self>> {
        let owner = Self::acquire(path)?;
        owner.recover_local(main)?;
        Ok(owner)
    }

    /// 业务作用：取得唯一目录权威并冻结当前已提交事实，不隐式解释或执行文件方向。
    ///
    /// 参数说明：
    /// - `path`：部署固定的已初始化目录。
    ///
    /// 返回：持锁owner；调用方必须选择明确的空闲、恢复或离线维护流程。
    fn acquire(path: &Path) -> Result<Arc<Self>> {
        let root = Root::open(path)?;
        let exclusive = root
            .try_lock()?
            .context("node journal already has an owner")?;
        // 只能解释当前完整身份；未知动作或初始化残留不能按空闲节点启动。
        root.inspect(false)?;
        let (identity, _) = root
            .read(IDENTITY)?
            .context("node journal is not initialized")?;
        let storage = storage::load(&root, &identity)?;
        Ok(Arc::new(Self {
            root,
            identity,
            storage: parking_lot::Mutex::new(storage),
            observation: Arc::new(tokio::sync::Semaphore::new(1)),
            #[cfg(feature = "node-actions")]
            action_boot: std::sync::OnceLock::new(),
            _exclusive: exclusive,
        }))
    }

    /// 业务作用：显式建立永久节点绑定，完整初始化残留仅可按原身份继续，不覆盖其它事实。
    ///
    /// 参数说明：
    /// - `path`：已由部署者创建的私有目录。
    /// - `node`：永久管理节点标识。
    /// - `cluster`：永久发行集群标识。
    ///
    /// 返回：确认提交的原存储身份；异身份、损坏或未知目录内容拒绝，I/O失败需原身份复查。
    pub fn initialize(path: &Path, node: &str, cluster: &str) -> Result<Status> {
        let root = Root::open(path)?;
        let _exclusive = root
            .try_lock()?
            .context("node journal already has an owner")?;
        root.inspect(true)?;
        let installed = root.read(IDENTITY)?;
        let staged = root.read(INITIALIZING)?;
        if installed.is_none() {
            // 永久身份缺席但已有存储记录时不能生成新store ID，否则会把原控制事实解释成另一节点。
            for entry in root.dir.read_dir(".")? {
                let name = entry?.file_name();
                ensure!(
                    name == INITIALIZING,
                    "node journal identity is absent with storage records"
                );
            }
        }
        let identity = match (installed, staged) {
            (Some((identity, bytes)), staged) => {
                identity.require_binding(node, cluster)?;
                if let Some((_, temporary)) = staged {
                    // 永久身份已经提交，只有同一完整记录才可收尾；不同证据不能被重试抹去。
                    ensure!(
                        bytes == temporary,
                        "node journal initialization records differ"
                    );
                    root.finish()?;
                }
                identity
            }
            (None, Some((identity, _))) => {
                identity.require_binding(node, cluster)?;
                // 临时记录本身已完整验证且节点身份相同，允许完成原提交，绝不生成新store ID。
                root.publish()?;
                identity
            }
            (None, None) => {
                let identity = Identity::new(node, cluster)?;
                root.stage(&identity.encode()?)?;
                root.publish()?;
                identity
            }
        };
        let storage = storage::load(&root, &identity)?;
        Ok(status(&identity, false, storage.as_ref()))
    }

    /// 业务作用：只读查看永久身份和目录占用，不尝试终止现有owner或补齐缺失结构。
    ///
    /// 参数说明：
    /// - `path`：待检查的固定目录。
    ///
    /// 返回：完整身份及真实锁占用；未完成初始化、未知记录或锁能力错误均拒绝。
    pub fn status(path: &Path) -> Result<Status> {
        let root = Root::open(path)?;
        let owner = root.try_lock()?;
        root.inspect(false)?;
        let (identity, _) = root
            .read(IDENTITY)?
            .context("node journal is not initialized")?;
        let storage = storage::load(&root, &identity)?;
        Ok(status(&identity, owner.is_none(), storage.as_ref()))
    }

    /// 业务作用：显式安装独立于配置的节点受理代际存储，不开启远程动作或业务监听。
    ///
    /// 参数说明：
    /// - `path`：已经绑定永久身份的私有目录。
    ///
    /// 返回：初始或原有已提交存储状态；在线owner、损坏和不符残留均拒绝。
    pub fn initialize_storage(path: &Path) -> Result<Status> {
        let (root, _exclusive, identity) = maintenance(path)?;
        let storage = storage::initialize(&root, &identity)?;
        Ok(status(&identity, false, Some(&storage)))
    }

    /// 业务作用：通过离线比较交换关闭受理代际，过期维护请求不能重复推进节点水位。
    ///
    /// 参数说明：
    /// - `path`：固定节点目录。
    /// - `expected`：只读状态提供的完整revision与SHA-256令牌。
    ///
    /// 返回：新水位持久提交后的状态；在线owner、冲突或溢出拒绝，I/O失败需只读复查。
    pub fn close_epoch(path: &Path, expected: &str) -> Result<Status> {
        let (root, _exclusive, identity) = maintenance(path)?;
        let storage = storage::close_epoch(&root, &identity, expected)?;
        Ok(status(&identity, false, Some(&storage)))
    }

    /// 业务作用：将初始配置及每次候选绑定回永久节点，防止热更把同一目录借给另一信任域。
    ///
    /// 参数说明：
    /// - `snapshot`：尚未开放资源或写入配置的完整候选。
    ///
    /// 返回：节点与全部目标的发行者验证计划匹配时成功；关闭管理、身份漂移或目录证据变化拒绝。
    pub fn validate_snapshot(&self, snapshot: &crate::config::GatewaySnapshot) -> Result<()> {
        let storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        ensure!(
            !snapshot
                .admin_management
                .as_ref()
                .is_some_and(|plan| plan.actions_enabled || plan.previews_enabled)
                || storage.is_some(),
            "node actions and previews require initialized journal storage"
        );
        // 身份握手关闭或跨集群后不能继承该目录的永久节点权威，普通热更也必须在资源准备前拒绝。
        ensure!(
            snapshot.admin_management.as_ref().is_some_and(
                |plan| plan.matches_journal(&self.identity.node_id, &self.identity.cluster_id)
            ),
            "node journal requires the matching node and proven issuer cluster"
        );
        if let Some(plan) = storage.as_ref().and_then(storage::Snapshot::local) {
            local::require_snapshot(plan, snapshot)?;
        }
        Ok(())
    }

    /// 业务作用：在每次文件副作用前复验目录事实，未知记录或被替换的身份不能继续写配置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：永久身份和已提交存储仍与owner承认的事实相同时成功；缺席、损坏、未知内容或外部换代拒绝。
    pub(crate) fn verify(&self) -> Result<()> {
        self.verify_expected(self.storage.lock().as_ref())
    }

    /// 业务作用：持状态锁复验外部事实，自己的完整提交之外的任何换代都不能取得写权。
    ///
    /// 参数说明：
    /// - `expected`：当前owner已经承认的提交，空表示identity-only模式。
    ///
    /// 返回：目录、身份和head完整相同时成功；缺席、损坏或外部变更拒绝。
    fn verify_expected(&self, expected: Option<&storage::Snapshot>) -> Result<()> {
        self.root.inspect(false)?;
        let (identity, _) = self
            .root
            .read(IDENTITY)?
            .context("node journal identity is absent")?;
        ensure!(
            identity == self.identity,
            "node journal identity changed while owned"
        );
        // 外部增删存储或换代不能通过热更隐式取得新写权；内存事实只由本owner确认同步的提交推进。
        ensure!(
            storage::load(&self.root, &identity)?.as_ref() == expected,
            "node journal storage changed while owned"
        );
        Ok(())
    }
}

/// 业务作用：只暴露永久身份和owner占用，不将已初始化存储冒充动作执行能力。
///
/// 参数说明：
/// - `identity`：经过完整性与业务字段校验的永久身份。
/// - `owner_busy`：独立目录句柄上非阻塞锁的实际结果。
/// - `storage`：经过head双读确认的可选存储事实。
///
/// 返回：不含原始配置或秘密的固定状态结构。
fn status(identity: &Identity, owner_busy: bool, storage: Option<&storage::Snapshot>) -> Status {
    Status {
        schema: identity.schema,
        node_id: identity.node_id.clone(),
        cluster_id: identity.cluster_id.clone(),
        store_id: identity.store_id.clone(),
        owner_busy,
        execution_supported: false,
        storage: storage.map(storage::Snapshot::status),
    }
}

/// 业务作用：维护动作取得独占目录与既有完整身份，不能借维护自动安装身份或与在线进程争写。
///
/// 参数说明：
/// - `path`：部署固定的节点目录。
///
/// 返回：必须保持到动作结束的目录、锁和身份；缺失或owner已占用时不写入。
fn maintenance(path: &Path) -> Result<(Root, File, Identity)> {
    let root = Root::open(path)?;
    let exclusive = root
        .try_lock()?
        .context("node journal already has an owner")?;
    root.inspect(true)?;
    ensure!(
        root.read(INITIALIZING)?.is_none(),
        "node journal identity installation is incomplete"
    );
    let (identity, _) = root
        .read(IDENTITY)?
        .context("node journal is not initialized")?;
    Ok((root, exclusive, identity))
}
