//! 配置版本历史与本地回滚归档。
//!
//! 只服务控制面:reload 成功/失败记录低频审计事件,成功版本归档三文件配置集,供 Admin 查询与本地 rollback。

mod actions;
mod files;
mod publication;

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

use crate::config::{
    config_fingerprint, load_gateway_config, resolve_relative, GatewaySnapshot,
    GatewaySnapshotSummary,
};

/// 单份归档配置文档硬上限。归档属于控制面低频路径，但磁盘内容仍可能被外部篡改，
/// 因此读取和归档都不能按文件声明大小无界分配/复制。
const MAX_ARCHIVED_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;

/// 配置历史共享状态。
#[derive(Clone)]
pub struct ConfigHistory {
    /// reload 局部视图冻结候选指纹；外层 None 表示非候选记录，内层 None 表示没有可靠指纹。
    candidate_fingerprint: Option<Option<u64>>,
    inner: Arc<Mutex<ConfigHistoryState>>,
    archive_root: Arc<PathBuf>,
    /// 本进程 local rollback 写三文件时独占；reload build 持共享锁，不能观察到中间态。
    file_transaction: Arc<RwLock<()>>,
    /// 永久节点目录与所有本地配置写者共用同一owner，不因快照换代重新取得锁。
    #[cfg(feature = "node-journal")]
    node_journal: Arc<std::sync::OnceLock<Arc<crate::control::journal::Journal>>>,
}

struct ConfigHistoryState {
    max_events: usize,
    next_event_id: u64,
    events: VecDeque<ConfigHistoryEvent>,
    archives: BTreeMap<u64, ArchivedConfigSet>,
}

/// Admin 输出的配置历史快照。
#[derive(Serialize)]
pub struct ConfigHistorySnapshot {
    /// 最近配置事件,按发生顺序排列。
    pub events: Vec<ConfigHistoryEvent>,
    /// 当前可回滚的已归档版本。
    pub archived_versions: Vec<u64>,
}

/// 单条配置审计事件。
#[derive(Clone, Serialize)]
pub struct ConfigHistoryEvent {
    /// 本节点单调事件号。
    pub id: u64,
    /// Unix epoch 毫秒。
    pub ts_ms: u128,
    /// 触发源:file/SIGHUP/nacos-config/admin-rollback 等。
    pub trigger: String,
    /// 本次读取的配置路径。
    pub cfg_path: String,
    /// 事件状态。
    pub status: String,
    /// 事件发生前的配置版本。
    pub old_version: u64,
    /// 成功上线后的新配置版本。
    pub new_version: Option<u64>,
    /// 候选版本。失败事件也有它。
    pub candidate_version: Option<u64>,
    /// 成功快照摘要。
    pub summary: Option<GatewaySnapshotSummary>,
    /// 失败原因或归档失败原因。
    pub error: Option<String>,
    /// 配置集指纹,用于审计配置是否重复。
    pub fingerprint: Option<u64>,
}

#[derive(Clone)]
struct ArchivedConfigSet {
    gateway: PathBuf,
    interface_guard: PathBuf,
    sentinel_rules: PathBuf,
}

/// 某归档版本的三文件配置原文。
///
/// 字段与 Nacos 配置源的三个 dataId 一一对应,供 CAS 回滚把归档内容写回 Nacos。
#[derive(Clone)]
pub struct ArchivedDocs {
    /// 主配置 `gateway.yml` 原文。
    pub gateway: String,
    /// 接口守卫 `interface-guard.yml` 原文。
    pub interface_guard: String,
    /// Sentinel 规则 `sentinel-rules.yml` 原文。
    pub sentinel_rules: String,
}

impl ArchivedDocs {
    /// 业务作用：为远端发布和节点已应用事实生成相同的三文档身份，不混入节点环境求值结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：按固定次序和长度分隔计算的 SHA-256，任一原文字节变化都会改变摘要。
    pub(crate) fn digest(&self) -> String {
        use sha2::Digest as _;
        let mut digest = sha2::Sha256::new();
        for document in [&self.gateway, &self.interface_guard, &self.sentinel_rules] {
            digest.update((document.len() as u64).to_be_bytes());
            digest.update(document.as_bytes());
        }
        format!("{:x}", digest.finalize())
    }

    /// 业务作用：有界读取明确文档集合的原文，供基线冻结与原文发布使用，不混入本机插值结果。
    ///
    /// 参数说明：
    /// - `main`：是已加载主文档
    /// - `guard`：是主配置指定的规则路径。
    /// - `sentinel`：是主配置指定的规则路径。
    ///
    /// 返回：三份有界 UTF-8 原文；任一读取失败或超限时不产生候选身份证据。
    pub(crate) fn read(main: &Path, guard: &Path, sentinel: &Path) -> Result<Self> {
        Ok(Self {
            gateway: String::from_utf8(read_archived_bytes(main, "gateway document")?)?,
            interface_guard: String::from_utf8(read_archived_bytes(
                guard,
                "interface guard document",
            )?)?,
            sentinel_rules: String::from_utf8(read_archived_bytes(sentinel, "sentinel document")?)?,
        })
    }
}

impl ConfigHistory {
    /// 业务作用：通过唯一节点目录owner观察动作基线与文件决定，不另开目录或绕过读预算。
    ///
    /// 参数说明：
    /// - `snapshot`：当前报告冻结的活动配置。
    ///
    /// 返回：同次完整状态及可选基线；未启用、未安装、保护异常或繁忙保留明确低敏原因。
    #[cfg(feature = "node-journal")]
    pub(crate) async fn node_observation(
        &self,
        snapshot: Arc<GatewaySnapshot>,
    ) -> crate::control::journal::Observation {
        match self.node_journal.get() {
            Some(owner) => owner.observe(snapshot).await,
            None => crate::control::journal::Observation::empty("disabled"),
        }
    }

    /// 业务作用：把启动时取得的永久节点owner交给唯一文件事务，禁止安装第二份目录权威。
    ///
    /// 参数说明：
    /// - `journal`：已经持有独占目录锁并通过初始配置绑定的owner。
    ///
    /// 返回：首次安装成功，重复安装拒绝；不创建新的锁或后台任务。
    #[cfg(feature = "node-journal")]
    pub fn attach_journal(&self, journal: Arc<crate::control::journal::Journal>) -> Result<()> {
        self.node_journal
            .set(journal)
            .map_err(|_| anyhow::anyhow!("configuration history already has a node journal owner"))
    }

    /// 业务作用：候选在资源准备或文件提交前必须保持永久节点与发行集群绑定。
    ///
    /// 参数说明：
    /// - `snapshot`：完整构建但尚未提交的配置。
    ///
    /// 返回：未使用journal时无副作用；启用时身份及目录事实匹配才可继续。
    pub(crate) fn validate_candidate(&self, snapshot: &GatewaySnapshot) -> Result<()> {
        #[cfg(feature = "node-actions")]
        anyhow::ensure!(
            !snapshot
                .admin_management
                .as_ref()
                .is_some_and(|plan| plan.actions_enabled)
                || self.node_journal.get().is_some(),
            "node actions require an installed journal owner"
        );
        #[cfg(feature = "node-journal")]
        if let Some(journal) = self.node_journal.get() {
            return journal.validate_snapshot(snapshot);
        }
        let _ = snapshot;
        Ok(())
    }

    /// 业务作用：文件写锁内再次复验节点目录，避免构建后出现的未知记录被管理写入绕过。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：目录证据完整或未启用journal时成功；异常拒绝任何后续文件替换。
    fn require_journal_ready(&self) -> Result<()> {
        #[cfg(feature = "node-journal")]
        if let Some(journal) = self.node_journal.get() {
            return journal.require_idle();
        }
        Ok(())
    }

    /// 业务作用：唯一发布者在最终文件事务内确认持久文件决定，资源尚未准备好时不得调用。
    ///
    /// 参数说明：
    /// - `snapshot`：完成资源准备及最终文件门的候选，或仍活动的条件补偿基线。
    ///
    /// 返回：持久记录与完整文件集合一致并结束时成功；未启用时无副作用，失败拒绝开放候选。
    pub fn complete_local_publication(&self, snapshot: &GatewaySnapshot) -> Result<()> {
        #[cfg(feature = "node-journal")]
        if let Some(journal) = self.node_journal.get() {
            return journal.complete_local_publication(snapshot);
        }
        let _ = snapshot;
        Ok(())
    }

    /// 业务作用：构造配置历史。
    ///
    /// 参数说明：
    /// - `archive_root`: 本地版本归档目录。
    /// - `max_events`: 内存保留的最近事件数。
    pub fn new(archive_root: PathBuf, max_events: usize) -> Self {
        Self {
            candidate_fingerprint: None,
            inner: Arc::new(Mutex::new(ConfigHistoryState {
                max_events: max_events.max(1),
                next_event_id: 1,
                events: VecDeque::new(),
                archives: BTreeMap::new(),
            })),
            archive_root: Arc::new(archive_root),
            file_transaction: Arc::new(RwLock::new(())),
            #[cfg(feature = "node-journal")]
            node_journal: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// 业务作用：为一次 reload 冻结事件归因，拒绝原因不会被之后的文件改动误记到另一候选。
    ///
    /// 参数说明：
    /// - `fingerprint`：是与候选构建在同一文件读事务中取得的完整指纹。
    ///
    /// 返回：共享事件/归档 owner 的局部视图，不改变常驻历史身份。
    pub(crate) fn for_candidate(&self, fingerprint: Option<u64>) -> Self {
        Self {
            candidate_fingerprint: Some(fingerprint),
            ..self.clone()
        }
    }

    /// 业务作用：记录启动时初始配置版本。
    ///
    /// 参数说明：
    /// - `cfg_path`: 初始配置路径。
    /// - `snap`: 已上线的初始快照。
    pub fn record_initial(&self, cfg_path: &Path, snap: &GatewaySnapshot) {
        self.record_success("initial", cfg_path, 0, snap);
    }

    /// 业务作用：记录已提交快照的冻结指纹，仅在事实源仍一致时归档配置集。
    ///
    /// 参数说明：
    /// - `trigger`: 触发源。
    /// - `cfg_path`: 本次成功读取的配置路径。
    /// - `old_version`: 换版前版本。
    /// - `snap`: 已成功构建并上线的新快照。
    ///
    /// 返回：追加提交事件；归档漂移或读取失败记录 applied_unarchived，不把另一候选冒充本版归档。
    pub fn record_success(
        &self,
        trigger: &str,
        cfg_path: &Path,
        old_version: u64,
        snap: &GatewaySnapshot,
    ) {
        let fingerprint = snap.config_fingerprint;
        let archive_result = self.with_stable_local_files(|| {
            anyhow::ensure!(
                fingerprint.is_some() && config_fingerprint(cfg_path).ok() == fingerprint,
                "configuration changed before archive"
            );
            let archive = self.archive_config_set(cfg_path, snap.version)?;
            anyhow::ensure!(
                config_fingerprint(cfg_path).ok() == fingerprint,
                "configuration changed during archive"
            );
            Ok(archive)
        });
        let (status, error) = match archive_result {
            Ok(archive) => {
                self.inner.lock().archives.insert(snap.version, archive);
                ("applied".to_string(), None)
            }
            Err(err) => (
                "applied_unarchived".to_string(),
                Some(format!("archive failed: {err}")),
            ),
        };
        self.push_event(ConfigHistoryEvent {
            id: 0,
            ts_ms: now_ms(),
            trigger: trigger.to_string(),
            cfg_path: cfg_path.display().to_string(),
            status,
            old_version,
            new_version: Some(snap.version),
            candidate_version: Some(snap.version),
            summary: Some(snap.summary()),
            error,
            fingerprint,
        });
    }

    /// 业务作用：记录未发布候选的拒绝结果，reload 局部视图使用构建时冻结的来源指纹。
    ///
    /// 参数说明：
    /// - `trigger`：触发候选构建的来源。
    /// - `cfg_path`：本次读取的主配置路径。
    /// - `old_version`：当前活动快照版本。
    /// - `candidate_version`：未提交候选的版本。
    /// - `error`：阻止候选提交的错误原因。
    ///
    /// 返回：追加有界历史事件，不改变当前快照或配置文件。
    pub fn record_rejected(
        &self,
        trigger: &str,
        cfg_path: &Path,
        old_version: u64,
        candidate_version: u64,
        error: impl Into<String>,
    ) {
        self.push_event(ConfigHistoryEvent {
            id: 0,
            ts_ms: now_ms(),
            trigger: trigger.to_string(),
            cfg_path: cfg_path.display().to_string(),
            status: "rejected".to_string(),
            old_version,
            new_version: None,
            candidate_version: Some(candidate_version),
            summary: None,
            error: Some(error.into()),
            fingerprint: self
                .candidate_fingerprint
                .unwrap_or_else(|| config_fingerprint(cfg_path).ok()),
        });
    }

    /// 业务作用：记录控制面动作事件,不代表配置已经上线。
    ///
    /// 参数说明：
    /// - `trigger`: 控制面动作名。
    /// - `cfg_path`: 目标配置路径。
    /// - `old_version`: 动作发生时线上版本。
    /// - `candidate_version`: 动作目标版本。
    /// - `status`: 动作状态。
    pub fn record_control_event(
        &self,
        trigger: &str,
        cfg_path: &Path,
        old_version: u64,
        candidate_version: u64,
        status: &str,
    ) {
        self.push_event(ConfigHistoryEvent {
            id: 0,
            ts_ms: now_ms(),
            trigger: trigger.to_string(),
            cfg_path: cfg_path.display().to_string(),
            status: status.to_string(),
            old_version,
            new_version: None,
            candidate_version: Some(candidate_version),
            summary: None,
            error: None,
            fingerprint: config_fingerprint(cfg_path).ok(),
        });
    }

    /// 业务作用：返回 Admin 可序列化的历史快照。
    pub fn snapshot(&self) -> ConfigHistorySnapshot {
        let state = self.inner.lock();
        ConfigHistorySnapshot {
            events: state.events.iter().cloned().collect(),
            archived_versions: state.archives.keys().copied().collect(),
        }
    }

    /// 业务作用：与本进程文件发布互斥地读取、构建或发布完整快照，避免观察三文档中间态。
    ///
    /// 参数说明：
    /// - `build`：是不包含异步等待的同步操作。
    ///
    /// 返回：原操作的返回值；作用域结束释放读事务。
    pub(crate) fn with_stable_local_files<T>(&self, build: impl FnOnce() -> T) -> T {
        let _transaction = self.file_transaction.read();
        build()
    }

    /// 业务作用：把远端完整配置物化与本地发布纳入同一写事务，阻止最终快照复验期间换文件。
    ///
    /// 参数说明：
    /// - `publish`：是有界同步物化操作，不得重入文件事务或执行异步等待。
    ///
    /// 返回：节点目录证据成立后执行原操作；门禁失败不物化文件，作用域结束释放独占事务。
    pub(crate) fn with_exclusive_local_files<T>(
        &self,
        publish: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let _transaction = self.file_transaction.write();
        self.require_journal_ready()?;
        publish()
    }

    /// 业务作用：读取某归档版本的三文件配置原文。
    ///
    /// 供 Nacos 配置源的 CAS 回滚使用:把归档版本的原文 compare-and-set 写回 Nacos dataId,
    /// 本地文件源则在完整候选验证后恢复原文，两种来源不能混用提交路径。
    ///
    /// 参数说明：
    /// - `version`: 已归档版本号。
    ///
    /// 返回：
    /// 该版本三文件(gateway/interface-guard/sentinel-rules)的原文;版本未归档或读文件失败时 `Err`。
    pub fn read_archived(&self, version: u64) -> Result<ArchivedDocs> {
        let archive = {
            let state = self.inner.lock();
            state
                .archives
                .get(&version)
                .cloned()
                .with_context(|| format!("config version `{version}` is not archived"))?
        };
        Ok(ArchivedDocs {
            gateway: read_archived_text(&archive.gateway, "archived gateway")?,
            interface_guard: read_archived_text(
                &archive.interface_guard,
                "archived interface guard",
            )?,
            sentinel_rules: read_archived_text(&archive.sentinel_rules, "archived sentinel rules")?,
        })
    }

    /// 业务作用：在候选构建前冻结活动原文基线，快照已发布但归档尚未完成时仍可安全比较回滚。
    ///
    /// 参数说明：
    /// - `paths`：活动快照经过完整合并后确定的三个真实来源路径。
    /// - `expected`：同一活动快照保存的完整依赖指纹。
    ///
    /// 返回：读取前后指纹一致时返回有界原文；来源已变返回空，读取失败不提供部分基线。
    pub(crate) fn read_current_documents(
        &self,
        paths: &crate::config::candidate::Paths,
        expected: u64,
    ) -> Result<Option<ArchivedDocs>> {
        self.with_stable_local_files(|| {
            // 未提交的外部文件不能被当作活动配置基线；后续写事务仍需再次比较同一原文集合。
            if config_fingerprint(&paths.gateway).ok() != Some(expected) {
                return Ok(None);
            }
            let documents = ArchivedDocs::read(&paths.gateway, &paths.guard, &paths.sentinel)?;
            if config_fingerprint(&paths.gateway).ok() != Some(expected) {
                return Ok(None);
            }
            Ok(Some(documents))
        })
    }

    /// 业务作用：把配置事件加入有界历史，保留最新事实而不让持续重载无限增长内存。
    fn push_event(&self, mut event: ConfigHistoryEvent) {
        let mut state = self.inner.lock();
        event.id = state.next_event_id;
        state.next_event_id = state.next_event_id.wrapping_add(1).max(1);
        state.events.push_back(event);
        while state.events.len() > state.max_events {
            state.events.pop_front();
        }
    }

    /// 业务作用：归档同一配置集的主文件和规则文件，为回滚保留可重建的输入。
    fn archive_config_set(&self, cfg_path: &Path, version: u64) -> Result<ArchivedConfigSet> {
        let cfg = load_gateway_config(cfg_path)
            .with_context(|| format!("read config set for archive {}", cfg_path.display()))?;
        let guard = resolve_relative(cfg_path, &cfg.interface_guard_file);
        let sentinel = resolve_relative(cfg_path, &cfg.sentinel_rules_file);
        let dir = self.archive_root.join(format!("v{version}"));
        fs::create_dir_all(&dir)
            .with_context(|| format!("create config archive dir {}", dir.display()))?;
        let gateway_dst = dir.join("gateway.yml");
        let guard_dst = dir.join("interface-guard.yml");
        let sentinel_dst = dir.join("sentinel-rules.yml");
        write_bounded_archive(cfg_path, &gateway_dst, "gateway config")?;
        write_bounded_archive(&guard, &guard_dst, "interface guard")?;
        write_bounded_archive(&sentinel, &sentinel_dst, "sentinel rules")?;
        Ok(ArchivedConfigSet {
            gateway: gateway_dst,
            interface_guard: guard_dst,
            sentinel_rules: sentinel_dst,
        })
    }
}

/// 业务作用：有界读取归档文本，拒绝损坏编码或超过历史文件上限的内容。
fn read_archived_text(path: &Path, kind: &str) -> Result<String> {
    let bytes = read_archived_bytes(path, kind)?;
    String::from_utf8(bytes).with_context(|| format!("{kind} {} is not UTF-8", path.display()))
}

/// 业务作用：按历史文件字节上限读取归档，避免归档目录成为无界内存输入。
fn read_archived_bytes(path: &Path, kind: &str) -> Result<Vec<u8>> {
    crate::io::bounded_io::read_file(path, MAX_ARCHIVED_DOCUMENT_BYTES, kind)
}

/// 业务作用：在写入历史归档前验证大小，保持归档容量的配置合同。
fn write_bounded_archive(src: &Path, dst: &Path, kind: &str) -> Result<()> {
    let bytes = crate::io::bounded_io::read_file(src, MAX_ARCHIVED_DOCUMENT_BYTES, kind)?;
    fs::write(dst, bytes)
        .with_context(|| format!("archive {kind} {} to {}", src.display(), dst.display()))
}

/// 业务作用：提供历史记录的 Unix 毫秒时间，用于排序与过期判断。
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}
