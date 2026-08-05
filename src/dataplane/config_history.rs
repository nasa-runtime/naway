//! 配置版本历史与本地回滚归档。
//!
//! 只服务控制面:reload 成功/失败记录低频审计事件,成功版本归档三文件配置集,供 Admin 查询与本地 rollback。

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
    inner: Arc<Mutex<ConfigHistoryState>>,
    archive_root: Arc<PathBuf>,
    /// 本进程 local rollback 写三文件时独占；reload build 持共享锁，不能观察到中间态。
    file_transaction: Arc<RwLock<()>>,
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
pub struct ArchivedDocs {
    /// 主配置 `gateway.yml` 原文。
    pub gateway: String,
    /// 接口守卫 `interface-guard.yml` 原文。
    pub interface_guard: String,
    /// Sentinel 规则 `sentinel-rules.yml` 原文。
    pub sentinel_rules: String,
}

impl ConfigHistory {
    /// 构造配置历史。
    ///
    /// # 参数
    /// - `archive_root`: 本地版本归档目录。
    /// - `max_events`: 内存保留的最近事件数。
    pub fn new(archive_root: PathBuf, max_events: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ConfigHistoryState {
                max_events: max_events.max(1),
                next_event_id: 1,
                events: VecDeque::new(),
                archives: BTreeMap::new(),
            })),
            archive_root: Arc::new(archive_root),
            file_transaction: Arc::new(RwLock::new(())),
        }
    }

    /// 记录启动时初始配置版本。
    ///
    /// # 参数
    /// - `cfg_path`: 初始配置路径。
    /// - `snap`: 已上线的初始快照。
    pub fn record_initial(&self, cfg_path: &Path, snap: &GatewaySnapshot) {
        self.record_success("initial", cfg_path, 0, snap);
    }

    /// 记录成功上线的配置版本,并尽力归档该配置集。
    ///
    /// # 参数
    /// - `trigger`: 触发源。
    /// - `cfg_path`: 本次成功读取的配置路径。
    /// - `old_version`: 换版前版本。
    /// - `snap`: 已成功构建并上线的新快照。
    pub fn record_success(
        &self,
        trigger: &str,
        cfg_path: &Path,
        old_version: u64,
        snap: &GatewaySnapshot,
    ) {
        let fingerprint = config_fingerprint(cfg_path).ok();
        let archive_result = self.archive_config_set(cfg_path, snap.version);
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

    /// 记录被拒绝的配置候选。
    ///
    /// # 参数
    /// - `trigger`: 触发源。
    /// - `cfg_path`: 本次读取的配置路径。
    /// - `old_version`: 当前线上版本。
    /// - `candidate_version`: 候选版本号。
    /// - `error`: 拒绝原因。
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
            fingerprint: config_fingerprint(cfg_path).ok(),
        });
    }

    /// 记录控制面动作事件,不代表配置已经上线。
    ///
    /// # 参数
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

    /// 返回 Admin 可序列化的历史快照。
    pub fn snapshot(&self) -> ConfigHistorySnapshot {
        let state = self.inner.lock();
        ConfigHistorySnapshot {
            events: state.events.iter().cloned().collect(),
            archived_versions: state.archives.keys().copied().collect(),
        }
    }

    /// 将归档版本恢复到当前本地配置文件位置。
    ///
    /// # 参数
    /// - `version`: 已归档版本。
    /// - `target_cfg_path`: 当前本地 `gateway.yml`。
    pub fn restore_to(&self, version: u64, target_cfg_path: &Path) -> Result<()> {
        // 与 apply_reload 的共享锁互斥。锁只覆盖同步本地文件操作，不跨任何 await。
        let _transaction = self.file_transaction.write();
        let archive = {
            let state = self.inner.lock();
            state
                .archives
                .get(&version)
                .cloned()
                .with_context(|| format!("config version `{version}` is not archived"))?
        };
        let target_cfg = load_gateway_config(target_cfg_path)
            .with_context(|| format!("read rollback target {}", target_cfg_path.display()))?;
        let target_guard = resolve_relative(target_cfg_path, &target_cfg.interface_guard_file);
        let target_sentinel = resolve_relative(target_cfg_path, &target_cfg.sentinel_rules_file);
        // 三个来源先全部验证/有界读完，避免 gateway 已替换后才发现第二个归档损坏或超限。
        let gateway = read_archived_bytes(&archive.gateway, "rollback gateway")?;
        let guard = read_archived_bytes(&archive.interface_guard, "rollback interface guard")?;
        let sentinel = read_archived_bytes(&archive.sentinel_rules, "rollback sentinel rules")?;
        // 主配置最后替换，缩短异常中止时“新 gateway 指向旧依赖”的窗口。三个固定路径在文件系统
        // 层仍不是一个事务；跨进程/掉电严格原子需要后续改成版本目录 + 单指针切换。
        write_atomic(&guard, &target_guard)?;
        write_atomic(&sentinel, &target_sentinel)?;
        write_atomic(&gateway, target_cfg_path)?;
        Ok(())
    }

    /// 在本地配置文件稳定期间执行一次同步候选构建。
    ///
    /// local rollback 持独占锁替换三份文件；reload worker 用本方法持共享锁读取并编译，因而
    /// 本进程不会发布三文件中间态。闭包不得执行异步等待。
    pub(crate) fn with_stable_local_files<T>(&self, build: impl FnOnce() -> T) -> T {
        let _transaction = self.file_transaction.read();
        build()
    }

    /// 读取某归档版本的三文件配置原文。
    ///
    /// 供 Nacos 配置源的 CAS 回滚使用:把归档版本的原文 compare-and-set 写回 Nacos dataId,
    /// 而不是像本地文件源那样直接覆盖本地文件([`restore_to`](Self::restore_to))。
    ///
    /// # 参数
    /// - `version`: 已归档版本号。
    ///
    /// # 返回
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

    fn push_event(&self, mut event: ConfigHistoryEvent) {
        let mut state = self.inner.lock();
        event.id = state.next_event_id;
        state.next_event_id = state.next_event_id.wrapping_add(1).max(1);
        state.events.push_back(event);
        while state.events.len() > state.max_events {
            state.events.pop_front();
        }
    }

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

fn read_archived_text(path: &Path, kind: &str) -> Result<String> {
    let bytes = read_archived_bytes(path, kind)?;
    String::from_utf8(bytes).with_context(|| format!("{kind} {} is not UTF-8", path.display()))
}

fn read_archived_bytes(path: &Path, kind: &str) -> Result<Vec<u8>> {
    crate::bounded_io::read_file(path, MAX_ARCHIVED_DOCUMENT_BYTES, kind)
}

fn write_bounded_archive(src: &Path, dst: &Path, kind: &str) -> Result<()> {
    let bytes = crate::bounded_io::read_file(src, MAX_ARCHIVED_DOCUMENT_BYTES, kind)?;
    fs::write(dst, bytes)
        .with_context(|| format!("archive {kind} {} to {}", src.display(), dst.display()))
}

fn write_atomic(bytes: &[u8], dst: &Path) -> Result<()> {
    let Some(parent) = dst.parent() else {
        anyhow::bail!("invalid rollback target {}", dst.display());
    };
    fs::create_dir_all(parent)
        .with_context(|| format!("create rollback target dir {}", parent.display()))?;
    let name = dst
        .file_name()
        .and_then(|name| name.to_str())
        .context("rollback target file name is invalid")?;
    let tmp = parent.join(format!(".{name}.rollback.tmp"));
    fs::write(&tmp, bytes).with_context(|| format!("write rollback temp {}", tmp.display()))?;
    fs::rename(&tmp, dst).with_context(|| format!("publish rollback target {}", dst.display()))?;
    Ok(())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}
