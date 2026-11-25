//! 业务范围文件输出只接收已选定目的地的格式化记录。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{ensure, Context, Result};
use nasa::log::FileLogConfig;
use tracing::Level;

const MAX_ARCHIVE_SCAN: usize = 100_000;
const SECONDS_PER_DAY: u64 = 86_400;

pub(super) struct Files {
    info: Append,
    error: Option<Append>,
}

struct Append {
    path: PathBuf,
    prefix: &'static str,
    file: File,
    bytes: u64,
}

impl Files {
    /// 业务作用：在业务配置发布前确认同一范围的全部文件都可写。
    ///
    /// 参数说明：
    /// - `directory`：已经定位的独立日志目录。
    /// - `config`：经 NASA 校验的级别分流和日志文件策略。
    ///
    /// 返回：候选日志文件已全部打开。任一文件失败由调用方保持原发布代。
    pub(super) fn open(directory: &Path, config: &FileLogConfig) -> Result<Self> {
        let info = Append::open(directory, "info")?;
        let error = config
            .split_error_file
            .then(|| Append::open(directory, "error"))
            .transpose()?;
        Ok(Self {
            info,
            error,
        })
    }

    /// 业务作用：在该范围成为活动日志后清理到期归档，候选准备时不删除原业务历史。
    ///
    /// 参数说明：
    /// - `config`：该范围实际启用的容量与保留规则。
    ///
    /// 返回：所有文件类别的归档完成扫描和清理时成功。读取或删除失败可随下次滚动重试。
    pub(super) fn prune(&self, config: &FileLogConfig) -> Result<()> {
        self.info.prune(config)?;
        if let Some(error) = &self.error {
            error.prune(config)?;
        }
        Ok(())
    }

    /// 业务作用：只向当前实例或模块输出已选定的记录，同时提供独立的 ERROR 过滤文件。
    ///
    /// 参数说明：
    /// - `config`：生成该记录的活动日志代持有的文件规则。
    /// - `level`：本记录实际 tracing 级别。
    /// - `record`：完成渲染的单条有界日志。
    ///
    /// 返回：按策略写入全部目标时成功。I/O 异常交给同一输出报告，不转写全局文件。
    pub(super) fn append(
        &mut self,
        config: &FileLogConfig,
        level: Level,
        record: &[u8],
    ) -> Result<()> {
        let info = self.info.append(config, record);
        let error = self
            .error
            .as_mut()
            .filter(|_| level == Level::ERROR)
            .map(|error| error.append(config, record))
            .transpose();
        info.and(error.map(|_| ()))
    }
}

impl Append {
    /// 业务作用：连接单个规范日志文件，避免配置回读时把符号链接或设备打开成为日志目的地。
    ///
    /// 参数说明：
    /// - `directory`：业务范围的独立目录。
    /// - `prefix`：由日志类别确定的文件名，只有 info 和 error。
    ///
    /// 返回：保留现有原文并从当前字节数继续写入。目标非普通文件、存在其它硬链接或无法打开时失败。
    fn open(directory: &Path, prefix: &'static str) -> Result<Self> {
        let path = directory.join(format!("{prefix}.log"));
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .with_context(|| format!("open {prefix} log destination"))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "log destination must be a regular file with one path"
        );
        Ok(Self {
            path,
            prefix,
            file,
            bytes: metadata.len(),
        })
    }

    /// 业务作用：按原始记录边界滚动，避免同一条日志在两个文件中各保留一半。
    ///
    /// 参数说明：
    /// - `config`：当前记录对应的大小与保留策略。
    /// - `record`：完整日志记录。
    ///
    /// 返回：日志已经写入时成功，滚动或写入异常时保留 I/O 原因。
    fn append(&mut self, config: &FileLogConfig, record: &[u8]) -> Result<()> {
        // 在途旧代和活动代可以共用目录。后台任务串行写入，每条记录先确认现行文件身份，避免写入已归档句柄。
        let actual = self.file.metadata()?;
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if (metadata.dev(), metadata.ino()) == (actual.dev(), actual.ino()) => {
                ensure!(
                    metadata.is_file() && metadata.nlink() == 1,
                    "scoped log path changed"
                );
                self.bytes = metadata.len();
            }
            Ok(_) => {
                *self = Self::open(
                    self.path.parent().context("scoped log directory missing")?,
                    self.prefix,
                )?;
            }
            Err(error) => return Err(error).context("read current scoped log identity"),
        }
        let bytes = record.len() as u64;
        if self.bytes != 0 && self.bytes.saturating_add(bytes) > config.max_file_size {
            // 滚动先安装新的写入目的地再清理历史，避免不可写的新文件使本记录无处落盘。
            self.roll()?;
            if let Err(error) = self.prune(config) {
                tracing::warn!(%error, category = self.prefix, "scoped log archive cleanup deferred");
            }
        }
        self.file.write_all(record)?;
        self.bytes = self.bytes.saturating_add(bytes);
        Ok(())
    }

    /// 业务作用：切换活动输出句柄，并为旧文件保留唯一可辨认的归档名称。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有新句柄可写且入口文件已更换时采用新文件。失败保留旧文件及其尚可恢复的路径。
    fn roll(&mut self) -> Result<()> {
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| anyhow::anyhow!("create scoped log archive identity: {error}"))?;
        let nonce = u128::from_be_bytes(nonce);
        let next = self
            .path
            .with_file_name(format!(".{}.naway-log-{nonce:032x}.pending", self.prefix));
        let archive = self.path.with_file_name(format!(
            "{}.naway-log-{}-{nonce:032x}.log",
            self.prefix,
            chrono::Utc::now().format("%Y%m%dT%H%M%S")
        ));
        let candidate = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(&next)?;
        let result = (|| -> Result<()> {
            let actual = self.file.metadata()?;
            let current = fs::symlink_metadata(&self.path)?;
            ensure!(
                current.is_file()
                    && current.nlink() == 1
                    && (current.dev(), current.ino()) == (actual.dev(), actual.ino()),
                "scoped log changed during rotation"
            );
            // 先保存旧原文，持有者仍保留打开的记录句柄。意外停机后可在保留归档的前提下重新创建入口。
            ensure!(
                !archive.try_exists()?,
                "scoped log archive identity already exists"
            );
            fs::rename(&self.path, &archive)?;
            if let Err(error) = fs::rename(&next, &self.path) {
                // 入口被外部替换时保留它和本次归档，避免补偿覆盖后来者的文件。
                if fs::symlink_metadata(&self.path)
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
                {
                    let _ = fs::rename(&archive, &self.path);
                }
                return Err(error).context("install scoped log after rotation");
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&next);
            return Err(error);
        }
        self.file = candidate;
        self.bytes = 0;
        Ok(())
    }

    /// 业务作用：按文件时间和数量上界清理本文件类别生成的归档，不把现有活动文件当作可回收历史。
    ///
    /// 参数说明：
    /// - `config`：本文件类别的历史天数及归档总容量。
    ///
    /// 返回：所有过期或超量归档被回收时成功；路径类型不可信或读取预算超限时拒绝本轮清理。
    fn prune(&self, config: &FileLogConfig) -> Result<()> {
        let directory = self.path.parent().context("scoped log directory missing")?;
        let archive_prefix = format!("{}.naway-log-", self.prefix);
        let mut archives = Vec::new();
        let mut used = 0_u64;
        for (index, entry) in fs::read_dir(directory)?.enumerate() {
            ensure!(
                index < MAX_ARCHIVE_SCAN,
                "scoped log archive scan limit reached"
            );
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(&archive_prefix) || !name.ends_with(".log") {
                continue;
            }
            let metadata = entry.metadata()?;
            if metadata.is_file() && metadata.nlink() == 1 {
                let age = metadata.modified()?;
                let bytes = metadata.len();
                used = used.saturating_add(bytes);
                archives.push((age, entry.path(), bytes));
            }
        }
        archives.sort_unstable();
        let now = SystemTime::now();
        let expires = u64::try_from(config.max_history_days)
            .ok()
            .map(|days| Duration::from_secs(days.saturating_mul(SECONDS_PER_DAY)));
        for (modified, path, bytes) in archives {
            let expired = expires.is_some_and(|duration| {
                now.duration_since(modified).is_ok_and(|age| age > duration)
            });
            if expired || (config.total_size_cap != 0 && used > config.total_size_cap) {
                // 仅删除扫描认可的归档路径。并行清理已经撤销该文件时也释放本轮容量计数。
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("prune scoped log archive"),
                }
                used = used.saturating_sub(bytes);
            }
        }
        Ok(())
    }
}
