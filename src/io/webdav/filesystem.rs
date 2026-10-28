//! 受目录能力约束的 DAV 文件系统；写入先进入本次请求的临时文件，成功后原子替换。

use crate::config::webdav::WebDavCfg;
use cap_std::fs::{Dir, Metadata, MetadataExt};
use dav_server::{davpath::DavPath, fs::*};
use parking_lot::Mutex;
use std::{
    fmt,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::SystemTime,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub(super) type Authority = Arc<dyn Fn() -> bool + Send + Sync>;

pub(super) struct Root {
    pub dir: Arc<Dir>,
    pub serial: Arc<tokio::sync::Mutex<()>>,
    pub locks: super::locks::Table,
    _exclusive: std::fs::File,
}

impl Root {
    /// 业务作用：准备目录能力并取得单进程独占权，阻止多个本地锁权威同时写同一目录。
    ///
    /// 参数说明：
    /// - `path`：构建期已解析的固定根目录。
    ///
    /// 返回：目录文件描述符和进程锁共同存活的根；不创建或删除业务文件。
    pub fn open(path: &Path) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            path.parent().is_some(),
            "WebDAV cannot expose a filesystem root"
        );
        let dir = Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
        let file = dir.try_clone()?.into_std_file();
        file.try_lock()
            .map_err(|_| anyhow::anyhow!("WebDAV root already has another process authority"))?;
        Ok(Arc::new(Self {
            dir: Arc::new(dir),
            serial: Arc::new(tokio::sync::Mutex::new(())),
            locks: Default::default(),
            _exclusive: file,
        }))
    }
}

#[derive(Clone)]
pub(super) struct FileSystem {
    root: Arc<Root>,
    cfg: Arc<WebDavCfg>,
    authority: Authority,
    pending: Arc<Mutex<Option<Pending>>>,
    _lease: Arc<tokio::sync::OwnedMutexGuard<()>>,
}

struct Pending {
    root: Arc<Root>,
    temporary: PathBuf,
    target: PathBuf,
    expected: Option<u64>,
    written: Arc<AtomicU64>,
    committed: bool,
}

impl Drop for Pending {
    /// 业务作用：取消或协议拒绝时只撤销本次创建的精确临时文件，原目标保持不变。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尽力移除未发布文件；失败记录固定告警并留给存储管理者核查。
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.root.dir.remove_file(&self.temporary) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("WebDAV uncommitted temporary file could not be removed");
                }
            }
        }
    }
}

impl FileSystem {
    /// 业务作用：为单次有界、已串行化的资源操作建立目录和当前权威视图。
    ///
    /// 参数说明：
    /// - `root`：跨快照共享的根目录和锁权威。
    /// - `cfg`：本次请求固定的资源预算。
    /// - `authority`：在执行外部副作用前复验配置代次与来源期限的回调。
    /// - `lease`：根的独占请求门；阻塞任务通过共享持有避免取消后提前开放下一操作。
    ///
    /// 返回：请求专用文件系统；克隆共享同一待提交文件，不扩大访问权限。
    pub fn new(
        root: Arc<Root>,
        cfg: Arc<WebDavCfg>,
        authority: Authority,
        lease: tokio::sync::OwnedMutexGuard<()>,
    ) -> Self {
        Self {
            root,
            cfg,
            authority,
            pending: Arc::new(Mutex::new(None)),
            _lease: Arc::new(lease),
        }
    }

    /// 业务作用：在标准协议确认完整成功后发布 PUT，避免短上传或取消截断既有文件。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有暂存写入时无副作用；长度、权威、配额全部成立后原子替换并同步目录。
    pub async fn commit(&self) -> FsResult<()> {
        let this = self.clone();
        blocking(move || {
            let Some(mut pending) = this.pending.lock().take() else {
                return Ok(());
            };
            let written = pending.written.load(Ordering::Acquire);
            if pending.expected.is_some_and(|expected| expected != written) {
                return Err(FsError::GeneralFailure);
            }
            this.check_authority()?;
            this.path_check(&pending.target, true)?;
            this.root
                .dir
                .open(&pending.temporary)
                .map_err(error)?
                .sync_all()
                .map_err(error)?;
            // 临时文件也计入当前磁盘使用，原子发布不能靠并发上传绕过目录总配额。
            this.scan_root()?;
            // 刷盘和全根计量都可能跨过撤权时刻，真正发布目录项前必须再确认许可。
            this.check_authority()?;
            this.root
                .dir
                .rename(&pending.temporary, &this.root.dir, &pending.target)
                .map_err(error)?;
            pending.committed = true;
            this.sync_parent(&pending.target)
        })
        .await
    }

    /// 业务作用：复验单次请求仍持有执行当前存储动作的权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前配置与来源证据有效时成功，失权立即拒绝，不继续写入。
    fn check_authority(&self) -> FsResult<()> {
        if (self.authority)() {
            Ok(())
        } else {
            Err(FsError::Forbidden)
        }
    }

    /// 业务作用：在标准引擎开始覆盖目标前证明整个操作范围有界，避免先删除再发现预算不成立。
    ///
    /// 参数说明：
    /// - `method`：已经过 allowlist 的 DAV 方法。
    /// - `source`：挂载点剥离后的源资源。
    /// - `destination`：COPY/MOVE 的同根目标，其它方法为空。
    ///
    /// 返回：全根条目和字节、重定位深度及保守复制配额均成立；失败不改变文件。
    pub async fn preflight(
        &self,
        method: &str,
        source: &DavPath,
        destination: Option<&DavPath>,
    ) -> FsResult<()> {
        let source = self.path(source)?;
        let destination = destination.map(|path| self.path(path)).transpose()?;
        let method = method.to_string();
        let this = self.clone();
        blocking(move || {
            this.check_authority()?;
            let (used_entries, used_bytes) = this.scan_root()?;
            this.path_check(&source, matches!(method.as_str(), "PUT" | "MKCOL" | "LOCK"))?;
            if source == Path::new(".")
                && matches!(
                    method.as_str(),
                    "DELETE" | "COPY" | "MOVE" | "PUT" | "MKCOL"
                )
            {
                return Err(FsError::Forbidden);
            }
            let Some(target) = destination else {
                return Ok(());
            };
            this.path_check(&target, true)?;
            if target == Path::new(".")
                || target.starts_with(&source)
                || source.starts_with(&target)
            {
                return Err(FsError::Forbidden);
            }
            let mut stack = vec![source.clone()];
            let (mut entries, mut bytes) = (0usize, 0u64);
            while let Some(path) = stack.pop() {
                this.check_authority()?;
                entries += 1;
                if entries > this.cfg.max_entries {
                    return Err(FsError::TooLarge);
                }
                let relative = path.strip_prefix(&source).map_err(|_| FsError::Forbidden)?;
                if target.components().count() + relative.components().count()
                    > this.cfg.max_path_depth
                {
                    return Err(FsError::Forbidden);
                }
                let meta = this.root.dir.symlink_metadata(&path).map_err(error)?;
                check_metadata(&meta)?;
                if meta.is_dir() {
                    for item in this.root.dir.read_dir(&path).map_err(error)? {
                        let item = item.map_err(error)?;
                        if item
                            .file_name()
                            .to_str()
                            .is_none_or(|name| name.starts_with('.'))
                        {
                            return Err(FsError::Forbidden);
                        }
                        stack.push(path.join(item.file_name()));
                        if stack.len() > this.cfg.max_entries {
                            return Err(FsError::TooLarge);
                        }
                    }
                } else {
                    bytes = bytes.checked_add(meta.len()).ok_or(FsError::TooLarge)?;
                }
            }
            // 覆盖对象尚未删除时按源的完整副本预留空间，失败不会先损坏原目标。
            if method == "COPY"
                && (used_entries.saturating_add(entries).saturating_add(1) > this.cfg.max_entries
                    || used_bytes.saturating_add(bytes) > this.cfg.max_total_bytes)
            {
                return Err(FsError::InsufficientStorage);
            }
            Ok(())
        })
        .await
    }

    /// 业务作用：限制每个 DAV 路径为非隐藏的相对普通组件，阻断目录能力之外的解释。
    ///
    /// 参数说明：
    /// - `path`：协议引擎已经解码的资源路径。
    ///
    /// 返回：根内相对路径；隐藏、过深、非法 UTF-8 或非普通组件拒绝。
    fn path(&self, path: &DavPath) -> FsResult<PathBuf> {
        let relative = path.as_rel_ospath();
        let mut count = 0;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(FsError::Forbidden);
            };
            let Some(name) = name.to_str() else {
                return Err(FsError::Forbidden);
            };
            count += 1;
            if count > self.cfg.max_path_depth
                || name.starts_with('.')
                || name.contains(['\\', '\0'])
                || name.len() > 255
            {
                return Err(FsError::Forbidden);
            }
        }
        Ok(if relative.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            relative.to_path_buf()
        })
    }

    /// 业务作用：拒绝符号链接、特殊文件和多硬链接文件，实际打开仍由目录能力防并发逃逸。
    ///
    /// 参数说明：
    /// - `path`：已经验证的相对路径。
    /// - `missing_leaf`：是否允许仅最后一段尚不存在。
    ///
    /// 返回：全部已有组件合法；缺失中间目录或不合法文件类型拒绝。
    fn path_check(&self, path: &Path, missing_leaf: bool) -> FsResult<()> {
        let mut current = PathBuf::new();
        let count = path.components().count();
        for (index, component) in path.components().enumerate() {
            current.push(component);
            match self.root.dir.symlink_metadata(&current) {
                Ok(meta) => {
                    check_metadata(&meta)?;
                    if index + 1 < count && !meta.is_dir() {
                        return Err(FsError::Forbidden);
                    }
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::NotFound
                        && missing_leaf
                        && index + 1 == count => {}
                Err(err) => return Err(error(err)),
            }
        }
        Ok(())
    }

    /// 业务作用：在写入前统计整个受管目录的条目、深度与磁盘字节，隐藏临时文件也不能逃避配额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界使用量；预算耗尽或危险文件类型出现时拒绝后续动作。
    pub fn scan_root(&self) -> FsResult<(usize, u64)> {
        let mut stack = vec![(PathBuf::from("."), 0usize)];
        let (mut count, mut bytes) = (0usize, 0u64);
        while let Some((path, depth)) = stack.pop() {
            self.check_authority()?;
            for item in self.root.dir.read_dir(&path).map_err(error)? {
                self.check_authority()?;
                let item = item.map_err(error)?;
                count += 1;
                if count > self.cfg.max_entries || depth + 1 > self.cfg.max_path_depth {
                    return Err(FsError::InsufficientStorage);
                }
                let meta = item.metadata().map_err(error)?;
                check_metadata(&meta)?;
                if meta.is_dir() {
                    stack.push((path.join(item.file_name()), depth + 1));
                } else {
                    if meta.len() > self.cfg.max_file_bytes {
                        return Err(FsError::TooLarge);
                    }
                    bytes = bytes
                        .checked_add(meta.len())
                        .ok_or(FsError::InsufficientStorage)?;
                    if bytes > self.cfg.max_total_bytes {
                        return Err(FsError::InsufficientStorage);
                    }
                }
            }
        }
        Ok((count, bytes))
    }

    /// 业务作用：同步实际变更的父目录，嵌套资源不能只同步根目录。
    ///
    /// 参数说明：
    /// - `path`：已经创建、删除或原子替换的资源相对路径。
    ///
    /// 返回：父目录项持久化成功；失败不能报告持久化成功。
    fn sync_parent(&self, path: &Path) -> FsResult<()> {
        self.root
            .dir
            .open_dir(
                path.parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )
            .map_err(error)?
            .into_std_file()
            .sync_all()
            .map_err(error)
    }
}

/// 业务作用：在异步 worker 之外执行受条目与字节预算约束的文件系统调用。
///
/// 参数说明：
/// - `operation`：已持有根请求名额的固定文件操作。
///
/// 返回：操作结果；线程任务失败作为存储错误返回。
async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> FsResult<T> + Send + 'static,
) -> FsResult<T> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| FsError::GeneralFailure)?
}

/// 业务作用：把系统错误归入稳定 DAV 状态，不向客户端输出绝对文件路径。
///
/// 参数说明：
/// - `value`：文件系统原始错误。
///
/// 返回：稳定、低敏的资源拒绝或存储失败类别。
fn error(value: std::io::Error) -> FsError {
    match value.kind() {
        std::io::ErrorKind::NotFound => FsError::NotFound,
        std::io::ErrorKind::AlreadyExists => FsError::Exists,
        std::io::ErrorKind::PermissionDenied => FsError::Forbidden,
        _ => FsError::GeneralFailure,
    }
}

/// 业务作用：只允许普通文件和目录进入 DAV 能力域，拒绝可越过根隔离的硬链接别名。
///
/// 参数说明：
/// - `meta`：不跟随符号链接取得的文件元数据。
///
/// 返回：普通单链接文件或目录成功；链接和设备等类型拒绝。
fn check_metadata(meta: &Metadata) -> FsResult<()> {
    if meta.is_symlink()
        || !(meta.is_dir() || meta.is_file())
        || (meta.is_file() && meta.nlink() > 1)
    {
        return Err(FsError::Forbidden);
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct Meta(Metadata);
impl DavMetaData for Meta {
    /// 业务作用：向 DAV 响应提供已打开资源的长度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：文件元数据报告的字节数。
    fn len(&self) -> u64 {
        self.0.len()
    }
    /// 业务作用：生成资源修改时间与条件请求证据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：文件系统时间；不可取得时明确拒绝该属性。
    fn modified(&self) -> FsResult<SystemTime> {
        self.0.modified().map(|time| time.into_std()).map_err(error)
    }
    /// 业务作用：区分 DAV collection 与文件资源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：目录为 true，普通文件为 false。
    fn is_dir(&self) -> bool {
        self.0.is_dir()
    }
}

struct Entry {
    name: Vec<u8>,
    meta: Meta,
}
impl DavDirEntry for Entry {
    /// 业务作用：返回已经验证的单段资源名，不泄露绝对根目录。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：单段 UTF-8 文件名的字节。
    fn name(&self) -> Vec<u8> {
        self.name.clone()
    }
    /// 业务作用：向有界目录枚举提供同次读取的元数据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：资源元数据快照，不额外遍历目录。
    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        Box::pin(std::future::ready(Ok(
            Box::new(self.meta.clone()) as Box<dyn DavMetaData>
        )))
    }
}

struct File {
    file: tokio::fs::File,
    written: Arc<AtomicU64>,
    max_bytes: u64,
    writable: bool,
    authority: Authority,
}
impl fmt::Debug for File {
    /// 业务作用：提供不包含路径或身份的文件句柄诊断。
    ///
    /// 参数说明：
    /// - `f`：诊断格式目标。
    ///
    /// 返回：固定描述，不暴露本地资源定位信息。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundedDavFile")
    }
}

impl DavFile for File {
    /// 业务作用：以打开的描述符生成响应和条件请求所需元数据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前文件元数据；I/O 失败不伪造属性。
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        Box::pin(async move {
            Ok(Box::new(Meta(Metadata::from_just_metadata(
                self.file.metadata().await.map_err(error)?,
            ))) as Box<dyn DavMetaData>)
        })
    }
    /// 业务作用：把任意 Buf 输入分成固定块，保持上传内存不随实体长度增长。
    ///
    /// 参数说明：
    /// - `buf`：本次收到的实体片段。
    ///
    /// 返回：全部片段写入暂存文件；权威失效或预算不足立即拒绝。
    fn write_buf(&mut self, mut buf: Box<dyn bytes::Buf + Send>) -> FsFuture<'_, ()> {
        Box::pin(async move {
            while buf.has_remaining() {
                let amount = buf.chunk().len().min(16 * 1024);
                if amount == 0 {
                    return Err(FsError::GeneralFailure);
                }
                self.write_bytes(bytes::Bytes::copy_from_slice(&buf.chunk()[..amount]))
                    .await?;
                buf.advance(amount);
            }
            Ok(())
        })
    }
    /// 业务作用：在每块上传前验证权威与剩余磁盘预算，不触碰原目标文件。
    ///
    /// 参数说明：
    /// - `buf`：可借用传递的单个实体片段。
    ///
    /// 返回：写入暂存文件并推进实收字节；超限、取消或存储错误拒绝。
    fn write_bytes(&mut self, buf: bytes::Bytes) -> FsFuture<'_, ()> {
        Box::pin(async move {
            if !self.writable || !(self.authority)() {
                return Err(FsError::Forbidden);
            }
            let total = self
                .written
                .load(Ordering::Acquire)
                .checked_add(buf.len() as u64)
                .ok_or(FsError::TooLarge)?;
            if total > self.max_bytes {
                return Err(FsError::TooLarge);
            }
            self.file.write_all(&buf).await.map_err(error)?;
            self.written.store(total, Ordering::Release);
            Ok(())
        })
    }
    /// 业务作用：按下游背压读取固定大小文件片段，避免大文件聚合。
    ///
    /// 参数说明：
    /// - `count`：协议引擎期望读取的最大字节数。
    ///
    /// 返回：至多 16 KiB；到达文件尾返回空，失权或 I/O 失败拒绝。
    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, bytes::Bytes> {
        Box::pin(async move {
            if !(self.authority)() {
                return Err(FsError::Forbidden);
            }
            let mut bytes = vec![0u8; count.min(16 * 1024)];
            let size = self.file.read(&mut bytes).await.map_err(error)?;
            bytes.truncate(size);
            Ok(bytes.into())
        })
    }
    /// 业务作用：支持只读 Range 定位，写入文件禁止部分覆盖。
    ///
    /// 参数说明：
    /// - `position`：读取位置。
    ///
    /// 返回：新的只读偏移；任何写文件 seek 均拒绝。
    fn seek(&mut self, position: std::io::SeekFrom) -> FsFuture<'_, u64> {
        Box::pin(async move {
            if self.writable {
                return Err(FsError::Forbidden);
            }
            self.file.seek(position).await.map_err(error)
        })
    }
    /// 业务作用：持久化暂存内容但不发布；最终长度与协议状态由外层确认后提交。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：内容 flush 与 fsync 成功；不能据此将暂存文件当作已提交资源。
    fn flush(&mut self) -> FsFuture<'_, ()> {
        Box::pin(async move {
            self.file.flush().await.map_err(error)?;
            self.file.sync_all().await.map_err(error)
        })
    }
}

impl DavFileSystem for FileSystem {
    /// 业务作用：只读打开当前资源，或为完整 PUT 准备独占临时文件。
    ///
    /// 参数说明：
    /// - `path`：解码后根内资源。
    /// - `options`：标准条件请求决定的创建/覆盖要求。
    ///
    /// 返回：有界文件句柄；拒绝 append、部分写、链接和超预算创建。
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        let path = self.path(path);
        let this = self.clone();
        Box::pin(async move {
            let path = path?;
            blocking(move || {
                this.check_authority()?;
                this.path_check(&path, options.create || options.create_new)?;
                let written = Arc::new(AtomicU64::new(0));
                let (file, max_bytes) = if options.write {
                    if path == Path::new(".") || options.append || this.pending.lock().is_some() {
                        return Err(FsError::Forbidden);
                    }
                    let existing = this.root.dir.symlink_metadata(&path).map_err(error);
                    // LOCK 在不存在的资源上创建零字节占位；不得借非截断选项打开既有文件做部分写。
                    if !options.truncate && (existing.is_ok() || options.size.is_some()) {
                        return Err(FsError::Forbidden);
                    }
                    if options.create_new && existing.is_ok() {
                        return Err(FsError::Exists);
                    }
                    if !options.create && !options.create_new && existing.is_err() {
                        return Err(FsError::NotFound);
                    }
                    if existing.as_ref().is_ok_and(|meta| !meta.is_file()) {
                        return Err(FsError::Forbidden);
                    }
                    let (entries, used) = this.scan_root()?;
                    if entries >= this.cfg.max_entries {
                        return Err(FsError::InsufficientStorage);
                    }
                    let max_bytes = this
                        .cfg
                        .max_file_bytes
                        .min(this.cfg.max_total_bytes.saturating_sub(used));
                    let max_bytes = if options.truncate {
                        max_bytes
                    } else {
                        0
                    };
                    if options.size.is_some_and(|size| size > max_bytes) {
                        return Err(FsError::TooLarge);
                    }
                    let mut random = [0u8; 32];
                    getrandom::getrandom(&mut random).map_err(|_| FsError::GeneralFailure)?;
                    let name = format!(
                        ".naway-dav-upload-{}",
                        random
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                    let temporary = path.parent().unwrap_or(Path::new(".")).join(name);
                    let mut open = cap_std::fs::OpenOptions::new();
                    open.read(true).write(true).create_new(true);
                    let file = this
                        .root
                        .dir
                        .open_with(&temporary, &open)
                        .map_err(error)?
                        .into_std();
                    let pending = Pending {
                        root: this.root.clone(),
                        temporary,
                        target: path.clone(),
                        expected: if options.truncate {
                            options.size
                        } else {
                            Some(0)
                        },
                        written: written.clone(),
                        committed: false,
                    };
                    // 覆盖实体不删除既有 dead properties；属性读取或复制失败仍只撤销临时文件。
                    if existing.is_ok() {
                        let old = this.root.dir.open(&path).map_err(error)?.into_std();
                        let properties = super::properties::read(&old, &this.cfg)?;
                        if !properties.is_empty() {
                            super::properties::write(&file, &properties)?;
                        }
                    }
                    *this.pending.lock() = Some(pending);
                    (file, max_bytes)
                } else {
                    let file = this.root.dir.open(&path).map_err(error)?.into_std();
                    let metadata = Metadata::from_file(&file).map_err(error)?;
                    check_metadata(&metadata)?;
                    if !metadata.is_file() || metadata.len() > this.cfg.max_file_bytes {
                        return Err(FsError::Forbidden);
                    }
                    (file, this.cfg.max_file_bytes)
                };
                Ok(Box::new(File {
                    file: tokio::fs::File::from_std(file),
                    written,
                    max_bytes,
                    writable: options.write,
                    authority: this.authority.clone(),
                }) as Box<dyn DavFile>)
            })
            .await
        })
    }

    /// 业务作用：一次只枚举有界目录，不向标准引擎提供隐藏文件、符号链接或无限流。
    ///
    /// 参数说明：
    /// - `path`：目标 collection。
    /// - `_meta`：协议引擎的元数据偏好；本实现始终使用同次快照。
    ///
    /// 返回：预算内的完整条目流；超限时不返回截断成功目录。
    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        let path = self.path(path);
        let this = self.clone();
        Box::pin(async move {
            let path = path?;
            let entries = blocking(move || {
                this.check_authority()?;
                this.path_check(&path, false)?;
                let mut values = Vec::new();
                for (count, item) in this.root.dir.read_dir(path).map_err(error)?.enumerate() {
                    if count >= this.cfg.max_entries {
                        return Err(FsError::TooLarge);
                    }
                    let item = item.map_err(error)?;
                    let name = item.file_name();
                    let Some(name) = name.to_str() else {
                        return Err(FsError::Forbidden);
                    };
                    if name.starts_with('.') {
                        continue;
                    }
                    let metadata = item.metadata().map_err(error)?;
                    check_metadata(&metadata)?;
                    values.push(Ok(Box::new(Entry {
                        name: name.as_bytes().to_vec(),
                        meta: Meta(metadata),
                    }) as Box<dyn DavDirEntry>));
                }
                Ok(values)
            })
            .await?;
            Ok(Box::pin(futures::stream::iter(entries)) as FsStream<Box<dyn DavDirEntry>>)
        })
    }

    /// 业务作用：给标准条件请求和资源操作提供根内可信元数据。
    ///
    /// 参数说明：
    /// - `path`：目标资源。
    ///
    /// 返回：合法普通资源元数据；失权、链接或不存在时返回对应错误。
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        let path = self.path(path);
        let this = self.clone();
        Box::pin(async move {
            let path = path?;
            blocking(move || {
                this.check_authority()?;
                this.path_check(&path, false)?;
                Ok(
                    Box::new(Meta(this.root.dir.symlink_metadata(&path).map_err(error)?))
                        as Box<dyn DavMetaData>,
                )
            })
            .await
        })
    }

    /// 业务作用：在根目录配额内创建一个 collection，不隐式创建缺失父目录。
    ///
    /// 参数说明：
    /// - `path`：目标 collection。
    ///
    /// 返回：单目录创建并同步成功；失权、满额、已存在或父目录缺失时拒绝。
    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let path = self.path(path);
        let this = self.clone();
        Box::pin(async move {
            let path = path?;
            blocking(move || {
                this.check_authority()?;
                this.path_check(&path, true)?;
                if path == Path::new(".") || this.scan_root()?.0 >= this.cfg.max_entries {
                    return Err(FsError::InsufficientStorage);
                }
                // 计量完成后再次复验，扫描期间换代不能授予迟到的目录创建。
                this.check_authority()?;
                this.root.dir.create_dir(&path).map_err(error)?;
                this.sync_parent(&path)
            })
            .await
        })
    }

    /// 业务作用：删除已经由 DAV 引擎逐项清空的 collection，根目录永远不可删除。
    ///
    /// 参数说明：
    /// - `path`：目标空目录。
    ///
    /// 返回：目录项删除并同步成功；非空目录或失权时拒绝，不进行无界递归删除。
    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let path = self.path(path);
        let this = self.clone();
        Box::pin(async move {
            let path = path?;
            blocking(move || {
                this.check_authority()?;
                this.path_check(&path, false)?;
                if path == Path::new(".") {
                    return Err(FsError::Forbidden);
                }
                // 元数据检查可能等待磁盘；删除前不能沿用此前的配置许可。
                this.check_authority()?;
                this.root.dir.remove_dir(&path).map_err(error)?;
                this.sync_parent(&path)
            })
            .await
        })
    }

    /// 业务作用：删除一个已经通过条件头和锁检查的普通文件。
    ///
    /// 参数说明：
    /// - `path`：精确目标文件。
    ///
    /// 返回：删除并同步成功；链接、目录、失权或不存在返回明确错误。
    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let path = self.path(path);
        let this = self.clone();
        Box::pin(async move {
            let path = path?;
            blocking(move || {
                this.check_authority()?;
                this.path_check(&path, false)?;
                if path == Path::new(".") {
                    return Err(FsError::Forbidden);
                }
                // 删除是不可逆目录副作用，只允许当前仍有效的请求发起。
                this.check_authority()?;
                this.root.dir.remove_file(&path).map_err(error)?;
                this.sync_parent(&path)
            })
            .await
        })
    }

    /// 业务作用：在同一目录能力内原子移动资源，文件扩展属性随 inode 保留。
    ///
    /// 参数说明：
    /// - `from`：原资源。
    /// - `to`：已通过 Destination 和 Overwrite 校验的目标。
    ///
    /// 返回：同根移动并同步成功；根操作、关系循环、深度超限或失权拒绝。
    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let from = self.path(from);
        let to = self.path(to);
        let this = self.clone();
        Box::pin(async move {
            let (from, to) = (from?, to?);
            blocking(move || {
                this.check_authority()?;
                this.path_check(&from, false)?;
                this.path_check(&to, true)?;
                if from == Path::new(".")
                    || to == Path::new(".")
                    || from.starts_with(&to)
                    || to.starts_with(&from)
                {
                    return Err(FsError::Forbidden);
                }
                let mut stack = vec![from.clone()];
                let mut count = 0usize;
                while let Some(path) = stack.pop() {
                    count += 1;
                    if count > this.cfg.max_entries {
                        return Err(FsError::TooLarge);
                    }
                    let relative = path.strip_prefix(&from).map_err(|_| FsError::Forbidden)?;
                    if to.components().count() + relative.components().count()
                        > this.cfg.max_path_depth
                    {
                        return Err(FsError::Forbidden);
                    }
                    let metadata = this.root.dir.symlink_metadata(&path).map_err(error)?;
                    check_metadata(&metadata)?;
                    if metadata.is_dir() {
                        for item in this.root.dir.read_dir(&path).map_err(error)? {
                            let item = item.map_err(error)?;
                            stack.push(path.join(item.file_name()));
                            if stack.len() > this.cfg.max_entries {
                                return Err(FsError::TooLarge);
                            }
                        }
                    }
                }
                this.check_authority()?;
                this.root
                    .dir
                    .rename(&from, &this.root.dir, &to)
                    .map_err(error)?;
                this.sync_parent(&from)?;
                this.sync_parent(&to)
            })
            .await
        })
    }

    /// 业务作用：在配额内分块复制单文件及持久属性，复制失败不发布半个目标文件。
    ///
    /// 参数说明：
    /// - `from`：源普通文件。
    /// - `to`：目标文件路径，collection 递归由有界标准引擎驱动。
    ///
    /// 返回：完整复制后原子发布；超限、失权或 I/O 失败撤销本次临时文件。
    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let from = self.path(from);
        let to = self.path(to);
        let this = self.clone();
        Box::pin(async move {
            let (from, to) = (from?, to?);
            blocking(move || {
                use std::io::{Read, Write};
                this.check_authority()?;
                this.path_check(&from, false)?;
                this.path_check(&to, true)?;
                if from == to || to == Path::new(".") {
                    return Err(FsError::Forbidden);
                }
                let mut source = this.root.dir.open(&from).map_err(error)?.into_std();
                let metadata = Metadata::from_file(&source).map_err(error)?;
                check_metadata(&metadata)?;
                if !metadata.is_file() || metadata.len() > this.cfg.max_file_bytes {
                    return Err(FsError::TooLarge);
                }
                let (count, used) = this.scan_root()?;
                if count >= this.cfg.max_entries
                    || used.saturating_add(metadata.len()) > this.cfg.max_total_bytes
                {
                    return Err(FsError::InsufficientStorage);
                }
                let mut random = [0u8; 32];
                getrandom::getrandom(&mut random).map_err(|_| FsError::GeneralFailure)?;
                let temporary = to.parent().unwrap_or(Path::new(".")).join(format!(
                    ".naway-dav-upload-{}",
                    random
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ));
                let mut options = cap_std::fs::OpenOptions::new();
                options.read(true).write(true).create_new(true);
                let mut target = this
                    .root
                    .dir
                    .open_with(&temporary, &options)
                    .map_err(error)?
                    .into_std();
                let mut pending = Pending {
                    root: this.root.clone(),
                    temporary,
                    target: to.clone(),
                    expected: Some(metadata.len()),
                    written: Arc::new(AtomicU64::new(0)),
                    committed: false,
                };
                let mut total = 0u64;
                let mut buffer = [0u8; 16 * 1024];
                loop {
                    this.check_authority()?;
                    let read = source.read(&mut buffer).map_err(error)?;
                    if read == 0 {
                        break;
                    }
                    total = total.checked_add(read as u64).ok_or(FsError::TooLarge)?;
                    if total > metadata.len() {
                        return Err(FsError::TooLarge);
                    }
                    target.write_all(&buffer[..read]).map_err(error)?;
                }
                if total != metadata.len() {
                    return Err(FsError::GeneralFailure);
                }
                let properties = super::properties::read(&source, &this.cfg)?;
                if !properties.is_empty() {
                    super::properties::write(&target, &properties)?;
                }
                target.sync_all().map_err(error)?;
                this.check_authority()?;
                this.scan_root()?;
                // 已复制内容仍是隐藏暂存，最终发布前再次复验控制权威。
                this.check_authority()?;
                this.root
                    .dir
                    .rename(&pending.temporary, &this.root.dir, &to)
                    .map_err(error)?;
                pending.committed = true;
                this.sync_parent(&to)
            })
            .await
        })
    }

    /// 业务作用：声明文件扩展属性提供持久 dead properties，而不伪造任意 live property 可写。
    ///
    /// 参数说明：
    /// - `_path`：协议引擎查询的资源。
    ///
    /// 返回：true；实际存储能力或预算失败由原子属性操作明确返回。
    fn have_props<'a>(
        &'a self,
        _path: &'a DavPath,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(std::future::ready(true))
    }

    /// 业务作用：按文档顺序构造完整属性候选，一次写入扩展属性防止部分 PROPPATCH。
    ///
    /// 参数说明：
    /// - `path`：目标资源。
    /// - `patch`：标准引擎已检查的增删属性序列。
    ///
    /// 返回：全部成功或全部拒绝状态；超限时旧属性集保持不变。
    fn patch_props<'a>(
        &'a self,
        path: &'a DavPath,
        patch: Vec<(bool, DavProp)>,
    ) -> FsFuture<'a, Vec<(http::StatusCode, DavProp)>> {
        let path = self.path(path);
        let this = self.clone();
        Box::pin(async move {
            let path = path?;
            blocking(move || {
                this.check_authority()?;
                this.path_check(&path, false)?;
                if patch.len() > 64 {
                    return Err(FsError::TooLarge);
                }
                let file = this.root.dir.open(&path).map_err(error)?.into_std();
                let mut properties = super::properties::read(&file, &this.cfg)?;
                for (set, value) in &patch {
                    properties.retain(|p| p.name != value.name || p.namespace != value.namespace);
                    if *set {
                        if let Some(xml) = &value.xml {
                            super::input::validate_xml(xml, &this.cfg, 8192)
                                .map_err(|_| FsError::TooLarge)?;
                        }
                        properties.push(value.clone());
                    }
                }
                this.check_authority()?;
                let status = match super::properties::write(&file, &properties) {
                    Ok(()) => http::StatusCode::OK,
                    Err(FsError::InsufficientStorage) => http::StatusCode::INSUFFICIENT_STORAGE,
                    Err(err) => return Err(err),
                };
                Ok(patch.into_iter().map(|(_, p)| (status, p)).collect())
            })
            .await
        })
    }

    /// 业务作用：读取有界持久属性，属性查询不产生写入。
    ///
    /// 参数说明：
    /// - `path`：目标资源。
    /// - `do_content`：是否需要返回完整 XML；propname 只返回名称。
    ///
    /// 返回：经过当前 XML 预算复验的属性集；损坏或失权拒绝。
    fn get_props<'a>(&'a self, path: &'a DavPath, do_content: bool) -> FsFuture<'a, Vec<DavProp>> {
        let path = self.path(path);
        let this = self.clone();
        Box::pin(async move {
            let path = path?;
            blocking(move || {
                this.check_authority()?;
                this.path_check(&path, false)?;
                let file = this.root.dir.open(path).map_err(error)?.into_std();
                let mut properties = super::properties::read(&file, &this.cfg)?;
                if !do_content {
                    for property in &mut properties {
                        property.xml = None;
                    }
                }
                Ok(properties)
            })
            .await
        })
    }

    /// 业务作用：按展开 namespace 与名称精确读取单个 dead property。
    ///
    /// 参数说明：
    /// - `path`：目标资源。
    /// - `prop`：要查询的展开属性名。
    ///
    /// 返回：完整属性 XML；不存在时返回 NotFound，不能按同名其它 namespace 替代。
    fn get_prop<'a>(&'a self, path: &'a DavPath, prop: DavProp) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            DavFileSystem::get_props(self, path, true)
                .await?
                .into_iter()
                .find(|value| value.name == prop.name && value.namespace == prop.namespace)
                .and_then(|value| value.xml)
                .ok_or(FsError::NotFound)
        })
    }
}
