//! WebDAV 的显式路由边界、存储所有权和资源硬上限。

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Proxy,
    Local,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LockScope {
    Process,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebDavCfg {
    pub mode: Mode,
    pub mount_prefix: String,
    #[serde(default)]
    pub upstream_prefix: Option<String>,
    pub methods: Vec<String>,
    #[serde(default)]
    pub lock_scope: Option<LockScope>,
    #[serde(default)]
    pub exclusive_process: bool,
    #[serde(default = "max_file_bytes")]
    pub max_file_bytes: u64,
    #[serde(default = "max_total_bytes")]
    pub max_total_bytes: u64,
    #[serde(default = "max_entries")]
    pub max_entries: usize,
    #[serde(default = "max_path_depth")]
    pub max_path_depth: usize,
    #[serde(default = "max_inflight")]
    pub max_inflight: usize,
    #[serde(default = "max_xml_bytes")]
    pub max_xml_bytes: usize,
    #[serde(default = "max_xml_nodes")]
    pub max_xml_nodes: usize,
    #[serde(default = "max_xml_depth")]
    pub max_xml_depth: usize,
    #[serde(default = "max_multistatus_bytes")]
    pub max_multistatus_bytes: usize,
    #[serde(default = "max_locks")]
    pub max_locks: usize,
    #[serde(default = "max_lock_seconds")]
    pub max_lock_seconds: u64,
    #[serde(default = "timeout_ms")]
    pub timeout_ms: u64,
}

macro_rules! defaults {
    ($($name:ident: $ty:ty = $value:expr;)+) => {$ (
        /// 业务作用：为同名 WebDAV 配置项提供保守的资源预算。
        /// 参数说明: 无。
        /// 返回：未显式配置时采用的非零硬上限。
        fn $name() -> $ty {
            $value
        }
    )+};
}
defaults! {
    max_file_bytes: u64 = 64 * 1024 * 1024;
    max_total_bytes: u64 = 1024 * 1024 * 1024;
    max_entries: usize = 1024;
    max_path_depth: usize = 16;
    max_inflight: usize = 16;
    max_xml_bytes: usize = 64 * 1024;
    max_xml_nodes: usize = 4096;
    max_xml_depth: usize = 16;
    max_multistatus_bytes: usize = 1024 * 1024;
    max_locks: usize = 256;
    max_lock_seconds: u64 = 3600;
    timeout_ms: u64 = 30_000;
}

impl WebDavCfg {
    /// 业务作用：在候选发布前证明方法、目录能力和全部资源预算可执行。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：独立制品能力与模式契约全部满足时成功，否则拒绝候选。
    pub fn validate(&self) -> Result<()> {
        ensure!(cfg!(feature = "webdav"), "WebDAV requires feature `webdav`");
        validate_prefix(&self.mount_prefix)?;
        ensure!(
            !self.methods.is_empty() && self.methods.len() <= 12,
            "webdav.methods requires 1..=12 explicit methods"
        );
        let mut methods = HashSet::new();
        for method in &self.methods {
            ensure!(
                matches!(
                    method.as_str(),
                    "GET"
                        | "HEAD"
                        | "OPTIONS"
                        | "PUT"
                        | "DELETE"
                        | "PROPFIND"
                        | "PROPPATCH"
                        | "MKCOL"
                        | "COPY"
                        | "MOVE"
                        | "LOCK"
                        | "UNLOCK"
                ),
                "unsupported webdav method"
            );
            ensure!(methods.insert(method), "duplicate webdav method");
        }
        match self.mode {
            Mode::Proxy => {
                validate_prefix(self.upstream_prefix.as_deref().unwrap_or("/"))?;
                ensure!(
                    self.lock_scope.is_none() && !self.exclusive_process,
                    "proxy WebDAV delegates lock authority to its upstream"
                );
            }
            Mode::Local => {
                ensure!(
                    self.upstream_prefix.is_none(),
                    "local WebDAV cannot set upstream_prefix"
                );
                // 本地锁不提供集群互斥；部署必须声明单进程独占目录，并在运行期持有文件锁。
                ensure!(self.lock_scope == Some(LockScope::Process) && self.exclusive_process,
                    "local WebDAV requires lock_scope=process and exclusive_process=true; shared storage needs an external DAV authority");
            }
        }
        ensure!(
            (1..=1024 * 1024 * 1024).contains(&self.max_file_bytes),
            "webdav.max_file_bytes outside 1..=1GiB"
        );
        ensure!(
            (self.max_file_bytes..=1024 * 1024 * 1024 * 1024).contains(&self.max_total_bytes),
            "webdav.max_total_bytes outside file limit..=1TiB"
        );
        ensure!(
            (1..=4096).contains(&self.max_entries),
            "webdav.max_entries outside 1..=4096"
        );
        ensure!(
            (1..=32).contains(&self.max_path_depth),
            "webdav.max_path_depth outside 1..=32"
        );
        ensure!(
            (1..=128).contains(&self.max_inflight),
            "webdav.max_inflight outside 1..=128"
        );
        ensure!(
            (1024..=1024 * 1024).contains(&self.max_xml_bytes),
            "webdav.max_xml_bytes outside 1KiB..=1MiB"
        );
        ensure!(
            (1..=16384).contains(&self.max_xml_nodes),
            "webdav.max_xml_nodes outside 1..=16384"
        );
        ensure!(
            (1..=32).contains(&self.max_xml_depth),
            "webdav.max_xml_depth outside 1..=32"
        );
        ensure!(
            (self.max_xml_bytes..=8 * 1024 * 1024).contains(&self.max_multistatus_bytes),
            "webdav.max_multistatus_bytes outside XML limit..=8MiB"
        );
        ensure!(
            (1..=1024).contains(&self.max_locks),
            "webdav.max_locks outside 1..=1024"
        );
        ensure!(
            (1..=86400).contains(&self.max_lock_seconds),
            "webdav.max_lock_seconds outside 1..=86400"
        );
        ensure!(
            (100..=60_000).contains(&self.timeout_ms),
            "webdav.timeout_ms outside 100..=60000"
        );
        Ok(())
    }

    /// 业务作用：确定该路由是否需要副作用审计及文件写权限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：允许任一改变资源或锁的操作时为 true。
    pub fn writable(&self) -> bool {
        self.methods
            .iter()
            .any(|method| !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "PROPFIND"))
    }
}

/// 业务作用：限定前缀为可证明边界的规范字面路径，避免模板或编码改变资源归属。
///
/// 参数说明：
/// - `value`：公开挂载或代理目标的路径前缀。
///
/// 返回：根路径或不带尾斜杠的规范路径成功；其它表示明确拒绝。
pub(crate) fn validate_prefix(value: &str) -> Result<()> {
    ensure!(
        value.starts_with('/') && value.len() <= 1024,
        "webdav prefix must be absolute and at most 1024 bytes"
    );
    if value == "/" {
        return Ok(());
    }
    ensure!(
        !value.ends_with('/')
            && !value.contains(['%', '\\', '?', '#', '$'])
            && !value.bytes().any(|b| b <= 0x20 || b >= 0x7f)
            && value[1..]
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != ".." && !s.starts_with('.')),
        "webdav prefix must be a canonical literal path"
    );
    Ok(())
}

/// 业务作用：在完整候选中确定 DAV 存储唯一归属、HTTP 上游和持久写审计，禁止别名绕过根目录隔离。
///
/// 参数说明：
/// - `cfg`：所有来源和策略已物化的候选配置。
/// - `config_dir`：本地根目录相对路径的解析基准。
///
/// 返回：每个本地目录只有一个不重叠挂载且写审计可用时成功，否则不允许发布。
pub(crate) fn validate_routes(
    cfg: &super::model::GatewayConfig,
    config_dir: &std::path::Path,
) -> Result<()> {
    let mut roots = Vec::<std::path::PathBuf>::new();
    let routes = || {
        cfg.routes
            .iter()
            .chain(cfg.proxies.iter().flat_map(|proxy| &proxy.routes))
    };
    for route in routes() {
        let Some(dav) = &route.webdav else {
            continue;
        };
        dav.validate()?;
        ensure!(
            !dav.writable() || (cfg.admin.audit.enabled && cfg.admin.audit.fsync),
            "writable WebDAV requires admin.audit.enabled=true and fsync=true"
        );
        match dav.mode {
            Mode::Local => {
                let storage = route
                    .serve
                    .as_ref()
                    .and_then(|serve| serve.r#static.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("local WebDAV requires serve.static.root"))?;
                let root = config_dir.join(&storage.root).canonicalize()?;
                ensure!(
                    !config_dir.canonicalize()?.starts_with(&root),
                    "WebDAV root cannot contain its configuration directory"
                );
                let audit = config_dir.join(&cfg.admin.audit.file);
                let mut parent = audit.parent();
                while parent.is_some_and(|path| !path.exists()) {
                    parent = parent.and_then(std::path::Path::parent);
                }
                if let Some(parent) = parent {
                    ensure!(
                        !parent.canonicalize()?.starts_with(&root),
                        "WebDAV root cannot contain its audit spool"
                    );
                }
                ensure!(
                    !roots
                        .iter()
                        .any(|existing| root.starts_with(existing) || existing.starts_with(&root)),
                    "WebDAV local roots must not overlap or have aliases"
                );
                roots.push(root);
            }
            Mode::Proxy => {
                ensure!(
                    !route.preserve_host,
                    "proxy WebDAV requires selected upstream authority"
                );
                if let Some(name) = route.uri.strip_prefix("lb://") {
                    let service = cfg
                        .upstreams
                        .services
                        .get(name)
                        .ok_or_else(|| anyhow::anyhow!("WebDAV service missing"))?;
                    ensure!(
                        matches!(
                            service.protocol.as_deref().unwrap_or("auto"),
                            "auto" | "h1" | "http1" | "http/1.1" | "h2" | "http2" | "h2c"
                        ),
                        "WebDAV requires an HTTP service transport"
                    );
                } else {
                    let uri: http::Uri = route.uri.parse()?;
                    ensure!(matches!(uri.scheme_str(), Some("http" | "https")) && uri.authority().is_some()
                        && matches!(uri.path(), "" | "/") && uri.query().is_none(),
                        "WebDAV proxy uri requires a fixed HTTP origin; use upstream_prefix for its path");
                }
            }
        }
    }
    // 同一目录的普通静态别名可能绕开 DAV 的归属和方法授权，因此也不能与 DAV 根重叠。
    for route in routes().filter(|route| !roots.is_empty() && route.webdav.is_none()) {
        if let Some(storage) = route
            .serve
            .as_ref()
            .and_then(|serve| serve.r#static.as_ref())
        {
            let root = config_dir.join(&storage.root).canonicalize()?;
            ensure!(
                !roots
                    .iter()
                    .any(|dav| root.starts_with(dav) || dav.starts_with(&root)),
                "ordinary static routes cannot overlap local WebDAV roots"
            );
        }
    }
    Ok(())
}
