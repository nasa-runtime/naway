//! 显式 WebDAV 路由的协议、目录能力与有界本地状态。

mod admission;
mod filesystem;
mod input;
mod locks;
pub(crate) mod metrics;
mod properties;
pub(crate) mod proxy;
mod semantic;
mod stream;

use crate::config::{
    model::StaticServeCfg,
    webdav::{Mode, WebDavCfg},
};
use crate::{full_body, text_status, BoxBody};
use anyhow::{ensure, Context, Result};
use cap_std::fs::MetadataExt;
use http::{HeaderValue, Request, Response};
use http_body_util::BodyExt;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

/// 入口认证前冻结的资源定位和协议条件；外部授权响应也不能悄悄改写写入目标。
#[derive(Clone)]
pub(crate) struct RequestHead {
    method: http::Method,
    uri: http::Uri,
    headers: Vec<(&'static str, Vec<HeaderValue>)>,
}

impl RequestHead {
    /// 业务作用：只为显式文件路由及可能进入该路由的父链冻结安全相关 head，不读取实体。
    ///
    /// 参数说明：
    /// - `parts`：已完成统一规范化、尚未执行认证响应注入的入口 head。
    ///
    /// 返回：供协议执行前比对的小型受信扩展，不能由客户端直接创建。
    pub fn capture(parts: &http::request::Parts) -> Self {
        let names = [
            "host",
            "destination",
            "if",
            "depth",
            "overwrite",
            "lock-token",
            "timeout",
            "content-length",
            "transfer-encoding",
            "content-type",
            "content-encoding",
            "if-match",
            "if-none-match",
            "if-modified-since",
            "if-unmodified-since",
            "range",
            "if-range",
            "connection",
            "trailer",
            "te",
            "upgrade",
        ];
        Self {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            headers: names
                .into_iter()
                .map(|name| (name, parts.headers.get_all(name).iter().cloned().collect()))
                .collect(),
        }
    }

    /// 业务作用：在任何文件或锁副作用之前验证认证和策略没有改变入口资源语义。
    ///
    /// 参数说明：
    /// - `parts`：统一安全管线交付的最终请求 head。
    ///
    /// 返回：定位、实体 framing、条件与锁头全部保持入口值时为 true。
    fn unchanged(&self, parts: &http::request::Parts) -> bool {
        self.method == parts.method
            && self.uri == parts.uri
            && self
                .headers
                .iter()
                .all(|(name, values)| parts.headers.get_all(*name).iter().eq(values.iter()))
    }
}

pub(crate) struct Plan {
    pub cfg: Arc<WebDavCfg>,
    root: Option<Arc<filesystem::Root>>,
    inflight: Arc<admission::Quota>,
    methods: dav_server::DavMethodSet,
    resource_fingerprint: String,
}

pub(crate) struct Session {
    plan: Arc<Plan>,
    request: Option<Request<BoxBody>>,
    lease: stream::Lease,
    deadline: tokio::time::Instant,
    origin: String,
    mapping: Option<proxy::Mapping>,
}

impl Plan {
    /// 业务作用：在完整候选中准备显式 DAV 计划，文件系统默认设置不能被悄悄解释为写权限。
    ///
    /// 参数说明：
    /// - `cfg`：固定模式、挂载点与所有资源预算。
    /// - `storage`：仅本地模式允许使用的现有静态根声明。
    /// - `config_dir`：相对根目录的配置基准目录。
    /// - `upstream`：代理模式的固定 HTTP origin 或逻辑服务名，用于跨快照的容量归属。
    ///
    /// 返回：已经取得目录能力的计划；不执行文件业务写入或建立上游连接。
    pub fn build(
        cfg: &WebDavCfg,
        storage: Option<&StaticServeCfg>,
        config_dir: &Path,
        upstream: &str,
    ) -> Result<Arc<Self>> {
        cfg.validate()?;
        let root = match cfg.mode {
            Mode::Proxy => {
                ensure!(storage.is_none(), "proxy WebDAV cannot use serve.static");
                None
            }
            Mode::Local => {
                ensure!(
                    cfg!(any(target_os = "macos", target_os = "linux")),
                    "local WebDAV requires macOS or Linux file attributes"
                );
                let storage = storage.context("local WebDAV requires serve.static.root")?;
                ensure!(storage.try_files.is_empty()&&storage.index.is_empty()&&storage.cache_control.is_none()&&storage.expires.is_none()
                    &&storage.default_type.is_none()&&storage.types.is_empty()&&!storage.allow_dotfiles&&storage.etag&&storage.range,
                    "local WebDAV uses exact resources and standard DAV metadata; static fallback, index, MIME overrides and disabled validators/range are unsupported");
                let path = config_dir.join(&storage.root).canonicalize()?;
                Some(shared_root(path)?)
            }
        };
        let identity = match cfg.mode {
            Mode::Local => serde_json::to_string(&(
                "local",
                config_dir
                    .join(&storage.expect("validated storage").root)
                    .canonicalize()?,
            ))?,
            Mode::Proxy => serde_json::to_string(&(
                "proxy",
                upstream,
                &cfg.mount_prefix,
                cfg.upstream_prefix.as_deref().unwrap_or("/"),
            ))?,
        };
        let resource_fingerprint = nasa::crypto::sha256(&identity);
        Ok(Arc::new(Self {
            cfg: Arc::new(cfg.clone()),
            root,
            inflight: admission::Quota::shared(resource_fingerprint.clone())?,
            methods: dav_server::DavMethodSet::from_vec(cfg.methods.clone())?,
            resource_fingerprint,
        }))
    }

    /// 业务作用：输出模式、预算和稳定指纹，不公开本地路径、锁 token 或身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：可供管理语义 diff 使用的低敏描述。
    pub fn semantic(&self) -> serde_json::Value {
        serde_json::json!({
            "mode":self.cfg.mode,
            "mount_prefix":self.cfg.mount_prefix,
            "methods":self.cfg.methods,
            "lock_scope":self.cfg.lock_scope,
            "max_inflight":self.cfg.max_inflight,
            "max_file_bytes":self.cfg.max_file_bytes,
            "max_entries":self.cfg.max_entries,
            "fingerprint":nasa::crypto::sha256(&serde_json::to_string(&(self.cfg.as_ref(), &self.resource_fingerprint)).expect("serializable DAV config"))
        })
    }

    /// 业务作用：在执行前完成控制头、协议 XML、并发和目录预检查，保留上传文件实体的流式形态。
    ///
    /// 参数说明：
    /// - `request`：已完成认证与安全策略的原始规范化请求。
    /// - `scheme`：真实入口 scheme。
    /// - `authority`：来自当前已发布快照和来源期限的权威复验。
    ///
    /// 返回：可执行的单次会话；拒绝不会修改业务文件或锁。
    pub async fn begin(
        self: &Arc<Self>,
        request: Request<BoxBody>,
        scheme: &str,
        authority: filesystem::Authority,
    ) -> Result<Session, Response<BoxBody>> {
        let budget = nabudget::RequestBudget::from_now(Duration::from_millis(self.cfg.timeout_ms));
        let deadline = budget.deadline();
        let permit = self
            .inflight
            .acquire(self.cfg.max_inflight)
            .ok_or_else(|| text_status(503, "WebDAV capacity reached"))?;
        let current_budget = budget.clone();
        let checked: filesystem::Authority =
            Arc::new(move || current_budget.check().is_ok() && authority());
        let mut lease = stream::Lease {
            _permit: permit,
            budget,
            authority: checked.clone(),
            filesystem: None,
        };
        let operation = async {
            let (mut parts, body) = request.into_parts();
            // 允许身份头注入，但不允许授权服务或公共策略替调用方选择另一个文件或放宽条件。
            if parts
                .extensions
                .get::<RequestHead>()
                .is_some_and(|head| !head.unchanged(&parts))
            {
                return Err(text_status(
                    400,
                    "WebDAV resource headers changed during authorization",
                ));
            }
            if !self
                .cfg
                .methods
                .iter()
                .any(|method| method == parts.method.as_str())
            {
                return Err(text_status(405, "WebDAV method not allowed"));
            }
            if parts.method.as_str() == "PROPFIND"
                && input::single(&parts.headers, "depth")
                    .ok()
                    .flatten()
                    .is_none_or(|depth| depth == "infinity")
            {
                return Err(text_status(403, "WebDAV requires finite PROPFIND Depth"));
            }
            input::validate_head(&parts, scheme, &self.cfg)
                .map_err(|_| text_status(400, "invalid WebDAV control headers"))?;
            let host = parts
                .uri
                .authority()
                .map(|a| a.as_str())
                .or(parts.headers.get("host").and_then(|h| h.to_str().ok()))
                .ok_or_else(|| text_status(400, "WebDAV authority required"))?;
            let origin = format!("{scheme}://{host}");
            if let Some(raw) = input::single(&parts.headers, "if")
                .map_err(|_| text_status(400, "invalid WebDAV If"))?
            {
                let value = input::map_if(raw, |tag| {
                    Ok(format!(
                        "{origin}{}",
                        input::resource(tag, &parts, scheme, &self.cfg)?
                    ))
                })
                .map_err(|_| text_status(400, "invalid WebDAV If"))?;
                parts.headers.insert(
                    "if",
                    HeaderValue::from_str(&value)
                        .map_err(|_| text_status(400, "invalid WebDAV If"))?,
                );
            }
            let destination = input::single(&parts.headers, "destination")
                .map_err(|_| text_status(400, "invalid WebDAV Destination"))?
                .map(|raw| input::resource(raw, &parts, scheme, &self.cfg))
                .transpose()
                .map_err(|_| text_status(400, "invalid WebDAV Destination"))?;
            if let Some(path) = &destination {
                parts.headers.insert(
                    "destination",
                    HeaderValue::from_str(&format!("{origin}{path}"))
                        .map_err(|_| text_status(400, "invalid WebDAV Destination"))?,
                );
            }
            let body = match parts.method.as_str() {
                "PUT" => {
                    let length = input::single(&parts.headers, "content-length")
                        .ok()
                        .flatten()
                        .and_then(|v| {
                            if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
                                v.parse::<u64>().ok()
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| text_status(411, "WebDAV PUT requires Content-Length"))?;
                    if length > self.cfg.max_file_bytes {
                        return Err(text_status(413, "WebDAV file limit exceeded"));
                    }
                    stream::CheckedBody::wrap(body, checked.clone(), deadline, length)
                }
                method => {
                    let xml = matches!(method, "PROPFIND" | "PROPPATCH" | "LOCK");
                    let limit = if method == "LOCK" {
                        self.cfg.max_xml_bytes.min(4096)
                    } else if xml {
                        self.cfg.max_xml_bytes
                    } else {
                        0
                    };
                    let bytes = stream::collect(body, limit)
                        .await
                        .map_err(|_| text_status(413, "WebDAV control entity rejected"))?;
                    if xml {
                        input::validate_xml(&bytes, &self.cfg, limit)
                            .map_err(|_| text_status(400, "invalid WebDAV XML"))?;
                        if !bytes.is_empty() {
                            let element = xmltree::Element::parse(bytes.as_ref())
                                .map_err(|_| text_status(400, "invalid WebDAV XML"))?;
                            let expected = match method {
                                "PROPFIND" => "propfind",
                                "PROPPATCH" => "propertyupdate",
                                _ => "lockinfo",
                            };
                            if element.namespace.as_deref() != Some("DAV:")
                                || element.name != expected
                            {
                                return Err(text_status(400, "unexpected WebDAV XML root"));
                            }
                        }
                    }
                    parts.headers.remove("transfer-encoding");
                    parts.headers.insert(
                        "content-length",
                        HeaderValue::from_str(&bytes.len().to_string()).expect("decimal length"),
                    );
                    full_body(bytes)
                }
            };
            if let Some(root) = &self.root {
                let serial = root
                    .serial
                    .clone()
                    .try_lock_owned()
                    .map_err(|_| text_status(503, "WebDAV root is busy"))?;
                let fs = filesystem::FileSystem::new(
                    root.clone(),
                    self.cfg.clone(),
                    checked.clone(),
                    serial,
                );
                let source = dav_server::davpath::DavPath::new(
                    input::suffix(parts.uri.path(), &self.cfg.mount_prefix)
                        .map_err(|_| text_status(400, "invalid WebDAV resource"))?,
                )
                .map_err(|_| text_status(400, "invalid WebDAV resource"))?;
                let destination = destination
                    .as_deref()
                    .map(|path| {
                        input::suffix(path, &self.cfg.mount_prefix)
                            .and_then(|path| Ok(dav_server::davpath::DavPath::new(path)?))
                    })
                    .transpose()
                    .map_err(|_| text_status(400, "invalid WebDAV Destination"))?;
                fs.preflight(parts.method.as_str(), &source, destination.as_ref())
                    .await
                    .map_err(fs_response)?;
                lease.filesystem = Some(fs);
            }
            if !checked() {
                return Err(text_status(409, "WebDAV authority expired"));
            }
            Ok((Request::from_parts(parts, body), origin))
        };
        let (request, origin) = tokio::time::timeout_at(deadline, operation)
            .await
            .map_err(|_| text_status(504, "WebDAV request deadline exceeded"))??;
        Ok(Session {
            plan: self.clone(),
            request: Some(request),
            lease,
            deadline,
            origin,
            mapping: None,
        })
    }
}

/// 业务作用：判定一个已经过 allowlist 的请求是否改变资源或锁状态。
///
/// 参数说明：
/// - `method`：当前 DAV 方法。
///
/// 返回：写实体、属性、命名空间或锁时为 true，供统一审计门使用。
pub(crate) fn writable(method: &http::Method) -> bool {
    !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "PROPFIND")
}

impl Session {
    /// 业务作用：执行标准 DAV 引擎，完整解析协议响应后才提交暂存实体。
    ///
    /// 参数说明：
    /// - `principal`：统一身份层冻结的稳定主体摘要，写请求不能使用匿名身份。
    ///
    /// 返回：有完整响应期资源保护的结果；协议、存储或期限失败保留原上传目标。
    pub async fn local(mut self, principal: Arc<str>) -> Response<BoxBody> {
        let Some(fs) = self.lease.filesystem.clone() else {
            return text_status(500, "WebDAV local filesystem missing");
        };
        let root = self.plan.root.as_ref().expect("local root");
        let handler = dav_server::DavHandler::builder()
            .filesystem(Box::new(fs.clone()))
            .locksystem(Box::new(root.locks.bind(
                principal.clone(),
                self.plan.cfg.max_locks,
                self.plan.cfg.max_lock_seconds,
                self.lease.authority.clone(),
            )))
            .principal(principal.to_string())
            .strip_prefix(self.plan.cfg.mount_prefix.clone())
            .methods(self.plan.methods)
            .autoindex(false)
            .hide_symlinks(true)
            .read_buf_size(16 * 1024)
            .build_handler();
        let request = self.request.take().expect("one DAV request");
        let file_response = matches!(request.method().as_str(), "GET" | "HEAD");
        let operation = async {
            let response = handler
                .handle(request.map(|body| body.map_err(std::io::Error::other)))
                .await;
            let (parts, body) = response.into_parts();
            let body = stream::engine_body(body);
            let body = if !file_response {
                let bytes = stream::collect(body, self.plan.cfg.max_multistatus_bytes)
                    .await
                    .map_err(|_| text_status(502, "WebDAV response limit exceeded"))?;
                if !bytes.is_empty() {
                    input::validate_xml(
                        &bytes,
                        &self.plan.cfg,
                        self.plan.cfg.max_multistatus_bytes,
                    )
                    .map_err(|_| text_status(502, "invalid WebDAV response XML"))?;
                }
                full_body(bytes)
            } else {
                body
            };
            if parts.status.is_success() {
                fs.commit().await.map_err(fs_response)?;
            }
            Ok::<_, Response<BoxBody>>(Response::from_parts(parts, body))
        };
        match tokio::time::timeout_at(self.deadline, operation).await {
            Ok(Ok(response)) => {
                response.map(|body| stream::GuardedBody::wrap(body, self.lease, self.deadline))
            }
            Ok(Err(response)) => response,
            Err(_) => text_status(504, "WebDAV operation deadline exceeded"),
        }
    }
}

/// 业务作用：将文件系统拒绝转成稳定 HTTP 状态，不输出路径和系统错误原文。
///
/// 参数说明：
/// - `error`：目录能力或资源预算的失败类别。
///
/// 返回：明确的 DAV 拒绝或存储失败响应。
fn fs_response(error: dav_server::fs::FsError) -> Response<BoxBody> {
    use dav_server::fs::FsError;
    text_status(
        match error {
            FsError::NotFound => 404,
            FsError::Forbidden => 403,
            FsError::Exists => 409,
            FsError::TooLarge => 413,
            FsError::InsufficientStorage => 507,
            _ => 500,
        },
        "WebDAV resource operation rejected",
    )
}

/// 业务作用：跨候选快照复用同一真实根的锁与串行写权威，配置热换不能重置活动锁。
///
/// 参数说明：
/// - `path`：已经 canonicalize 的根目录。
///
/// 返回：有界进程目录中的同一根；重叠根、身份变化或超过 64 根时拒绝。
fn shared_root(path: PathBuf) -> Result<Arc<filesystem::Root>> {
    static ROOTS: OnceLock<parking_lot::Mutex<BTreeMap<PathBuf, Arc<filesystem::Root>>>> =
        OnceLock::new();
    let mut roots = ROOTS.get_or_init(Default::default).lock();
    roots.retain(|_, root| Arc::strong_count(root) > 1 || root.locks.active());
    if let Some(root) = roots.get(&path) {
        let actual = cap_std::fs::Metadata::from_just_metadata(std::fs::metadata(&path)?);
        let held = root.dir.dir_metadata()?;
        ensure!(
            actual.dev() == held.dev() && actual.ino() == held.ino(),
            "WebDAV root identity changed"
        );
        return Ok(root.clone());
    }
    ensure!(roots.len() < 64, "WebDAV root registry is full");
    ensure!(
        !roots
            .keys()
            .any(|other| other.starts_with(&path) || path.starts_with(other)),
        "overlapping WebDAV roots are forbidden"
    );
    let root = filesystem::Root::open(&path)?;
    properties::read_raw(&root.dir.try_clone()?.into_std_file()).map_err(|_| {
        anyhow::anyhow!("WebDAV filesystem must support bounded extended attributes")
    })?;
    roots.insert(path, root.clone());
    Ok(root)
}
