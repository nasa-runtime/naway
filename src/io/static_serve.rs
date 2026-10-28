//! 本地静态文件 / SPA 后端。
//!
//! 该模块对齐 nginx `root` / `try_files` / `index` 的主流反向代理搭配用法。数据面按需
//! `tokio::fs::File` 流式读取,不把文件整体读进内存。

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as AnyhowContext, Result};
use bytes::{Bytes, BytesMut};
use http::header::EXPIRES;
use http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
    IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED, RANGE,
};
use http::request::Parts;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::{Response, StatusCode};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncSeekExt, ReadBuf};

use crate::config::model::StaticServeCfg;
use crate::routing::variable::{EvalContext, ValueTemplate, VariablePlan};
use crate::{full_body, text_status, BoxBody, BoxError};

const DEFAULT_TYPE: &str = "application/octet-stream";
const FILE_CHUNK_SIZE: usize = 16 * 1024;

/// 已编译静态文件后端配置。
#[derive(Clone)]
pub struct StaticServe {
    /// 配置 root 的原始绝对路径。
    root: PathBuf,
    /// canonicalize 后的 root,用于防符号链接逃逸。
    canonical_root: PathBuf,
    /// `try_files` 模板,按顺序尝试。
    try_files: Vec<ValueTemplate>,
    /// 目录请求的索引文件列表。
    index: Vec<String>,
    /// 可选 Cache-Control 响应头。
    cache_control: Option<http::HeaderValue>,
    /// 可选 Expires max-age 秒数。
    expires: Option<u64>,
    /// 未识别 MIME 时的默认 Content-Type。
    default_type: http::HeaderValue,
    /// 自定义扩展名 MIME 映射。
    types: HashMap<String, http::HeaderValue>,
    /// 是否允许访问点文件。
    allow_dotfiles: bool,
    /// 是否生成弱 ETag。
    etag: bool,
    /// 是否支持单段 HTTP Range。
    range: bool,
    #[cfg(feature = "media-streaming")]
    media: Option<std::sync::Arc<super::media::Plan>>,
}

impl StaticServe {
    /// 业务作用：在发布前解析固定静态根、文件选择模板与响应头，不允许配置指向非目录目标。
    ///
    /// 参数说明：
    /// - `cfg`: `serve.static` 配置块。
    /// - `config_dir`: `gateway.yml` 所在目录,用于解析相对 root。
    /// - `variables`: 全局变量计划,用于编译 `try_files` 模板。
    ///
    /// 返回：可执行的只读静态计划；路径、模板或响应头无效则拒绝候选。
    pub fn build(
        cfg: &StaticServeCfg,
        config_dir: &Path,
        variables: &VariablePlan,
    ) -> Result<Self> {
        if cfg.root.trim().is_empty() {
            bail!("serve.static.root must not be empty");
        }
        let root = resolve_root(config_dir, cfg.root.trim());
        let canonical_root = root
            .canonicalize()
            .with_context(|| format!("canonicalize static root `{}`", root.display()))?;
        if !canonical_root.is_dir() {
            bail!("serve.static.root `{}` is not a directory", root.display());
        }
        let raw_try_files = if cfg.try_files.is_empty() {
            vec!["${uri}".to_string(), "${uri}/index.html".to_string()]
        } else {
            cfg.try_files.clone()
        };
        let mut try_files = Vec::with_capacity(raw_try_files.len());
        for raw in raw_try_files {
            try_files.push(
                variables
                    .compile_template(raw.trim())
                    .with_context(|| format!("compile try_files `{raw}`"))?,
            );
        }
        let index = if cfg.index.is_empty() {
            vec!["index.html".to_string()]
        } else {
            cfg.index.clone()
        };
        for name in &index {
            validate_index_name(name)?;
        }
        let cache_control = cfg
            .cache_control
            .as_deref()
            .map(|value| {
                http::HeaderValue::from_str(value)
                    .with_context(|| format!("invalid static cache_control `{value}`"))
            })
            .transpose()?;
        let expires = cfg
            .expires
            .as_deref()
            .map(parse_expires_seconds)
            .transpose()?
            .flatten();
        let default_type =
            http::HeaderValue::from_str(cfg.default_type.as_deref().unwrap_or(DEFAULT_TYPE))
                .context("invalid static default_type")?;
        let mut types = HashMap::new();
        for (raw_ext, raw_value) in &cfg.types {
            let ext = normalize_ext(raw_ext)?;
            let value = http::HeaderValue::from_str(raw_value)
                .with_context(|| format!("invalid static type for `{raw_ext}`"))?;
            types.insert(ext, value);
        }
        Ok(Self {
            root,
            canonical_root,
            try_files,
            index,
            cache_control,
            expires,
            default_type,
            types,
            allow_dotfiles: cfg.allow_dotfiles,
            etag: cfg.etag,
            range: cfg.range,
            #[cfg(feature = "media-streaming")]
            media: None,
        })
    }

    /// 业务作用：把显式媒体配置绑定到已经规范化的静态根；普通静态路由不建立解析状态。
    ///
    /// 参数说明：
    /// - `cfg`：当前路由的容器和预算配置。
    ///
    /// 返回：静态后端持有同根跨快照的只读媒体计划，配置非法则拒绝候选。
    #[cfg(feature = "media-streaming")]
    pub(crate) fn enable_media(&mut self, cfg: &crate::config::media::MediaCfg) -> Result<()> {
        self.media = Some(std::sync::Arc::new(super::media::Plan::build(
            cfg,
            &self.canonical_root,
        )?));
        Ok(())
    }

    /// 业务作用：向路由管理摘要提供媒体配置指纹，不输出本地文件根。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：显式媒体计划的低敏摘要，普通静态后端没有该摘要。
    #[cfg(feature = "media-streaming")]
    pub(crate) fn media_semantic(&self) -> Option<serde_json::Value> {
        self.media.as_ref().map(|plan| plan.semantic())
    }

    /// 业务作用：根据请求返回静态文件响应。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    /// - `variables`: route 使用的变量计划。
    /// - `eval_ctx`: 本请求变量求值上下文。
    pub async fn serve(
        &self,
        parts: &Parts,
        variables: &VariablePlan,
        eval_ctx: &EvalContext<'_>,
    ) -> Response<BoxBody> {
        if parts.method != http::Method::GET && parts.method != http::Method::HEAD {
            return text_status(405, "method not allowed");
        }
        match self.resolve(parts, variables, eval_ctx).await {
            Ok(Some(file)) => self.file_response(parts, file).await,
            Ok(None) => text_status(404, "not found"),
            Err(StaticServeError::Forbidden) => text_status(403, "forbidden"),
            Err(StaticServeError::Io(err)) => {
                tracing::warn!(error = %err, root = %self.root.display(), "static serve error");
                text_status(500, "static serve error")
            }
        }
    }

    /// 业务作用：依次执行 `try_files`,找到第一个可服务文件。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    /// - `variables`: route 使用的变量计划。
    /// - `eval_ctx`: 本请求变量求值上下文。
    async fn resolve(
        &self,
        parts: &Parts,
        variables: &VariablePlan,
        eval_ctx: &EvalContext<'_>,
    ) -> std::result::Result<Option<StaticFile>, StaticServeError> {
        for template in &self.try_files {
            let candidate = template.render(eval_ctx, variables);
            match self.resolve_candidate(parts, &candidate).await? {
                Some(file) => return Ok(Some(file)),
                None => continue,
            }
        }
        Ok(None)
    }

    /// 业务作用：解析单个 `try_files` 候选。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head,用于 `${uri}` 兜底为空时回退。
    /// - `candidate`: 渲染后的候选路径。
    async fn resolve_candidate(
        &self,
        parts: &Parts,
        candidate: &str,
    ) -> std::result::Result<Option<StaticFile>, StaticServeError> {
        let candidate = if candidate.trim().is_empty() {
            parts.uri.path()
        } else {
            candidate.trim()
        };
        let path = self.safe_join(candidate)?;
        let Some(canonical) = canonicalize_existing(&path).await? else {
            return Ok(None);
        };
        self.ensure_inside_root(&canonical)?;
        if !self.allow_dotfiles {
            ensure_no_dot_component(
                canonical
                    .strip_prefix(&self.canonical_root)
                    .unwrap_or(canonical.as_path()),
            )?;
        }
        let meta = tokio::fs::metadata(&canonical)
            .await
            .map_err(StaticServeError::Io)?;
        if meta.is_file() {
            return Ok(Some(StaticFile {
                path: canonical,
                len: meta.len(),
                modified: meta.modified().ok(),
            }));
        }
        if !meta.is_dir() {
            return Ok(None);
        }
        for index in &self.index {
            let indexed = canonical.join(index);
            let Some(indexed) = canonicalize_existing(&indexed).await? else {
                continue;
            };
            self.ensure_inside_root(&indexed)?;
            if !self.allow_dotfiles {
                ensure_no_dot_component(
                    indexed
                        .strip_prefix(&self.canonical_root)
                        .unwrap_or(indexed.as_path()),
                )?;
            }
            let meta = tokio::fs::metadata(&indexed)
                .await
                .map_err(StaticServeError::Io)?;
            if meta.is_file() {
                return Ok(Some(StaticFile {
                    path: indexed,
                    len: meta.len(),
                    modified: meta.modified().ok(),
                }));
            }
        }
        Ok(None)
    }

    /// 业务作用：把 root-relative 候选路径安全拼到 root 下。
    ///
    /// 参数说明：
    /// - `candidate`: `try_files` 渲染后的候选路径。
    fn safe_join(&self, candidate: &str) -> std::result::Result<PathBuf, StaticServeError> {
        let mut out = self.root.clone();
        let candidate = candidate
            .split_once('?')
            .map(|(path, _)| path)
            .unwrap_or(candidate);
        for segment in candidate.split('/') {
            if segment.is_empty() || segment == "." {
                continue;
            }
            if segment == ".." || segment.as_bytes().contains(&0) {
                return Err(StaticServeError::Forbidden);
            }
            if !self.allow_dotfiles && segment.starts_with('.') {
                return Err(StaticServeError::Forbidden);
            }
            out.push(segment);
        }
        Ok(out)
    }

    /// 业务作用：校验 canonical path 未逃出 root。
    ///
    /// 参数说明：
    /// - `path`: 已 canonicalize 的候选路径。
    fn ensure_inside_root(&self, path: &Path) -> std::result::Result<(), StaticServeError> {
        if path.starts_with(&self.canonical_root) {
            Ok(())
        } else {
            Err(StaticServeError::Forbidden)
        }
    }

    /// 业务作用：生成只读文件响应；显式媒体先选择表示，避免使用原文件 ETag 错误命中裁剪片段。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    /// - `file`: 已解析且校验安全的静态文件。
    ///
    /// 返回：媒体片段、原文件整段/Range 或明确拒绝；普通静态路由保持原条件语义。
    async fn file_response(&self, parts: &Parts, file: StaticFile) -> Response<BoxBody> {
        #[cfg(feature = "media-streaming")]
        if let Some(plan) = &self.media {
            if let Some(response) = plan.serve(parts, &file.path, file.len, file.modified).await {
                return response;
            }
        }
        let etag = if self.etag {
            Some(file.etag())
        } else {
            None
        };
        let last_modified = file.modified.and_then(http_date);
        if etag
            .as_deref()
            .map(|tag| request_etag_matches(parts, tag))
            .unwrap_or(false)
        {
            return not_modified(etag.as_deref(), file.modified);
        }
        if !parts.headers.contains_key(IF_NONE_MATCH)
            && request_not_modified_since(parts, file.modified)
        {
            return not_modified(etag.as_deref(), file.modified);
        }
        let range = if self.range
            && range_allowed_by_if_range(parts, etag.as_deref(), last_modified.as_deref())
        {
            parse_byte_range(parts, file.len)
        } else {
            RangeSelection::Full
        };
        if matches!(range, RangeSelection::Unsatisfiable) {
            return range_not_satisfiable(file.len, etag.as_deref(), last_modified.as_deref());
        }
        let (status, start, body_len) = match range {
            RangeSelection::Full => (StatusCode::OK, 0, file.len),
            RangeSelection::Partial(range) => (
                StatusCode::PARTIAL_CONTENT,
                range.start,
                range.end.saturating_sub(range.start).saturating_add(1),
            ),
            RangeSelection::Unsatisfiable => unreachable!("handled above"),
        };
        let mut builder = Response::builder()
            .status(status)
            .header(CONTENT_LENGTH, body_len.to_string())
            .header(CONTENT_TYPE, self.content_type(&file.path));
        if self.range {
            builder = builder.header(ACCEPT_RANGES, "bytes");
        }
        if status == StatusCode::PARTIAL_CONTENT {
            let end = start.saturating_add(body_len).saturating_sub(1);
            builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{}", file.len));
        }
        if let Some(cache_control) = &self.cache_control {
            builder = builder.header(CACHE_CONTROL, cache_control.clone());
        } else if let Some(max_age) = self.expires {
            builder = builder.header(CACHE_CONTROL, format!("max-age={max_age}"));
        }
        if let Some(max_age) = self.expires {
            // 极端运维值不能在请求路径触发 SystemTime 加法 panic；Cache-Control 仍可表达该
            // 秒数，只有平台时间无法表示绝对日期时省略兼容性的 Expires 头。
            if let Some(value) = SystemTime::now()
                .checked_add(Duration::from_secs(max_age))
                .and_then(http_date)
            {
                builder = builder.header(EXPIRES, value);
            }
        }
        if let Some(tag) = &etag {
            builder = builder.header(ETAG, tag.as_str());
        }
        if let Some(modified) = &last_modified {
            builder = builder.header(LAST_MODIFIED, modified);
        }
        if parts.method == http::Method::HEAD {
            return builder
                .body(empty_body())
                .expect("build static HEAD response");
        }
        match File::open(&file.path).await {
            Ok(mut opened) => {
                if start > 0 {
                    if let Err(err) = opened.seek(std::io::SeekFrom::Start(start)).await {
                        tracing::warn!(path = %file.path.display(), error = %err, "seek static file failed");
                        return text_status(500, "static serve error");
                    }
                }
                builder
                    .body(
                        FileBody {
                            file: opened,
                            remaining: body_len,
                        }
                        .boxed(),
                    )
                    .expect("build static file response")
            }
            Err(err) => {
                tracing::warn!(path = %file.path.display(), error = %err, "open static file failed");
                text_status(500, "static serve error")
            }
        }
    }

    /// 业务作用：根据扩展名返回 Content-Type。
    ///
    /// 参数说明：
    /// - `path`: 文件路径。
    fn content_type(&self, path: &Path) -> http::HeaderValue {
        let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
            return self.default_type.clone();
        };
        let ext = ext.to_ascii_lowercase();
        self.types
            .get(&ext)
            .cloned()
            .or_else(|| content_type_for_ext(&ext).map(http::HeaderValue::from_static))
            .unwrap_or_else(|| self.default_type.clone())
    }
}

/// Range 选择结果。
enum RangeSelection {
    /// 不使用 Range,返回完整文件。
    Full,
    /// 返回单段字节范围。
    Partial(ByteRange),
    /// Range 语法不支持或越界。
    Unsatisfiable,
}

/// 单段 HTTP byte range。
struct ByteRange {
    /// 起始字节,包含。
    start: u64,
    /// 结束字节,包含。
    end: u64,
}

/// 业务作用：解析请求中的单段 `Range: bytes=...`。
///
/// 参数说明：
/// - `parts`: 下游请求 head。
/// - `len`: 文件总长度。
fn parse_byte_range(parts: &Parts, len: u64) -> RangeSelection {
    let Some(raw) = parts
        .headers
        .get(RANGE)
        .and_then(|value| value.to_str().ok())
    else {
        return RangeSelection::Full;
    };
    let Some(spec) = raw.trim().strip_prefix("bytes=") else {
        return RangeSelection::Full;
    };
    if spec.contains(',') || len == 0 {
        return RangeSelection::Unsatisfiable;
    }
    let Some((start_raw, end_raw)) = spec.split_once('-') else {
        return RangeSelection::Unsatisfiable;
    };
    let start_raw = start_raw.trim();
    let end_raw = end_raw.trim();
    if start_raw.is_empty() {
        let Ok(suffix_len) = end_raw.parse::<u64>() else {
            return RangeSelection::Unsatisfiable;
        };
        if suffix_len == 0 {
            return RangeSelection::Unsatisfiable;
        }
        let start = len.saturating_sub(suffix_len);
        return RangeSelection::Partial(ByteRange {
            start,
            end: len - 1,
        });
    }
    let Ok(start) = start_raw.parse::<u64>() else {
        return RangeSelection::Unsatisfiable;
    };
    let end = if end_raw.is_empty() {
        len - 1
    } else {
        match end_raw.parse::<u64>() {
            Ok(end) => end.min(len - 1),
            Err(_) => return RangeSelection::Unsatisfiable,
        }
    };
    if start >= len || start > end {
        return RangeSelection::Unsatisfiable;
    }
    RangeSelection::Partial(ByteRange {
        start,
        end,
    })
}

/// 业务作用：判断 If-Range 是否允许本次 Range 生效。
///
/// 参数说明：
/// - `parts`: 下游请求 head。
/// - `etag`: 当前文件 ETag。
/// - `last_modified`: 当前文件 Last-Modified 文本。
fn range_allowed_by_if_range(
    parts: &Parts,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> bool {
    let Some(raw) = parts
        .headers
        .get(IF_RANGE)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return true;
    };
    etag.map(|tag| raw == tag).unwrap_or(false)
        || last_modified.map(|value| raw == value).unwrap_or(false)
}

/// 业务作用：构造 416 Range Not Satisfiable。
///
/// 参数说明：
/// - `len`: 文件总长度。
/// - `etag`: 当前文件 ETag。
/// - `last_modified`: 当前文件 Last-Modified 文本。
fn range_not_satisfiable(
    len: u64,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Response<BoxBody> {
    let mut builder = Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(CONTENT_RANGE, format!("bytes */{len}"))
        .header(CONTENT_LENGTH, "0")
        .header(ACCEPT_RANGES, "bytes");
    if let Some(tag) = etag {
        builder = builder.header(ETAG, tag);
    }
    if let Some(value) = last_modified {
        builder = builder.header(LAST_MODIFIED, value);
    }
    builder
        .body(empty_body())
        .expect("build static 416 response")
}

/// 已解析的静态文件元数据。
struct StaticFile {
    /// canonicalize 后的文件路径。
    path: PathBuf,
    /// 文件长度。
    len: u64,
    /// 文件修改时间。
    modified: Option<SystemTime>,
}

impl StaticFile {
    /// 业务作用：生成弱 ETag。
    fn etag(&self) -> String {
        let modified = self
            .modified
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|dur| dur.as_secs())
            .unwrap_or(0);
        format!("W/\"{:x}-{:x}\"", self.len, modified)
    }
}

/// 静态文件读取 body。
struct FileBody {
    /// 已打开文件。
    file: File,
    /// 剩余可读字节数。
    remaining: u64,
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：按下游轮询推进正文流，把数据、trailers、失败和结束状态交给统一 HTTP 管线。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let this = self.as_mut().get_mut();
        let max_read = FILE_CHUNK_SIZE.min(this.remaining as usize);
        let mut buf = BytesMut::with_capacity(max_read);
        let n = {
            let mut read_buf = ReadBuf::uninit(buf.spare_capacity_mut());
            match Pin::new(&mut this.file).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => read_buf.filled().len(),
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Some(Err(Box::new(err) as BoxError)));
                }
            }
        };
        if n == 0 {
            this.remaining = 0;
            return Poll::Ready(None);
        }
        this.remaining = this.remaining.saturating_sub(n as u64);
        // SAFETY:poll_read 已按 ReadBuf 的 filled 长度初始化了前 n 个字节。
        unsafe {
            buf.set_len(n);
        }
        Poll::Ready(Some(Ok(Frame::data(buf.freeze()))))
    }

    /// 业务作用：向 HTTP 编码层报告流是否已经结束，避免省略尚未发送的正文或 trailers。
    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    /// 业务作用：向 HTTP 编码层提供剩余实体长度约束，供帧传输选择定长或流式编码。
    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        hint.set_exact(self.remaining);
        hint
    }
}

/// 静态文件解析错误。
enum StaticServeError {
    /// 用户请求了被禁止的路径。
    Forbidden,
    /// 文件系统 IO 错误。
    Io(std::io::Error),
}

/// 业务作用：解析 root 路径。
///
/// 参数说明：
/// - `config_dir`: `gateway.yml` 所在目录。
/// - `root`: 配置中的 root。
fn resolve_root(config_dir: &Path, root: &str) -> PathBuf {
    let path = PathBuf::from(root);
    if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    }
}

/// 业务作用：canonicalize 一个已存在路径,不存在则返回 None。
///
/// 参数说明：
/// - `path`: 待 canonicalize 路径。
async fn canonicalize_existing(
    path: &Path,
) -> std::result::Result<Option<PathBuf>, StaticServeError> {
    match tokio::fs::canonicalize(path).await {
        Ok(path) => Ok(Some(path)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(StaticServeError::Io(err)),
    }
}

/// 业务作用：校验目录索引文件名不包含路径穿越。
///
/// 参数说明：
/// - `name`: 配置中的 index 文件名。
fn validate_index_name(name: &str) -> Result<()> {
    if name.trim().is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.bytes().any(|b| b == 0 || b < 0x20)
    {
        bail!("serve.static.index contains invalid file name `{name}`");
    }
    Ok(())
}

/// 业务作用：解析 nginx `expires` 常用时长。
///
/// 参数说明：
/// - `raw`: 配置值,如 `3600`、`1h`、`7d`、`off`。
fn parse_expires_seconds(raw: &str) -> Result<Option<u64>> {
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let (number, multiplier) = match raw.as_bytes().last().copied() {
        Some(b's') | Some(b'S') => (&raw[..raw.len() - 1], 1_u64),
        Some(b'm') | Some(b'M') => (&raw[..raw.len() - 1], 60_u64),
        Some(b'h') | Some(b'H') => (&raw[..raw.len() - 1], 3_600_u64),
        Some(b'd') | Some(b'D') => (&raw[..raw.len() - 1], 86_400_u64),
        _ => (raw, 1_u64),
    };
    let value = number
        .parse::<u64>()
        .with_context(|| format!("invalid serve.static.expires `{raw}`"))?;
    Ok(Some(value.saturating_mul(multiplier)))
}

/// 业务作用：规范化静态 MIME 扩展名。
///
/// 参数说明：
/// - `raw`: `serve.static.types` 中的扩展名 key,可带前导点。
fn normalize_ext(raw: &str) -> Result<String> {
    let ext = raw.trim().trim_start_matches('.').to_ascii_lowercase();
    if ext.is_empty()
        || ext.contains('/')
        || ext.contains('\\')
        || ext.bytes().any(|b| b == 0 || b <= 0x20)
    {
        bail!("serve.static.types contains invalid extension `{raw}`");
    }
    Ok(ext)
}

/// 业务作用：校验相对路径不包含点文件/点目录。
///
/// 参数说明：
/// - `relative`: 已确认在 root 内的相对路径。
fn ensure_no_dot_component(relative: &Path) -> std::result::Result<(), StaticServeError> {
    for component in relative.components() {
        if let Component::Normal(name) = component {
            if name.to_string_lossy().starts_with('.') {
                return Err(StaticServeError::Forbidden);
            }
        }
    }
    Ok(())
}

/// 业务作用：判断 If-None-Match 是否命中当前 ETag。
///
/// 参数说明：
/// - `parts`: 下游请求 head。
/// - `etag`: 当前文件 ETag。
fn request_etag_matches(parts: &Parts, etag: &str) -> bool {
    parts
        .headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .any(|candidate| candidate == "*" || candidate == etag)
        })
        .unwrap_or(false)
}

/// 业务作用：判断 If-Modified-Since 是否命中当前文件修改时间。
///
/// 参数说明：
/// - `parts`: 下游请求 head。
/// - `modified`: 当前文件修改时间。
fn request_not_modified_since(parts: &Parts, modified: Option<SystemTime>) -> bool {
    let Some(modified_secs) = modified
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
    else {
        return false;
    };
    let Some(since_secs) = parts
        .headers
        .get(IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date)
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
    else {
        return false;
    };
    modified_secs <= since_secs
}

/// 业务作用：构造 304 Not Modified 响应。
///
/// 参数说明：
/// - `etag`: 当前文件 ETag。
/// - `modified`: 当前文件修改时间。
fn not_modified(etag: Option<&str>, modified: Option<SystemTime>) -> Response<BoxBody> {
    let mut builder = Response::builder().status(StatusCode::NOT_MODIFIED);
    if let Some(tag) = etag {
        builder = builder.header(ETAG, tag);
    }
    if let Some(value) = modified.and_then(http_date) {
        builder = builder.header(LAST_MODIFIED, value);
    }
    builder
        .body(empty_body())
        .expect("build static 304 response")
}

/// 业务作用：构造空 body。
fn empty_body() -> BoxBody {
    full_body(Bytes::new())
}

/// 业务作用：根据扩展名返回主流 MIME。
///
/// 参数说明：
/// - `ext`: 文件扩展名。
fn content_type_for_ext(ext: &str) -> Option<&'static str> {
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => Some("text/html; charset=utf-8"),
        "css" => Some("text/css; charset=utf-8"),
        "js" | "mjs" => Some("text/javascript; charset=utf-8"),
        "json" => Some("application/json"),
        "txt" => Some("text/plain; charset=utf-8"),
        "xml" => Some("application/xml"),
        "svg" => Some("image/svg+xml"),
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "ico" => Some("image/x-icon"),
        "wasm" => Some("application/wasm"),
        "pdf" => Some("application/pdf"),
        "woff" => Some("font/woff"),
        "woff2" => Some("font/woff2"),
        _ => None,
    }
}

/// 业务作用：把 SystemTime 格式化成 HTTP-date。
///
/// 参数说明：
/// - `time`: 系统时间。
fn http_date(time: SystemTime) -> Option<String> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    let days = (duration.as_secs() / 86_400) as i64;
    let seconds = duration.as_secs() % 86_400;
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    let (year, month, day) = civil_from_days(days);
    let weekday = WEEKDAYS[(days + 4).rem_euclid(7) as usize];
    let month = MONTHS[month - 1];
    Some(format!(
        "{weekday}, {day:02} {month} {year:04} {hour:02}:{minute:02}:{second:02} GMT"
    ))
}

/// 业务作用：解析 IMF-fixdate HTTP-date。
///
/// 参数说明：
/// - `raw`: HTTP-date 文本,如 `Wed, 21 Oct 2015 07:28:00 GMT`。
fn parse_http_date(raw: &str) -> Option<SystemTime> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 6 || parts[5] != "GMT" {
        return None;
    }
    let day = parts[1].parse::<u32>().ok()?;
    let month = MONTHS
        .iter()
        .position(|month| *month == parts[2])
        .map(|idx| idx as u32 + 1)?;
    let year = parts[3].parse::<i32>().ok()?;
    let mut hms = parts[4].split(':');
    let hour = hms.next()?.parse::<u64>().ok()?;
    let minute = hms.next()?.parse::<u64>().ok()?;
    let second = hms.next()?.parse::<u64>().ok()?;
    if hms.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    if days < 0 {
        return None;
    }
    let secs = (days as u64)
        .saturating_mul(86_400)
        .saturating_add(hour.saturating_mul(3_600))
        .saturating_add(minute.saturating_mul(60))
        .saturating_add(second);
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

/// 业务作用：Unix epoch 天数转公历年月日。
///
/// 参数说明：
/// - `days`: 自 1970-01-01 起的天数。
fn civil_from_days(days: i64) -> (i32, usize, usize) {
    let z = days + 719_468;
    let era = if z >= 0 {
        z
    } else {
        z - 146_096
    } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp
        + if mp < 10 {
            3
        } else {
            -9
        };
    year += if month <= 2 {
        1
    } else {
        0
    };
    (year, month as usize, day as usize)
}

/// 业务作用：公历年月日转 Unix epoch 天数。
///
/// 参数说明：
/// - `year`: 公历年。
/// - `month`: 1..=12。
/// - `day`: 1..=31。
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 {
        year
    } else {
        year - 399
    } / 400;
    let yoe = year - era * 400;
    let month = i64::from(month);
    let doy = (153
        * (month
            + if month > 2 {
                -3
            } else {
                9
            })
        + 2)
        / 5
        + i64::from(day)
        - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
