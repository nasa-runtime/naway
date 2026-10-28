//! 显式媒体静态路由：有界索引裁剪、文件载荷流式输出与不可变请求计划。
mod admission;
mod boxes;
mod flv;
pub(crate) mod metrics;
mod mp4;
mod reader;

use crate::config::media::{Format, MediaCfg};
use crate::{text_status, BoxBody, BoxError};
use bytes::{Bytes, BytesMut};
use http::{header, request::Parts, Method, Response};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};
use tokio::io::{AsyncRead, ReadBuf};

#[derive(Debug)]
enum Error {
    Malformed,
    Unsupported,
    Limit,
    Position,
    Timeout,
    Io,
}
type Result<T> = std::result::Result<T, Error>;
struct Segment {
    prefix: Vec<u8>,
    offset: u64,
    len: u64,
}
pub(crate) struct Plan {
    cfg: Arc<MediaCfg>,
    quota: Arc<admission::Quota>,
    fingerprint: String,
}

impl Plan {
    /// 业务作用：编译固定容器解析计划并绑定真实静态根，不在构建期扫描媒体实体。
    ///
    /// 参数说明：
    /// - `cfg`：显式路由媒体配置。
    /// - `root`：已规范化且验证存在的静态根。
    ///
    /// 返回：跨快照共享并发计数、内容指纹和只读解析预算。
    pub fn build(cfg: &MediaCfg, root: &Path) -> anyhow::Result<Self> {
        cfg.validate()?;
        let key = nasa::crypto::sha256(&root.to_string_lossy());
        Ok(Self {
            cfg: Arc::new(cfg.clone()),
            quota: admission::Quota::shared(key.clone())?,
            fingerprint: nasa::crypto::sha256(&serde_json::to_string(&(cfg, key))?),
        })
    }
    /// 业务作用：输出不含文件路径的管理摘要，预算与根变化均能产生语义差异。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定配置与不可逆资源域摘要。
    pub fn semantic(&self) -> serde_json::Value {
        serde_json::json!({
            "format":self.cfg.format,
            "max_file_bytes":self.cfg.max_file_bytes,
            "max_inflight":self.cfg.max_inflight,
            "fingerprint":self.fingerprint
        })
    }
    /// 业务作用：只对显式 start 请求准备媒体响应，Range 优先保持原文件字节语义。
    ///
    /// 参数说明：
    /// - `parts`：已通过公共安全管线的请求 head。
    /// - `path`：静态解析器已限定在 root 内的规范文件路径。
    /// - `len`：解析时的文件长度。
    /// - `modified`：解析时的文件修改时间。
    ///
    /// 返回：伪流或明确拒绝响应；无 start、Range 或不支持布局时返回 None 继续原静态管线。
    pub async fn serve(
        &self,
        parts: &Parts,
        path: &Path,
        len: u64,
        modified: Option<SystemTime>,
    ) -> Option<Response<BoxBody>> {
        let start = match start_parameter(parts.uri.query(), &self.cfg.format) {
            Ok(Some(value)) => value,
            Ok(None) => return None,
            Err(_) => return Some(text_status(400, "invalid media start")),
        };
        if parts.headers.contains_key(header::RANGE) {
            return None;
        }
        let mut metric = metrics::Operation::begin(&self.cfg.format);
        if len > self.cfg.max_file_bytes {
            metric.finish("rejected");
            return Some(text_status(413, "media file limit"));
        }
        let Some(permit) = self
            .quota
            .acquire(self.cfg.max_inflight, self.cfg.memory_reservation())
        else {
            metric.finish("rejected");
            return Some(text_status(503, "media capacity"));
        };
        let permit = Arc::new(permit);
        let worker_permit = permit.clone();
        let budget = nabudget::RequestBudget::from_now(Duration::from_millis(self.cfg.timeout_ms));
        let cancel = Cancel(budget.clone());
        let worker_budget = budget.clone();
        let cfg = self.cfg.clone();
        let path = path.to_owned();
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = worker_permit;
            worker_budget.check().map_err(|_| Error::Timeout)?;
            let file = std::fs::File::open(path).map_err(|_| Error::Io)?;
            let before = file.metadata().map_err(|_| Error::Io)?;
            if !before.is_file() || before.len() != len || before.modified().ok() != modified {
                return Err(Error::Io);
            }
            let mut reader = reader::Reader::new(file, len, cfg.clone(), worker_budget);
            let segment = match cfg.format {
                Format::Mp4 => mp4::prepare(&mut reader, start),
                Format::Flv => flv::prepare(&mut reader, start),
            }?;
            reader.check()?;
            let after = reader.file.metadata().map_err(|_| Error::Io)?;
            // 索引只对同一文件状态有效；发布响应前拒绝原地改写，不能把旧索引与新实体混合发送。
            if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
                return Err(Error::Io);
            }
            std::io::Seek::seek(&mut reader.file, std::io::SeekFrom::Start(segment.offset))
                .map_err(|_| Error::Io)?;
            Ok((reader.file, segment))
        });
        let outcome =
            match tokio::time::timeout(Duration::from_millis(self.cfg.timeout_ms), worker).await {
                Ok(Ok(value)) => value,
                Ok(Err(_)) => Err(Error::Io),
                Err(_) => Err(Error::Timeout),
            };
        drop(cancel);
        match outcome {
            Ok((file, segment)) => {
                metric.finish("prepared");
                let length = segment.prefix.len() as u64 + segment.len;
                let response = Response::builder()
                    .status(200)
                    .header(
                        header::CONTENT_TYPE,
                        match self.cfg.format {
                            Format::Mp4 => "video/mp4",
                            Format::Flv => "video/x-flv",
                        },
                    )
                    .header(header::CONTENT_LENGTH, length.to_string())
                    .header(header::CACHE_CONTROL, "no-store")
                    .header(header::ACCEPT_RANGES, "none")
                    .header("x-naway-media", "segment");
                if parts.method == Method::HEAD {
                    return Some(
                        response
                            .body(crate::full_body(Bytes::new()))
                            .expect("media HEAD"),
                    );
                }
                let body = MediaBody {
                    prefix: Some(Bytes::from(segment.prefix)),
                    file: tokio::fs::File::from_std(file),
                    remaining: segment.len,
                    permit: Some(permit),
                };
                Some(response.body(body.boxed()).expect("media response"))
            }
            Err(Error::Unsupported) => {
                metric.finish("fallback");
                None
            }
            Err(error) => {
                let status = match error {
                    Error::Malformed => 422,
                    Error::Limit => 413,
                    Error::Position => 416,
                    Error::Timeout => 504,
                    Error::Io => 503,
                    Error::Unsupported => unreachable!(),
                };
                metric.finish(if status < 500 {
                    "rejected"
                } else {
                    "failed"
                });
                Some(text_status(status, "media request unavailable"))
            }
        }
    }
}
struct Cancel(nabudget::RequestBudget);
impl Drop for Cancel {
    /// 业务作用：取消调用者等待时通知阻塞解析循环，不依赖 JoinHandle 取消同步任务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：后续读取和索引构造检查立即失效。
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// 业务作用：按解码后的唯一键解析起播参数，重复值、浮点特殊值与不支持的 end 均不能静默忽略。
///
/// 参数说明：
/// - `query`：未经解码的查询串。
/// - `format`：路由固定容器类型。
///
/// 返回：MP4 微秒或 FLV 字节位置；没有起播参数为 None，非法参数明确拒绝。
fn start_parameter(query: Option<&str>, format: &Format) -> Result<Option<u64>> {
    let mut start = None;
    let query = query.unwrap_or("");
    if query.len() > 8192 {
        return Err(Error::Limit);
    }
    for (index, (key, value)) in form_urlencoded::parse(query.as_bytes()).enumerate() {
        if index >= 128 {
            return Err(Error::Limit);
        }
        if key == "end" {
            return Err(Error::Position);
        }
        if key != "start" {
            continue;
        }
        if start.is_some() || value.is_empty() || value.len() > 24 {
            return Err(Error::Position);
        }
        let (whole, fraction) = value.split_once('.').unwrap_or((&value, ""));
        if whole.is_empty()
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
            || fraction.len() > 6
            || matches!(format, Format::Flv) && value.contains('.')
            || value.ends_with('.')
        {
            return Err(Error::Position);
        }
        let whole = whole.parse::<u64>().map_err(|_| Error::Position)?;
        let parsed = if matches!(format, Format::Mp4) {
            let decimal = if fraction.is_empty() {
                0
            } else {
                fraction.parse::<u64>().map_err(|_| Error::Position)?
                    * 10u64.pow(6 - fraction.len() as u32)
            };
            whole
                .checked_mul(1_000_000)
                .and_then(|n| n.checked_add(decimal))
                .ok_or(Error::Position)?
        } else {
            whole
        };
        start = Some(parsed);
    }
    Ok(start)
}

struct MediaBody {
    prefix: Option<Bytes>,
    file: tokio::fs::File,
    remaining: u64,
    permit: Option<Arc<admission::Permit>>,
}
impl Body for MediaBody {
    type Data = Bytes;
    type Error = BoxError;
    /// 业务作用：先发送有界元数据，再以 16KiB 帧发送原文件媒体区，响应取消释放准入凭证。
    ///
    /// 参数说明：
    /// - `cx`：下游背压唤醒上下文。
    ///
    /// 返回：下一帧或流结束；文件提前结束必须报错，不伪造完整片段。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        if self.remaining == 0 {
            self.permit.take();
            return Poll::Ready(None);
        }
        let mut bytes = BytesMut::with_capacity((self.remaining.min(16384)) as usize);
        let mut buffer = ReadBuf::uninit(bytes.spare_capacity_mut());
        let count = match Pin::new(&mut self.file).poll_read(cx, &mut buffer) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => buffer.filled().len(),
            Poll::Ready(Err(error)) => {
                self.remaining = 0;
                self.permit.take();
                return Poll::Ready(Some(Err(Box::new(error))));
            }
        };
        if count == 0 {
            self.remaining = 0;
            self.permit.take();
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "media file shortened",
            )))));
        }
        // SAFETY: ReadBuf 已初始化 count 字节，只把这部分交给下游。
        unsafe {
            bytes.set_len(count);
        }
        self.remaining -= count as u64;
        Poll::Ready(Some(Ok(Frame::data(bytes.freeze()))))
    }
    /// 业务作用：让下游识别元数据和实体全部完成后的流状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有剩余前缀或实体时为 true。
    fn is_end_stream(&self) -> bool {
        self.prefix.is_none() && self.remaining == 0
    }
    /// 业务作用：报告片段剩余字节数，不回退成原文件长度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：元数据与媒体区剩余字节的精确长度。
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(
            self.remaining + self.prefix.as_ref().map_or(0, |value| value.len() as u64),
        )
    }
}
