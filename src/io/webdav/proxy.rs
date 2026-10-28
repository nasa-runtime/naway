//! DAV 代理只改变固定前缀与已选上游 authority，不改变标准方法、锁和条件语义。

use super::{input, stream, Session};
use crate::{full_body, text_status, BoxBody};
use anyhow::{ensure, Context, Result};
use http::{request::Parts, HeaderValue, Request, Response, Uri};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct Mapping {
    public_prefix: String,
    upstream_prefix: String,
    selected_origin: Arc<parking_lot::Mutex<Option<String>>>,
    authority: super::filesystem::Authority,
    config: Arc<crate::config::webdav::WebDavCfg>,
}

impl Session {
    /// 业务作用：准备唯一普通 HTTP 转发请求，把 DAV 资源映射作为可信扩展传给当次上游选择。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：主请求路径已按固定前缀改写的请求；不能再次取出或用于本地文件执行。
    pub fn proxy_request(&mut self) -> Result<Request<BoxBody>> {
        ensure!(self.plan.root.is_none(), "local WebDAV cannot proxy");
        let mut request = self
            .request
            .take()
            .context("WebDAV request already consumed")?;
        let mapping = Mapping {
            public_prefix: self.plan.cfg.mount_prefix.clone(),
            upstream_prefix: self
                .plan
                .cfg
                .upstream_prefix
                .clone()
                .unwrap_or_else(|| "/".into()),
            selected_origin: Arc::new(parking_lot::Mutex::new(None)),
            authority: self.lease.authority.clone(),
            config: self.plan.cfg.clone(),
        };
        let path = input::map_path(
            request.uri().path(),
            &mapping.public_prefix,
            &mapping.upstream_prefix,
        )?;
        *request.uri_mut() = path.parse()?;
        // 协议 XML 需要按明文字节设置预算；上游若忽略 identity 仍不能跳过响应实体门。
        request
            .headers_mut()
            .insert("accept-encoding", HeaderValue::from_static("identity"));
        request.extensions_mut().insert(mapping.clone());
        self.mapping = Some(mapping);
        Ok(request)
    }

    /// 业务作用：提供与准入共用的绝对时限，HTTP 等待不能在文件协议之外另起一段期限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：从请求开始计算的截止时刻。
    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    /// 业务作用：在发布代理协议响应前检查并重写 bounded multistatus，保留文件正文流式形态。
    ///
    /// 参数说明：
    /// - `response`：唯一普通 HTTP 转发路径返回的响应。
    /// - `file_response`：原始方法是否 GET/HEAD；非文件方法的 XML 必须有界处理。
    ///
    /// 返回：客户端可见挂载点的资源 href 和完整租约包装；跨根 href、压缩控制体或超限拒绝。
    pub async fn proxy_response(
        self,
        response: Response<BoxBody>,
        file_response: bool,
    ) -> Response<BoxBody> {
        let Some(mapping) = self.mapping.as_ref() else {
            return text_status(502, "WebDAV upstream mapping missing");
        };
        let Some(selected) = mapping.selected_origin.lock().clone() else {
            return response.map(|body| stream::GuardedBody::wrap(body, self.lease, self.deadline));
        };
        let operation = async {
            let (mut parts, body) = response.into_parts();
            if let Some(location) = parts.headers.get("location") {
                let value = response_resource(
                    location
                        .to_str()
                        .map_err(|_| text_status(502, "invalid WebDAV Location"))?,
                    mapping,
                    &selected,
                    &self.origin,
                )
                .map_err(|_| text_status(502, "WebDAV Location outside authority"))?;
                parts.headers.insert(
                    "location",
                    HeaderValue::from_str(&value)
                        .map_err(|_| text_status(502, "invalid WebDAV Location"))?,
                );
            }
            let body = if !file_response || parts.status == http::StatusCode::MULTI_STATUS {
                if parts.headers.contains_key("content-encoding") {
                    return Err(text_status(
                        502,
                        "encoded WebDAV control response unsupported",
                    ));
                }
                let bytes = stream::collect(body, self.plan.cfg.max_multistatus_bytes)
                    .await
                    .map_err(|_| text_status(502, "WebDAV response limit exceeded"))?;
                let xml = parts.status == http::StatusCode::MULTI_STATUS
                    || parts
                        .headers
                        .get("content-type")
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| {
                            matches!(
                                value.split(';').next().unwrap_or("").trim(),
                                "application/xml" | "text/xml"
                            )
                        });
                let bytes = if bytes.is_empty() || !xml {
                    bytes
                } else {
                    input::validate_xml(
                        &bytes,
                        &self.plan.cfg,
                        self.plan.cfg.max_multistatus_bytes,
                    )
                    .map_err(|_| text_status(502, "invalid WebDAV XML response"))?;
                    let mut tree = xmltree::Element::parse(bytes.as_ref())
                        .map_err(|_| text_status(502, "invalid WebDAV XML response"))?;
                    if parts.status == http::StatusCode::MULTI_STATUS
                        && (tree.namespace.as_deref() != Some("DAV:") || tree.name != "multistatus"
                            || tree.children.iter().filter(|child| matches!(child, xmltree::XMLNode::Element(element)
                                if element.namespace.as_deref() == Some("DAV:") && element.name == "response")).count()
                                > self.plan.cfg.max_entries.saturating_add(1)) {
                            return Err(text_status(502, "invalid or oversized WebDAV multistatus"));
                    }
                    rewrite_tree(&mut tree, None, mapping, &selected, &self.origin)
                        .map_err(|_| text_status(502, "WebDAV resource href outside authority"))?;
                    let mut writer = BoundedWriter {
                        bytes: Vec::new(),
                        limit: self.plan.cfg.max_multistatus_bytes,
                    };
                    tree.write_with_config(
                        &mut writer,
                        xmltree::EmitterConfig::new().perform_indent(false),
                    )
                    .map_err(|_| text_status(502, "WebDAV XML serialization limit exceeded"))?;
                    writer.bytes.into()
                };
                for name in ["transfer-encoding", "etag", "content-md5", "digest"] {
                    parts.headers.remove(name);
                }
                parts.headers.insert(
                    "content-length",
                    HeaderValue::from_str(&bytes.len().to_string()).expect("decimal length"),
                );
                full_body(bytes)
            } else {
                body
            };
            Ok::<_, Response<BoxBody>>(Response::from_parts(parts, body))
        };
        match tokio::time::timeout_at(self.deadline, operation).await {
            Ok(Ok(response)) => {
                response.map(|body| stream::GuardedBody::wrap(body, self.lease, self.deadline))
            }
            Ok(Err(response)) => response,
            Err(_) => text_status(504, "WebDAV response deadline exceeded"),
        }
    }
}

impl Mapping {
    /// 业务作用：按实际选中实例重写 Destination 与 If 的资源标签，重试不能沿用旧实例 authority。
    ///
    /// 参数说明：
    /// - `parts`：单次转发已完成头操作的请求 head。
    /// - `uri`：该次已选择的上游完整 URI。
    ///
    /// 返回：同根目标均换为所选实例；无选择、非 HTTP scheme 或路径越界拒绝发送。
    pub fn apply(&self, parts: &mut Parts, uri: &Uri) -> Result<()> {
        // 完成认证或审计不代表权威永久有效；真正发送上游前仍要拒绝已换代或被取消的请求。
        ensure!((self.authority)(), "WebDAV request authority expired");
        let scheme = uri.scheme_str().context("WebDAV upstream scheme missing")?;
        ensure!(
            matches!(scheme, "http" | "https"),
            "invalid WebDAV upstream scheme"
        );
        let origin = format!(
            "{scheme}://{}",
            uri.authority()
                .context("WebDAV upstream authority missing")?
        );
        let map = |value: &str| -> Result<String> {
            let uri: Uri = value.parse()?;
            ensure!(uri.query().is_none(), "WebDAV resource query unsupported");
            Ok(format!(
                "{origin}{}",
                input::map_path(uri.path(), &self.public_prefix, &self.upstream_prefix)?
            ))
        };
        if let Some(value) = input::single(&parts.headers, "destination")? {
            let value = map(value)?;
            parts
                .headers
                .insert("destination", HeaderValue::from_str(&value)?);
        }
        if let Some(value) = input::single(&parts.headers, "if")? {
            let value = input::map_if(value, map)?;
            parts.headers.insert("if", HeaderValue::from_str(&value)?);
        }
        *self.selected_origin.lock() = Some(origin);
        Ok(())
    }
}

/// 业务作用：将后端资源 URI 还原为公开挂载点，不把外部 href 当作本根资源发布。
///
/// 参数说明：
/// - `value`：后端提供的资源 URI。
/// - `mapping`：固定前缀契约。
/// - `selected`：实际请求的后端 origin。
/// - `origin`：当前客户端请求的公开 origin。
///
/// 返回：同根资源的公开绝对 URI；外域、query、fragment 或危险路径拒绝。
fn response_resource(
    value: &str,
    mapping: &Mapping,
    selected: &str,
    origin: &str,
) -> Result<String> {
    ensure!(
        value.len() <= 4096 && !value.contains('#'),
        "invalid WebDAV response resource"
    );
    let uri: Uri = value.parse()?;
    ensure!(uri.query().is_none(), "WebDAV response query forbidden");
    if uri.authority().is_some() {
        ensure!(
            format!(
                "{}://{}",
                uri.scheme_str().unwrap_or(""),
                uri.authority().expect("authority")
            )
            .eq_ignore_ascii_case(selected),
            "cross-origin WebDAV response"
        );
    } else {
        ensure!(
            value.starts_with('/') && !value.starts_with("//"),
            "invalid WebDAV response path"
        );
    }
    let (mut parts, _) = Request::new(()).into_parts();
    parts.uri = uri;
    let limits = crate::config::model::ServerLimitsCfg {
        max_path_bytes: 4096,
        max_path_segments: 64,
        ..Default::default()
    };
    ensure!(
        crate::proxy::normalize_request_path(&mut parts, &limits),
        "unsafe WebDAV response path"
    );
    let path = input::map_path(
        parts.uri.path(),
        &mapping.upstream_prefix,
        &mapping.public_prefix,
    )?;
    let path = input::resource(&path, &parts, "http", &mapping.config)?;
    Ok(format!("{origin}{path}"))
}

/// 业务作用：只重写 DAV 资源引用，不解释 owner 展示 XML 或秘密 lock-token href。
///
/// 参数说明：
/// - `node`：已经过节点/深度预算验证的 XML 节点。
/// - `parent`：父 DAV 节点名，用于区分资源和 token。
/// - `mapping`：固定前缀映射。
/// - `selected`：实际后端 origin。
/// - `origin`：客户端可见 origin。
///
/// 返回：资源引用完成还原；非法资源文本拒绝整个控制响应。
fn rewrite_tree(
    node: &mut xmltree::Element,
    parent: Option<&str>,
    mapping: &Mapping,
    selected: &str,
    origin: &str,
) -> Result<()> {
    // 只进入标准协议结构；dead property 即使包含同名 DAV 元素也属于用户数据，不能被当成导航指令。
    if node.namespace.as_deref() != Some("DAV:") {
        return Ok(());
    }
    if node.name == "href"
        && matches!(
            parent,
            Some(
                "response"
                    | "lockroot"
                    | "location"
                    | "lock-token-submitted"
                    | "no-conflicting-lock"
            )
        )
    {
        ensure!(
            node.children.iter().all(|child| matches!(
                child,
                xmltree::XMLNode::Text(_) | xmltree::XMLNode::CData(_)
            )),
            "invalid WebDAV href children"
        );
        let value = node.get_text().context("empty WebDAV href")?;
        let mapped = response_resource(&value, mapping, selected, origin)?;
        node.children = vec![xmltree::XMLNode::Text(mapped)];
        return Ok(());
    }
    if !matches!(
        (node.name.as_str(), parent),
        ("multistatus" | "prop" | "error", None)
            | ("response", Some("multistatus"))
            | ("propstat" | "location", Some("response"))
            | ("prop", Some("propstat"))
            | ("lockdiscovery", Some("prop"))
            | ("activelock", Some("lockdiscovery"))
            | ("lockroot", Some("activelock"))
            | (
                "lock-token-submitted" | "no-conflicting-lock",
                Some("error")
            )
    ) {
        return Ok(());
    }
    let parent = Some(node.name.as_str());
    for child in &mut node.children {
        if let xmltree::XMLNode::Element(child) = child {
            rewrite_tree(child, parent, mapping, selected, origin)?;
        }
    }
    Ok(())
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}
impl std::io::Write for BoundedWriter {
    /// 业务作用：在 XML 转义膨胀时仍先扣字节预算再追加，禁止无界输出分配。
    ///
    /// 参数说明：
    /// - `value`：序列化器生成的下一块编码字节。
    ///
    /// 返回：全部追加或明确超限错误，不写入半块。
    fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
        if value.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("WebDAV XML output limit"));
        }
        self.bytes.extend_from_slice(value);
        Ok(value.len())
    }
    /// 业务作用：完成有界内存编码，无外部存储副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：成功；完整字节在响应发布前统一校验。
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
