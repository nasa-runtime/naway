//! 脚本适配只编译到显式 feature；实体所有权沿有界慢路径或带背压的逐帧路径传递。
use crate::{
    config::scripts::Phase,
    extensions::{
        resources,
        scripts::{Chain, Context, Failure},
    },
    routing::Route,
    text_status, BoxBody, BoxError,
};
use bytes::Bytes;
use http::{request::Parts, HeaderMap, Method, Response};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

/// 业务作用：在公共安全门之后执行请求脚本，只在全部成功后允许进入上游并保留响应上下文。
///
/// 参数说明：
/// - `route`：当前快照路由。
/// - `parts`：请求头部唯一修改目标。
/// - `body`：请求实体唯一所有权槽。
/// - `scheme`：可信入口协议。
/// - `proxy`：已发布 listener 的稳定标识，用于平台域资源隔离。
/// - `snapshot`：成功后供响应阶段使用的最小上下文。
///
/// 返回：None 继续转发；明确拒绝、超限或执行失败返回本地响应且不发布半完成输出。
pub(super) async fn request(
    route: &Route,
    parts: &mut Parts,
    body: &mut Option<BoxBody>,
    scheme: &str,
    proxy: &str,
    snapshot: &mut Option<Context>,
) -> Option<Response<BoxBody>> {
    let chain = route.script_plugins.as_ref()?;
    if parts.method == Method::CONNECT || parts.headers.contains_key(http::header::UPGRADE) {
        return Some(text_status(400, "script route requires ordinary HTTP"));
    }
    let mut context = Context {
        scope: parts
            .extensions
            .get::<crate::control::ownership::RequestScope>()
            .map(|scope| scope.0.clone())
            .unwrap_or_else(|| format!("platform:{proxy}:{}", route.id)),
        state_budget: parts
            .extensions
            .get::<crate::control::ownership::state::Budget>()
            .cloned(),
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        scheme: scheme.to_owned(),
        status: 0,
        eof: body.as_ref().is_none_or(Body::is_end_stream),
    };
    match chain
        .execute(Phase::RequestHeaders, &mut parts.headers, &context, None)
        .await
    {
        Ok(output) => {
            if let Some(status) = output.reject {
                return Some(text_status(status, "script rejected request"));
            }
        }
        Err(error) => return Some(failure(error)),
    }
    if chain.has(Phase::RequestBodyStream) {
        let current = body.take().expect("script request owns body");
        match stream(
            chain.clone(),
            Phase::RequestBodyStream,
            &mut parts.headers,
            current,
            context.clone(),
        ) {
            Ok(wrapped) => *body = Some(wrapped),
            Err(error) => return Some(failure(error)),
        }
    } else if chain.has(Phase::RequestBody) {
        let current = body.take().expect("script request owns body");
        context.eof = true;
        match whole(
            chain,
            Phase::RequestBody,
            &mut parts.headers,
            current,
            &context,
        )
        .await
        {
            Ok(Ok(wrapped)) => *body = Some(wrapped),
            Ok(Err(status)) => return Some(text_status(status, "script rejected request")),
            Err(error) => return Some(failure(error)),
        }
    }
    if [
        Phase::ResponseHeaders,
        Phase::ResponseBody,
        Phase::ResponseBodyStream,
    ]
    .into_iter()
    .any(|p| chain.has(p))
    {
        *snapshot = Some(context);
    }
    None
}
/// 业务作用：执行响应脚本；完整实体在发布前验证，流式错误在已发头之后关闭实体流。
///
/// 参数说明：
/// - `chain`：当前请求冻结的脚本链。
/// - `response`：上游响应唯一所有权。
/// - `context`：请求阶段冻结的最小上下文。
///
/// 返回：完整通过或明确拒绝的响应；不允许 HEAD、204、304 被脚本附加实体。
pub(super) async fn response(
    chain: Arc<Chain>,
    mut response: Response<BoxBody>,
    mut context: Context,
) -> Response<BoxBody> {
    context.status = response.status().as_u16();
    context.eof = response.body().is_end_stream();
    match chain
        .execute(
            Phase::ResponseHeaders,
            response.headers_mut(),
            &context,
            None,
        )
        .await
    {
        Ok(output) => {
            if let Some(status) = output.reject {
                return text_status(status, "script rejected response");
            }
        }
        Err(error) => return failure(error),
    }
    if context.method == "HEAD"
        || context.status == 204
        || context.status == 304
        || response.status().is_informational()
    {
        return response;
    }
    if chain.has(Phase::ResponseBodyStream) {
        let (mut parts, body) = response.into_parts();
        return match stream(
            chain,
            Phase::ResponseBodyStream,
            &mut parts.headers,
            body,
            context,
        ) {
            Ok(body) => Response::from_parts(parts, body),
            Err(error) => failure(error),
        };
    }
    if chain.has(Phase::ResponseBody) {
        let (mut parts, body) = response.into_parts();
        context.eof = true;
        return match whole(
            &chain,
            Phase::ResponseBody,
            &mut parts.headers,
            body,
            &context,
        )
        .await
        {
            Ok(Ok(body)) => Response::from_parts(parts, body),
            Ok(Err(status)) => text_status(status, "script rejected response"),
            Err(error) => failure(error),
        };
    }
    response
}
/// 业务作用：显式聚合阶段先预留共享工作集，再在限定时间与字节内读取和重建实体。
///
/// 参数说明：
/// - `chain`：不可变执行链。
/// - `phase`：完整实体方向。
/// - `headers`：实体元数据的唯一修改目标。
/// - `body`：原始实体。
/// - `context`：冻结请求上下文。
///
/// 返回：持有资源凭证的新实体或明确拒绝；超限、读取失败和期限均失败关闭。
async fn whole(
    chain: &Chain,
    phase: Phase,
    headers: &mut HeaderMap,
    body: BoxBody,
    context: &Context,
) -> Result<Result<BoxBody, u16>, Failure> {
    validate_entity(headers, context)?;
    let lease = Arc::new(chain.reserve(phase)?);
    let limit = chain.body_limit(phase);
    if headers.get(http::header::CONTENT_LENGTH).is_some_and(|v| {
        v.to_str()
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .is_none_or(|n| n > limit as u64)
    }) {
        return Err(Failure::Input);
    }
    let collected = tokio::time::timeout(
        Duration::from_secs(30),
        super::collect_wasm_box_body(body, limit),
    )
    .await
    .map_err(|_| Failure::Deadline)?
    .map_err(|_| Failure::Input)?;
    let output = chain
        .execute(phase, headers, context, Some(collected.bytes))
        .await?;
    if let Some(status) = output.reject {
        return Ok(Err(status));
    }
    let bytes = output.body.unwrap_or_default();
    clear_entity_metadata(headers);
    super::normalize_content_length(headers, bytes.len());
    let trailers = collected.trailers.map(|mut value| {
        clear_entity_metadata(&mut value);
        value
    });
    Ok(Ok(HeldBody {
        body: super::replay_wasm_body(bytes, trailers),
        cancel: tokio_util::sync::CancellationToken::new(),
        _lease: lease,
    }
    .boxed()))
}
/// 业务作用：在发送新实体前去掉失效的校验和、长度及范围元数据，不能沿用原表示的验证器。
///
/// 参数说明：
/// - `headers`：当前实体头或尾部字段。
///
/// 返回：删除旧表示元数据；普通业务字段不变。
fn clear_entity_metadata(headers: &mut HeaderMap) {
    for name in [
        "content-length",
        "content-md5",
        "digest",
        "content-digest",
        "repr-digest",
        "etag",
        "last-modified",
        "content-range",
        "accept-ranges",
    ] {
        headers.remove(name);
    }
}
/// 业务作用：只为有实体权限的脚本安装有界背压包装，每个切片与 EOF 使用独立 VM。
///
/// 参数说明：
/// - `chain`：冻结脚本链，旧连接不追随热替换。
/// - `phase`：流式方向。
/// - `headers`：发送前可清除实体 framing 的头部。
/// - `body`：原始流。
/// - `context`：冻结最小上下文。
///
/// 返回：单槽输出流；资源不足或输入头越界时不安装包装。
fn stream(
    chain: Arc<Chain>,
    phase: Phase,
    headers: &mut HeaderMap,
    body: BoxBody,
    context: Context,
) -> Result<BoxBody, Failure> {
    validate_entity(headers, &context)?;
    let lease = Arc::new(chain.reserve(phase)?);
    let selected = chain.stream_headers(phase, headers)?;
    clear_entity_metadata(headers);
    let cancel = tokio_util::sync::CancellationToken::new();
    let worker_cancel = cancel.clone();
    let worker_lease = lease.clone();
    let (mut sender, receiver) = http_body_util::channel::Channel::<Bytes, BoxError>::new(1);
    tokio::spawn(async move {
        let _lease = worker_lease;
        // 下游 Drop 立即撤销生产任务，正在执行的客体由调用预算的 Drop 继续中断并保留资源至结束。
        let result = tokio::select! {
            _ = worker_cancel.cancelled() => return,
            result = produce(&chain, phase, selected, body, context, &mut sender) => result,
        };
        if let Err(error) = result {
            sender.abort(Box::new(error));
        }
    });
    Ok(HeldBody {
        body: receiver.boxed(),
        cancel,
        _lease: lease,
    }
    .boxed())
}
/// 业务作用：按配置上限切分输入视图并逐片执行脚本，最多保留一片输出且尾部不参与客体改写。
///
/// 参数说明：
/// - `chain`：不可变执行链。
/// - `phase`：流式方向。
/// - `headers`：有界只读白名单字段。
/// - `body`：原始流。
/// - `context`：每次调用的最小元数据。
/// - `sender`：容量为一的下游背压通道。
///
/// 返回：完整 EOF 后成功；输入、客体、下游或尾部协议失败终止流。
async fn produce(
    chain: &Chain,
    phase: Phase,
    mut headers: HeaderMap,
    mut body: BoxBody,
    mut context: Context,
    sender: &mut http_body_util::channel::Sender<Bytes, BoxError>,
) -> Result<(), Failure> {
    let limit = chain.body_limit(phase);
    let mut trailers = None;
    context.eof = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| Failure::Input)?;
        match frame.into_data() {
            Ok(mut data) => {
                if trailers.is_some() {
                    return Err(Failure::Input);
                }
                while !data.is_empty() {
                    let chunk = data.split_to(data.len().min(limit));
                    let output = chain
                        .execute(phase, &mut headers, &context, Some(chunk))
                        .await?;
                    if output.reject.is_some() {
                        return Err(Failure::Script);
                    }
                    if let Some(output) = output.body.filter(|b| !b.is_empty()) {
                        sender
                            .send_data(output)
                            .await
                            .map_err(|_| Failure::Cancelled)?;
                    }
                }
            }
            Err(frame) => {
                let mut value = frame.into_trailers().map_err(|_| Failure::Input)?;
                if trailers.is_some()
                    || value.len() > 128
                    || value
                        .iter()
                        .map(|(n, v)| n.as_str().len() + v.len())
                        .sum::<usize>()
                        > 8192
                {
                    return Err(Failure::Input);
                }
                clear_entity_metadata(&mut value);
                trailers = Some(value);
            }
        }
    }
    context.eof = true;
    let output = chain
        .execute(phase, &mut headers, &context, Some(Bytes::new()))
        .await?;
    if output.reject.is_some() {
        return Err(Failure::Script);
    }
    if let Some(output) = output.body.filter(|b| !b.is_empty()) {
        sender
            .send_data(output)
            .await
            .map_err(|_| Failure::Cancelled)?;
    }
    if let Some(trailers) = trailers {
        sender
            .send_trailers(trailers)
            .await
            .map_err(|_| Failure::Cancelled)?;
    }
    Ok(())
}
struct HeldBody {
    body: BoxBody,
    cancel: tokio_util::sync::CancellationToken,
    _lease: Arc<resources::Lease>,
}
impl Body for HeldBody {
    type Data = Bytes;
    type Error = BoxError;
    /// 业务作用：透明传递数据帧并把资源凭证与实际响应寿命绑定。
    ///
    /// 参数说明：
    /// - `cx`：下游唤醒上下文。
    ///
    /// 返回：原始帧、EOF、错误或等待，不改变背压。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }
    /// 业务作用：保留底层流的 EOF 状态，允许无实体响应立即完成。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层已结束时为 true。
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    /// 业务作用：保持有界完整实体的准确长度，逐帧变换则保持未知长度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层实体长度提示。
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
impl Drop for HeldBody {
    /// 业务作用：下游取消或完成时撤销生产任务，避免已断开连接继续占用输入流。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：发出取消；阻塞客体持有的独立凭证直到实际退出才归还。
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
/// 业务作用：映射固定失败语义，不把脚本源码或请求数据放进响应和日志。
///
/// 参数说明：
/// - `error`：已归类的拒绝原因。
///
/// 返回：输入 413、期限 504、容量或依赖 503，其余执行错误 500。
fn failure(error: Failure) -> Response<BoxBody> {
    let status = match error {
        Failure::Input => 413,
        Failure::Deadline => 504,
        Failure::Capacity | Failure::Dependency => 503,
        _ => 500,
    };
    text_status(status, &error.to_string())
}
/// 业务作用：拒绝解释压缩或局部表示，正文脚本不能使编码和 Range 语义与实体脱节。
///
/// 参数说明：
/// - `headers`：当前实体元数据。
/// - `context`：当前响应状态。
///
/// 返回：完整 identity 编码实体可处理；压缩、多值编码或部分响应拒绝。
fn validate_entity(headers: &HeaderMap, context: &Context) -> Result<(), Failure> {
    if context.status == 206
        || headers.contains_key(http::header::CONTENT_RANGE)
        || headers
            .get_all(http::header::CONTENT_ENCODING)
            .iter()
            .any(|value| value.as_bytes() != b"identity")
        || headers
            .get_all(http::header::CONTENT_ENCODING)
            .iter()
            .count()
            > 1
    {
        return Err(Failure::Input);
    }
    Ok(())
}
