//! 在原业务 body 上做无原文留存的白名单观察，所有内存与处理字节均先预留。

use super::*;
use bytes::Bytes;
use http::{HeaderMap, Response};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

struct State {
    head: Option<(u16, u64)>,
    request: Option<Value>,
    response: Option<Value>,
    committed: bool,
}
pub(crate) struct Capture {
    registry: Weak<Registry>,
    id: String,
    generation: u64,
    method: String,
    policy: BodyPolicy,
    permit: Arc<std::sync::atomic::AtomicBool>,
    expires: Instant,
    state: Mutex<State>,
}

impl Registry {
    /// 业务作用：在成功认证后为精确范围预留单条最坏字节和进程解析名额，正文尚未读取。
    ///
    /// 参数说明：
    /// - `generation`：是冻结路由
    /// - `proxy`：是冻结路由
    /// - `route`：是冻结路由
    /// - `consumer`：是认证身份
    /// - `method`：是入口方法。
    ///
    /// 返回：最多一个正文观察器；未批准、满载、争用或换代均直接跳过，不影响业务。
    pub(crate) fn begin(
        self: &Arc<Self>,
        generation: u64,
        proxy: &str,
        route: &str,
        consumer: Option<&str>,
        method: &http::Method,
    ) -> Option<Arc<Capture>> {
        if method.as_str().len() > 32 {
            return None;
        }
        let snapshot = self.current().ok()?;
        if snapshot.version != generation || !enabled(&snapshot) {
            return None;
        }
        let mut inner = self.inner.try_lock()?;
        Self::expire(&mut inner, &snapshot);
        let entry = inner.entries.values_mut().find(|entry| {
            entry.approver.is_some()
                && entry.request.body.is_some()
                && entry.request.proxy == proxy
                && entry.request.route == route
                && entry
                    .request
                    .consumer
                    .as_deref()
                    .is_none_or(|selected| Some(selected) == consumer)
        })?;
        if entry.samples.len() + entry.reserved >= entry.request.max_samples
            || entry
                .bytes
                .saturating_add((entry.reserved + 1).saturating_mul(entry.request.max_record_bytes))
                > entry.request.max_total_bytes
        {
            return None;
        }
        self.inflight
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                (current < 64).then_some(current + 1)
            })
            .ok()?;
        // 许可先于包装业务帧；取消、TTL 和 reload 均不能重置仍被旧流持有的进程名额。
        entry.reserved += 1;
        let policy = entry.request.body.as_ref()?.clone();
        Some(Arc::new(Capture {
            registry: Arc::downgrade(self),
            id: entry.id.clone(),
            generation,
            method: method.as_str().into(),
            permit: entry.permit.clone(),
            expires: entry.expires,
            state: Mutex::new(State {
                head: None,
                request: policy.request_fields.is_empty().then(|| {
                    json!({
                        "state":"not_requested"
                    })
                }),
                response: policy.response_fields.is_empty().then(|| {
                    json!({
                        "state":"not_requested"
                    })
                }),
                committed: false,
            }),
            policy,
        }))
    }
}

impl Capture {
    /// 业务作用：在每次正文检查前复验活动权威，撤回、过期和配置变化立即停止解析。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有原审批仍有效且当前代一致才为真，不执行 I/O。
    fn active(&self) -> bool {
        self.permit.load(Ordering::Acquire)
            && Instant::now() < self.expires
            && self
                .registry
                .upgrade()
                .and_then(|registry| registry.current().ok())
                .is_some_and(|snapshot| snapshot.version == self.generation && enabled(&snapshot))
    }

    /// 业务作用：在原始请求正文保持流式和背压的前提下附加有限观察。
    ///
    /// 参数说明：
    /// - `body`：是认证后请求；只借用内容类型和编码是否可检查。
    /// - `headers`：是认证后请求；只借用内容类型和编码是否可检查。
    ///
    /// 返回：原帧保真的正文，未知格式不采集。
    pub(crate) fn request(
        self: &Arc<Self>,
        body: crate::BoxBody,
        headers: &HeaderMap,
    ) -> crate::BoxBody {
        self.wrap(body, headers, false)
    }

    /// 业务作用：冻结最终响应头并观察交付正文，不提前读流、不改变业务实体。
    ///
    /// 参数说明：
    /// - `response`：是最终下游响应
    /// - `elapsed`：为到响应头的耗时。
    ///
    /// 返回：头和帧语义不变的响应，记录只在有限观测结束后提交。
    pub(crate) fn response(
        self: Arc<Self>,
        response: Response<crate::BoxBody>,
        elapsed: Duration,
    ) -> Response<crate::BoxBody> {
        self.state.lock().head = Some((
            response.status().as_u16(),
            elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
        ));
        let (parts, body) = response.into_parts();
        let body = self.wrap(body, &parts.headers, true);
        self.commit();
        Response::from_parts(parts, body)
    }

    /// 业务作用：只对明确 JSON、未压缩且被批准方向建立解析器，其余只报告不可检查状态。
    ///
    /// 参数说明：
    /// - `body`：是原始流
    /// - `headers`：是原始流
    /// - `response`：选择已批准的方向白名单。
    ///
    /// 返回：无额外完整正文缓存的包装；空白名单直接返回原 body。
    fn wrap(
        self: &Arc<Self>,
        body: crate::BoxBody,
        headers: &HeaderMap,
        response: bool,
    ) -> crate::BoxBody {
        let fields = if response {
            &self.policy.response_fields
        } else {
            &self.policy.request_fields
        };
        if fields.is_empty() {
            return body;
        }
        let json = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| {
                value.trim().eq_ignore_ascii_case("application/json")
                    || value.trim().ends_with("+json")
            });
        let clear = headers
            .get(http::header::CONTENT_ENCODING)
            .is_none_or(|value| value.as_bytes().eq_ignore_ascii_case(b"identity"));
        if !json || !clear {
            self.finish(
                response,
                json!({
                    "state":"unsupported"
                }),
            );
            return body;
        }
        let parser = mask::JsonMask::new(fields.clone().into(), self.policy.max_inspect_bytes);
        if body.is_end_stream() {
            self.finish(response, parser.finish(true));
            return body;
        }
        Observed {
            body,
            capture: Some(self.clone()),
            parser: Some(parser),
            response,
        }
        .boxed()
    }

    /// 业务作用：保存已强制遮蔽的方向结果，双向流完成后尝试一次提交。
    ///
    /// 参数说明：
    /// - `response`：是方向
    /// - `value`：只来自固定字段解析器，不得传入业务正文。
    ///
    /// 返回：最多写入一个方向，不覆盖已完成观测。
    fn finish(&self, response: bool, value: Value) {
        let mut state = self.state.lock();
        let target = if response {
            &mut state.response
        } else {
            &mut state.request
        };
        if target.is_none() {
            *target = Some(value);
        }
        drop(state);
        self.commit();
    }

    /// 业务作用：在完整遮蔽结果与响应头齐备后复验授权和字节硬门，非阻塞提交唯一记录。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：失权、争用或越界时丢弃；不会重建退休会话或修改业务流。
    fn commit(&self) {
        let mut state = self.state.lock();
        if state.committed
            || state.head.is_none()
            || state.request.is_none()
            || state.response.is_none()
        {
            return;
        }
        state.committed = true;
        let (status, elapsed) = state.head.expect("checked head");
        let value = json!({
            "method":self.method,
            "status":status,
            "elapsed_us":elapsed,
            "request_body":state.request.take(),
            "response_body":state.response.take()
        });
        drop(state);
        if !self.active() {
            return;
        }
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let Some(mut inner) = registry.inner.try_lock() else {
            return;
        };
        let Some(entry) = inner.entries.get_mut(&self.id) else {
            return;
        };
        let bytes = serde_json::to_vec(&value).map_or(usize::MAX, |value| value.len());
        if bytes > entry.request.max_record_bytes
            || bytes > entry.request.max_total_bytes.saturating_sub(entry.bytes)
            || entry.samples.len() >= entry.request.max_samples
        {
            return;
        }
        entry.bytes += bytes;
        entry.samples.push(value);
    }
}

impl Drop for Capture {
    /// 业务作用：在最后一个流观察者释放时归还进程名额，旧会话退休不能提前重用该容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：减少活动解析数；会话锁争用时保守保留其预约至 TTL，不阻塞数据面。
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.inflight.fetch_sub(1, Ordering::AcqRel);
            if let Some(mut inner) = registry.inner.try_lock() {
                if let Some(entry) = inner.entries.get_mut(&self.id) {
                    entry.reserved = entry.reserved.saturating_sub(1);
                }
            }
        }
    }
}

struct Observed {
    body: crate::BoxBody,
    capture: Option<Arc<Capture>>,
    parser: Option<mask::JsonMask>,
    response: bool,
}
impl Observed {
    /// 业务作用：在结束、读取失败或取消时终结增量检查，不保存未完成原文。
    ///
    /// 参数说明：
    /// - `complete`：区分正常结束和中断。
    ///
    /// 返回：释放解析器和本方向 owner，重复调用无副作用。
    fn finish(&mut self, complete: bool) {
        if let (Some(capture), Some(parser)) = (self.capture.take(), self.parser.take()) {
            capture.finish(self.response, parser.finish(complete));
        }
    }
}
impl Body for Observed {
    type Data = Bytes;
    type Error = crate::BoxError;
    /// 业务作用：借用当前帧推进固定解析状态，禁止预读、修改或聚合业务数据。
    ///
    /// 参数说明：
    /// - `cx`：是原业务任务上下文。
    ///
    /// 返回：原帧、等待或结束；观察失权后立即停止检查并释放状态。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self
            .capture
            .as_ref()
            .is_some_and(|capture| !capture.active())
        {
            self.finish(false);
        }
        let result = Pin::new(&mut self.body).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(parser), Some(bytes)) = (self.parser.as_mut(), frame.data_ref()) {
                    parser.feed(bytes);
                }
                if self.body.is_end_stream() {
                    self.finish(true);
                }
            }
            Poll::Ready(None) => self.finish(true),
            Poll::Ready(Some(Err(_))) => self.finish(false),
            _ => {}
        }
        result
    }
    /// 业务作用：保持原正文大小提示，不因诊断影响 Content-Length 或发送策略。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原 body 的大小边界。
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
    /// 业务作用：保持协议结束提示，空实体不被诊断变成悬挂流。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原 body 的结束状态。
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}
impl Drop for Observed {
    /// 业务作用：把取消和未读取到结束的 body 标记为不完整，确保解析名额有界释放。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：提交遮蔽后的失败状态，不读剩余正文。
    fn drop(&mut self) {
        self.finish(false);
    }
}
