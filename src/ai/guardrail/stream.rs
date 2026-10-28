use super::{Direction, Plan};
use crate::observability::metrics::Metrics;
use crate::{BoxBody, BoxError};
use anyhow::{bail, ensure, Context as _, Result};
use bytes::{Bytes, BytesMut};
use http::{header, Response};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

struct TextLane {
    tail: String,
    total: usize,
}

struct PendingEvent {
    wire: Bytes,
    ends: Vec<(String, usize)>,
    fragments: HashMap<String, String>,
    approved: bool,
}

pub(crate) trait StreamGate: Send + Sync {
    /// 业务作用：检查流式裁决所依赖的配置与时间权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仍允许交付为 true，撤权或到期立即禁止输出。
    fn live(&self) -> bool;
    /// 业务作用：给出外部裁决声明覆盖的有限文本前瞻范围。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：每个文本通道需要保留的字节数。
    fn window_bytes(&self) -> usize;
    /// 业务作用：对尚未交付的跨事件文本作异步裁决。
    ///
    /// 参数说明：
    /// - `text`：是按通道归并的有界窗口。
    ///
    /// 返回：许可或显式依赖 fail-open 为成功；拒绝或预算耗尽为失败。
    fn inspect(self: Arc<Self>, text: String) -> futures::future::BoxFuture<'static, Result<()>>;
}

/// 业务作用：把统一 Chat SSE 转为裁决后交付的有界流，保证跨 event 的匹配前缀不会提前泄露。
///
/// 参数说明：
/// - `response`：统一 SSE 响应。
/// - `plan`：当前快照中的内容规则。
/// - `metrics`：只记录固定结果分类的指标目录。
/// - `max_frame_bytes`：单个流帧字节上限。
/// - `max_response_bytes`：完整响应累计字节上限。
/// - `max_duration`：流生命周期上限。
/// - `gate`：持续检查权限与资源的交付门。
///
/// 返回：带延迟交付门的响应；非 SSE 响应由调用方拒绝，不接受未知流协议作为旁路。
pub(crate) fn wrap_response(
    mut response: Response<BoxBody>,
    plan: Arc<Plan>,
    metrics: Arc<Metrics>,
    max_frame_bytes: usize,
    max_response_bytes: usize,
    max_duration: Duration,
    gate: Option<Arc<dyn StreamGate>>,
) -> Response<BoxBody> {
    response.headers_mut().remove(header::CONTENT_LENGTH);
    response.map(|inner| {
        GuardedBody {
            window_bytes: plan
                .window_bytes
                .max(gate.as_ref().map_or(0, |gate| gate.window_bytes())),
            gate,
            inspection: None,
            approve_count: 0,
            authority_tick: Box::pin(tokio::time::sleep(Duration::from_millis(100))),
            inner,
            plan,
            metrics,
            max_frame_bytes,
            remaining: max_response_bytes,
            deadline: Box::pin(tokio::time::sleep(max_duration)),
            current: Bytes::new(),
            wire: BytesMut::new(),
            pending: VecDeque::new(),
            pending_bytes: 0,
            lanes: HashMap::new(),
            source_done: false,
            failed: false,
        }
        .boxed()
    })
}

struct GuardedBody {
    window_bytes: usize,
    gate: Option<Arc<dyn StreamGate>>,
    inspection: Option<parking_lot::Mutex<futures::future::BoxFuture<'static, Result<()>>>>,
    approve_count: usize,
    authority_tick: Pin<Box<tokio::time::Sleep>>,
    inner: BoxBody,
    plan: Arc<Plan>,
    metrics: Arc<Metrics>,
    max_frame_bytes: usize,
    remaining: usize,
    deadline: Pin<Box<tokio::time::Sleep>>,
    current: Bytes,
    wire: BytesMut,
    pending: VecDeque<PendingEvent>,
    pending_bytes: usize,
    lanes: HashMap<String, TextLane>,
    source_done: bool,
    failed: bool,
}

impl GuardedBody {
    /// 业务作用：在任何字节交付前解码完整 SSE event，并独立维护各 choice/tool 的跨片段文本。
    ///
    /// 参数说明: 无。
    ///
    /// 待处理 event 位于本实例的有界 wire 缓冲。
    ///
    /// 返回：通过时入队等待安全前瞻；畸形协议、内容命中或容量耗尽时终止，不返回原始内容。
    fn accept_event(&mut self) -> Result<()> {
        let wire = self.wire.split().freeze();
        let event = std::str::from_utf8(&wire).context("AI SSE is not UTF-8")?;
        let mut data = String::new();
        for line in event.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(value) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value.strip_prefix(' ').unwrap_or(value));
            } else if !line.is_empty()
                && !line.starts_with(':')
                && line != "event: message"
                && !line.starts_with("id:")
                && !line.starts_with("retry:")
            {
                bail!("AI SSE field is unsupported");
            }
        }
        // 注释、event id 和重连建议不是业务内容，不把这些未检查的上游文本转发给客户端。
        if data.is_empty() {
            return Ok(());
        }
        let mut ends = Vec::new();
        let mut external_fragments = HashMap::new();
        if data.trim() == "[DONE]" {
            self.source_done = true;
        } else {
            let value: Value = serde_json::from_str(&data).context("AI SSE data is not JSON")?;
            ensure!(value.is_object(), "AI SSE requires an object");
            if let Some(category) = self.plan.inspect_json(Direction::Response, &value) {
                self.metrics
                    .inc_ai_guardrail(Direction::Response, category.label());
                bail!("AI stream blocked by content policy");
            }
            let choices = value
                .get("choices")
                .and_then(Value::as_array)
                .context("AI SSE requires choices")?;
            ensure!(choices.len() <= 16, "AI SSE choices exceed limit");
            let mut fragments = HashMap::new();
            for choice in choices {
                let index = choice
                    .get("index")
                    .and_then(Value::as_u64)
                    .context("AI choice has no index")?;
                ensure!(index < 64, "AI choice index exceeds limit");
                let delta = choice
                    .get("delta")
                    .and_then(Value::as_object)
                    .context("AI choice requires delta")?;
                for (name, value) in delta {
                    ensure!(
                        [
                            "role",
                            "content",
                            "refusal",
                            "reasoning_content",
                            "function_call",
                            "tool_calls"
                        ]
                        .contains(&name.as_str()),
                        "unsupported AI delta field"
                    );
                    if name == "role" {
                        ensure!(value.as_str() == Some("assistant"), "invalid AI delta role");
                        continue;
                    }
                    if name == "tool_calls" {
                        let calls = value
                            .as_array()
                            .context("AI tool delta requires an array")?;
                        ensure!(calls.len() <= 16, "AI tool deltas exceed limit");
                        for call in calls {
                            let tool_index = call
                                .get("index")
                                .and_then(Value::as_u64)
                                .context("AI tool delta has no index")?;
                            ensure!(tool_index < 64, "AI tool index exceeds limit");
                            if let Some(function) = call.get("function") {
                                collect_fragments(
                                    &format!("{index}/tool/{tool_index}"),
                                    function,
                                    &mut fragments,
                                    0,
                                )?;
                            }
                        }
                    } else {
                        collect_fragments(&format!("{index}/{name}"), value, &mut fragments, 0)?;
                    }
                }
            }
            for (key, text) in fragments {
                if self.gate.is_some() {
                    external_fragments.insert(key.clone(), text.clone());
                }
                ensure!(
                    self.lanes.contains_key(&key) || self.lanes.len() < 128,
                    "AI text lanes exceed limit"
                );
                let lane = self.lanes.entry(key.clone()).or_insert_with(|| TextLane {
                    tail: String::new(),
                    total: 0,
                });
                lane.tail.push_str(&text);
                lane.total = lane
                    .total
                    .checked_add(text.len())
                    .context("AI text length overflow")?;
                // 每条输出通道单独拼接，交错的 choice/tool 不能把敏感短语拆散后绕过检测。
                if let Some(category) = self.plan.classify(Direction::Response, &lane.tail) {
                    self.metrics
                        .inc_ai_guardrail(Direction::Response, category.label());
                    bail!("AI stream blocked by content policy");
                }
                let mut drop_before = lane.tail.len().saturating_sub(self.window_bytes);
                while !lane.tail.is_char_boundary(drop_before) {
                    drop_before += 1;
                }
                lane.tail.drain(..drop_before);
                ends.push((key, lane.total));
            }
        }
        let wire = Bytes::from(format!("data: {data}\n\n"));
        let max_pending = self
            .window_bytes
            .saturating_mul(4)
            .saturating_add(self.max_frame_bytes.saturating_mul(2));
        ensure!(
            self.pending.len() < 1024
                && self.pending_bytes.saturating_add(wire.len()) <= max_pending,
            "AI undecided output exceeds stream window capacity"
        );
        self.pending_bytes += wire.len();
        self.pending.push_back(PendingEvent {
            wire,
            ends,
            fragments: external_fragments,
            approved: self.gate.is_none(),
        });
        Ok(())
    }

    /// 业务作用：只释放已不可能参与后续命中的完整 event，保持事件顺序与下游背压。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：队首 event 的所有文本通道均经过足够前瞻或完整流正常结束时返回 wire，否则继续等待。
    fn ready_event(&mut self) -> Option<Bytes> {
        let event = self.pending.front()?;
        let ready = self.source_done
            || event.ends.iter().all(|(key, end)| {
                self.lanes
                    .get(key)
                    .is_some_and(|lane| lane.total.saturating_sub(*end) >= self.window_bytes)
            });
        if !ready || !event.approved {
            return None;
        }
        let event = self.pending.pop_front().expect("front event exists");
        self.pending_bytes -= event.wire.len();
        Some(event.wire)
    }

    /// 业务作用：批量审核可安全释放的前缀，并把后续有限前瞻一起送入裁决，避免片段拆分绕过规则。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：窗口具备足够进度时启动一次有界裁决；否则继续读取但不交付未审内容。
    fn schedule_inspection(&mut self) {
        let Some(gate) = self.gate.clone() else {
            return;
        };
        if self.inspection.is_some() || self.pending.front().is_none_or(|event| event.approved) {
            return;
        }
        let count = self
            .pending
            .iter()
            .take_while(|event| {
                self.source_done
                    || event.ends.iter().all(|(key, end)| {
                        self.lanes.get(key).is_some_and(|lane| {
                            lane.total.saturating_sub(*end) >= self.window_bytes
                        })
                    })
            })
            .count();
        let ready_bytes: usize = self
            .pending
            .iter()
            .take(count)
            .flat_map(|event| event.fragments.values())
            .map(String::len)
            .sum();
        if count == 0 || (!self.source_done && ready_bytes < self.window_bytes) {
            return;
        }
        let mut lanes = std::collections::BTreeMap::<&str, String>::new();
        for event in &self.pending {
            for (key, text) in &event.fragments {
                lanes.entry(key).or_default().push_str(text);
            }
        }
        let mut text = lanes.values().cloned().collect::<Vec<_>>().join("\n");
        // 原始事件中的非 delta 文本也必须进入外部裁决，不能以 metadata 或扩展字段隐藏内容。
        for event in &self.pending {
            text.push('\n');
            text.push_str(std::str::from_utf8(&event.wire).expect("canonical SSE is UTF-8"));
        }
        self.approve_count = count;
        self.inspection = Some(parking_lot::Mutex::new(gate.inspect(text)));
    }

    /// 业务作用：清空未裁决数据并把失败收敛为不含内容的流终止。
    ///
    /// 参数说明：
    /// - `reason`：是实现定义的低敏错误信息。
    ///
    /// 返回：只返回一次错误；之后不再从上游读取或向下游发送缓存内容。
    fn stop(&mut self, reason: &'static str) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.failed = true;
        self.pending.clear();
        self.wire.clear();
        self.current = Bytes::new();
        Poll::Ready(Some(Err(Box::new(std::io::Error::other(reason)))))
    }
}

impl Body for GuardedBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：在解码、策略与容量裁决后交付 SSE，任何异常都丢弃仍在窗口内的文本。
    ///
    /// 参数说明：
    /// - `cx`：是下游消费驱动的任务上下文。
    ///
    /// 返回：已裁决 event、暂时等待或一次低敏错误；未审核字节永远不出现在 DATA frame。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        if self.deadline.as_mut().poll(cx).is_ready() {
            return self.stop("AI stream guardrail deadline exceeded");
        }
        if self.gate.as_ref().is_some_and(|gate| !gate.live()) {
            return self.stop("AI stream governance authority retired");
        }
        if self.gate.is_some() && self.authority_tick.as_mut().poll(cx).is_ready() {
            self.authority_tick
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_millis(100));
            let _ = self.authority_tick.as_mut().poll(cx);
        }
        for _ in 0..128 {
            self.schedule_inspection();
            if let Some(inspection) = self.inspection.as_mut() {
                match inspection.get_mut().as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        return self.stop("AI output rejected by external moderation")
                    }
                    Poll::Ready(Ok(())) => {
                        self.inspection = None;
                        let count = self.approve_count;
                        for event in self.pending.iter_mut().take(count) {
                            event.approved = true;
                        }
                    }
                }
            }
            if let Some(wire) = self.ready_event() {
                return Poll::Ready(Some(Ok(Frame::data(wire))));
            }
            if self.source_done {
                return Poll::Ready(None);
            }
            if !self.current.is_empty() {
                let length = self
                    .current
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(self.current.len(), |i| i + 1);
                if self.wire.len().saturating_add(length) > self.max_frame_bytes {
                    return self.stop("AI SSE event exceeds byte limit");
                }
                let segment = self.current.split_to(length);
                self.wire.extend_from_slice(&segment);
                if (self.wire.ends_with(b"\n\n") || self.wire.ends_with(b"\r\n\r\n"))
                    && self.accept_event().is_err()
                {
                    return self.stop("AI stream rejected by guardrail");
                }
                continue;
            }
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if data.len() > self.remaining {
                            return self.stop("AI stream exceeds cumulative byte limit");
                        }
                        self.remaining -= data.len();
                        self.current = data;
                    }
                    Err(_) => return self.stop("AI SSE trailers are unsupported"),
                },
                Poll::Ready(Some(Err(_))) => return self.stop("AI upstream stream failed"),
                Poll::Ready(None) => return self.stop("AI SSE ended without completion marker"),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// 业务作用：保持 Hyper 对护栏待发送内容与流结束状态的一致判断。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：发生失败，或正常完成且待发送队列为空时为 true。
    fn is_end_stream(&self) -> bool {
        self.failed || (self.source_done && self.pending.is_empty())
    }
}

/// 业务作用：按结构路径收集增量文本，防止同一 event 内多个字段覆盖或混淆通道。
///
/// 参数说明：
/// - `path`：是固定增量路径
/// - `value`：是当前节点
/// - `output`：保存片段
/// - `depth`：限制结构深度。
///
/// 返回：合法文本、空节点和浅层对象被收集；未知数组或超深结构拒绝。
fn collect_fragments(
    path: &str,
    value: &Value,
    output: &mut HashMap<String, String>,
    depth: usize,
) -> Result<()> {
    ensure!(
        depth <= 4 && path.len() <= 256 && output.len() <= 128,
        "AI delta structure exceeds limit"
    );
    match value {
        Value::Null => {}
        Value::String(text) => {
            output.entry(path.to_owned()).or_default().push_str(text);
        }
        Value::Object(values) => {
            ensure!(values.len() <= 8, "AI delta object exceeds limit");
            for (key, value) in values {
                ensure!(
                    key == "name" || key == "arguments",
                    "unsupported AI function delta field"
                );
                collect_fragments(&format!("{path}/{key}"), value, output, depth + 1)?;
            }
        }
        _ => bail!("unsupported AI text delta"),
    }
    Ok(())
}
