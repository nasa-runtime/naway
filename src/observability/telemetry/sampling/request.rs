//! 路由选定后才开始记录 span；未选中的请求只保存固定大小摘要，提升不重建子 trace。

use std::cell::Cell;
use std::time::{Instant, SystemTime};

use super::Policy;
use crate::config::telemetry::RemoteParent;
use opentelemetry::trace::{
    Link, SpanBuilder, SpanContext, SpanId, SpanKind, TraceContextExt, TraceFlags, TraceId, Tracer,
};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::{
    IdGenerator, Sampler, SamplingDecision, SamplingResult, SdkTracer, ShouldSample,
};

#[derive(Clone, Copy, Debug)]
struct Decision(bool);

#[derive(Clone, Debug)]
pub(in crate::observability::telemetry) struct ScopedSampler(pub Sampler);

impl ShouldSample for ScopedSampler {
    /// 业务作用：按请求冻结的作用域决策记录 server span，其余 SDK span 继续遵循父或平台采样。
    ///
    /// 参数说明：
    /// - `parent`：SDK 传入的父 Context，本地私有决策只由当前模块写入。
    /// - `trace_id`：SDK 分配的 trace 标识。
    /// - `name`：待创建 span 的名称。
    /// - `kind`：待创建 span 的角色。
    /// - `attributes`：SDK 提供的初始 span 属性。
    /// - `links`：SDK 提供的关联 span 链接。
    ///
    /// 返回：明确 RecordAndSample 或 Drop，不从传播头接受私有采样指令。
    fn should_sample(
        &self,
        parent: Option<&Context>,
        trace_id: TraceId,
        name: &str,
        kind: &SpanKind,
        attributes: &[KeyValue],
        links: &[Link],
    ) -> SamplingResult {
        if let Some(decision) = parent.and_then(|parent| parent.get::<Decision>()) {
            return SamplingResult {
                decision: if decision.0 {
                    SamplingDecision::RecordAndSample
                } else {
                    SamplingDecision::Drop
                },
                attributes: vec![],
                trace_state: parent
                    .map(|p| p.span().span_context().trace_state().clone())
                    .unwrap_or_default(),
            };
        }
        self.0
            .should_sample(parent, trace_id, name, kind, attributes, links)
    }
}

#[derive(Clone, Copy)]
struct AssignedIds {
    trace: Option<TraceId>,
    span: Option<SpanId>,
}
thread_local! { static ASSIGNED: Cell<Option<AssignedIds>> = const {
    Cell::new(None)
}; }

#[derive(Debug)]
pub(in crate::observability::telemetry) struct SamplingIds;

impl IdGenerator for SamplingIds {
    /// 业务作用：让延迟构造的 root span 保留入口已经传播的 trace id。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前同步构造作用域预留的 ID，否则使用进程唯一快速 ID。
    fn new_trace_id(&self) -> TraceId {
        ASSIGNED.with(|cell| {
            let mut assigned = cell.get();
            let id = assigned.as_mut().and_then(|ids| ids.trace.take());
            cell.set(assigned);
            id.unwrap_or_else(super::super::fast_trace_id)
        })
    }

    /// 业务作用：让延迟构造的 server span 保留入口已经确定的 span id。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：每个预留 ID 只消费一次，嵌套 instrumentation 获得不同 ID。
    fn new_span_id(&self) -> SpanId {
        ASSIGNED.with(|cell| {
            let mut assigned = cell.get();
            let id = assigned.as_mut().and_then(|ids| ids.span.take());
            cell.set(assigned);
            id.unwrap_or_else(super::super::fast_span_id)
        })
    }
}

struct IdScope(Option<AssignedIds>);
impl Drop for IdScope {
    /// 业务作用：退出同步 SDK 构造后恢复上一层 ID 作用域，异常展开也不能污染下一请求。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：线程局部预留恢复；该守卫不会越过任何 await。
    fn drop(&mut self) {
        ASSIGNED.with(|cell| cell.set(self.0));
    }
}

pub(in crate::observability::telemetry) struct RequestSampling {
    parent: Context,
    trace_id: TraceId,
    span_id: SpanId,
    started: SystemTime,
    elapsed: Instant,
    policy: Policy,
    method: String,
    scheme: &'static str,
    rejected_context: bool,
    selected: bool,
    recording: bool,
}

impl RequestSampling {
    /// 业务作用：在信任边界后冻结 lineage 与有限请求摘要，尚不创建记录中的 SDK span。
    ///
    /// 参数说明：
    /// - `parent`：已通过信任校验的父上下文。
    /// - `policy`：平台缺省采样策略。
    /// - `method`：当前请求方法。
    /// - `scheme`：来自受信 listener 的协议 scheme。
    /// - `rejected_context`：是否拒绝了入站不可信 trace 上下文。
    ///
    /// 返回：只保存方法、scheme、ID 和时刻，不保留 URL、header map 或 body。
    pub fn new(
        parent: Context,
        policy: Policy,
        method: &http::Method,
        scheme: &'static str,
        rejected_context: bool,
    ) -> Self {
        let inherited = parent.span().span_context().clone();
        Self {
            parent,
            trace_id: if inherited.is_valid() {
                inherited.trace_id()
            } else {
                super::super::fast_trace_id()
            },
            span_id: super::super::fast_span_id(),
            started: SystemTime::now(),
            elapsed: Instant::now(),
            policy,
            method: method.as_str().chars().take(32).collect(),
            scheme,
            rejected_context,
            selected: false,
            recording: false,
        }
    }

    /// 业务作用：选择路由前应用入口缺省，让未命中或早拒绝使用真实 listener 的策略。
    ///
    /// 参数说明：
    /// - `policy`：来自冻结的入口配置。
    ///
    /// 返回：尚未选路时返回更新后的传播上下文；已选定时为空，不能替换或结束活动 SDK span。
    pub fn fallback(&mut self, policy: Policy) -> Option<Context> {
        if self.selected {
            return None;
        }
        self.policy = policy;
        Some(self.context())
    }

    /// 业务作用：提供已经确定的 server 身份用于传播，延迟记录不会再生成另一组 ID。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：包含本地非记录 span context 的 Context；不改变父身份或 baggage。
    pub fn context(&self) -> Context {
        let parent = self.parent.span().span_context().clone();
        let flags = TraceFlags::default().with_sampled(self.head());
        Context::new().with_remote_span_context(SpanContext::new(
            self.trace_id,
            self.span_id,
            flags,
            false,
            parent.trace_state().clone(),
        ))
    }

    /// 业务作用：在真实路由命中后冻结最终 head decision，记录完整已采样 server span。
    ///
    /// 参数说明：
    /// - `policy`：是该路由的最终投影
    /// - `tracer`：属请求进入时的 exporter 代。
    ///
    /// 返回：对应本次选择的上下文；重复调用不允许更换已冻结决策。
    pub fn select(&mut self, policy: Policy, tracer: &SdkTracer) -> Option<Context> {
        if self.selected {
            return None;
        }
        self.policy = policy;
        self.selected = true;
        if self.head() {
            Some(self.start(tracer, None))
        } else {
            Some(self.context())
        }
    }

    /// 业务作用：响应头形成后只为错误或慢请求补一个有限 server 摘要，不缓存或重建子 span。
    ///
    /// 参数说明：
    /// - `status`：是最终响应头状态
    /// - `tracer`：是本请求固定的 SDK 代。
    ///
    /// 返回：需要初次记录或提升时提供 SDK 上下文，否则不改变现有上下文。
    pub fn finish(&mut self, status: u16, tracer: &SdkTracer) -> Option<Context> {
        if !self.selected && self.head() {
            self.selected = true;
            return Some(self.start(tracer, None));
        }
        if self.recording {
            return None;
        }
        self.selected = true;
        let parent = self.parent.span().span_context().clone();
        // 尊重远端父的未采样决定时，不得通过完成阶段提升绕开该显式策略。
        if self.policy.remote_parent == RemoteParent::Inherit
            && parent.is_valid()
            && !parent.is_sampled()
        {
            return None;
        }
        let reason =
            if status >= 500 && ratio(self.trace_id, self.policy.error_ratio, 0x9e3779b97f4a7c15) {
                Some("error")
            } else if self.policy.slow_ms > 0
                && self.elapsed.elapsed().as_millis() >= u128::from(self.policy.slow_ms)
                && ratio(self.trace_id, self.policy.slow_ratio, 0xd1b54a32d192ed03)
            {
                Some("slow")
            } else {
                None
            };
        reason.map(|reason| self.start(tracer, Some(reason)))
    }

    /// 业务作用：计算当前作用域头采样，远端父覆盖与本地比例重采样具有明确优先级。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：稳定 trace-id 决策；同一策略下不因线程或容器重调度改变。
    fn head(&self) -> bool {
        let parent = self.parent.span().span_context().clone();
        if self.policy.remote_parent == RemoteParent::Inherit && parent.is_valid() {
            return parent.is_sampled();
        }
        ratio(self.trace_id, self.policy.head_ratio, 0)
    }

    /// 业务作用：同步创建与预留 ID 相同的 SDK span，保留真实开始时刻并标记摘要提升原因。
    ///
    /// 参数说明：
    /// - `tracer`：是固定代
    /// - `promotion`：只允许固定 error/slow 分类。
    ///
    /// 返回：已记录上下文；ID 预留守卫在函数返回前解除，不跨线程或 await 传播。
    fn start(&mut self, tracer: &SdkTracer, promotion: Option<&'static str>) -> Context {
        let assigned = AssignedIds {
            trace: Some(self.trace_id),
            span: Some(self.span_id),
        };
        let _scope = IdScope(ASSIGNED.with(|cell| cell.replace(Some(assigned))));
        let mut attributes = vec![
            KeyValue::new("http.request.method", self.method.clone()),
            KeyValue::new("url.scheme", self.scheme),
            KeyValue::new("gateway.trace_context_rejected", self.rejected_context),
        ];
        if let Some(reason) = promotion {
            attributes.push(KeyValue::new("gateway.sampling.promotion", reason));
        }
        let parent = self.parent.with_value(Decision(true));
        let span = tracer.build_with_context(
            SpanBuilder::from_name("gateway.request")
                .with_kind(SpanKind::Server)
                .with_start_time(self.started)
                .with_attributes(attributes),
            &parent,
        );
        self.recording = true;
        parent.with_span(span)
    }
}

/// 业务作用：用均匀 trace ID 的固定比特做确定性比例抽样，不引入用户标签或每请求随机锁。
///
/// 参数说明：
/// - `id`：是合法 trace ID
/// - `probability`：已校验
/// - `salt`：区分 head/error/slow 决策。
///
/// 返回：零比例永不命中，一比例始终命中，其余按固定阈值选择。
fn ratio(id: TraceId, probability: f64, salt: u64) -> bool {
    if probability <= 0.0 {
        return false;
    }
    if probability >= 1.0 {
        return true;
    }
    let bytes = id.to_bytes();
    let value = u64::from_be_bytes(bytes[8..].try_into().expect("trace id suffix")) ^ salt;
    ((value >> 11) as f64) < probability * ((1u64 << 53) as f64)
}
