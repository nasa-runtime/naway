//! 响应成本只传累计整数；确认补扣后才交付原始帧，取消以已交付事实关闭共享回执。

use super::*;
use crate::runtime::traffic_limit::{
    metrics,
    redis::{
        settlement::{Operation, Receipt},
        Failure,
    },
    resources::Rejected,
    CostSource, QuotaFailMode,
};

pub(super) struct Settlement {
    receipt: Receipt,
    source: CostSource,
    fail_mode: QuotaFailMode,
    usage: Option<crate::runtime::traffic_limit::usage::Facts>,
}

impl Settlement {
    /// 业务作用：将准入上下文与同一快照的成本来源绑定，降级时仍保留本地硬上限。
    ///
    /// 参数说明：
    /// - `receipt`：本次准入上下文，只有确认成功的回执拥有远端结算权威。
    /// - `source`：构建期声明的响应事实来源。
    /// - `fail_mode`：仅用于依赖不可用的明确处置。
    /// - `usage`：provider 或原始上游头的同源事实，独立于下游读取进度。
    ///
    /// 返回：尚未读取响应实体的结算上下文。
    pub(super) fn new(
        receipt: Receipt,
        source: CostSource,
        fail_mode: QuotaFailMode,
        usage: Option<crate::runtime::traffic_limit::usage::Facts>,
    ) -> Self {
        Self {
            receipt,
            source,
            fail_mode,
            usage,
        }
    }

    /// 业务作用：在最终实体变换后计量并核验协议，插件头不能替代回执权威。
    ///
    /// 参数说明：
    /// - `response`：待交付下游的完整响应入口。
    ///
    /// 返回：只保留一个原始帧、带共享成本确认与闲置期限的响应。
    pub(super) async fn wrap(mut self, response: Response<BoxBody>) -> Response<BoxBody> {
        self.receipt.delivered(
            self.source.admission_cost(None).expect("response reserve"),
            false,
        );
        if self.usage.as_ref().is_some_and(|facts| facts.known()) {
            // 完整成本必须先于响应头发布；有限 RPC 持有原名额与已缓冲实体的逻辑字节预算。
            if !self
                .receipt
                .retain(response.body().size_hint().upper().unwrap_or(0))
            {
                return text_status(503, "shared usage response capacity exceeded");
            }
            if self.receipt.confirmed() {
                if let Err(failure) = self.receipt.finish().await {
                    if self.fail_mode != QuotaFailMode::FailOpen
                        || !matches!(failure, Failure::Unavailable | Failure::StateCapacity)
                    {
                        return text_status(503, "shared usage settlement unavailable");
                    }
                }
            }
            return response;
        }
        let (observation, trustworthy) = match self.source {
            CostSource::TrustedUsage {
                ..
            } => (
                TrafficObservation::TrustedUsage(
                    self.usage.take().expect("compiled trusted usage"),
                ),
                true,
            ),
            CostSource::ResponseBytes {
                ..
            } => (TrafficObservation::ResponseBytes(0), true),
            CostSource::GrpcMessages {
                ..
            } => (
                TrafficObservation::GrpcMessages(GrpcMessageCounter::default()),
                grpc_response_is_trustworthy(response.headers()),
            ),
            _ => unreachable!("only compiled response cost creates a receipt"),
        };
        let operation = self.receipt.operation();
        let shared = self.receipt.confirmed();
        self.receipt.delivered(
            observed_cost(&self.source, &observation, trustworthy),
            trustworthy && observation.known(),
        );
        response.map(|inner| {
            SettledBody {
                inner: Box::pin(inner),
                receipt: Some(self.receipt),
                operation: operation.clone(),
                source: self.source,
                fail_mode: self.fail_mode,
                observation,
                trustworthy,
                shared,
                pending: None,
                proposed: None,
                wait: None,
                idle: Box::pin(tokio::time::sleep(operation.idle())),
                finishing: false,
                ended: false,
            }
            .boxed()
        })
    }
}

struct SettledBody {
    inner: Pin<Box<BoxBody>>,
    receipt: Option<Receipt>,
    operation: Operation,
    source: CostSource,
    fail_mode: QuotaFailMode,
    observation: TrafficObservation,
    trustworthy: bool,
    shared: bool,
    pending: Option<Frame<Bytes>>,
    proposed: Option<TrafficObservation>,
    wait: Option<parking_lot::Mutex<futures::future::BoxFuture<'static, Result<(), Failure>>>>,
    idle: Pin<Box<tokio::time::Sleep>>,
    finishing: bool,
    ended: bool,
}

impl SettledBody {
    /// 业务作用：在允许交付后接受暂存计数器，待确认帧在此之前不能改变最终退款事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原始帧；归还该帧的逻辑字节预算并保留响应回执名额。
    fn deliver(&mut self) -> Poll<Option<Result<Frame<Bytes>, crate::BoxError>>> {
        let observation = self.proposed.take().expect("pending response observation");
        let actual = observed_cost(&self.source, &observation, self.trustworthy);
        self.observation = observation;
        let receipt = self.receipt.as_mut().expect("response receipt context");
        receipt.delivered(actual, self.trustworthy && self.observation.known());
        receipt.retain(0);
        Poll::Ready(self.pending.take().map(Ok))
    }

    /// 业务作用：依赖降级仅覆盖不可用，回执失效、坏账本和硬资源上限仍关闭流。
    ///
    /// 参数说明：
    /// - `failure`：本次共享操作的明确错误类别。
    ///
    /// 返回：声明允许降级且确为依赖不可用时为真，同时登记低基数观测。
    fn permits_failure(&self, failure: &Failure) -> bool {
        if self.fail_mode == QuotaFailMode::FailOpen
            && matches!(failure, Failure::Unavailable | Failure::StateCapacity)
        {
            metrics::STATE_OPEN.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            metrics::STATE_CLOSED.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// 业务作用：关闭底层读取并丢弃未交付帧，最终结算只使用之前已经交付的事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本地流量拒绝错误；原回执在有限名额内执行取消清理。
    fn reject(&mut self) -> Poll<Option<Result<Frame<Bytes>, crate::BoxError>>> {
        self.ended = true;
        self.wait = None;
        self.pending = None;
        self.proposed = None;
        self.inner = Box::pin(full_body(Bytes::new()));
        self.receipt = None;
        Poll::Ready(Some(Err(Box::new(Rejected))))
    }
}

/// 业务作用：把已交付的有限计数器换算成累计成本，协议不完整时不据此返还预留。
///
/// 参数说明：
/// - `source`：构建期冻结的换算规则。
/// - `observation`：已交付字节或五字节 gRPC 状态机。
/// - `trustworthy`：响应内容类型及编码是否符合声明协议。
///
/// 返回：真实已交付成本；证据不足时至少保留原预留。
fn observed_cost(source: &CostSource, observation: &TrafficObservation, trustworthy: bool) -> u64 {
    let reserved = source.admission_cost(None).expect("response cost source");
    if !trustworthy {
        return reserved;
    }
    let observed = match observation {
        TrafficObservation::TrustedUsage(facts) => facts.cost(reserved),
        TrafficObservation::ResponseBytes(bytes) => *bytes,
        TrafficObservation::GrpcMessages(counter) => {
            if counter.invalid || counter.header_len != 0 || counter.payload_remaining.is_some() {
                counter.completed.max(reserved)
            } else {
                counter.completed
            }
        }
    };
    source.settle_cost(observed)
}

impl Body for SettledBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 业务作用：只复制有限计数器进行预检，原 Bytes 在累计补扣确认后才交付下游。
    ///
    /// 参数说明：
    /// - `cx`：响应异步轮询上下文。
    ///
    /// 返回：保持帧与 trailer 顺序；未知写按故障策略处理，失效回执和超界成本终止流。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        loop {
            if let Some(wait) = self.wait.as_mut() {
                let result = match wait.get_mut().as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result,
                };
                self.wait = None;
                if result
                    .as_ref()
                    .err()
                    .is_some_and(|failure| !self.permits_failure(failure))
                {
                    return self.reject();
                }
                if self.finishing {
                    self.ended = true;
                    return Poll::Ready(None);
                }
                return self.deliver();
            }
            // 无进展期限不因客户端背压重置；过期后不能通过下一帧重新创建已经失去的回执。
            if self.idle.as_mut().poll(cx).is_ready() {
                metrics::DEADLINE.fetch_add(1, Ordering::Relaxed);
                return self.reject();
            }
            let frame = match self.inner.as_mut().poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(error))) => {
                    self.ended = true;
                    self.inner = Box::pin(full_body(Bytes::new()));
                    self.receipt = None;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    let receipt = self.receipt.take().expect("unfinished response receipt");
                    if !self.shared {
                        // 依赖降级期间没有已确认的退款权威，不能用响应完成去补发未知准入或猜测退款。
                        self.ended = true;
                        return Poll::Ready(None);
                    }
                    self.finishing = true;
                    self.wait = Some(parking_lot::Mutex::new(Box::pin(receipt.finish())));
                    continue;
                }
                Poll::Ready(Some(Ok(frame))) => frame,
            };
            let mut proposed = self.observation.clone();
            let bytes = frame.data_ref().map_or(0, |data| data.len() as u64);
            if self.trustworthy {
                if let Some(data) = frame.data_ref() {
                    match &mut proposed {
                        TrafficObservation::ResponseBytes(total) => {
                            *total = total.saturating_add(bytes)
                        }
                        TrafficObservation::GrpcMessages(counter) => counter.observe(data),
                        TrafficObservation::TrustedUsage(_) => {}
                    }
                }
            }
            let cost = observed_cost(&self.source, &proposed, self.trustworthy);
            // 成本与物理保留门都必须先于共享副作用；超限不能按 fail-open 发送未经约束的实体。
            if matches!(&proposed, TrafficObservation::TrustedUsage(facts) if facts.invalid())
                || !self.operation.accepts(cost)
                || !self
                    .receipt
                    .as_mut()
                    .expect("response receipt")
                    .retain(bytes)
            {
                return self.reject();
            }
            let operation = self.operation.clone();
            self.idle
                .as_mut()
                .reset(tokio::time::Instant::now() + operation.idle());
            self.pending = Some(frame);
            self.proposed = Some(proposed);
            if !self.shared {
                return self.deliver();
            }
            self.wait = Some(parking_lot::Mutex::new(Box::pin(async move {
                operation.invoke(1, cost, None).await.map(|_| ())
            })));
        }
    }

    /// 业务作用：要求有机会提交最终结算，底层结束不能提前丢弃最后一帧或回执。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有最终结算完成或明确关闭时结束。
    fn is_end_stream(&self) -> bool {
        self.ended
    }

    /// 业务作用：将已经移入共享等待的原始帧计回实体长度，保持 HTTP framing 一致。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层与当前待交付帧的联合大小界限。
    fn size_hint(&self) -> SizeHint {
        let original = self.inner.size_hint();
        let bytes = self
            .pending
            .as_ref()
            .and_then(Frame::data_ref)
            .map_or(0, |data| data.len() as u64);
        let mut hint = SizeHint::new();
        hint.set_lower(original.lower().saturating_add(bytes));
        if let Some(upper) = original.upper().and_then(|upper| upper.checked_add(bytes)) {
            hint.set_upper(upper);
        }
        hint
    }
}
