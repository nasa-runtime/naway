//! 独立流量成本事件：归属来自路由和认证事实，持久开始确认先于额度与上游副作用。

use super::*;
use std::sync::atomic::{AtomicU8, AtomicUsize};
use tokio::sync::Notify;

#[derive(Serialize)]
pub(crate) struct Attribution {
    pub(crate) owner: String,
    pub(crate) listener: String,
    pub(crate) route: String,
    pub(crate) scope: String,
    pub(crate) dimension_sha256: String,
    pub(crate) policy: u64,
    pub(crate) config_generation: u64,
    pub(crate) gateway_request_id: String,
    pub(crate) source: &'static str,
}

/// 一个请求只分配一个固定事实槽；帧路径不生成事件或序列化正文。
#[derive(Clone)]
pub(crate) struct Facts(Arc<State>);

struct State {
    reserve: u64,
    cost: parking_lot::Mutex<Cost>,
    admission: AtomicU8,
    settlement: AtomicU8,
    leases: AtomicUsize,
    finished: Notify,
}

struct Cost {
    observed: Option<u64>,
    effective: u64,
}

/// 账本持有原始事实完成权；取消清理结束前，事件不能把仍在途的结果写成已结算。
pub(crate) struct Lease(Facts);

pub(crate) struct Request {
    attribution: Attribution,
    request: String,
    facts: Facts,
    started: Instant,
    status: u16,
    outcome: &'static str,
    pending: mpsc::Sender<Pending>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Facts {
    /// 业务作用：为声明持久事件的请求保存预留与未知状态，不把预留冒充实际消耗。
    ///
    /// 参数说明：
    /// - `reserve`：本次准入计划使用的额度。
    ///
    /// 返回：尚未执行额度操作的固定容量事实。
    pub(crate) fn new(reserve: u64) -> Self {
        Self(Arc::new(State {
            reserve,
            cost: parking_lot::Mutex::new(Cost {
                observed: None,
                effective: reserve,
            }),
            admission: AtomicU8::new(0),
            settlement: AtomicU8::new(0),
            leases: AtomicUsize::new(0),
            finished: Notify::new(),
        }))
    }

    /// 业务作用：在账本可能跨越响应取消前保留完成权，结束事件等待原持有者解除。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：唯一账本生命周期租约，释放时唤醒结束事件。
    pub(crate) fn lease(&self) -> Lease {
        self.0.leases.fetch_add(1, Ordering::AcqRel);
        Lease(self.clone())
    }

    /// 业务作用：记录明确额度准入结果，拒绝与未知写入不能混作业务放行。
    ///
    /// 参数说明：
    /// - `allowed`：同一后端确认的准入结果。
    ///
    /// 返回：明确放行或拒绝状态，不猜测依赖失联结果。
    pub(crate) fn admitted(&self, allowed: bool) {
        self.0.admission.store(
            if allowed {
                1
            } else {
                2
            },
            Ordering::Release,
        );
    }

    /// 业务作用：在发出可能修改账本的准入前标记未知，任务取消也不会留下虚假的未执行事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：后续明确结果可以覆盖未知，超时与断连保留未知。
    pub(crate) fn admission_pending(&self) {
        self.0.admission.store(3, Ordering::Release);
    }

    /// 业务作用：保存最终结算所依据的金额，并明确区分已观测成本和保守预留。
    ///
    /// 参数说明：
    /// - `cost`：同一账本提交的有效成本。
    /// - `known`：完整事实是否足以证明实际成本。
    ///
    /// 返回：更新固定整数槽；不会在帧路径分配或编码 JSON。
    pub(crate) fn cost(&self, cost: u64, known: bool) {
        *self.0.cost.lock() = Cost {
            effective: cost,
            observed: known.then_some(cost),
        };
    }

    /// 业务作用：记录最终账本提交是否已经获得明确确认，未知响应不虚构结算成功。
    ///
    /// 参数说明：
    /// - `confirmed`：本地提交完成或共享后端返回有效终态回执。
    ///
    /// 返回：确定提交或未知状态；完成权仍由原账本租约控制。
    pub(crate) fn settled(&self, confirmed: bool) {
        self.0.settlement.store(
            if confirmed {
                1
            } else {
                2
            },
            Ordering::Release,
        );
    }

    /// 业务作用：在结束事件编码前等待有界取消清理，让事件包含最终可知的账本状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原账本全部完成或1500毫秒到期；到期后保留未知状态而不拖延整个事件队列。
    async fn wait(&self) {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
        while self.0.leases.load(Ordering::Acquire) != 0 {
            if tokio::time::timeout_at(deadline, self.0.finished.notified())
                .await
                .is_err()
            {
                return;
            }
        }
    }

    /// 业务作用：只在请求结束时将固定事实槽投影为低敏持久载荷。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：预留、实际可知成本与账本结果；在途或缺失证据明确标为未知。
    fn payload(&self) -> Value {
        let admission = match self.0.admission.load(Ordering::Acquire) {
            0 => "not_attempted",
            1 => "accepted",
            2 => "rejected",
            _ => "unknown",
        };
        let settlement = if self.0.leases.load(Ordering::Acquire) != 0 {
            "unknown"
        } else {
            match self.0.settlement.load(Ordering::Acquire) {
                0 => "not_attempted",
                1 => "confirmed",
                _ => "unknown",
            }
        };
        let cost = self.0.cost.lock();
        json!({
            "reserved_cost":self.0.reserve,
            "observed_cost":cost.observed,
            "settlement_cost":cost.effective,
            "admission":admission,
            "settlement":settlement
        })
    }
}

impl Drop for Lease {
    /// 业务作用：在原账本提交或取消清理真正结束时解除事件等待，不提前冒充确认。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最后持有者唤醒有界结束任务；尚未开始等待时通知仍保留。
    fn drop(&mut self) {
        if self.0 .0.leases.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0 .0.finished.notify_one();
        }
    }
}

impl Meter {
    /// 业务作用：为普通流量建立独立持久开始事件，容量和收据确认均先于业务副作用。
    ///
    /// 参数说明：
    /// - `attribution`：由同代路由、归属与认证维度冻结的低敏关联字段。
    /// - `facts`：本次额度操作共用的固定成本槽。
    ///
    /// 返回：持久确认后的唯一事件凭据；不可用、容量不足或坏收据失败关闭。
    pub(crate) async fn admit_traffic(
        &self,
        attribution: Attribution,
        facts: Facts,
    ) -> Result<Request> {
        ensure!(
            self.accepting.load(Ordering::Acquire),
            "traffic meter is draining"
        );
        let settings = self
            .settings
            .as_ref()
            .context("traffic meter is disabled")?;
        let permit = self.capacity.clone().try_acquire_owned().map_err(|_| {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            anyhow::anyhow!("traffic meter capacity exhausted")
        })?;
        let request = OutboxEvent::new(
            "GatewayTraffic",
            &attribution.gateway_request_id,
            "request_started",
            Vec::new(),
        )
        .event_id;
        let record = event_record(
            "GatewayTraffic",
            &request,
            "request_started",
            &attribution.owner,
            json!({
                "attribution":attribution,"timestamp_ms":now_ms(),"reserved_cost":facts.0.reserve
            }),
        );
        let mut guard = Request {
            attribution,
            request,
            facts,
            started: Instant::now(),
            status: 0,
            outcome: "not_dispatched",
            pending: self
                .pending
                .as_ref()
                .expect("enabled traffic meter queue")
                .clone(),
            permit: Some(permit),
        };
        // 无持久开始证据就不能执行额度或上游动作；结束事件仍记录未分派，不能伪造业务成功。
        if settings.deliver(&record).await.is_err() {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("traffic meter admission was not durably acknowledged");
        }
        self.admitted.fetch_add(1, Ordering::Relaxed);
        guard.outcome = "cancelled_before_response";
        Ok(guard)
    }

    /// 业务作用：将流量事件的传输与容量指标和产品计量分开，避免重复同名时间序列。
    ///
    /// 参数说明：
    /// - `output`：指标响应缓冲。
    ///
    /// 返回：固定 gw_traffic_meter 指标，不包含请求身份标签。
    pub(crate) fn render_traffic_metrics(&self, output: &mut String) {
        self.render_named_metrics(output, "traffic_meter");
    }
}

impl Request {
    /// 业务作用：随最终响应移动事件凭据，只有实体真正结束才记录完成，取消保留独立结果。
    ///
    /// 参数说明：
    /// - `response`：已完成计量与响应策略的最终响应。
    ///
    /// 返回：不复制实体的包装响应；账本包装体先销毁，之后才等待最终事件事实。
    pub(crate) fn wrap(
        mut self,
        response: http::Response<crate::BoxBody>,
    ) -> http::Response<crate::BoxBody> {
        use http_body_util::BodyExt as _;
        use hyper::body::Body as _;
        self.status = response.status().as_u16();
        let remaining = response.body().size_hint().exact();
        self.outcome = if response.body().is_end_stream() || remaining == Some(0) {
            "complete"
        } else {
            "cancelled"
        };
        response.map(|inner| {
            Body {
                inner: Some(inner),
                request: Some(self),
                remaining,
            }
            .boxed()
        })
    }
}

struct Body {
    inner: Option<crate::BoxBody>,
    request: Option<Request>,
    remaining: Option<u64>,
}

impl hyper::body::Body for Body {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;

    /// 业务作用：透传原始帧，结束和失败时先释放账本完成权，再固定事件结果。
    ///
    /// 参数说明：
    /// - `cx`：下游背压与取消上下文。
    ///
    /// 返回：原始响应帧；EOF与错误各只产生一个结束事件。
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let Some(inner) = self.inner.as_mut() else {
            return std::task::Poll::Ready(None);
        };
        let polled = std::pin::Pin::new(inner).poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(frame))) = &polled {
            if let (Some(remaining), Some(data)) = (&mut self.remaining, frame.data_ref()) {
                *remaining = remaining.saturating_sub(data.len() as u64);
                // 已声明长度的 HTTP 发送端可以在最后一帧后直接销毁 body，不保证额外轮询 EOF。
                if *remaining == 0 {
                    if let Some(request) = &mut self.request {
                        request.outcome = "complete";
                    }
                }
            }
        }
        let outcome = match &polled {
            std::task::Poll::Ready(None) => Some("complete"),
            std::task::Poll::Ready(Some(Err(_))) => Some("failed"),
            _ => None,
        };
        if let Some(outcome) = outcome {
            self.inner.take();
            if let Some(mut request) = self.request.take() {
                request.outcome = outcome;
            }
        }
        polled
    }

    /// 业务作用：为无正文响应保留终态轮询，防止已完成响应被当作取消。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有事件凭据已经移交后才结束。
    fn is_end_stream(&self) -> bool {
        self.request.is_none()
    }

    /// 业务作用：保持原始 HTTP 长度合同，不为了事件收集缓冲实体。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原始响应长度提示，结束后为零。
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.as_ref().map_or_else(
            || hyper::body::SizeHint::with_exact(0),
            |inner| inner.size_hint(),
        )
    }
}

impl Drop for Request {
    /// 业务作用：使用原容量名额等待有限账本清理并提交幂等结束事件，崩溃保留远端 incomplete。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：任务、队列与交付共用同一 semaphore 名额，进程没有运行时时不虚构结束确认。
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let facts = self.facts.clone();
        let request = std::mem::take(&mut self.request);
        let attribution =
            serde_json::to_value(&self.attribution).expect("bounded traffic attribution");
        let owner = std::mem::take(&mut self.attribution.owner);
        let (status, outcome, latency) = (
            self.status,
            self.outcome,
            self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
        );
        let pending = self.pending.clone();
        runtime.spawn(async move {
            facts.wait().await;
            let record = event_record(
                "GatewayTraffic",
                &request,
                "request_finished",
                &owner,
                json!({"attribution":attribution,"request_id":request,"timestamp_ms":now_ms(),
                    "status":status,"outcome":outcome,"latency_us":latency,"cost":facts.payload()}),
            );
            if pending
                .try_send(Pending {
                    record,
                    _permit: permit,
                })
                .is_err()
            {
                tracing::error!(
                    "traffic meter worker unavailable; durable admission remains incomplete"
                );
            }
        });
    }
}
