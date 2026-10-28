//! HTTP 正文消费与响应生命周期观测；不保存正文、身份或历史样本。

mod body;
pub(crate) mod metrics;
pub(crate) mod routes;

use super::metrics::Metrics;
use crate::BoxBody;
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Body;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

pub(crate) use body::Observed;

#[derive(Clone, Copy)]
pub(super) enum Outcome {
    Eof = 0,
    BodyError = 1,
    Dropped = 2,
    Upgraded = 3,
}

/// 一个请求方向或响应生命周期的唯一结算权；移动不创建第二份终态。
pub(crate) struct Tracker {
    metrics: Arc<Metrics>,
    started: Option<Instant>,
    finished: bool,
    route: Option<Arc<routes::Counters>>,
}

impl Tracker {
    /// 业务作用：在统一HTTP入口占用响应在途量，取消等待响应头也能释放占用。
    ///
    /// 参数说明：
    /// - `metrics`：整个网关进程共享的计数事实。
    ///
    /// 返回：持有唯一响应结算权的观察器，不启动任务或读取正文。
    pub(crate) fn response(metrics: Arc<Metrics>) -> Self {
        metrics.http_stream.active.fetch_add(1, Ordering::Relaxed);
        Self {
            metrics,
            started: Some(Instant::now()),
            finished: false,
            route: None,
        }
    }

    /// 业务作用：为原始请求正文建立消费观察，不把未读取的声明长度当作输入流量。
    ///
    /// 参数说明：
    /// - `metrics`：整个网关进程共享的计数事实。
    ///
    /// 返回：请求方向观察器，丢弃时单独记录未完成消费。
    fn request(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
            started: None,
            finished: false,
            route: None,
        }
    }

    /// 业务作用：在首次公开路由命中时冻结计数所有者，内部跳转与重试不能改变入口归属。
    ///
    /// 参数说明：
    /// - `counters`：与本次配置快照一起编译的路由事实。
    ///
    /// 返回：首次绑定增加一次请求与在途占用；请求方向、已终结或重复选择不产生第二份会计。
    pub(crate) fn select_route(&mut self, counters: &Arc<routes::Counters>) {
        if self.started.is_some() && !self.finished && self.route.is_none() {
            counters.start();
            self.route = Some(counters.clone());
        }
    }

    /// 业务作用：在最后的HTTP正文边界接管响应结算，升级隧道与无正文响应不误入正文时延。
    ///
    /// 参数说明：
    /// - `response`：经过全部治理和编码后的响应。
    /// - `method`：进入管线时的原始HTTP方法。
    ///
    /// 返回：保留原头和帧的响应；终态发生在本地交付边界，不代表对端已接收。
    pub(crate) fn attach(
        mut self,
        response: Response<BoxBody>,
        method: &Method,
    ) -> Response<BoxBody> {
        let status = response.status();
        if let Some(route) = &self.route {
            route.headers(status.as_u16());
        }
        if status == StatusCode::SWITCHING_PROTOCOLS
            || (*method == Method::CONNECT && status.is_success())
        {
            // 隧道后续数据不再属于普通HTTP实体，不能用握手耗时冒充完整长连接耗时。
            self.finish(Outcome::Upgraded);
            return response;
        }
        if *method == Method::HEAD
            || status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
            || response.body().is_end_stream()
        {
            self.finish(Outcome::Eof);
            return response;
        }
        response.map(|body| Observed::new(body, self).boxed())
    }

    /// 业务作用：只按已交付DATA帧累计实体字节，保持流式背压且不访问正文内容。
    ///
    /// 参数说明：
    /// - `length`：当前原始帧的数据长度，不含trailers及协议开销。
    ///
    /// 返回：增加固定方向分片计数，不分配或克隆正文。
    fn bytes(&self, length: usize) {
        self.metrics.http_stream.bytes[usize::from(self.started.is_some())].add(length as u64);
        if let Some(route) = &self.route {
            route.bytes(length);
        }
    }

    /// 业务作用：恰好一次记录消费终态，完整响应才进入完成分布，其余终态释放在途量。
    ///
    /// 参数说明：
    /// - `outcome`：EOF、正文错误、提前丢弃或协议升级的实际观察。
    ///
    /// 返回：更新有限计数；重复终态不再次结算或释放资源。
    fn finish(&mut self, outcome: Outcome) {
        if self.finished {
            return;
        }
        self.finished = true;
        let counters = &self.metrics.http_stream;
        if let Some(started) = self.started {
            let elapsed = started.elapsed();
            if let Some(route) = &self.route {
                route.finish(outcome, elapsed);
            }
            counters.responses[outcome as usize].add(1);
            if matches!(outcome, Outcome::Eof) {
                counters
                    .duration_micros
                    .add(elapsed.as_micros().min(u64::MAX as u128) as u64);
                let bucket = metrics::BOUNDS_MS
                    .partition_point(|bound| elapsed.as_micros() > u128::from(*bound) * 1000);
                counters.buckets[bucket].add(1);
                counters.duration_count.add(1);
            }
            counters.active.fetch_sub(1, Ordering::Relaxed);
        } else {
            counters.requests[outcome as usize].add(1);
        }
    }
}

impl Drop for Tracker {
    /// 业务作用：覆盖头前取消及正文提前释放，不将未确认EOF的流记作完成。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未结算时记dropped并释放响应占用，已结算时不重复记账。
    fn drop(&mut self) {
        self.finish(Outcome::Dropped);
    }
}
