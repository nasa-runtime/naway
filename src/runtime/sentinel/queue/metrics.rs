//! 队列监控只记录固定事件与当前占用，不保存请求、维度或监控历史。

use super::Rejected;
use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const OUTCOMES: [&str; 11] = [
    "admitted",
    "capacity",
    "deadline",
    "unknown_body",
    "clock",
    "state_capacity",
    "unavailable",
    "retired",
    "cancelled",
    "queued",
    "state_fail_open",
];
static EVENTS: [AtomicU64; 11] = [const {
    AtomicU64::new(0)
}; 11];
static WAITING: AtomicU64 = AtomicU64::new(0);
static WAIT_COUNT: AtomicU64 = AtomicU64::new(0);
static WAIT_MICROS: AtomicU64 = AtomicU64::new(0);
pub(crate) static DESCRIPTORS: [MetricDescriptor; 4] = [
    MetricDescriptor {
        name: "gw_sentinel_queue_events_total",
        help: "Uniform queue admission outcomes.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["outcome"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_sentinel_queue_waiting",
        help: "Requests retaining a queue reservation or cancellation cleanup.",
        unit: "",
        kind: MetricKind::Gauge,
        label_names: &[],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_sentinel_queue_wait_count",
        help: "Finished uniform queue waits including cancellation cleanup.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &[],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_sentinel_queue_wait_microseconds_total",
        help: "Total retained queue time including bounded cancellation cleanup.",
        unit: "us",
        kind: MetricKind::Counter,
        label_names: &[],
        histogram_bounds: &[],
    },
];

pub(crate) struct Attempt(bool);
pub(crate) struct Wait(Instant);

impl Attempt {
    /// 业务作用：把入口调用绑定到唯一终态，future 被取消也形成明确事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚无终态的请求观察凭证。
    pub(crate) fn new() -> Self {
        Self(false)
    }

    /// 业务作用：按固定类别记录最终调度结果，不暴露请求维度。
    ///
    /// 参数说明：
    /// - `outcome`：完成配置权威复验后的实际结果。
    ///
    /// 返回：记录一次终态，后续析构不重复记录取消。
    pub(crate) fn complete(&mut self, outcome: Result<(), Rejected>) {
        let index = match outcome {
            Ok(()) => 0,
            Err(Rejected::Capacity) => 1,
            Err(Rejected::Deadline) => 2,
            Err(Rejected::UnknownBody) => 3,
            Err(Rejected::Clock) => 4,
            Err(Rejected::StateCapacity) => 5,
            Err(Rejected::Unavailable) => 6,
            Err(Rejected::Retired) => 7,
        };
        if !self.0 {
            EVENTS[index].fetch_add(1, Ordering::Relaxed);
            self.0 = true;
        }
    }
}

impl Drop for Attempt {
    /// 业务作用：标记未取得终态便被取消的入口，避免把取消请求当作准入成功。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只增加固定取消计数，不影响调度账本。
    fn drop(&mut self) {
        if !self.0 {
            EVENTS[8].fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Wait {
    /// 业务作用：使监控占用与实际预约及其有限清理保持同一生命周期。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：开始统计当前占用和等待时长的凭证。
    pub(crate) fn new() -> Self {
        EVENTS[9].fetch_add(1, Ordering::Relaxed);
        WAITING.fetch_add(1, Ordering::Relaxed);
        Self(Instant::now())
    }
}

impl Drop for Wait {
    /// 业务作用：仅在预约及清理结束时减少占用并累计实际保留时长。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：归还一个当前占用，形成一条累计时长事实，不保留单请求历史。
    fn drop(&mut self) {
        WAITING.fetch_sub(1, Ordering::Relaxed);
        WAIT_COUNT.fetch_add(1, Ordering::Relaxed);
        WAIT_MICROS.fetch_add(
            self.0.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }
}

/// 业务作用：记录显式活跃维度软门放行，区分实际预约授权与容量降级。
///
/// 参数说明: 无。
///
/// 返回：增加固定计数，不创建维度状态。
pub(crate) fn state_open() {
    EVENTS[10].fetch_add(1, Ordering::Relaxed);
}

/// 业务作用：让实时管理、Prometheus与OTLP读取相同有界队列事实。
///
/// 参数说明: 无。
///
/// 返回：固定十四项样本，不随请求、规则或集群节点数量扩张。
pub(crate) fn samples() -> Vec<MetricSample> {
    let mut samples: Vec<_> = OUTCOMES
        .iter()
        .zip(EVENTS.iter())
        .map(|(outcome, value)| MetricSample {
            name: DESCRIPTORS[0].name,
            labels: vec![("outcome", (*outcome).into())],
            value: MetricValue::Counter(value.load(Ordering::Relaxed)),
        })
        .collect();
    samples.push(MetricSample {
        name: DESCRIPTORS[1].name,
        labels: vec![],
        value: MetricValue::Gauge(WAITING.load(Ordering::Relaxed) as f64),
    });
    for (descriptor, value) in [
        (&DESCRIPTORS[2], &WAIT_COUNT),
        (&DESCRIPTORS[3], &WAIT_MICROS),
    ] {
        samples.push(MetricSample {
            name: descriptor.name,
            labels: vec![],
            value: MetricValue::Counter(value.load(Ordering::Relaxed)),
        });
    }
    samples
}

/// 业务作用：按共用描述符输出队列当前占用和累计事实，保持遥测口径一致。
///
/// 参数说明：
/// - `out`：已有Prometheus响应缓冲。
///
/// 返回：追加固定样本，不访问请求或共享账本。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(
        &DESCRIPTORS.iter().collect::<Vec<_>>(),
        &samples(),
        out,
    );
}
