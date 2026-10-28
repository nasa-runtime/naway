//! 治理事件的固定进程累计事实；配置换代不创建动态指标系列。

use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
pub(crate) enum Admission {
    RetryGranted,
    RetryRejected,
    ConcurrencyGranted,
    ConcurrencyBusy,
    Queued,
    QueueRejected,
    LimitIncreased,
    LimitDecreased,
}
const ADMISSION_LABELS: [(&str, &str); 8] = [
    ("retry_budget", "granted"),
    ("retry_budget", "rejected"),
    ("adaptive", "granted"),
    ("adaptive", "busy"),
    ("adaptive", "queued"),
    ("adaptive", "queue_rejected"),
    ("adaptive", "limit_increased"),
    ("adaptive", "limit_decreased"),
];
static ADMISSION: [AtomicU64; 8] = [const {
    AtomicU64::new(0)
}; 8];
const PHASES: [&str; 11] = [
    "published",
    "canary_published",
    "observing",
    "awaiting_approval",
    "promoting",
    "rolling_back",
    "succeeded",
    "rolled_back",
    "failed",
    "cleanup_failed",
    "other",
];
static ROLLOUT: [AtomicU64; 11] = [const {
    AtomicU64::new(0)
}; 11];
const RESULTS: [&str; 5] = ["completed", "dependency", "protocol", "input", "cancelled"];
static EXT_PROC: [[AtomicU64; 5]; 2] = [const {
    [const {
        AtomicU64::new(0)
    }; 5]
}; 2];

pub(crate) static DESCRIPTORS: [MetricDescriptor; 3] = [
    MetricDescriptor {
        name: "gw_admission_events_total",
        help: "Admission attempts and adaptive limit changes by fixed outcome.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["policy", "outcome"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_rollout_transitions_total",
        help: "Committed local rollout transitions by fixed phase.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["phase"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_ext_proc_exchange_total",
        help: "Processor phase send and receive completions by fixed outcome.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["direction", "outcome"],
        histogram_bounds: &[],
    },
];

/// 业务作用：记录一次准入事实，不把服务、路由或主体变成动态标签。
///
/// 参数说明：
/// - `event`：是已经确认的许可、容量拒绝或上限变化。
///
/// 返回：进程累计计数饱和递增，不影响准入判断。
pub(crate) fn admission(event: Admission) {
    nametrics_core::atomic::add(&ADMISSION[event as usize], 1);
}

/// 业务作用：在 rollout 状态实际提交后记录固定阶段，重复同阶段更新不产生转移。
///
/// 参数说明：
/// - `previous`：是锁内转移前后阶段；首次登记没有前态。
/// - `next`：是锁内转移前后阶段；首次登记没有前态。
///
/// 返回：最多递增一个计数，未知阶段折叠到 other。
pub(crate) fn rollout(previous: Option<&str>, next: &str) {
    if previous == Some(next) {
        return;
    }
    let index = PHASES
        .iter()
        .position(|value| *value == next)
        .unwrap_or(PHASES.len() - 1);
    nametrics_core::atomic::add(&ROLLOUT[index], 1);
}

#[cfg(feature = "ext-proc")]
pub(crate) struct Exchange {
    direction: usize,
    outcome: usize,
}

#[cfg(feature = "ext-proc")]
impl Exchange {
    /// 业务作用：在可取消的处理器相位开始时登记收尾守卫。
    ///
    /// 参数说明：
    /// - `receive`：区分发送与等待响应。
    ///
    /// 返回：默认取消结果的守卫；未正常完成也会记账。
    pub(crate) fn new(receive: bool) -> Self {
        Self {
            direction: usize::from(receive),
            outcome: 4,
        }
    }

    /// 业务作用：按已分类协议结果更新观测，不参与 fail-open 裁决。
    ///
    /// 参数说明：
    /// - `result`：是相位实际完成结果。
    ///
    /// 返回：更新低敏结果，错误正文永不保存。
    pub(crate) fn finish<T>(
        &mut self,
        result: &Result<T, crate::extensions::ext_proc::ExtProcError>,
    ) {
        use crate::extensions::ext_proc::ExtProcErrorClass;
        self.outcome = match result {
            Ok(_) => 0,
            Err(error) => match error.class() {
                ExtProcErrorClass::Dependency => 1,
                ExtProcErrorClass::Protocol => 2,
                ExtProcErrorClass::Input => 3,
            },
        };
    }
}

#[cfg(feature = "ext-proc")]
impl Drop for Exchange {
    /// 业务作用：在正常完成或取消时提交唯一收尾计数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只修改固定原子事实，不执行 I/O。
    fn drop(&mut self) {
        nametrics_core::atomic::add(&EXT_PROC[self.direction][self.outcome], 1);
    }
}

/// 业务作用：从同一固定事实源生成 Prometheus 与 OTLP 共用样本。
///
/// 参数说明: 无。
///
/// 返回：恰好二十九个低基数累计系列，无配置或请求身份。
pub(crate) fn samples() -> Vec<MetricSample> {
    let mut result = Vec::with_capacity(29);
    for (index, (policy, outcome)) in ADMISSION_LABELS.iter().enumerate() {
        result.push(MetricSample {
            name: DESCRIPTORS[0].name,
            labels: vec![("policy", (*policy).into()), ("outcome", (*outcome).into())],
            value: MetricValue::Counter(ADMISSION[index].load(Ordering::Relaxed)),
        });
    }
    for (index, phase) in PHASES.iter().enumerate() {
        result.push(MetricSample {
            name: DESCRIPTORS[1].name,
            labels: vec![("phase", (*phase).into())],
            value: MetricValue::Counter(ROLLOUT[index].load(Ordering::Relaxed)),
        });
    }
    for (direction, name) in ["send", "receive"].iter().enumerate() {
        for (outcome, label) in RESULTS.iter().enumerate() {
            result.push(MetricSample {
                name: DESCRIPTORS[2].name,
                labels: vec![("direction", (*name).into()), ("outcome", (*label).into())],
                value: MetricValue::Counter(EXT_PROC[direction][outcome].load(Ordering::Relaxed)),
            });
        }
    }
    result
}
