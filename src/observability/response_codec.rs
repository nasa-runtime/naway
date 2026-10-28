//! 响应codec的实际处理量与成对完成事实，透传响应不进入此目录。

use super::metrics::ShardedCounter;
use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(crate) enum Transform {
    EncodeGzip = 0,
    EncodeBrotli = 1,
    DecodeGzip = 2,
    DecodeBrotli = 3,
}

#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Eof,
    BodyError,
    Dropped,
}

#[derive(Default, Clone, Copy)]
struct Completed {
    count: u64,
    input: u64,
    output: u64,
}

#[derive(Default)]
struct Flow {
    input: ShardedCounter,
    output: ShardedCounter,
    active: AtomicU64,
    errors: ShardedCounter,
    dropped: ShardedCounter,
    completed: Mutex<Completed>,
}

#[derive(Default)]
pub(crate) struct Counters {
    flows: [Flow; 4],
}

pub(crate) static DESCRIPTORS: [MetricDescriptor; 5] = [
    MetricDescriptor {
        name: "gw_response_codec_bytes_total",
        help: "Actual response codec input consumed and output produced; excludes passthrough, protocol overhead and peer acknowledgement.",
        unit: "bytes",
        kind: MetricKind::Counter,
        label_names: &["operation", "algorithm", "side"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_response_codec_events_total",
        help: "Unique response codec outcome; codec EOF does not imply downstream HTTP completion.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["operation", "algorithm", "outcome"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_response_codec_completed_input_bytes_total",
        help: "Input bytes of successfully completed response codecs, paired with completed output bytes.",
        unit: "bytes",
        kind: MetricKind::Counter,
        label_names: &["operation", "algorithm"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_response_codec_completed_output_bytes_total",
        help: "Output bytes of successfully completed response codecs; compression expansion remains visible.",
        unit: "bytes",
        kind: MetricKind::Counter,
        label_names: &["operation", "algorithm"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_response_codec_inflight",
        help: "Active response codec wrappers, including pending input or downstream backpressure.",
        unit: "",
        kind: MetricKind::Gauge,
        label_names: &["operation", "algorithm"],
        histogram_bounds: &[],
    },
];

/// 与已有trailer共享对象共同持有，不保留请求身份或正文。
pub(crate) struct Observation {
    counters: Arc<Counters>,
    transform: Transform,
    input: AtomicU64,
    output: AtomicU64,
    finished: AtomicBool,
}

impl Observation {
    /// 业务作用：在实际创建codec时取得唯一活动观察凭证，不为协商透传创建虚假变换。
    ///
    /// 参数说明：
    /// - `counters`：进程固定统计owner。
    /// - `transform`：已选择的方向及算法。
    ///
    /// 返回：尚未结算的观察凭证，释放时自动记录未完成取消。
    pub(crate) fn new(counters: Arc<Counters>, transform: Transform) -> Self {
        counters.flows[transform as usize]
            .active
            .fetch_add(1, Ordering::Relaxed);
        Self {
            counters,
            transform,
            input: AtomicU64::new(0),
            output: AtomicU64::new(0),
            finished: AtomicBool::new(false),
        }
    }

    /// 业务作用：记录codec已经消费的源前缀，重复借用或未消费输入不计量。
    ///
    /// 参数说明：
    /// - `bytes`：本次consume确认的字节数。
    ///
    /// 返回：更新固定累计量和本次变换总量，不复制正文或进入完成锁。
    pub(crate) fn input(&self, bytes: usize) {
        self.input.fetch_add(bytes as u64, Ordering::Relaxed);
        self.counters.flows[self.transform as usize]
            .input
            .add(bytes as u64);
    }

    /// 业务作用：记录即将交付下一层的有效输出DATA，错误时丢弃的缓冲不计交付。
    ///
    /// 参数说明：
    /// - `bytes`：本次输出帧实际长度。
    ///
    /// 返回：更新实际产出量，不解释为网络发送或对端确认。
    pub(crate) fn output(&self, bytes: usize) {
        self.output.fetch_add(bytes as u64, Ordering::Relaxed);
        self.counters.flows[self.transform as usize]
            .output
            .add(bytes as u64);
    }

    /// 业务作用：唯一结算codec生命周期，只为成功EOF保存成对输入输出及次数。
    ///
    /// 参数说明：
    /// - `outcome`：已确定的codec结束原因。
    ///
    /// 返回：首次结算归还活动数；重复调用无副作用，错误或取消不产生成功收益。
    pub(crate) fn finish(&self, outcome: Outcome) {
        if self.finished.swap(true, Ordering::Relaxed) {
            return;
        }
        let flow = &self.counters.flows[self.transform as usize];
        match outcome {
            Outcome::Eof => {
                // 成功次数和两侧字节必须同锁发布，采样不能把一侧的新值配给另一侧的旧值。
                let mut completed = flow.completed.lock();
                completed.count = completed.count.saturating_add(1);
                completed.input = completed
                    .input
                    .saturating_add(self.input.load(Ordering::Relaxed));
                completed.output = completed
                    .output
                    .saturating_add(self.output.load(Ordering::Relaxed));
            }
            Outcome::BodyError => flow.errors.add(1),
            Outcome::Dropped => flow.dropped.add(1),
        }
        flow.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for Observation {
    /// 业务作用：随最后一个codec共享引用归还未完成观察，取消不冒充成功结束。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚未结算时记dropped；正常EOF或错误后释放不重复计数。
    fn drop(&mut self) {
        self.finish(Outcome::Dropped);
    }
}

impl Counters {
    /// 业务作用：建立四种固定变换的同源样本，完成收益的成对数值从一致快照取得。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：32个有限系列；普通帧计数允许并发弱一致，成功完成组保持成对一致。
    pub(crate) fn samples(&self) -> Vec<MetricSample> {
        let mut samples = Vec::with_capacity(32);
        for (index, flow) in self.flows.iter().enumerate() {
            let operation = if index < 2 {
                "encode"
            } else {
                "decode"
            };
            let algorithm = if index % 2 == 0 {
                "gzip"
            } else {
                "br"
            };
            let labels = vec![
                ("operation", operation.into()),
                ("algorithm", algorithm.into()),
            ];
            let completed = *flow.completed.lock();
            for (name, value) in [
                (DESCRIPTORS[2].name, MetricValue::Counter(completed.input)),
                (DESCRIPTORS[3].name, MetricValue::Counter(completed.output)),
                (
                    DESCRIPTORS[4].name,
                    MetricValue::Gauge(flow.active.load(Ordering::Relaxed) as f64),
                ),
            ] {
                samples.push(MetricSample {
                    name,
                    labels: labels.clone(),
                    value,
                });
            }
            for (side, value) in [("input", flow.input.load()), ("output", flow.output.load())] {
                let mut labels = labels.clone();
                labels.push(("side", side.into()));
                samples.push(MetricSample {
                    name: DESCRIPTORS[0].name,
                    labels,
                    value: MetricValue::Counter(value),
                });
            }
            for (outcome, value) in [
                ("eof", completed.count),
                ("body_error", flow.errors.load()),
                ("dropped", flow.dropped.load()),
            ] {
                let mut labels = labels.clone();
                labels.push(("outcome", outcome.into()));
                samples.push(MetricSample {
                    name: DESCRIPTORS[1].name,
                    labels,
                    value: MetricValue::Counter(value),
                });
            }
        }
        samples
    }

    /// 业务作用：通过NASA描述符输出响应变换事实，文本出口与结构化出口采用相同采样。
    ///
    /// 参数说明：
    /// - `output`：已有Prometheus响应缓冲。
    ///
    /// 返回：追加32个固定系列，不遍历活动请求或读取正文。
    pub(crate) fn render(&self, output: &mut String) {
        nametrics_core::atomic::render_snapshot(
            &DESCRIPTORS.iter().collect::<Vec<_>>(),
            &self.samples(),
            output,
        );
    }
}
