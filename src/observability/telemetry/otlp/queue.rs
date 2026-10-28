//! 每种信号独占有界队列与后台 runtime；请求完成路径只进行限长编码和 try_send。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc as blocking, Arc};
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::transport::{Failure, Transport};
use super::wire::Signal;
use crate::config::telemetry::{OtlpProtocol, OtlpSignalCfg};

pub(super) const OUTCOMES: [&str; 11] = [
    "queued",
    "queue_full",
    "oversized",
    "closed",
    "exported",
    "rejected",
    "failed",
    "retry",
    "circuit_open",
    "shutdown",
    "collector_warning",
];
pub(super) static COUNTERS: [[AtomicU64; 11]; 3] = [const {
    [const {
        AtomicU64::new(0)
    }; 11]
}; 3];

#[derive(Debug)]
enum Work {
    Record {
        body: Vec<u8>,
        units: u64,
    },
    Flush(blocking::SyncSender<()>),
}

#[derive(Clone, Debug)]
pub(super) struct Sender {
    tx: mpsc::Sender<Work>,
    accepting: Arc<AtomicBool>,
    signal: Signal,
    max_record_bytes: usize,
}

impl Sender {
    /// 业务作用：将单个已审核记录提交到独占队列，满队列和关闭态立即丢弃。
    ///
    /// 参数说明：
    /// - `record`：是本信号的标准 protobuf
    /// - `units`：是 span、log record 或 metric data point 数。
    ///
    /// 返回：无返回值；仅编码受限载荷，不等待网络、不暂停请求。
    pub fn record(&self, record: &impl Message, units: u64) {
        if !self.accepting.load(Ordering::Acquire) {
            count(self.signal, 3, units);
            return;
        }
        if record.encoded_len() > self.max_record_bytes {
            count(self.signal, 2, units);
            return;
        }
        match self.tx.try_send(Work::Record {
            body: record.encode_to_vec(),
            units,
        }) {
            Ok(()) => count(self.signal, 0, units),
            Err(mpsc::error::TrySendError::Full(_)) => count(self.signal, 1, units),
            Err(mpsc::error::TrySendError::Closed(_)) => count(self.signal, 3, units),
        }
    }

    /// 业务作用：关闭本代生产入口，让排空边界之后的在途请求不能延长停机。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：后续记录立即按关闭原因丢弃，已入队记录仍可排空。
    pub fn close(&self) {
        self.accepting.store(false, Ordering::Release);
    }

    /// 业务作用：向同一 FIFO 插入有界排空屏障，只供控制面 flush 使用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：屏障收据；队列满或已退出时立即返回错误，不把 flush 等待带入数据面。
    pub fn barrier(&self) -> anyhow::Result<blocking::Receiver<()>> {
        let (tx, rx) = blocking::sync_channel(1);
        self.tx
            .try_send(Work::Flush(tx))
            .map_err(|_| anyhow::anyhow!("OTLP flush queue unavailable"))?;
        Ok(rx)
    }
}

#[derive(Default)]
struct Batch {
    records: Vec<Vec<u8>>,
    units: u64,
}

impl Batch {
    /// 业务作用：批次处理完成后同时清除载荷与协议计数，避免下一批继承旧状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：保留有限容量以供复用，记录与数量归零。
    fn clear(&mut self) {
        self.records.clear();
        self.units = 0;
    }
}

/// 业务作用：累计固定信号、固定原因的进程事实，热换出口不会重置计数。
///
/// 参数说明：
/// - `signal`：来自静态目录
/// - `outcome`：来自静态目录
/// - `amount`：是该事件的数量。
///
/// 返回：原子饱和累加，不引入动态标签。
pub(super) fn count(signal: Signal, outcome: usize, amount: u64) {
    nametrics_core::atomic::add(&COUNTERS[signal as usize][outcome], amount);
}

/// 业务作用：为一个信号创建独立 worker，并等待本地 client 装配成功后才交回候选。
///
/// 参数说明：
/// - `signal`：固化本代协议与预算
/// - `cfg`：固化本代协议与预算
/// - `protocol`：固化本代协议与预算
/// - `endpoint`：固化本代协议与预算
/// - `resource`：固化本代协议与预算
/// - `stop`：撤销后台任务
/// - `lease`：约束存活代数。
///
/// 返回：非阻塞生产句柄；线程或本地客户端构建失败时拒绝候选。
pub(super) fn start(
    signal: Signal,
    cfg: OtlpSignalCfg,
    protocol: OtlpProtocol,
    endpoint: String,
    resource: Resource,
    stop: CancellationToken,
    lease: Arc<super::GenerationPermit>,
) -> anyhow::Result<Sender> {
    let (tx, rx) = mpsc::channel(cfg.queue_size);
    let (ready_tx, ready_rx) = blocking::sync_channel(1);
    let sender = Sender {
        tx,
        accepting: Arc::new(AtomicBool::new(true)),
        signal,
        max_record_bytes: cfg.max_record_bytes,
    };
    std::thread::Builder::new()
        .name(format!("otlp-{}", signal.name()))
        .spawn(move || {
            let _lease = lease;
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => {
                    let _ = ready_tx.send(false);
                    return;
                }
            };
            runtime.block_on(async move {
                let transport = match Transport::build(
                    protocol,
                    endpoint,
                    Duration::from_millis(cfg.deadline_ms),
                ) {
                    Ok(transport) => transport,
                    Err(_) => {
                        let _ = ready_tx.send(false);
                        return;
                    }
                };
                if ready_tx.send(true).is_err() {
                    return;
                }
                run(signal, cfg, resource, transport, rx, stop).await;
            });
        })?;
    anyhow::ensure!(
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or(false),
        "OTLP worker initialization failed"
    );
    Ok(sender)
}

/// 业务作用：独立聚合、导出并维护本信号熔断，不抢占其它信号队列容量。
///
/// 参数说明：
/// - `signal`：固化出口
/// - `cfg`：固化出口
/// - `resource`：固化出口
/// - `transport`：固化出口
/// - `rx`：是独占消费端
/// - `stop`：是撤销权威。
///
/// 返回：撤销或生产者全部退出后释放所有排队载荷；取消丢弃量保留在固定指标中。
async fn run(
    signal: Signal,
    cfg: OtlpSignalCfg,
    resource: Resource,
    mut transport: Transport,
    mut rx: mpsc::Receiver<Work>,
    stop: CancellationToken,
) {
    let mut batch = Batch {
        records: Vec::with_capacity(cfg.batch_size),
        units: 0,
    };
    let mut size = 1024usize;
    let mut circuit = Circuit {
        failures: 0,
        open_until: Instant::now(),
    };
    let mut ticker = tokio::time::interval(Duration::from_millis(cfg.batch_delay_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let mut receipt = None;
        let flush = tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            work = rx.recv() => match work {
                Some(Work::Record {
                    body: record, units
                }) => {
                    if size + record.len() + 8 > cfg.max_batch_bytes && !batch.records.is_empty() {
                        deliver(signal, &cfg, &resource, &mut transport, &mut batch, &mut circuit, &stop).await;
                        size = 1024;
                    }
                    size += record.len() + 8;
                    batch.records.push(record);
                    batch.units = batch.units.saturating_add(units);
                    batch.records.len() >= cfg.batch_size
                }
                Some(Work::Flush(tx)) => {
                    receipt = Some(tx); true
                }
                None => break,
            },
            _ = ticker.tick() => true,
        };
        if flush {
            deliver(
                signal,
                &cfg,
                &resource,
                &mut transport,
                &mut batch,
                &mut circuit,
                &stop,
            )
            .await;
            size = 1024;
            if let Some(receipt) = receipt {
                let _ = receipt.send(());
            }
        }
    }
    // 撤销后停止接纳并回收排队载荷，不能让失效代继续向旧 collector 发包。
    rx.close();
    let mut dropped = batch.units;
    while let Ok(work) = rx.try_recv() {
        if let Work::Record {
            units,
            ..
        } = work
        {
            dropped = dropped.saturating_add(units);
        }
    }
    count(signal, 9, dropped);
}

struct Circuit {
    failures: u32,
    open_until: Instant,
}

/// 业务作用：在固定绝对期限内导出一个批次，错误只改变本信号的退避和熔断状态。
///
/// 参数说明：
/// - `signal`：待导出的固定信号类别。
/// - `cfg`：本代导出端点与预算配置。
/// - `resource`：本代冻结的资源属性。
/// - `transport`：当前 worker 使用的受控导出传输。
/// - `batch`：本次有界记录批次。
/// - `circuit`：当前出口的熔断状态。
/// - `stop`：撤销本代 worker 的停止信号。
///
/// 返回：清空本批次；成功、部分拒绝、不可重试、超时、熔断和取消分别计数。
async fn deliver(
    signal: Signal,
    cfg: &OtlpSignalCfg,
    resource: &Resource,
    transport: &mut Transport,
    batch: &mut Batch,
    circuit: &mut Circuit,
    stop: &CancellationToken,
) {
    if batch.records.is_empty() {
        return;
    }
    let records = batch.units;
    if Instant::now() < circuit.open_until {
        count(signal, 8, records);
        batch.clear();
        return;
    }
    let body = signal.encode(&batch.records, resource);
    batch.clear();
    let Ok(body) = body else {
        count(signal, 6, records);
        return;
    };
    if body.len() > cfg.max_batch_bytes {
        count(signal, 2, records);
        return;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(cfg.deadline_ms);
    for attempt in 0..=cfg.retry_limit {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let result = tokio::select! {
            biased;
            _ = stop.cancelled() => {
                count(signal, 9, records); return;
            },
            result = tokio::time::timeout_at(deadline, transport.send(signal, &body, remaining)) => result,
        };
        match result {
            Ok(Ok(rejected)) => {
                let rejected = rejected.min(records);
                count(signal, 4, records.saturating_sub(rejected));
                count(signal, 5, rejected);
                circuit.failures = 0;
                return;
            }
            Ok(Err(Failure::Retry(delay))) if attempt < cfg.retry_limit => {
                let base = Duration::from_millis(cfg.retry_base_ms.saturating_mul(1 << attempt));
                let wait = delay.unwrap_or_default().max(jitter(base));
                // 服务端等待提示不能缩短成提前重试；超过本批期限时放弃该批，不扩展期限。
                if wait >= deadline.saturating_duration_since(tokio::time::Instant::now()) {
                    break;
                }
                count(signal, 7, 1);
                tokio::select! { _ = stop.cancelled() => {
                    count(signal, 9, records); return;
                }, _ = tokio::time::sleep(wait) => {} }
            }
            _ => break,
        }
    }
    count(signal, 6, records);
    circuit.failures = circuit.failures.saturating_add(1);
    // 唯一 worker 在开放期后最多放行一批探测；成功才解除保护，不创建并行半开请求。
    if circuit.failures >= cfg.circuit_failures {
        circuit.open_until = Instant::now() + Duration::from_millis(cfg.circuit_open_ms);
    }
}

/// 业务作用：对指数退避增加有限抖动，避免多个网关在 collector 恢复边界同步重试。
///
/// 参数说明：
/// - `base`：是本次指数退避时长。
///
/// 返回：约为基础时长的一半到一点五倍；随机源不可用时使用基础等待。
fn jitter(base: Duration) -> Duration {
    let mut random = [0u8; 8];
    if getrandom::getrandom(&mut random).is_err() {
        return base;
    }
    let micros = base.as_micros().min(u128::from(u64::MAX)) as u64;
    Duration::from_micros(micros / 2 + u64::from_le_bytes(random) % micros.saturating_add(1))
}
