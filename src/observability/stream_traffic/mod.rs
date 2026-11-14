//! 当前监听器的本地流量事实；会话只更新接入时捕获的配置所有者。

mod io;
mod snapshot;
pub use io::ObservedIo;
pub(crate) use snapshot::{Catalog, Reading, Snapshot, MAX_LISTENERS};

use crate::observability::http_stream::metrics::BOUNDS_MS;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// 转发写入的固定方向，不携带客户端或上游地址。
#[derive(Clone, Copy)]
pub enum Direction {
    /// 下游数据成功写入上游应用流。
    DownstreamToUpstream,
    /// 上游数据或协议控制响应成功写入下游应用流。
    UpstreamToDownstream,
}

#[derive(Default)]
struct Counters {
    attempts: AtomicU64,
    admitted: AtomicU64,
    active: AtomicU64,
    outcomes: [AtomicU64; 5],
    bytes: [AtomicU64; 2],
    datagrams: [AtomicU64; 2],
    dropped_datagrams: AtomicU64,
    duration_micros: AtomicU64,
    buckets: [AtomicU64; 13],
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Totals {
    pub attempts: u64,
    pub admitted: u64,
    pub active: u64,
    pub outcomes: [u64; 5],
    pub bytes: [u64; 2],
    pub datagrams: [u64; 2],
    pub dropped_datagrams: u64,
    pub duration_micros: u64,
    pub buckets: [u64; 13],
}

/// 已冻结监听器计数的轻量引用，不持有会话地址、正文或当前配置槽。
#[derive(Clone)]
pub struct Handle {
    counters: Arc<Counters>,
}

/// 一次 TCP 接入或 UDP 会话创建的唯一生命周期，释放时结算尚未报告的本地取消。
pub struct Observation {
    handle: Handle,
    started: Instant,
    phase: AtomicU8,
}

impl Counters {
    /// 业务作用：读取当前所有者的固定累计值，采样方仍须检查并发弱一致与区间回退。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不包含会话身份的有限累计快照，不分配或遍历在途会话。
    fn read(&self) -> Totals {
        Totals {
            attempts: self.attempts.load(Ordering::Relaxed),
            admitted: self.admitted.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            outcomes: std::array::from_fn(|index| self.outcomes[index].load(Ordering::Relaxed)),
            bytes: std::array::from_fn(|index| self.bytes[index].load(Ordering::Relaxed)),
            datagrams: std::array::from_fn(|index| self.datagrams[index].load(Ordering::Relaxed)),
            dropped_datagrams: self.dropped_datagrams.load(Ordering::Relaxed),
            duration_micros: self.duration_micros.load(Ordering::Relaxed),
            buckets: std::array::from_fn(|index| self.buckets[index].load(Ordering::Relaxed)),
        }
    }
}

impl Handle {
    /// 业务作用：在当前监听器所有者下开始一次接入，覆盖随后资源准入和协议握手。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已增加尝试与在途量的唯一观察器；未取得会话资格就释放时记为本地拒绝。
    fn start(&self) -> Observation {
        self.counters.attempts.fetch_add(1, Ordering::Relaxed);
        self.counters.active.fetch_add(1, Ordering::Relaxed);
        Observation {
            handle: self.clone(),
            started: Instant::now(),
            phase: AtomicU8::new(0),
        }
    }

    /// 业务作用：记录已经成功提交给一个应用流写入边界的字节，不以读取长度推测交付。
    ///
    /// 参数说明：
    /// - `direction`：固定转发方向。
    /// - `length`：底层写入操作实际确认的字节数。
    ///
    /// 返回：只更新原配置所有者；Pending、写错误与协议头不由此推算字节。
    fn written(&self, direction: Direction, length: usize) {
        let index = match direction {
            Direction::DownstreamToUpstream => 0,
            Direction::UpstreamToDownstream => 1,
        };
        self.counters.bytes[index].fetch_add(length as u64, Ordering::Relaxed);
    }

    /// 业务作用：在 UDP socket 确认一次发送后累计报文和实际提交字节。
    ///
    /// 参数说明：
    /// - `direction`：本次成功发送的固定方向。
    /// - `length`：该次 socket 发送确认的字节数，空数据报仍计一枚报文。
    ///
    /// 返回：保留原会话所有者的发送事实，不把排队或本地 connect 当作发送成功。
    pub fn datagram_sent(&self, direction: Direction, length: usize) {
        let index = match direction {
            Direction::DownstreamToUpstream => 0,
            Direction::UpstreamToDownstream => 1,
        };
        self.counters.datagrams[index].fetch_add(1, Ordering::Relaxed);
        self.written(direction, length);
    }

    /// 业务作用：记录本地明确丢弃的数据报，不推断远端接收或应用失败。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅更新选择该门禁时捕获的所有者，不保存地址或报文内容。
    pub fn datagram_dropped(&self) {
        self.counters
            .dropped_datagrams
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl Observation {
    /// 业务作用：确认接入已经取得本地会话资源，协议或上游随后失败仍保留受理事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：首次受理增加一次累计；重复调用或已经终止后调用不改变状态。
    pub fn admit(&self) {
        if self
            .phase
            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.handle
                .counters
                .admitted
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 业务作用：让数据报队列或 I/O 包装共享原所有者，不复制唯一生命周期责任。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只持有固定原子计数的轻量引用，不能通过它重复增加或释放会话占用。
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }

    /// 业务作用：在 TLS 和 PROXY 头处理之后包装应用流，按底层实际成功写入观察字节。
    ///
    /// 参数说明：
    /// - `inner`：原异步流，读取、背压、刷新与关闭语义保持透传。
    /// - `direction`：写入该流对应的固定转发方向。
    ///
    /// 返回：不缓存正文的 I/O 包装；每次写入只累计成功部分，不改变错误或 Pending。
    pub fn observe_io<T>(&self, inner: T, direction: Direction) -> ObservedIo<T> {
        ObservedIo::new(inner, self.handle(), direction)
    }

    /// 业务作用：按网关已有归一化终态结束本地会话，日志是否启用不影响计数。
    ///
    /// 参数说明：
    /// - `status`：本地结束原因，正常关闭为 2xx，408/504 为超时，其它 4xx 为拒绝，其余为失败。
    ///
    /// 返回：首次结算归还在途量并记录寿命；重复结算不会重复减计数。
    pub fn finish_from_status(&self, status: u16) {
        let outcome = match status {
            200..=299 => 0,
            408 | 504 => 2,
            400..=499 => 3,
            _ => 1,
        };
        self.finish(outcome);
    }

    /// 业务作用：以唯一原子状态转移完成寿命和占用结算，避免显式终态与取消释放重复记账。
    ///
    /// 参数说明：
    /// - `outcome`：固定结局位置，依次为正常关闭、失败、超时、拒绝、本地取消。
    ///
    /// 返回：只有尚未结束的接入能够成功转换，所有累计都属于捕获的原配置。
    fn finish(&self, outcome: usize) {
        let mut phase = self.phase.load(Ordering::Relaxed);
        while phase < 2 {
            match self.phase.compare_exchange_weak(
                phase,
                outcome as u8 + 2,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let counters = &self.handle.counters;
                    counters.outcomes[outcome].fetch_add(1, Ordering::Relaxed);
                    let elapsed = self.started.elapsed().as_micros();
                    counters
                        .duration_micros
                        .fetch_add(elapsed.min(u128::from(u64::MAX)) as u64, Ordering::Relaxed);
                    let bucket =
                        BOUNDS_MS.partition_point(|bound| elapsed > u128::from(*bound) * 1000);
                    counters.buckets[bucket].fetch_add(1, Ordering::Relaxed);
                    counters.active.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                Err(current) => phase = current,
            }
        }
    }
}

impl Drop for Observation {
    /// 业务作用：在未报告终态的早退或任务取消时归还原监听器在途量，不冒充远端错误。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未受理的接入记本地拒绝，已受理的会话记本地取消；已结算状态保持不变。
    fn drop(&mut self) {
        self.finish(if self.phase.load(Ordering::Relaxed) == 0 {
            3
        } else {
            4
        });
    }
}
