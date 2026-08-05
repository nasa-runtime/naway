//! 长连接注册表(架构规范 §6.1 / review L2)。
//!
//! WS / gRPC-stream 可能持续数小时、一直持有【旧配置快照】,导致「接口禁用 / 应急封杀 / ACL 生效」
//! 只作用于新请求、不影响既有长连接。本注册表登记每条长连接的元信息,支持按 **route / ip / consumer / 快照版本**
//! 触发【优雅关闭】(WS 发标准 Close 帧,而非裸 drop TCP),让应急开关对既有长连接也成立。

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use dashmap::DashMap;
use futures::task::AtomicWaker;
use parking_lot::Mutex;
use tokio::sync::watch;
use tokio::time::Instant;

/// 长连接协议类型:决定优雅关闭语义。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LongProto {
    /// WebSocket 隧道:关闭发标准 Close 控制帧。
    Ws,
    /// gRPC streaming：注册表关闭时由响应 body 优先发送 `grpc-status=14` trailer。
    GrpcStream,
    /// SSE 长响应：关闭时结束 body，客户端按 EventSource 重连语义处理。
    Sse,
}

/// 一条长连接的登记项(内部)。
struct ConnEntry {
    /// 命中的路由 id —— 按路由批量 drain。
    route_id: Arc<str>,
    /// 客户端 IP —— 按 IP 应急封杀。
    peer_ip: IpAddr,
    /// 已认证 consumer（Basic user / API-Key consumer / JWT sub）；未识别身份时为空。
    consumer: Option<Arc<str>>,
    /// 建连时的配置快照版本 —— 判 current / stale、按版本清旧。
    snapshot_version: u64,
    /// 协议类型 —— 决定优雅关闭语义。
    proto: LongProto,
    /// 触发本连接优雅关闭的 waker。它与元数据共用一份 `Arc<ConnEntry>`，避免每条 gRPC
    /// 短流另建 `Arc<Notify>` 和装箱 `Notified` future。
    close_waker: AtomicWaker,
    /// 0 表示尚未关闭；1001 表示换版/drain，1008 表示按 IP 策略封禁。
    /// gRPC 用它选择可读 message，Release/Acquire 同时发布关闭事件。
    ws_close_code: AtomicU16,
}

/// 合并后的旧快照长连接 drain 计划。
///
/// reload 可以比 drain grace 更频繁；计划只保留需要覆盖的最新快照版本和所有重叠计划中
/// 最早的截止时间，既不延长旧连接原本承诺的 grace，也无需为每次 reload 新建 sleeping task。
#[derive(Clone, Copy)]
struct ScheduledStaleDrain {
    /// 到期时关闭所有早于该版本的连接；重叠 reload 取最大值。
    before_version: u64,
    /// 本轮最晚开始关闭的单调时钟；重叠 reload 取最小值。
    deadline: Instant,
}

/// 长连接注册表(常驻,生命周期 = 进程,**不进 Snapshot**)。
pub struct ConnectionRegistry {
    // gRPC 无法仅凭 response head 区分 unary/server-streaming，因此所有原生 gRPC 响应都要
    // 在 body 存活期登记。单个 Mutex 会让不同 h2 connection 的短流 register/drop 串行；
    // DashMap 按 hash shard，只锁命中的桶，同时仍让管理面获得逐项一致的安全访问。
    conns: DashMap<u64, Arc<ConnEntry>>,
    next_id: AtomicU64,
    /// reload 控制面的有界 drain 调度器。只在确有 stale 连接且 grace>0 时惰性启动一个
    /// watch worker；请求注册/注销/关闭通知的热路径不读取这把锁。
    stale_drain_schedule: Mutex<Option<watch::Sender<Option<ScheduledStaleDrain>>>>,
}

impl ConnectionRegistry {
    /// 新建一个空注册表。
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            conns: DashMap::new(),
            next_id: AtomicU64::new(1),
            stale_drain_schedule: Mutex::new(None),
        })
    }

    /// 登记一条长连接,返回 [`ConnGuard`]。守卫 `Drop` 时自动注销；[`ConnGuard::closed`]
    /// 供隧道任务 `select!` 等待关闭信号。
    ///
    /// # 参数
    /// - `route_id`: 命中的路由 id(按路由关闭用)。
    /// - `peer_ip`: 真实客户端 IP(按 IP 应急封杀用)。
    /// - `consumer`: 已认证 consumer；按租户 drain 用，不能放原始 API key/secret。
    /// - `snapshot_version`: 建连时配置版本(判 current/stale、按版本清旧用)。
    /// - `proto`: 长连接协议(决定关闭语义)。
    pub fn register(
        self: &Arc<Self>,
        route_id: Arc<str>,
        peer_ip: IpAddr,
        consumer: Option<Arc<str>>,
        snapshot_version: u64,
        proto: LongProto,
    ) -> ConnGuard {
        let conn_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // registry 与 guard 共享这一份 entry；关闭状态、waker 和元数据都内联其中。gRPC body
        // 无论有多少消息帧都不再为通知机制建立额外 Arc/Box，也不复制任何帧数据。
        let entry = Arc::new(ConnEntry {
            route_id,
            peer_ip,
            consumer,
            snapshot_version,
            proto,
            close_waker: AtomicWaker::new(),
            ws_close_code: AtomicU16::new(0),
        });
        self.conns.insert(conn_id, entry.clone());
        ConnGuard {
            registry: self.clone(),
            conn_id,
            entry,
        }
    }

    fn unregister(&self, conn_id: u64) {
        self.conns.remove(&conn_id);
    }

    /// 优雅关闭命中某路由的所有长连接(接口禁用 / 规则变更时用)。返回触发数。
    pub fn close_by_route(&self, route_id: &str) -> usize {
        self.notify_matching(1001, |e| e.route_id.as_ref() == route_id)
    }

    /// 优雅关闭某 IP 的所有长连接(应急封杀 / ACL 黑名单时用)。返回触发数。
    pub fn close_by_ip(&self, ip: IpAddr) -> usize {
        self.notify_matching(1008, |e| e.peer_ip == ip)
    }

    /// 优雅关闭某个已认证 consumer 的全部长连接。返回触发数。
    pub fn close_by_consumer(&self, consumer: &str) -> usize {
        self.notify_matching(1008, |entry| entry.consumer.as_deref() == Some(consumer))
    }

    /// 优雅关闭所有【早于】给定版本的长连接(按需清旧,非默认;drain_on_config_change 才调用)。
    pub fn drain_stale(&self, before_version: u64) -> usize {
        self.notify_matching(1001, |e| e.snapshot_version < before_version)
    }

    /// 为旧快照长连接安排带宽限期的 drain。
    ///
    /// # 参数
    /// - `before_version`: 建连版本早于它的连接进入本轮 drain。
    /// - `grace`: 继续完成在途帧的宽限期；0 表示立即发送关闭信号。
    ///
    /// 返回：安排时匹配的连接数。宽限期内已自然结束的连接不会再次操作；新连接版本不匹配。
    /// 重叠计划合并进单 worker：版本取最大值、deadline 取最小值，任务数不会随 reload 次数增长。
    pub fn schedule_drain_stale(self: &Arc<Self>, before_version: u64, grace: Duration) -> usize {
        let scheduled = self.count_matching(|entry| entry.snapshot_version < before_version);
        if scheduled == 0 {
            return 0;
        }
        if grace.is_zero() {
            return self.drain_stale(before_version);
        }
        let request = ScheduledStaleDrain {
            before_version,
            deadline: Instant::now() + grace,
        };
        let mut scheduler = self.stale_drain_schedule.lock();
        if let Some(sender) = scheduler.as_ref() {
            sender.send_modify(|pending| match pending {
                Some(current) => {
                    current.before_version = current.before_version.max(request.before_version);
                    current.deadline = current.deadline.min(request.deadline);
                }
                None => *pending = Some(request),
            });
        } else {
            let (sender, receiver) = watch::channel(Some(request));
            *scheduler = Some(sender);
            // worker 只持有 Weak，注册表随 Nate 退出时 sender 被释放，任务随 channel 关闭结束；
            // 不能让低频控制面定时器反向延长整个数据面对象的生命周期。
            tokio::spawn(run_stale_drain_scheduler(Arc::downgrade(self), receiver));
        }
        scheduled
    }

    /// 只遍历分片并计数，不发送信号；供带宽限期 drain 返回安排时的近似数量。
    ///
    /// DashMap 不冻结整张表，因此并发注册/注销可能跨越这个管理面采样窗口；返回值只用于
    /// 可观测性，真正到期时仍按版本条件重新匹配，不能把这里的数量当作关闭授权。
    fn count_matching(&self, pred: impl Fn(&ConnEntry) -> bool) -> usize {
        self.conns
            .iter()
            .filter(|entry| pred(entry.value().as_ref()))
            .count()
    }

    /// 为命中项发布关闭原因后再唤醒连接任务。
    ///
    /// # 参数
    /// - `ws_close_code`: WS 客户端可观察的 RFC 6455 状态码；gRPC 映射为对应说明文字。
    /// - `pred`: 只读匹配条件；持有当前 shard 的读 guard 时执行，不能阻塞或递归修改本表。
    ///
    /// 返回：本次首次发出关闭信号的连接数。已经进入关闭态的项不会被重复计数，也不会让
    /// 较晚的 drain/封禁覆盖先到达且已经被连接任务观察到的关闭原因。
    fn notify_matching(&self, ws_close_code: u16, pred: impl Fn(&ConnEntry) -> bool) -> usize {
        let mut n = 0;
        for entry in &self.conns {
            let e = entry.value().as_ref();
            if pred(e)
                && e.ws_close_code
                    .compare_exchange(0, ws_close_code, Ordering::Release, Ordering::Acquire)
                    .is_ok()
            {
                e.close_waker.wake();
                n += 1;
            }
        }
        n
    }

    /// 长连接观测快照(§13 低基数):总数 + current/stale 拆分 + 最旧快照版本。
    pub fn stats(&self, current_version: u64) -> LongConnStats {
        // 统计是管理面瞬时快照，不需要冻结全部 shard；并发 register/drop 可能使各字段跨越
        // 一个极短时间窗，但不会阻塞数据面，也不会产生内存不安全或丢失关闭通知。
        // 一次遍历同时累加三个字段，保证这个弱一致管理面快照内部始终满足
        // `current <= total`。若先读 len 再二次遍历，并发 insert 可能让 current 大于旧 total，
        // `total - current` 随即下溢；为了统计冻结全部 shard 反而会阻塞数据面，得不偿失。
        let (total, current, oldest) = self.conns.iter().fold(
            (0usize, 0usize, None::<u64>),
            |(total, current, oldest), entry| {
                let version = entry.value().snapshot_version;
                (
                    total + 1,
                    current + usize::from(version >= current_version),
                    Some(oldest.map_or(version, |candidate| candidate.min(version))),
                )
            },
        );
        LongConnStats {
            total,
            current,
            stale: total - current,
            oldest_version: oldest,
        }
    }
}

/// 驱动一个注册表唯一的 stale-drain 定时器。
///
/// # 参数
/// - `registry`: 弱引用，防止调度任务让已停机的 Nate 注册表泄漏。
/// - `receiver`: 最新合并计划；reload 更新会唤醒 worker 并重新计算最早截止时间。
///
/// channel 关闭、注册表销毁时退出。到期后仅在计划仍与已执行值相同时清空，避免覆盖并发到达
/// 的更新；若更新已经提高版本，下一轮会立即按保留的 deadline 继续处理。
async fn run_stale_drain_scheduler(
    registry: Weak<ConnectionRegistry>,
    mut receiver: watch::Receiver<Option<ScheduledStaleDrain>>,
) {
    loop {
        let request = loop {
            if let Some(request) = *receiver.borrow_and_update() {
                break request;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        };

        tokio::select! {
            changed = receiver.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep_until(request.deadline) => {
                let Some(registry) = registry.upgrade() else {
                    return;
                };
                registry.drain_stale(request.before_version);
                let scheduler = registry.stale_drain_schedule.lock();
                if let Some(sender) = scheduler.as_ref() {
                    sender.send_modify(|pending| {
                        if pending.as_ref().is_some_and(|current| {
                            current.before_version == request.before_version
                                && current.deadline == request.deadline
                        }) {
                            *pending = None;
                        }
                    });
                }
            }
        }
    }
}

/// 长连接观测统计(§13,低基数:只出数值,不出高基数 label)。
pub struct LongConnStats {
    /// 当前登记的 WS + gRPC streaming 总数。
    pub total: usize,
    /// 建连版本不早于当前快照版本的连接数。
    pub current: usize,
    /// 仍持有旧配置版本的连接数。
    pub stale: usize,
    /// 最早仍被长连接持有的快照版本；没有长连接时为空。
    pub oldest_version: Option<u64>,
}

/// 登记句柄:隧道任务持有；`Drop` 时自动从注册表注销。
pub struct ConnGuard {
    registry: Arc<ConnectionRegistry>,
    conn_id: u64,
    /// 与 registry map 共享的稳定 entry；DashMap resize 不会移动 future 正在观察的状态。
    entry: Arc<ConnEntry>,
}

impl ConnGuard {
    /// 返回登记时固定的长连接协议类型。
    pub fn protocol(&self) -> LongProto {
        self.entry.proto
    }

    /// 创建一个等待当前连接被管理面关闭的 future。
    ///
    /// future 只 clone 一次 entry Arc，无堆分配；`AtomicWaker` 使用“先查状态→注册→复查”
    /// 模式封住注册与关闭之间的竞态。每个连接只允许一个 body/tunnel waiter。
    pub fn closed(&self) -> CloseNotified {
        CloseNotified {
            entry: self.entry.clone(),
            registered_waker: None,
        }
    }

    /// 非阻塞读取管理面是否已经请求关闭。
    ///
    /// gRPC body 在上游连续返回 ready frame 时只需要一次 Acquire load；只有 body 真正
    /// Pending、需要被异步关闭唤醒时才注册 [`AtomicWaker`]。这既封住 response head 到首次
    /// body poll 的关闭竞态，也避免为每个同步就绪的消息重复比较/clone task waker。
    pub fn requested_close_code(&self) -> Option<u16> {
        match self.entry.ws_close_code.load(Ordering::Acquire) {
            0 => None,
            code => Some(code),
        }
    }

    /// 读取本次关闭原因对应的 WS 状态码。
    ///
    /// 返回：默认/换版 drain 为 1001；按 IP 策略封禁为 1008。仅在 `closed` 就绪后读取。
    pub fn ws_close_code(&self) -> u16 {
        self.requested_close_code().unwrap_or(1001)
    }
}

/// 单连接关闭等待器；内部共享固定地址的注册项，不装箱、不持有 DashMap shard guard。
pub struct CloseNotified {
    entry: Arc<ConnEntry>,
    /// 最近一次写入 `AtomicWaker` 的调度器 waker。gRPC 每个 data/trailer frame 都会 poll
    /// 本 future；同一 task 的 waker 未变时不能重复 clone/register。
    registered_waker: Option<Waker>,
}

impl CloseNotified {
    /// 确保当前 task waker 已登记；只在首次订阅或 executor 更换 waker 时写 `AtomicWaker`。
    ///
    /// 调用方须已在本次 poll 开头检查关闭码。若 waker 未变，管理面仍持有原订阅，关闭会
    /// 唤醒 task；若发生重登记，则在 register 后复查关闭码，封住检查与登记之间的竞态。
    pub(crate) fn subscribe_if_needed(&mut self, cx: &Context<'_>) -> bool {
        let waker_changed = self
            .registered_waker
            .as_ref()
            .is_none_or(|registered| !registered.will_wake(cx.waker()));
        if !waker_changed {
            return false;
        }
        self.entry.close_waker.register(cx.waker());
        self.registered_waker = Some(cx.waker().clone());
        self.entry.ws_close_code.load(Ordering::Acquire) != 0
    }
}

impl Future for CloseNotified {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.entry.ws_close_code.load(Ordering::Acquire) != 0 {
            return Poll::Ready(());
        }
        this.subscribe_if_needed(cx);
        // 注册后必须复查；管理线程可能恰好在第一次 load 与 register 之间完成 store+wake。
        if this.entry.ws_close_code.load(Ordering::Acquire) != 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.registry.unregister(self.conn_id);
    }
}

/// 构造一个 WebSocket Close 控制帧(server→client 方向,**不 mask**;RFC 6455 §5.5.1)。
///
/// # 参数
/// - `code`: 关闭状态码。约定:`1001` going away(配置变更)/ `1008` policy violation(应急封杀)。
pub fn ws_close_frame(code: u16) -> [u8; 4] {
    // 字节 0:FIN=1(0x80) + opcode=0x8(close) = 0x88;字节 1:MASK=0 + payload len=2;字节 2-3:状态码大端。
    [0x88, 0x02, (code >> 8) as u8, (code & 0xff) as u8]
}

/// 构造网关 client→upstream 的带掩码 WebSocket Close 控制帧。
///
/// # 参数
/// - `code`: RFC 6455 关闭状态码。
/// - `mask`: 本帧独立的 4 字节不可预测 mask；调用方应由系统随机源生成。
///
/// 返回：8 字节固定数组，避免关闭热路径分配。payload 按 RFC 6455 与 mask 异或。
pub fn ws_masked_close_frame(code: u16, mask: [u8; 4]) -> [u8; 8] {
    let payload = [(code >> 8) as u8, (code & 0xff) as u8];
    [
        0x88,
        0x82,
        mask[0],
        mask[1],
        mask[2],
        mask[3],
        payload[0] ^ mask[0],
        payload[1] ^ mask[1],
    ]
}

#[path = "../../tests/unit/conn_registry.rs"]
#[cfg(test)]
mod tests;
