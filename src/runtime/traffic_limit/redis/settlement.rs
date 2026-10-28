//! 有限响应回执：累计事实补扣、终态封锁与持有原名额的取消清理。

use super::{decode, queue, Failure, Ledger, Policy, QuotaDecision};
use crate::runtime::traffic_limit::{metrics, resources::Retained};
use sha2::Digest;
use std::{
    sync::{atomic::Ordering, Arc, LazyLock},
    time::Duration,
};

const SCRIPT: &str = include_str!("settlement.lua");
static SHA: LazyLock<String> =
    LazyLock::new(|| format!("{:x}", sha1::Sha1::digest(SCRIPT.as_bytes())));

#[derive(PartialEq, Eq)]
pub(super) struct Limits {
    pub(super) maximum: u64,
    pub(super) maximum_arg: String,
    pub(super) idle: Duration,
    pub(super) idle_arg: String,
}

#[derive(Clone)]
pub(crate) struct Operation {
    policy: Arc<Policy>,
    ledger: Arc<Ledger>,
    key: Arc<str>,
    events: Option<crate::observability::meter::traffic::Facts>,
}

/// 只有确认准入成功后才有退款权威；未知提交保守留在共享窗口自然衰减。
pub(crate) struct Receipt {
    operation: Operation,
    retained: Option<Retained>,
    active: bool,
    actual: u64,
    usage: Option<(crate::runtime::traffic_limit::usage::Facts, u64)>,
    actual_known: bool,
    actual_started: bool,
    event_lease: Option<crate::observability::meter::traffic::Lease>,
}

impl Receipt {
    /// 业务作用：让持久事件等待原回执终态，取消不会创造第二份额度操作权威。
    ///
    /// 参数说明：
    /// - `facts`：同一请求的持久成本事实槽。
    ///
    /// 返回：只保留固定事实与原生命周期名额，不复制实体。
    pub(crate) fn bind_events(&mut self, facts: crate::observability::meter::traffic::Facts) {
        self.event_lease = Some(facts.lease());
        self.operation.events = Some(facts);
    }

    /// 业务作用：终态前读取独立用量或已交付事实，未知提交也保留实际可知消耗。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：更新事件的固定整数槽，不执行网络操作。
    fn record_cost(&self) {
        // 尚未进入响应结算的拒绝保留准入事实，不能用空计数器覆盖明确拒绝的零成本。
        if !self.actual_started {
            return;
        }
        if let Some(events) = &self.operation.events {
            let known = self
                .usage
                .as_ref()
                .map_or(self.actual_known, |(facts, _)| facts.known());
            events.cost(self.final_cost(), known);
        }
    }

    /// 业务作用：将 provider 消耗绑定原回执，取消不能用尚未交付的帧状态覆盖真实用量。
    ///
    /// 参数说明：
    /// - `facts`：准入冻结的可信事实槽。
    /// - `reserve`：证据不足时必须保留的预留成本。
    ///
    /// 返回：之后的终态与取消均读取最新已确认事实。
    pub(crate) fn bind_usage(
        &mut self,
        facts: crate::runtime::traffic_limit::usage::Facts,
        reserve: u64,
    ) {
        self.usage = Some((facts, reserve));
    }

    /// 业务作用：区分上游真实消耗与下游交付成本，终止时选取同源事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：可信用量的保守事实或原交付成本。
    fn final_cost(&self) -> u64 {
        self.usage
            .as_ref()
            .map_or(self.actual, |(facts, reserve)| facts.cost(*reserve))
    }

    /// 业务作用：在共享准入前取得一个有限响应槽并生成不可预测的同 slot 回执身份。
    ///
    /// 参数说明：
    /// - `policy`：构建时冻结的响应成本策略。
    /// - `ledger`：本次调用的共享身份、连接和工作区容量。
    ///
    /// 返回：普通请求成本返回空；响应成本返回未激活回执，物理容量不足失败关闭。
    pub(crate) fn prepare(
        policy: Arc<Policy>,
        ledger: Arc<Ledger>,
    ) -> Result<Option<Self>, Failure> {
        if policy.settlement.is_none() {
            return Ok(None);
        }
        let retained = Retained::acquire(0).ok_or(Failure::Deadline)?;
        let mut token = [0u8; 16];
        getrandom::getrandom(&mut token).map_err(|_| Failure::Invalid)?;
        let key = format!(
            "{}:receipt:{:032x}",
            ledger.data,
            u128::from_be_bytes(token)
        );
        Ok(Some(Self {
            operation: Operation {
                policy,
                ledger,
                key: Arc::from(key),
                events: None,
            },
            retained: Some(retained),
            active: false,
            actual: 0,
            usage: None,
            actual_known: false,
            actual_started: false,
            event_lease: None,
        }))
    }

    /// 业务作用：提供不持有实体的调用描述，网络等待期间仍由原回执占用有限槽。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：共享连接、参数及同一回执键的轻量引用。
    pub(crate) fn operation(&self) -> Operation {
        self.operation.clone()
    }

    /// 业务作用：只在收到明确成功准入后开放该回执的最终退款权限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：随后取消或响应终止可以提交最终事实，未知准入不会调用此方法。
    pub(crate) fn activate(&mut self) {
        self.active = true;
    }

    /// 业务作用：区分已经确认的共享回执与依赖降级时仅用于本地硬上限的上下文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有收到成功准入确认后为真；未知提交不能成为补扣或退款权威。
    pub(crate) fn confirmed(&self) -> bool {
        self.active
    }

    /// 业务作用：调整当前待交付帧的保留预算，不复制实体或创建额外等待名额。
    ///
    /// 参数说明：
    /// - `bytes`：待交付帧字节数，交付或取消后为零。
    ///
    /// 返回：取得字节预算为真，超界时原名额仍有效且调用方必须关闭流。
    pub(crate) fn retain(&mut self, bytes: u64) -> bool {
        self.retained
            .as_mut()
            .is_some_and(|retained| retained.resize(bytes))
    }

    /// 业务作用：仅接受已经交付下游的累计事实，待发送帧不能提前成为退款依据。
    ///
    /// 参数说明：
    /// - `actual`：已交付或因协议不完整而保守保留的成本。
    /// - `known`：该成本是否由完整事实证明，预留和协议残缺为假。
    ///
    /// 返回：更新最终结算事实，不执行远端副作用。
    pub(crate) fn delivered(&mut self, actual: u64, known: bool) {
        self.actual = actual;
        self.actual_known = known;
        self.actual_started = true;
    }

    /// 业务作用：在响应自然终止时等待一次有界终态提交，令迟到帧不能重新补扣。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：明确终态结果或失败；未知提交不重发，保留远端已有债务等待到期。
    pub(crate) async fn finish(mut self) -> Result<(), Failure> {
        self.record_cost();
        // 终态已经发出后，取消只保留未知；不能让 Drop 再发一份可能逆序的结算。
        self.active = false;
        let outcome = self
            .operation
            .invoke(2, self.final_cost(), None)
            .await
            .map(|_| ());
        // 已发起的终态操作不因响应未知而再次尝试；其原子回执仍防止与迟到增量发生逆序。
        outcome
    }
}

impl Operation {
    /// 业务作用：提供当前回执的有限寿命，约束无响应进展的流。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：构建期校验的闲置期限。
    pub(crate) fn idle(&self) -> Duration {
        self.policy
            .settlement
            .as_ref()
            .expect("response receipt policy")
            .idle
    }

    /// 业务作用：在读取更多实体前检查累计事实成本硬上限，不用静默截断金额换取放行。
    ///
    /// 参数说明：
    /// - `cost`：拟交付后的累计成本。
    ///
    /// 返回：成本在精确整数及配置上限以内时为真。
    pub(crate) fn accepts(&self, cost: u64) -> bool {
        cost <= self
            .policy
            .settlement
            .as_ref()
            .expect("response receipt policy")
            .maximum
    }

    /// 业务作用：在单个原子操作中准入、补扣或关闭回执，传输只包含累计整数与已冻结身份。
    ///
    /// 参数说明：
    /// - `mode`：零为准入，一为增量，二为不可逆终态。
    /// - `cost`：本次准入预留或累计事实成本。
    /// - `slot`：延迟准入必须复验的队列名额。
    ///
    /// 返回：明确原子结果；缺失回执失败关闭，未知提交不重试。
    pub(crate) async fn invoke(
        &self,
        mode: u8,
        cost: u64,
        slot: Option<&queue::Slot>,
    ) -> Result<QuotaDecision, Failure> {
        let limits = self
            .policy
            .settlement
            .as_ref()
            .expect("response receipt policy");
        if mode > 2 || !self.accepts(cost) {
            return Err(Failure::Invalid);
        }
        let action = mode;
        let mode = match mode {
            0 => "0",
            1 => "1",
            _ => "2",
        };
        let cost = cost.to_string();
        let mut args = [""; 56];
        args[0] = &self.ledger.capacity;
        args[1] = mode;
        args[2] = &cost;
        args[3] = &limits.idle_arg;
        args[4] = &limits.maximum_arg;
        for (target, value) in args[5..].iter_mut().zip(self.policy.args.iter()) {
            *target = value;
        }
        let mut count = self.policy.args.len() + 5;
        let mut keys = [
            self.ledger.data.as_str(),
            self.ledger.index.as_str(),
            self.key.as_ref(),
            "",
        ];
        let key_count = if let Some(slot) = slot {
            args[count] = &slot.token;
            count += 1;
            keys[3] = &slot.ledger.data;
            4
        } else {
            3
        };
        if let Some(events) = &self.events {
            if action == 0 {
                events.admission_pending();
            } else if action == 2 {
                events.settled(false);
            }
        }
        let outcome = decode(
            self.ledger
                .invoke_keys(SCRIPT, &SHA, &keys[..key_count], &args[..count])
                .await?,
        );
        if let (Some(events), Ok(decision)) = (&self.events, &outcome) {
            if action == 0 {
                events.admitted(decision.allowed);
                if !decision.allowed {
                    events.cost(0, true);
                }
            } else if action == 2 {
                events.settled(true);
            }
        }
        outcome
    }
}

impl Drop for Receipt {
    /// 业务作用：取消响应时在原容量名额内提交一次终态；无运行时只依赖有限回执到期。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不会新建无界等待者，最多保留原名额至 500 毫秒 RPC 结束。
    fn drop(&mut self) {
        self.record_cost();
        if !self.active {
            return;
        }
        let Some(mut retained) = self.retained.take() else {
            return;
        };
        retained.resize(0);
        let operation = self.operation.clone();
        let actual = self.final_cost();
        let event_lease = self.event_lease.take();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _retained = retained;
                let _event_lease = event_lease;
                if operation.invoke(2, actual, None).await.is_err() {
                    metrics::STATE_CLOSED.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    }
}
