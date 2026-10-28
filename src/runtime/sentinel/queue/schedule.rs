//! 单维度的有限FIFO调度状态，实际放行时复验间隔，不追赶释放积压。

use super::policy::{Claim, Policy, Rejected, Reservation};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
struct Ticket {
    due_us: u64,
    deadline_us: u64,
}

#[derive(Debug, Default)]
pub(crate) struct Schedule {
    clock_us: u64,
    next_due_us: u64,
    last_grant_us: Option<u64>,
    sequence: u64,
    tickets: BTreeMap<u64, Ticket>,
    expiries: BTreeSet<(u64, u64)>,
}

impl Schedule {
    /// 业务作用：原子决定立即准入或预留有限未来时刻，拒绝分支不推进调度债务。
    ///
    /// 参数说明：
    /// - `policy`：该维度冻结的时序合同。
    /// - `now_us`：权威单调时钟微秒值。
    /// - `deadline_us`：从请求最初等待预算派生的绝对期限。
    /// - `can_wait`：调用方已证明实体上界且已取得物理保留预算。
    ///
    /// 返回：实际准入、唯一等待令牌或拒绝；立即准入不消耗队列槽。
    pub(crate) fn reserve(
        &mut self,
        policy: Policy,
        now_us: u64,
        deadline_us: u64,
        can_wait: bool,
    ) -> Reservation {
        if !self.advance(now_us) {
            return Reservation::Rejected(Rejected::Clock);
        }
        let Some(maximum_deadline) = now_us.checked_add(policy.max_wait.as_micros() as u64) else {
            return Reservation::Rejected(Rejected::Clock);
        };
        let deadline_us = deadline_us.min(maximum_deadline);
        if now_us >= deadline_us {
            return Reservation::Rejected(Rejected::Deadline);
        }
        let due_us = self.next_due_us.max(now_us);
        let Some(next_due) = due_us.checked_add(policy.interval_us) else {
            return Reservation::Rejected(Rejected::Clock);
        };
        if self.tickets.is_empty() && due_us == now_us {
            self.last_grant_us = Some(now_us);
            self.next_due_us = next_due;
            return Reservation::Admitted;
        }
        if !can_wait {
            return Reservation::Rejected(Rejected::UnknownBody);
        }
        if self.tickets.len() >= policy.capacity {
            return Reservation::Rejected(Rejected::Capacity);
        }
        if due_us >= deadline_us {
            return Reservation::Rejected(Rejected::Deadline);
        }
        let Some(sequence) = self.sequence.checked_add(1) else {
            return Reservation::Rejected(Rejected::Capacity);
        };
        self.sequence = sequence;
        self.next_due_us = next_due;
        self.tickets.insert(
            sequence,
            Ticket {
                due_us,
                deadline_us,
            },
        );
        self.expiries.insert((deadline_us, sequence));
        Reservation::Waiting {
            ticket: sequence,
            due_us,
        }
    }

    /// 业务作用：只向仍持有队首令牌且实际间隔已满足的请求授予放行权。
    ///
    /// 参数说明：
    /// - `policy`：预留时的同一策略。
    /// - `ticket`：本请求唯一动作令牌。
    /// - `now_us`：实际尝试放行时的权威时钟。
    ///
    /// 返回：实际准入、有限重试间隔或过期拒绝；晚唤醒不会一次放开全部积压。
    pub(crate) fn claim(&mut self, policy: Policy, ticket: u64, now_us: u64) -> Claim {
        if !self.advance(now_us) {
            return Claim::Rejected(Rejected::Clock);
        }
        let Some(entry) = self.tickets.get(&ticket) else {
            // 期限已失效或令牌已经被消费，不能凭旧预留重新取得放行权。
            return Claim::Rejected(Rejected::Deadline);
        };
        let Some((&first, head)) = self.tickets.first_key_value() else {
            return Claim::Rejected(Rejected::Deadline);
        };
        if first != ticket {
            return Claim::Wait(head.deadline_us.saturating_sub(now_us).clamp(1, 50_000));
        }
        let Some(previous_due) = self
            .last_grant_us
            .unwrap_or(0)
            .checked_add(policy.interval_us)
        else {
            return Claim::Rejected(Rejected::Clock);
        };
        let due = entry.due_us.max(previous_due);
        if due >= entry.deadline_us {
            self.cancel(ticket);
            return Claim::Rejected(Rejected::Deadline);
        }
        if now_us < due {
            return Claim::Wait(due - now_us);
        }
        let Some(next_due) = now_us.checked_add(policy.interval_us) else {
            return Claim::Rejected(Rejected::Clock);
        };
        // 实际grant先推进最早放行时刻，再解除本令牌；积压请求继续受新的间隔约束。
        self.last_grant_us = Some(now_us);
        self.next_due_us = self.next_due_us.max(next_due);
        self.cancel(ticket);
        Claim::Admitted
    }

    /// 业务作用：释放本请求的精确队列名额，保留已经承诺给其它请求的时间安排。
    ///
    /// 参数说明：
    /// - `ticket`：应由当前请求独占的动作令牌。
    ///
    /// 返回：存在的令牌删除成功；重复释放无副作用，不回滚调度债务。
    pub(crate) fn cancel(&mut self, ticket: u64) -> bool {
        if let Some(entry) = self.tickets.remove(&ticket) {
            self.expiries.remove(&(entry.deadline_us, ticket));
            true
        } else {
            false
        }
    }

    /// 业务作用：在回收维度状态前确认既无等待者也无尚未流出的调度债务。
    ///
    /// 参数说明：
    /// - `now_us`：回收时刻的权威时钟。
    ///
    /// 返回：状态可安全丢弃时为true，时钟回退不授予回收权。
    pub(crate) fn expired(&mut self, now_us: u64) -> bool {
        self.advance(now_us) && self.tickets.is_empty() && self.next_due_us <= now_us
    }

    /// 业务作用：按到期索引撤销失效令牌，避免已取消或过期请求阻塞有限队列。
    ///
    /// 参数说明：
    /// - `now_us`：当前权威时钟。
    ///
    /// 返回：正常前进返回true；时钟回退拒绝状态变动，不伪造新的信用。
    fn advance(&mut self, now_us: u64) -> bool {
        if now_us < self.clock_us {
            return false;
        }
        self.clock_us = now_us;
        while let Some(&(deadline, ticket)) = self.expiries.first() {
            if deadline > now_us {
                break;
            }
            self.expiries.remove(&(deadline, ticket));
            self.tickets.remove(&ticket);
        }
        true
    }
}
