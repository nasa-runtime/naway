//! 熔断事实跨同源热更新保留，熔断原因不能把本地拒绝转换成依赖 fail-open。
use super::Failure;
use crate::config::scripts::CircuitCfg;
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock, Weak},
    time::{Duration, Instant},
};
#[derive(Default)]
struct State {
    failures: u32,
    epoch: u64,
    open: Option<(Instant, Failure)>,
}
pub(super) struct Circuit {
    state: parking_lot::Mutex<State>,
    _lease: Option<crate::control::ownership::state::Lease>,
}
impl Circuit {
    /// 业务作用：为同一路由、脚本身份与源码复用熔断状态，修改预算不能清空失败事实。
    ///
    /// 参数说明：
    /// - `key`：不可逆业务域和源码摘要。
    /// - `budget`：来自冻结路由归属的常驻状态额度；平台域可为空。
    ///
    /// 返回：最多 1024 个存活脚本域中的共享状态；满额拒绝执行且不借用其它域额度。
    pub fn shared(
        key: String,
        budget: Option<&crate::control::ownership::state::Budget>,
    ) -> Result<Arc<Self>, Failure> {
        static ENTRIES: OnceLock<parking_lot::Mutex<BTreeMap<String, Weak<Circuit>>>> =
            OnceLock::new();
        let mut entries = ENTRIES.get_or_init(Default::default).lock();
        entries.retain(|_, value| value.strong_count() > 0);
        if let Some(value) = entries.get(&key).and_then(Weak::upgrade) {
            return Ok(value);
        }
        if entries.len() >= 1024 {
            return Err(Failure::Capacity);
        }
        // 状态表的名额属于配置工作区，换语言或换源码不能绕过与 Wasm 共用的常驻状态门。
        let lease = budget
            .map(|budget| budget.acquire())
            .transpose()
            .map_err(|_| Failure::Capacity)?;
        let value = Arc::new(Self {
            state: Default::default(),
            _lease: lease,
        });
        entries.insert(key, Arc::downgrade(&value));
        Ok(value)
    }
    /// 业务作用：执行前检查保护态并返回事实代次，迟到结果不能关闭后来打开的熔断。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：开放执行的代次；保护期内返回导致保护的原始原因。
    pub fn enter(&self) -> Result<u64, Failure> {
        let mut state = self.state.lock();
        if let Some((until, reason)) = state.open {
            if Instant::now() < until {
                return Err(reason);
            }
            // 到期只允许重新积累证据；旧调用持有的代次已经失效，不能覆盖此状态。
            state.open = None;
            state.failures = 0;
            state.epoch = state.epoch.wrapping_add(1);
        }
        Ok(state.epoch)
    }
    /// 业务作用：按照明确失败阈值进入保护态，并隔离在途旧证据。
    ///
    /// 参数说明：
    /// - `epoch`：准入时冻结的代次。
    /// - `failure`：执行完成原因，None 为成功。
    /// - `cfg`：本快照的阈值与保护期限。
    ///
    /// 返回：更新当前代次的失败事实；迟到结果无副作用。
    pub fn complete(&self, epoch: u64, failure: Option<Failure>, cfg: &CircuitCfg) {
        let mut state = self.state.lock();
        if state.epoch != epoch {
            return;
        }
        if let Some(reason) = failure {
            state.failures = state.failures.saturating_add(1);
            if state.failures >= cfg.failure_threshold {
                // 先关闭准入再废弃旧代次；保护原因必须保留，使本地资源拒绝持续失败关闭。
                state.open = Some((Instant::now() + Duration::from_millis(cfg.open_ms), reason));
                state.epoch = state.epoch.wrapping_add(1);
            }
        } else {
            state.failures = 0;
        }
    }
}
