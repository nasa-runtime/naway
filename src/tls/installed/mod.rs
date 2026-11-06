//! 监听器安装事实与 generation 权威；控制面发布门不进入握手或请求路径。

#[cfg(feature = "node-actions")]
pub(crate) mod material;

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::config::TlsRuntimeCfg;
use crate::tls::material::{CertificateObservation, CertificateSnapshot};

const MAX_LISTENERS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateProtocol {
    Https,
    Http3,
    StreamTls,
}

type Key = (CertificateProtocol, Arc<str>);

struct Entry {
    token: Arc<()>,
    plan: Arc<TlsRuntimeCfg>,
    observation: CertificateObservation,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<Key, Entry>,
    overflow: usize,
}

/// 同一节点的实际监听器事实；读取与 transport 配置更新经过同一控制面门。
#[derive(Clone, Default)]
pub struct InstalledCertificates {
    state: Arc<Mutex<State>>,
}

/// 一次读取固定的安装事实；材料计划仅用于与当前配置复验，不能被序列化导出。
pub struct InstalledCertificate {
    pub listener: Arc<str>,
    pub protocol: CertificateProtocol,
    pub observation: Arc<CertificateSnapshot>,
    plan: Arc<TlsRuntimeCfg>,
}

pub struct InstalledSnapshot {
    pub capacity: bool,
    pub entries: Vec<InstalledCertificate>,
}

impl InstalledSnapshot {
    /// 业务作用：判断观察源是否换代，让多个管理上报目标共享一次目录构建结果。
    ///
    /// 参数说明：
    /// - `other`：前一次保留的有界安装快照。
    ///
    /// 返回：入口、计划和当前公开事实指针全部一致时为真；SPIRE 换材或失权也会改变事实指针。
    pub fn same_generation(&self, other: &Self) -> bool {
        self.capacity == other.capacity
            && self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .zip(&other.entries)
                .all(|(left, right)| {
                    left.listener == right.listener
                        && left.protocol == right.protocol
                        && Arc::ptr_eq(&left.plan, &right.plan)
                        && Arc::ptr_eq(&left.observation, &right.observation)
                })
    }
}

/// 唯一生命周期所有者；退出立即撤销所有 watcher 克隆持有的发布权。
pub struct CertificateOwner {
    publisher: CertificatePublisher,
    overflow: bool,
}

/// watcher 与 transport actor 持有的发布能力；该能力不能延长 listener 的管理所有权。
#[derive(Clone)]
pub struct CertificatePublisher {
    state: Arc<Mutex<State>>,
    key: Key,
    token: Arc<()>,
    active: Arc<std::sync::atomic::AtomicBool>,
    tracked: bool,
}

impl InstalledCertificates {
    /// 业务作用：在同一发布门内先安装 transport 配置，再登记对应公开证书事实。
    ///
    /// 参数说明：
    /// - `listener`：已绑定的逻辑入口标识。
    /// - `protocol`：区分同一入口的 TCP、QUIC 与 L4 身份。
    /// - `plan`：本代实际安装的材料计划，用于拒绝与新配置错配的观察值。
    /// - `observation`：与待安装材料同源的公开事实。
    /// - `install`：commit 阶段不可失败的实际 transport 安装动作，不得重入本注册表。
    ///
    /// 返回：安装结果及唯一 owner；观察容量不足仍安装合法配置，并以容量状态阻止完整性推断。
    pub fn activate<T>(
        &self,
        listener: Arc<str>,
        protocol: CertificateProtocol,
        plan: Arc<TlsRuntimeCfg>,
        observation: CertificateObservation,
        install: impl FnOnce() -> T,
    ) -> (T, CertificateOwner) {
        let key = (protocol, listener);
        let token = Arc::new(());
        let mut state = self.state.lock();
        // 只有实际安装动作完成后才能替换观察值；失败候选不应调用 activate。
        let result = install();
        let tracked = key.1.len() <= 256
            && !key.1.chars().any(char::is_control)
            && (state.entries.len() < MAX_LISTENERS || state.entries.contains_key(&key));
        if tracked {
            state.entries.insert(
                key.clone(),
                Entry {
                    token: token.clone(),
                    plan,
                    observation,
                },
            );
        } else {
            state.overflow += 1;
        }
        let publisher = CertificatePublisher {
            state: self.state.clone(),
            key,
            token,
            active: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            tracked,
        };
        (
            result,
            CertificateOwner {
                publisher,
                overflow: !tracked,
            },
        )
    }

    /// 业务作用：读取控制面门保护下的当前安装事实，防止跨指针读取“新事实、旧配置”。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界监听器集合；SPIRE 当前失权和目录容量不足明确保留，不推断证书不存在。
    pub fn snapshot(&self) -> InstalledSnapshot {
        let state = self.state.lock();
        InstalledSnapshot {
            capacity: state.overflow != 0,
            entries: state
                .entries
                .iter()
                .map(|((protocol, listener), entry)| InstalledCertificate {
                    listener: listener.clone(),
                    protocol: *protocol,
                    observation: entry.observation.snapshot(),
                    plan: entry.plan.clone(),
                })
                .collect(),
        }
    }
}

impl InstalledCertificate {
    /// 业务作用：确认实际安装材料仍属于当前声明计划，避免 reload 切换窗口混用配置与证书事实。
    ///
    /// 参数说明：
    /// - `plan`：当前已发布配置中的对应 TLS 计划。
    ///
    /// 返回：材料来源及授权策略完全一致时为 true；不一致时调用方必须报告未知而非使用旧事实。
    pub fn matches(&self, plan: &TlsRuntimeCfg) -> bool {
        self.plan.as_ref() == plan
    }
}

impl CertificateOwner {
    /// 业务作用：向本代 watcher 或 transport actor 发放可撤销的材料发布能力。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：共享发布能力；克隆不能阻止 owner 退出时撤销权威。
    pub fn publisher(&self) -> CertificatePublisher {
        self.publisher.clone()
    }
}

impl CertificatePublisher {
    /// 业务作用：复验 listener 所有权后安装新材料，再发布同源观察值。
    ///
    /// 参数说明：
    /// - `observation`：已验证候选配置的公开事实。
    /// - `install`：实际换入 TCP/QUIC 配置的不可失败短操作，不得重入注册表。
    ///
    /// 返回：仍持有本代权威时执行安装并返回 true；失权时既不改变 transport，也不发布事实。
    pub fn publish(&self, observation: CertificateObservation, install: impl FnOnce()) -> bool {
        let mut state = self.state.lock();
        // 替换、删除或停机必须同时撤销迟到回调，不能让旧 generation 重新开放入口。
        if !self.active.load(std::sync::atomic::Ordering::Acquire)
            || (self.tracked
                && !state
                    .entries
                    .get(&self.key)
                    .is_some_and(|entry| Arc::ptr_eq(&entry.token, &self.token)))
        {
            return false;
        }
        install();
        if let Some(entry) = state.entries.get_mut(&self.key).filter(|_| self.tracked) {
            entry.observation = observation;
        }
        true
    }
}

impl Drop for CertificateOwner {
    /// 业务作用：撤销本代全部发布能力并移除安装事实，旧 owner 退出不得移除替换后的新代。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；已建立连接继续持有原 TLS 状态，不因此被中断。
    fn drop(&mut self) {
        let mut state = self.publisher.state.lock();
        self.publisher
            .active
            .store(false, std::sync::atomic::Ordering::Release);
        if self.overflow {
            state.overflow -= 1;
        } else if state
            .entries
            .get(&self.publisher.key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.token, &self.publisher.token))
        {
            state.entries.remove(&self.publisher.key);
        }
    }
}
