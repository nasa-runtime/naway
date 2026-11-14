//! 配置代际冻结监听器身份、协议与归属，超出观测预算只撤下该域。

use super::{Counters, Handle, Observation, Totals};
use crate::config::{StreamProtocolRuntime, StreamRuntime};
use crate::control::ownership::OwnershipCatalog;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(crate) const MAX_LISTENERS: usize = 512;

pub(crate) struct Catalog {
    capacity: bool,
    entries: Vec<Entry>,
}

struct Entry {
    listener: String,
    protocol: &'static str,
    workspace: String,
    counters: Arc<Counters>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub capacity: bool,
    pub rows: Vec<Reading>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reading {
    pub listener: String,
    pub protocol: String,
    pub workspace: String,
    pub totals: Totals,
}

impl Catalog {
    /// 业务作用：在配置编译时为完整有界监听器目录冻结独立原子所有者，不参与拓扑比较。
    ///
    /// 参数说明：
    /// - `listeners`：已经通过语义校验的 TCP/UDP 监听器。
    /// - `ownership`：与监听器同代的对象归属权威。
    ///
    /// 返回：完整观测目录；数量、身份或归属字段越界时仅返回 capacity，不截取部分目录。
    pub(crate) fn build(listeners: &[StreamRuntime], ownership: &OwnershipCatalog) -> Self {
        if listeners.len() > MAX_LISTENERS {
            return Self {
                capacity: true,
                entries: Vec::new(),
            };
        }
        let identities: Vec<_> = listeners
            .iter()
            .map(|listener| {
                let workspace = ownership
                    .object_owner(&format!("stream_listener:{}", listener.id))
                    .map_or("platform", |owner| owner.workspace.as_str());
                (listener, workspace)
            })
            .collect();
        if identities.len() > MAX_LISTENERS
            || identities
                .iter()
                .any(|(listener, workspace)| !valid_id(&listener.id) || !valid_id(workspace))
        {
            return Self {
                capacity: true,
                entries: Vec::new(),
            };
        }
        let mut entries: Vec<_> = identities
            .into_iter()
            .map(|(listener, workspace)| Entry {
                listener: listener.id.clone(),
                protocol: match listener.protocol {
                    StreamProtocolRuntime::Tcp => "tcp",
                    StreamProtocolRuntime::Udp => "udp",
                },
                workspace: workspace.into(),
                counters: Arc::default(),
            })
            .collect();
        entries.sort_unstable_by(|first, second| first.listener.cmp(&second.listener));
        if entries
            .windows(2)
            .any(|pair| pair[0].listener == pair[1].listener)
        {
            return Self {
                capacity: true,
                entries: Vec::new(),
            };
        }
        Self {
            capacity: false,
            entries,
        }
    }

    /// 业务作用：为同代真实监听器返回固定所有者，不从旧 socket 或客户端内容推导归属。
    ///
    /// 参数说明：
    /// - `listener`：当前快照已经选择的监听器身份。
    ///
    /// 返回：完整目录中的原子引用；缺席或 capacity 时为空，不影响数据转发。
    pub(crate) fn handle(&self, listener: &str) -> Option<Handle> {
        let index = self
            .entries
            .binary_search_by(|entry| entry.listener.as_str().cmp(listener))
            .ok()?;
        Some(Handle {
            counters: self.entries[index].counters.clone(),
        })
    }

    /// 业务作用：为当前监听器建立唯一接入生命周期，旧会话释放不写入新配置所有者。
    ///
    /// 参数说明：
    /// - `listener`：同一已选配置中的监听器身份。
    ///
    /// 返回：已登记一次尝试的观察器；观测域不可用时为空。
    pub(crate) fn start(&self, listener: &str) -> Option<Observation> {
        self.handle(listener).map(|handle| handle.start())
    }

    /// 业务作用：只枚举当前配置的完整目录，零流量监听器仍有真实零累计。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同代身份与弱一致累计的有界快照，不读取或保留已经退出的会话目录。
    pub(crate) fn capture(&self) -> Snapshot {
        Snapshot {
            capacity: self.capacity,
            rows: self
                .entries
                .iter()
                .map(|entry| Reading {
                    listener: entry.listener.clone(),
                    protocol: entry.protocol.into(),
                    workspace: entry.workspace.clone(),
                    totals: entry.counters.read(),
                })
                .collect(),
        }
    }
}

impl Snapshot {
    /// 业务作用：在本机采样或远端接收时拒绝重复、非法协议和 capacity 夹带事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：数量、身份、协议和严格排序全部符合完整目录合同时为真。
    pub(crate) fn valid(&self) -> bool {
        self.rows.len() <= MAX_LISTENERS
            && (!self.capacity || self.rows.is_empty())
            && self.rows.iter().all(|row| {
                valid_id(&row.listener)
                    && valid_id(&row.workspace)
                    && matches!(row.protocol.as_str(), "tcp" | "udp")
            })
            && self
                .rows
                .windows(2)
                .all(|pair| pair[0].listener < pair[1].listener)
    }

    /// 业务作用：将目录容器和全部拥有的身份字符串计入既有采样资源预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前快照保守保留成本，不凭序列化后的较小长度提高预算。
    pub(crate) fn retained_bytes(&self) -> usize {
        self.rows.capacity() * std::mem::size_of::<Reading>()
            + self
                .rows
                .iter()
                .map(|row| {
                    row.listener.capacity() + row.protocol.capacity() + row.workspace.capacity()
                })
                .sum::<usize>()
    }
}

/// 业务作用：限制观测身份输出尺寸与控制字符，越界身份不会被截断后发布。
///
/// 参数说明：
/// - `value`：配置中的监听器或工作区身份。
///
/// 返回：非空、最长128字节且没有控制字符时为真。
fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
