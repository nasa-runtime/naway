//! 同次材料动作复用物理来源索引，多个逻辑目标不能重复扫描整份文件系统计划。

use super::{Impact, Listener, Position};
use crate::{
    config::{GatewaySnapshot, TlsRuntimeCfg},
    tls::targets::{self, Kind},
};
use anyhow::{ensure, Result};

pub(in crate::tls::keypair) struct Index<'a> {
    identities: Vec<Identity<'a>>,
}

struct Identity<'a> {
    kind: Kind,
    id: &'a str,
    entry: Option<usize>,
    plan: &'a TlsRuntimeCfg,
    position: Position,
}

impl<'a> Index<'a> {
    /// 业务作用：按原逻辑身份借用本批已解析的位置，同源目标不重复解析目录别名。
    ///
    /// 参数说明：
    /// - `target`：在同一配置中已经解析的默认或 SNI 目标。
    ///
    /// 返回：该身份的物理位置；未纳入文件来源索引时返回空。
    pub(in crate::tls::keypair) fn position(&self, target: &targets::Target) -> Option<&Position> {
        self.identities
            .iter()
            .find(|identity| {
                identity.kind == target.kind
                    && identity.id == target.listener
                    && match identity.entry {
                        None => target.entry == "default",
                        Some(index) => {
                            target
                                .entry
                                .strip_prefix("sni-")
                                .and_then(|value| value.parse::<usize>().ok())
                                == Some(index)
                        }
                    }
            })
            .map(|identity| &identity.position)
    }

    /// 业务作用：在同一材料锁内一次定位所有声明身份，后续目标比较只借用已解析的槽位。
    ///
    /// 参数说明：
    /// - `snapshot`：调用方持有配置发布权的完整已发布计划。
    ///
    /// 返回：最多4096个身份的有界索引；任何位置无法证明时拒绝，不读取私钥正文。
    pub(in crate::tls::keypair) fn read(snapshot: &'a GatewaySnapshot) -> Result<Self> {
        let plans = || {
            snapshot
                .proxies
                .iter()
                .filter_map(|proxy| {
                    proxy
                        .tls
                        .as_ref()
                        .map(|tls| (Kind::Proxy, proxy.id.as_str(), tls))
                })
                .chain(snapshot.stream_listeners.iter().filter_map(|listener| {
                    listener
                        .tls
                        .as_ref()
                        .map(|tls| (Kind::Stream, listener.id.as_str(), tls))
                }))
        };
        let count = plans().try_fold(0usize, |count, (_, _, plan)| {
            count.checked_add(plan.certs.len().saturating_add(1))
        });
        ensure!(
            count.is_some_and(|count| count <= 4096),
            "TLS material impact exceeds identity budget"
        );
        let mut identities = Vec::with_capacity(count.unwrap_or_default());
        for (kind, id, plan) in plans() {
            if plan.in_memory.is_some() || plan.spire.is_some() {
                continue;
            }
            identities.push(Identity {
                kind,
                id,
                entry: None,
                plan,
                position: Position::read(plan)?,
            });
            for (index, sni) in plan.certs.iter().enumerate() {
                identities.push(Identity {
                    kind,
                    id,
                    entry: Some(index),
                    plan,
                    position: Position::read(&targets::sni_source(plan, sni))?,
                });
            }
        }
        Ok(Self {
            identities,
        })
    }

    /// 业务作用：从同一物理索引确认完整写入影响，部分共享或外部提供者重叠不能被过滤成独立来源。
    ///
    /// 参数说明：
    /// - `selected`：同一材料锁内解析且已经按逻辑目标授权的来源槽位。
    ///
    /// 返回：借用监听计划的完整影响；来源冲突或没有对应声明时拒绝，比较过程中不再访问文件系统。
    pub(in crate::tls::keypair) fn impact(&self, selected: &Position) -> Result<Impact<'a>> {
        ensure!(
            selected.private_key.is_some()
                && selected.private_key.as_ref() != Some(&selected.certificate),
            "TLS material requires distinct local pair slots"
        );
        let mut listeners: Vec<Listener<'a>> = Vec::new();
        for identity in &self.identities {
            if !selected.shares(&identity.position)? {
                continue;
            }
            if let Some(listener) = listeners
                .last_mut()
                .filter(|listener| listener.kind == identity.kind && listener.id == identity.id)
            {
                listener.entries.push(identity.entry);
            } else {
                listeners.push(Listener {
                    plan: identity.plan,
                    kind: identity.kind,
                    id: identity.id,
                    entries: vec![identity.entry],
                });
            }
        }
        ensure!(
            !listeners.is_empty(),
            "TLS material target is no longer declared"
        );
        Ok(Impact {
            listeners,
        })
    }
}
