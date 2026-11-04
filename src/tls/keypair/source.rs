//! 物理来源与完整共享影响在同一材料锁内解析，不向管理调用者暴露路径。

use super::generation;
use crate::config::{GatewaySnapshot, TlsRuntimeCfg};
use crate::tls::targets::{self, Kind};
use anyhow::{ensure, Result};
use std::path::PathBuf;

pub(super) struct Position {
    certificate: PathBuf,
    private_key: Option<PathBuf>,
    manifest: Option<PathBuf>,
    manifest_active: bool,
}

impl Position {
    /// 业务作用：定位实际文件槽位与指针，使共享来源判定不会被目录别名或默认 seed 混淆。
    ///
    /// 参数说明：
    /// - `source`：默认或 SNI 的独立来源计划。
    ///
    /// 返回：规范化槽位；不能解析当前来源时拒绝证明无冲突，不读取私钥内容。
    pub(super) fn read(source: &TlsRuntimeCfg) -> Result<Self> {
        let active = source
            .keypair_manifest_file
            .as_deref()
            .map(super::current_material_directory)
            .transpose()?
            .flatten();
        let (certificate, private_key) = match &active {
            Some(directory) => (directory.join("cert.pem"), directory.join("key.pem")),
            None => (source.cert_file.clone(), source.key_file.clone()),
        };
        Ok(Self {
            certificate: generation::identity_path(&certificate)?,
            private_key: if source.private_key_provider.is_none() {
                Some(generation::identity_path(&private_key)?)
            } else {
                None
            },
            manifest: source
                .keypair_manifest_file
                .as_deref()
                .map(generation::identity_path)
                .transpose()?,
            manifest_active: active.is_some(),
        })
    }

    /// 业务作用：区分完整共同来源与危险的部分文件共享，单个身份不能覆盖另一来源的材料。
    ///
    /// 参数说明：
    /// - `other`：同一快照中另一身份的实际槽位。
    ///
    /// 返回：同一受管来源为真、完全独立为假；部分共享、跨模式复用或外部 signer 重叠均失败。
    pub(super) fn shares(&self, other: &Self) -> Result<bool> {
        let same = match (&self.manifest, &other.manifest) {
            (Some(left), Some(right)) => left == right,
            (None, _) if !other.manifest_active => {
                self.certificate == other.certificate
                    && self.private_key.is_some()
                    && self.private_key == other.private_key
            }
            _ => false,
        };
        if same {
            ensure!(
                other.private_key.is_some(),
                "shared TLS source has an external signer"
            );
            return Ok(true);
        }
        // 首次激活 manifest 只写新目录和指针，原 seed 文件继续供其它监听使用，不把只读 seed 视为写入。
        if let Some(manifest) = &self.manifest {
            if !self.manifest_active {
                ensure!(
                    !other
                        .slots()
                        .into_iter()
                        .flatten()
                        .any(|slot| slot == manifest),
                    "TLS manifest overlaps another source slot"
                );
                return Ok(false);
            }
        }
        // 任一文件角色重叠都不能被当成无关监听；manifest 目录也不得手工借给另一来源。
        ensure!(
            !self.slots().into_iter().flatten().any(|left| {
                other
                    .slots()
                    .into_iter()
                    .flatten()
                    .any(|right| left == right)
            }),
            "TLS sources share only part of their material authority"
        );
        Ok(false)
    }

    /// 业务作用：在文件角色之间检查重叠，证书、私钥和指针不能借角色不同绕过共享保护。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用固定三个槽位，不分配或复制路径。
    fn slots(&self) -> [Option<&PathBuf>; 3] {
        [
            Some(&self.certificate),
            self.private_key.as_ref(),
            self.manifest.as_ref(),
        ]
    }
}

/// 共享来源的全部逻辑身份；实际来源证明留在控制面，不由路径文本推测共同所有权。
pub(super) struct Impact<'a> {
    pub(super) position: Position,
    pub(super) listeners: Vec<Listener<'a>>,
}

pub(super) struct Listener<'a> {
    pub(super) plan: &'a TlsRuntimeCfg,
    pub(super) kind: Kind,
    pub(super) id: &'a str,
    pub(super) entries: Vec<Option<usize>>,
}

impl<'a> Impact<'a> {
    /// 业务作用：取得材料动作影响的全部逻辑身份，任何不确定来源均不能被遗漏后当作独立写入。
    ///
    /// 参数说明：
    /// - `snapshot`：调用方已冻结的完整监听计划。
    /// - `selected`：当前目标声明解析出的本地材料来源。
    ///
    /// 返回：有界且完整的共享监听集合；来源冲突、超量或目标已不存在时拒绝。
    pub(super) fn read(snapshot: &'a GatewaySnapshot, selected: &TlsRuntimeCfg) -> Result<Self> {
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
        let identities = plans().try_fold(0usize, |count, (_, _, plan)| {
            count.checked_add(plan.certs.len().saturating_add(1))
        });
        ensure!(
            identities.is_some_and(|count| count <= 4096),
            "TLS material impact exceeds identity budget"
        );
        let position = Position::read(selected)?;
        ensure!(
            position.private_key.is_some()
                && position.private_key.as_ref() != Some(&position.certificate),
            "TLS material requires distinct local pair slots"
        );
        let mut listeners = Vec::new();
        for (kind, id, plan) in plans() {
            if plan.in_memory.is_some() || plan.spire.is_some() {
                continue;
            }
            let mut entries = Vec::new();
            if position.shares(&Position::read(plan)?)? {
                entries.push(None);
            }
            for (index, sni) in plan.certs.iter().enumerate() {
                if position.shares(&Position::read(&targets::sni_source(plan, sni))?)? {
                    entries.push(Some(index));
                }
            }
            if !entries.is_empty() {
                listeners.push(Listener {
                    plan,
                    kind,
                    id,
                    entries,
                });
            }
        }
        ensure!(
            !listeners.is_empty(),
            "TLS material target is no longer declared"
        );
        Ok(Self {
            position,
            listeners,
        })
    }
}
