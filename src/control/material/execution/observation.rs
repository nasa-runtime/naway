//! 稳定材料结果保留全部原协议的实际安装证据，不能用磁盘新代代替监听确认。

use crate::{
    config::GatewaySnapshot,
    control::material::{installation, node::Intent},
    tls::{
        installed::CertificateProtocol,
        targets::{Kind, Target},
    },
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

/// 准备时冻结的单个逻辑目标协议分母，缺席的HTTP3或stream不能由在线协议代替。
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Protocols {
    Https,
    HttpsAndHttp3,
    StreamTls,
}

/// 同一真实启动观察到的完整来源与协议事实，文件目标代不能单独构成此证据。
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Evidence {
    boot_id: String,
    observed: installation::Batch,
}

impl Protocols {
    /// 业务作用：按原准备配置确定必须同时确认的协议数，不按当前在线监听缩减成功分母。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：HTTPS与HTTP3组合为两个，其它声明为一个。
    pub(crate) fn count(self) -> usize {
        match self {
            Self::HttpsAndHttp3 => 2,
            Self::Https | Self::StreamTls => 1,
        }
    }

    /// 业务作用：从原本机配置冻结每个共享目标必须确认的协议集合，运行时缺席不能缩减收据分母。
    ///
    /// 参数说明：
    /// - `snapshot`：准备时持有发布权的完整原配置。
    /// - `target`：完整来源影响中的一个原逻辑目标。
    ///
    /// 返回：实际声明的协议组合；监听或TLS声明缺失时为空，不从观察到的在线协议反推。
    pub(crate) fn capture(snapshot: &GatewaySnapshot, target: &Target) -> Option<Self> {
        match target.kind {
            Kind::Proxy => {
                let proxy = snapshot
                    .proxies
                    .iter()
                    .find(|proxy| proxy.id == target.listener)?;
                proxy.tls.as_ref()?;
                Some(if proxy.http3.enabled {
                    Self::HttpsAndHttp3
                } else {
                    Self::Https
                })
            }
            Kind::Stream => {
                snapshot
                    .stream_listeners
                    .iter()
                    .find(|stream| stream.id == target.listener)?
                    .tls
                    .as_ref()?;
                Some(Self::StreamTls)
            }
        }
    }

    /// 业务作用：验证持久协议集合仍属于该类原逻辑目标，L4证据不能替代HTTPS或HTTP3。
    ///
    /// 参数说明：
    /// - `kind`：原完整影响记录中的目标类型。
    ///
    /// 返回：协议组合与目标类型对应才为真；HTTP3是否必须存在仍由原准备配置决定。
    pub(crate) fn allows(self, kind: Kind) -> bool {
        matches!(
            (self, kind),
            (Self::Https | Self::HttpsAndHttp3, Kind::Proxy) | (Self::StreamTls, Kind::Stream)
        )
    }

    /// 业务作用：要求实际观察逐项覆盖原协议集合，遗漏HTTP3或附加不相干协议均不能完成收据。
    ///
    /// 参数说明：
    /// - `observed`：同一原共享目标的实际安装观察。
    ///
    /// 返回：协议数量与顺序精确匹配为真，安装状态与材料代仍由完整证据门复验。
    fn matches(self, observed: &installation::Target) -> bool {
        let expected: &[CertificateProtocol] = match self {
            Self::Https => &[CertificateProtocol::Https],
            Self::HttpsAndHttp3 => &[CertificateProtocol::Https, CertificateProtocol::Http3],
            Self::StreamTls => &[CertificateProtocol::StreamTls],
        };
        observed.protocols.len() == expected.len()
            && observed
                .protocols
                .iter()
                .zip(expected)
                .all(|(actual, expected)| actual.protocol == *expected)
    }
}

impl Evidence {
    /// 业务作用：向交付层借用原boot实际确认的完整监听观察，查询不得改用当前注册表覆盖它。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与原协议分母和预分配代一起验证过的观察批次，不包含文件路径或秘密。
    pub(crate) fn observed(&self) -> &installation::Batch {
        &self.observed
    }

    /// 业务作用：在材料受理之前确认完整协议分母可生成合法成功证据，避免文件完成后才发现观察无法表达。
    ///
    /// 参数说明：
    /// - `protocols`：原本机配置冻结的全部来源、共享目标与协议集合。
    ///
    /// 返回：按实际观察同一规则计算的目标数、内存和线预算全部满足时成功，不构造虚假监听事实。
    pub(crate) fn require_capacity(protocols: &[Vec<Protocols>]) -> Result<()> {
        let mut budget = installation::Budget::new(protocols.len());
        for group in protocols {
            budget.group(group.len());
            for required in group {
                budget.target(required.count());
                for _ in 0..required.count() {
                    budget.observation(64, 64);
                }
            }
        }
        // 完整材料代必须能覆盖所有原协议；仅缺席状态较小或部分协议可观察不能获得执行资格。
        ensure!(
            budget.fits(),
            "material installation evidence capacity exceeded"
        );
        Ok(())
    }

    /// 业务作用：把本进程实际监听观察移入稳定证据，整批未达到预分配材料代时不产生成功对象。
    ///
    /// 参数说明：
    /// - `boot_id`：真正完成此次观察的进程启动身份。
    /// - `intent`：原完整节点意图，不按当前目录缩减目标。
    /// - `generations`：文件决定之前已持久分配的每来源目标代，按原来源顺序借用。
    /// - `protocols`：原准备配置冻结的每来源完整影响协议集合。
    /// - `observed`：来自实际安装注册表的完整原生结果，直接转移所有权。
    ///
    /// 返回：所有来源/目标/协议都安装精确新代时得到证据；未知或缺项拒绝，不写收据。
    pub(crate) fn new(
        boot_id: String,
        intent: &Intent,
        generations: &[&str],
        protocols: &[Vec<Protocols>],
        observed: installation::Batch,
    ) -> Result<Self> {
        let evidence = Self {
            boot_id,
            observed,
        };
        evidence.validate(intent, generations, protocols)?;
        Ok(evidence)
    }

    /// 业务作用：复验持久监听证据的完整分母和目标代，原pair相同或仅一个协议成功都不足以结算。
    ///
    /// 参数说明：
    /// - `intent`：同一持久动作的原节点意图。
    /// - `generations`：该执行或补偿方向的原预分配材料代。
    /// - `protocols`：与本机原来源计划绑定的完整协议集合。
    ///
    /// 返回：实际观察与全部原影响及目标代精确对应时成功；不证明今后的监听永远不变。
    pub(crate) fn validate(
        &self,
        intent: &Intent,
        generations: &[&str],
        protocols: &[Vec<Protocols>],
    ) -> Result<()> {
        ensure!(
            crate::config::operations::token(&self.boot_id, 128)
                && self.observed.valid(&intent.conditions)
                && generations.len() == intent.conditions.groups.len()
                && protocols.len() == intent.conditions.groups.len(),
            "material installation evidence bounds differ"
        );
        for (((observed, source), generation), required) in self
            .observed
            .groups
            .iter()
            .zip(&intent.conditions.groups)
            .zip(generations)
            .zip(protocols)
        {
            // 补偿恢复相同旧字节也必须是全新代；原材料代不能被借回作为另一动作的成功证据。
            ensure!(
                crate::tls::keypair::valid_material_generation(generation)
                    && source.material_generation.as_deref() != Some(*generation)
                    && required.len() == source.affected.len(),
                "material installation direction or protocol count differs"
            );
            for ((observed, affected), required) in
                observed.targets.iter().zip(&source.affected).zip(required)
            {
                ensure!(
                    required.allows(affected.target.kind) && required.matches(observed),
                    "material installation protocol coverage differs"
                );
                ensure!(
                    observed.protocols.iter().all(|protocol| protocol.state
                        == installation::State::DifferentMaterial
                        && protocol.material_generation.as_deref() == Some(*generation)),
                    "material installation is not complete for the original direction"
                );
            }
        }
        Ok(())
    }

    /// 业务作用：向收据交付层提供真实确认进程身份，重启后不能把旧观察伪装成本次加载。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已经完整验证的原观察boot，不从当前在线目录替换。
    pub(crate) fn boot_id(&self) -> &str {
        &self.boot_id
    }
}
