//! 同代管理身份与固定出站端点；构建计划不会创建网络连接。

use super::{issuer, security};
use crate::config::management::Config;
use anyhow::{ensure, Context, Result};
use nagrpc::GrpcTlsAcceptor;
use nasa::grpc::{Certificate, ClientTlsConfig, Endpoint, GrpcTlsIdentity, Identity};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct Plan {
    pub(crate) actions_enabled: bool,
    pub(super) report_metrics: bool,
    pub(super) authority: [u8; 32],
    pub(in crate::admin) node_id: String,
    pub(in crate::admin) receiver: Option<Receiver>,
    pub(super) targets: Vec<Target>,
}

pub(in crate::admin) struct Receiver {
    pub metrics: bool,
    pub listen: SocketAddr,
    pub acceptor: GrpcTlsAcceptor,
    pub nodes: BTreeMap<String, String>,
    pub expires_at: u64,
    pub(super) issuer: Option<issuer::Signer>,
}

pub(super) struct Target {
    pub endpoint: Endpoint,
    pub expires_at: u64,
    pub issuer: Option<Arc<issuer::Verifier>>,
}

impl Plan {
    /// 业务作用：在配置构建期确认执行集群有明确的本机发行身份，不把网络接收能力等同签名权。
    ///
    /// 参数说明：
    /// - cluster：持久执行声明的唯一集群。
    ///
    /// 返回：当前计划显式配置同集群配对签名密钥才为真，不授予实际租约或业务权限。
    #[cfg(feature = "node-actions")]
    pub(crate) fn can_issue(&self, cluster: &str) -> bool {
        self.receiver
            .as_ref()
            .and_then(|receiver| receiver.issuer.as_ref())
            .is_some_and(|issuer| issuer.cluster() == cluster)
    }

    /// 业务作用：将节点本地持久目录限制到同一节点和全部显式可信的发行目标。
    ///
    /// 参数说明：
    /// - `node`：目录永久绑定的管理节点。
    /// - `cluster`：目录永久绑定的发行集群。
    ///
    /// 返回：目标均要求发行者证明且集群匹配时为true；缺少验证计划、跨域或节点变化时为false。
    #[cfg(feature = "node-journal")]
    pub(crate) fn matches_journal(&self, node: &str, cluster: &str) -> bool {
        self.node_id == node
            && !self.targets.is_empty()
            && self.targets.iter().all(|target| {
                target
                    .issuer
                    .as_ref()
                    .is_some_and(|issuer| issuer.cluster() == cluster)
            })
            && self
                .receiver
                .as_ref()
                .and_then(|receiver| receiver.issuer.as_ref())
                .is_none_or(|issuer| issuer.cluster() == cluster)
    }

    /// 业务作用：向候选分类提供管理监听拓扑，避免把需要预绑定的地址变更当作普通内容换代。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已声明的接收地址；仅主动上报的节点返回空。
    pub(crate) fn receiver_address(&self) -> Option<SocketAddr> {
        self.receiver.as_ref().map(|receiver| receiver.listen)
    }

    /// 业务作用：完整验证管理接收身份与主动上报端点，关闭管理时不读取材料或扩大网络权限。
    ///
    /// 参数说明：
    /// - `cfg`：强类型管理声明。
    /// - `root`：材料路径的唯一配置根。
    ///
    /// 返回：关闭时为空；开启时返回有界不可变计划，任意身份或TLS错误阻止候选发布。
    pub(crate) fn build(cfg: &Config, root: &Path) -> Result<Option<Arc<Self>>> {
        if !cfg.enabled {
            return Ok(None);
        }
        ensure!(
            security::identifier(&cfg.node_id),
            "invalid management node_id"
        );
        ensure!(
            cfg.receiver.is_some() || cfg.reporter.is_some(),
            "management needs receiver or reporter"
        );
        let mut authority = Sha256::new();
        stamp(&mut authority, cfg.node_id.as_bytes());
        stamp(
            &mut authority,
            &[
                u8::from(cfg.receiver.is_some()),
                u8::from(cfg.reporter.is_some()),
            ],
        );
        let receiver = cfg
            .receiver
            .as_ref()
            .map(|receiver| {
                let listen: SocketAddr = receiver
                    .listen
                    .parse()
                    .context("management listen needs IP:port")?;
                ensure!(
                    listen.port() != 0 && !listen.ip().is_multicast(),
                    "invalid management listen"
                );
                ensure!(
                    receiver.nodes.len() <= 127,
                    "management receiver allows at most 127 remote nodes"
                );
                let mut nodes = BTreeMap::new();
                stamp(&mut authority, &[u8::from(receiver.metrics)]);
                stamp(&mut authority, receiver.listen.as_bytes());
                let mut certificates = BTreeSet::new();
                for (id, member) in &receiver.nodes {
                    ensure!(
                        security::identifier(id) && id != &cfg.node_id,
                        "invalid or local management member id"
                    );
                    let hash = &member.certificate_sha256;
                    ensure!(
                        hash.len() == 64
                            && hash
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                        "management certificate requires lowercase SHA-256 hex"
                    );
                    ensure!(
                        certificates.insert(hash),
                        "management certificate must bind exactly one node"
                    );
                    nodes.insert(id.clone(), format!("sha256:{hash}"));
                    stamp(&mut authority, id.as_bytes());
                    stamp(&mut authority, hash.as_bytes());
                }
                let certificate = security::pem(root, &receiver.tls.cert_file)?;
                let key = security::pem(root, &receiver.tls.key_file)?;
                let ca = security::pem(root, &receiver.tls.ca_file)?;
                for material in [&certificate, &key, &ca] {
                    stamp(&mut authority, material);
                }
                let identity = GrpcTlsIdentity::mutual(certificate, key, ca)?;
                let issuer = issuer::Signer::build(&receiver.issuer, root, &mut authority)?;
                Ok::<_, anyhow::Error>(Receiver {
                    metrics: receiver.metrics,
                    listen,
                    expires_at: identity.certificate_expiry_timestamp()?,
                    acceptor: GrpcTlsAcceptor::prepare(&identity)?,
                    nodes,
                    issuer,
                })
            })
            .transpose()?;
        let mut targets = Vec::new();
        if let Some(reporter) = &cfg.reporter {
            ensure!(
                !reporter.actions || cfg!(feature = "node-actions"),
                "management reporter actions require node-actions"
            );
            stamp(&mut authority, &[u8::from(reporter.actions)]);
            stamp(&mut authority, &[u8::from(reporter.metrics)]);
            ensure!(
                !reporter.targets.is_empty() && reporter.targets.len() <= 8,
                "management reporter needs 1..=8 targets"
            );
            let ca = security::pem(root, &reporter.tls.ca_file)?;
            let certificate = security::pem(root, &reporter.tls.cert_file)?;
            let key = security::pem(root, &reporter.tls.key_file)?;
            for material in [&certificate, &key, &ca] {
                stamp(&mut authority, material);
            }
            // 空CA不能回退到系统根；身份必须允许clientAuth且在当前时刻有效。
            crate::tls::root_store_from_ca_bytes(&ca, "management CA")?;
            let expires_at = nagrpc::client_certificate_expiry_timestamp(&certificate)?;
            let tls = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca))
                .identity(Identity::from_pem(certificate, key));
            let mut addresses = BTreeSet::new();
            for target in &reporter.targets {
                let address: SocketAddr = target
                    .address
                    .parse()
                    .context("management target needs IP:port")?;
                ensure!(
                    address.port() != 0
                        && !address.ip().is_unspecified()
                        && !address.ip().is_multicast(),
                    "invalid management target"
                );
                ensure!(addresses.insert(address), "duplicate management target");
                stamp(&mut authority, target.address.as_bytes());
                stamp(&mut authority, target.authority.as_bytes());
                let issuer = issuer::Verifier::build(&target.issuer, root, &mut authority)?;
                ensure!(
                    !reporter.actions || issuer.is_some(),
                    "management reporter actions require trusted issuers"
                );
                ensure!(
                    !target.authority.is_empty()
                        && target.authority.len() <= 253
                        && target
                            .authority
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte)),
                    "invalid management TLS authority"
                );
                let endpoint = Endpoint::from_shared(format!("https://{address}"))?
                    .tls_config(tls.clone().domain_name(target.authority.clone()))?
                    .connect_timeout(super::RPC_TIMEOUT)
                    .timeout(super::RPC_TIMEOUT)
                    .concurrency_limit(2)
                    .buffer_size(1)
                    .initial_stream_window_size(32 * 1024)
                    .initial_connection_window_size(64 * 1024)
                    .tcp_nodelay(true)
                    .tcp_keepalive(Some(Duration::from_secs(10)));
                targets.push(Target {
                    endpoint,
                    expires_at,
                    issuer,
                });
            }
        }
        Ok(Some(Arc::new(Self {
            actions_enabled: cfg
                .reporter
                .as_ref()
                .is_some_and(|reporter| reporter.actions),
            report_metrics: cfg
                .reporter
                .as_ref()
                .is_some_and(|reporter| reporter.metrics),
            authority: authority.finalize().into(),
            node_id: cfg.node_id.clone(),
            receiver,
            targets,
        })))
    }
}

/// 业务作用：用长度前缀摘要冻结管理端点、成员与实际材料，不复制或序列化秘密到中间文档。
///
/// 参数说明：
/// - `hash`：当前完整权威的增量摘要器。
/// - `bytes`：本段身份、目标或材料的原始字节。
///
/// 返回：只更新不可逆摘要状态，分段不会因串接歧义产生同一合同。
pub(super) fn stamp(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
