//! 节点主动管理的独立开关、静态接入和证书身份声明。

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub node_id: String,
    pub receiver: Option<Receiver>,
    pub reporter: Option<Reporter>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receiver {
    #[serde(default)]
    pub metrics: bool,
    pub listen: String,
    pub tls: Tls,
    pub nodes: BTreeMap<String, Member>,
    #[serde(default)]
    pub issuer: Issuer,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub certificate_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reporter {
    #[serde(default)]
    pub actions: bool,
    #[serde(default)]
    pub metrics: bool,
    pub tls: Tls,
    pub targets: Vec<Target>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub address: String,
    pub authority: String,
    #[serde(default)]
    pub issuer: TrustedIssuer,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Issuer {
    pub enabled: bool,
    pub cluster_id: String,
    pub private_key: String,
    pub public_key: String,
}

impl std::fmt::Debug for Issuer {
    /// 业务作用：配置诊断只展示发行身份开关与集群，避免将字面私钥或秘密来源带入日志。
    ///
    /// 参数说明：
    /// - `formatter`：调用方的诊断输出目标。
    ///
    /// 返回：写入不含密钥字段的诊断结构，格式器失败向上传播。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Issuer")
            .field("enabled", &self.enabled)
            .field("cluster_id", &self.cluster_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustedIssuer {
    pub enabled: bool,
    pub cluster_id: String,
    pub node_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub ca_file: String,
    pub cert_file: String,
    pub key_file: String,
}

/// 业务作用：把启用管理通道的全部证书材料纳入同代配置指纹和精确文件观察。
///
/// 参数说明：
/// - `cfg`：未经运行态展开的管理声明。
/// - `root`：主配置文件的解析根目录。
///
/// 返回：关闭时为空；开启时返回确定的文件路径，不读取凭据或创建连接。
pub(crate) fn dependencies(cfg: &Config, root: &Path) -> Vec<PathBuf> {
    if !cfg.enabled {
        return Vec::new();
    }
    let mut paths: Vec<_> = cfg
        .receiver
        .iter()
        .map(|receiver| &receiver.tls)
        .chain(cfg.reporter.iter().map(|reporter| &reporter.tls))
        .flat_map(|tls| [&tls.ca_file, &tls.cert_file, &tls.key_file])
        .map(|path| root.join(path))
        .collect();
    for issuer in cfg
        .receiver
        .iter()
        .map(|receiver| &receiver.issuer)
        .filter(|issuer| issuer.enabled)
    {
        paths.extend(
            [&issuer.private_key, &issuer.public_key]
                .into_iter()
                .filter_map(|value| crate::security::secret::dependency_path(value, root)),
        );
    }
    for issuer in cfg
        .reporter
        .iter()
        .flat_map(|reporter| &reporter.targets)
        .map(|target| &target.issuer)
        .filter(|issuer| issuer.enabled)
    {
        paths.extend(crate::security::secret::dependency_path(
            &issuer.public_key,
            root,
        ));
    }
    paths
}
