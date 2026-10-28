//! 本地控制的动态配置来源目录与最小能力声明；远端载荷不具有修改这些字段的权限。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ProvidersCfg {
    pub enabled: bool,
    pub sources: Vec<SourceCfg>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceCfg {
    pub id: String,
    pub namespace: String,
    pub workspace: String,
    #[serde(default)]
    pub priority: i32,
    pub max_stale_ms: u64,
    pub poll_interval_ms: u64,
    pub deadline_ms: u64,
    pub max_body_bytes: usize,
    pub scope: ScopeCfg,
    pub transport: TransportCfg,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ScopeCfg {
    pub listeners: Vec<String>,
    pub backend_origins: Vec<String>,
    pub backend_networks: Vec<NetworkCfg>,
    pub templates: Vec<String>,
    pub references: Vec<ReferenceCfg>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkCfg {
    pub cidr: String,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReferenceCfg {
    pub namespace: String,
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransportCfg {
    Ecs {
        endpoint: String,
        region: String,
        cluster_arn: String,
        service: String,
        container: String,
        credentials: EcsCredentialsCfg,
        #[serde(default)]
        security: HttpSecurityCfg,
    },
    Nomad {
        endpoint: String,
        namespace: String,
        service: String,
        region: String,
        long_poll_ms: u64,
        #[serde(default)]
        security: HttpSecurityCfg,
    },
    Docker {
        endpoint: String,
        address: DockerAddressCfg,
        #[serde(default)]
        security: HttpSecurityCfg,
    },
    Zookeeper {
        endpoint: String,
        path: String,
        long_poll_ms: u64,
        security: ZookeeperSecurityCfg,
    },
    Etcd {
        endpoint: String,
        key: String,
        /// 使用十进制字符串保留整个无符号 64 位身份，不能经过浮点配置转换。
        cluster_id: String,
        long_poll_ms: u64,
        #[serde(default)]
        security: HttpSecurityCfg,
    },
    ConsulKv {
        endpoint: String,
        key: String,
        long_poll_ms: u64,
        #[serde(default)]
        security: HttpSecurityCfg,
    },
    Https {
        endpoint: String,
        #[serde(default)]
        security: HttpSecurityCfg,
    },
    Redis {
        endpoint: String,
        key: String,
        protocol_namespace: String,
        security: RedisSecurityCfg,
    },
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EcsCredentialsCfg {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DockerAddressCfg {
    Network {
        name: String,
    },
    Published,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ZookeeperSecurityCfg {
    /// 本地 SecretSource 中的 user:password，仅授予目标持久 znode 的 READ 权限。
    pub digest_auth: String,
    pub ca_certificate: String,
    pub client_certificate: String,
    pub client_private_key: String,
    pub allow_loopback_plaintext: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RedisSecurityCfg {
    pub username: String,
    /// 必须使用本地 SecretSource；URL 不接受内嵌凭据。
    pub password: String,
    /// 只授权 IP 字面量 loopback 的明文 Redis；其它地址必须使用 rediss。
    pub allow_loopback_plaintext: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct HttpSecurityCfg {
    /// 非空认证与证书材料必须使用本地 SecretSource 引用，不能把明文密钥写进配置出口。
    pub bearer_token: String,
    pub ca_certificate: String,
    pub client_certificate: String,
    pub client_private_key: String,
    /// 仅允许 IP 字面量 loopback 的明确本机联调入口；公网始终要求 HTTPS。
    pub allow_loopback_http: bool,
}
