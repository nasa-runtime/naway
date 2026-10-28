//! xDS 管理端的显式传输身份、节点可见域与硬预算。

#[cfg(not(feature = "xds-server"))]
#[derive(Debug, serde::Deserialize)]
pub enum ServerCfg {}

#[cfg(feature = "xds-server")]
pub use enabled::*;

#[cfg(feature = "xds-server")]
mod enabled {
    use serde::Deserialize;
    use std::collections::BTreeMap;

    /// 管理端只提供 ADS；不存在明文或匿名回退。
    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ServerCfg {
        /// 显式选择路由资源投影；不承诺复制 Naway 进程内配额、连接池或运维动态状态。
        pub profile: Profile,
        /// 独立管理端监听地址，不复用数据面或管理 HTTP 端口。
        pub listen: String,
        /// 服务端证书、私钥与强制客户端认证的信任根。
        pub tls: TlsCfg,
        /// 节点 id 到证书绑定与投影范围；未知节点没有默认可见域。
        pub nodes: BTreeMap<String, NodeCfg>,
        /// 资源失联撤回期限；0 显式关闭，非零要求客户端声明 TTL 能力。
        #[serde(default = "default_ttl")]
        pub resource_ttl_ms: u64,
    }

    /// 管理端当前唯一的资源合同；未来能力不能通过默认值悄然扩大。
    #[derive(Clone, Debug, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Profile {
        HttpRouting,
    }

    /// 传输密钥只允许配置根内的有界 PEM 文件。
    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TlsCfg {
        pub ca_file: String,
        pub cert_file: String,
        pub key_file: String,
    }

    /// 节点声明不能授权执行 Naway 私有策略，也不能产生额外路由事实。
    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct NodeCfg {
        /// 已通过 CA 认证的叶证书 DER SHA-256；node.id 本身不是认证凭据。
        pub certificate_sha256: String,
        /// 必须与每个投影 proxy 和 route 的已验证 owner 一致。
        pub workspace: String,
        /// 允许读取的已存在 proxy 标识；对应资源命名空间不能跨节点越权查询。
        pub proxies: Vec<String>,
        /// 单独授权私钥下发；启用还要求持久、同步刷盘的管理审计。
        #[serde(default)]
        pub allow_sds: bool,
    }

    /// 业务作用：为失联的数据面提供有限资源保留期，避免控制端消失后无限保留旧授权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认保留 30 秒，由在线管理端在期限内续期。
    fn default_ttl() -> u64 {
        30_000
    }
}
