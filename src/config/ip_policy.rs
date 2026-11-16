//! 数据面静态访问控制与受信来源声明。

use serde::{Deserialize, Serialize};

/// 全局静态 ACL 的判定方式；动态封禁始终独立生效。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    #[default]
    Off,
    Whitelist,
    Blacklist,
}

/// 在路由选择前执行的全局 IPv4/IPv6 地址集合。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessCfg {
    /// off 不执行静态集合，whitelist 仅允许命中，blacklist 拒绝命中。
    #[serde(default)]
    pub mode: AccessMode,
    /// 地址与 CIDR，最多 4096 项；空 whitelist 拒绝全部业务请求。
    #[serde(default)]
    pub entries: Vec<String>,
}

/// 来源头是否参与真实客户端地址判定。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIpMode {
    #[default]
    SocketAddr,
    Forwarded,
}

/// 代理必须清理并维护所选头，不自动信任另一种客户端来源头。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedHeader {
    #[default]
    XForwardedFor,
    Forwarded,
}

/// 只有入口已经声明的可信代理才可提交来源链。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientIpCfg {
    /// socket_addr 忽略来源头；forwarded 仍要求实际连接对端属于 trusted_proxies。
    #[serde(default)]
    pub mode: ClientIpMode,
    /// 明确选择代理维护的头，默认 x_forwarded_for；不在两种头之间回退。
    #[serde(default)]
    pub header: ForwardedHeader,
    /// 每请求来源链元素上限，允许 1 至 64；超限拒绝请求，不取部分链作为权威。
    #[serde(default = "default_hops")]
    pub max_forwarded_hops: usize,
}

impl Default for ClientIpCfg {
    /// 业务作用：为显式来源配置提供保守默认值，声明对象本身不授予代理信任。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认使用连接地址并限制来源链至 64 元素；只有显式 forwarded 才读取所选来源头。
    fn default() -> Self {
        Self {
            mode: ClientIpMode::SocketAddr,
            header: ForwardedHeader::XForwardedFor,
            max_forwarded_hops: default_hops(),
        }
    }
}

/// 业务作用：为省略的来源链预算提供固定上限，防止读取无界代理链。
///
/// 参数说明: 无。
///
/// 返回：最多检查 64 个来源元素。
fn default_hops() -> usize {
    64
}
