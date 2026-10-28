//! IP 网段(CIDR)解析与匹配。
//!
//! 供多处复用：PROXY protocol 的 `accept_from` 与数据面 `trusted_proxies`。
//! **在【构建期】解析并校验成 [`Cidr`],运行期只做无分配的位比较**——避免每条连接/每个请求重复解析字符串
//! (原 `proxy_protocol::is_trusted` 每连接都 `parse` 一次 CIDR,现收敛到构建期一次)。

use std::net::IpAddr;

use anyhow::{Context, Result};

/// 一个网段或单 IP。构建期解析定型,运行期只读匹配。
#[derive(Clone, PartialEq, Eq)]
pub enum Cidr {
    /// 精确单 IP(无 `/prefix`)。
    Single(IpAddr),
    /// IPv4 前缀:`base` 已按 `mask` 归零低位,匹配 = `(ip & mask) == base`。
    V4 {
        /// 已按掩码归零主机位的网络地址。
        base: u32,
        /// 由 CIDR prefix 生成的网络掩码。
        mask: u32,
    },
    /// IPv6 前缀:同上,128 位。
    V6 {
        /// 已按掩码归零主机位的网络地址。
        base: u128,
        /// 由 CIDR prefix 生成的网络掩码。
        mask: u128,
    },
}

impl Cidr {
    /// 业务作用：解析 `"10.0.0.0/8"` / `"192.168.1.1"` / `"::1"` / `"fd00::/8"`。构建期调用,非法即 `Err`(fail-fast)。
    ///
    /// 参数说明：
    /// - `spec`: CIDR 或单 IP 字面量;含 `/` 时按前缀网段,否则按精确 IP。
    pub fn parse(spec: &str) -> Result<Self> {
        if let Some((base, prefix)) = spec.split_once('/') {
            let base: IpAddr = base
                .trim()
                .parse()
                .with_context(|| format!("invalid CIDR address `{spec}`"))?;
            let prefix: u8 = prefix
                .trim()
                .parse()
                .with_context(|| format!("invalid CIDR prefix `{spec}`"))?;
            match base {
                IpAddr::V4(v4) => {
                    anyhow::ensure!(prefix <= 32, "IPv4 CIDR prefix must be <= 32 in `{spec}`");
                    // prefix==0 时 `u32::MAX << 32` 是 UB(移位量 = 位宽),单独处理成全 0 掩码。
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    };
                    Ok(Cidr::V4 {
                        base: u32::from(v4) & mask,
                        mask,
                    })
                }
                IpAddr::V6(v6) => {
                    anyhow::ensure!(prefix <= 128, "IPv6 CIDR prefix must be <= 128 in `{spec}`");
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    };
                    Ok(Cidr::V6 {
                        base: u128::from(v6) & mask,
                        mask,
                    })
                }
            }
        } else {
            let ip: IpAddr = spec
                .trim()
                .parse()
                .with_context(|| format!("invalid IP `{spec}`"))?;
            Ok(Cidr::Single(ip))
        }
    }

    /// 业务作用：该网段是否包含 `ip`。运行期热路径:纯位比较、零分配。v4/v6 交叉一律不匹配。
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::Single(expected), ip) => *expected == ip,
            (
                Cidr::V4 {
                    base,
                    mask,
                },
                IpAddr::V4(ip),
            ) => (u32::from(ip) & mask) == *base,
            (
                Cidr::V6 {
                    base,
                    mask,
                },
                IpAddr::V6(ip),
            ) => (u128::from(ip) & mask) == *base,
            _ => false,
        }
    }

    /// 业务作用：返回该网段的匹配精度位数,供 `geo` 等重叠 CIDR 规则做最长前缀优先。
    pub fn prefix_bits(&self) -> u32 {
        match self {
            Cidr::Single(IpAddr::V4(_)) => 32,
            Cidr::Single(IpAddr::V6(_)) => 128,
            Cidr::V4 {
                mask,
                ..
            } => mask.count_ones(),
            Cidr::V6 {
                mask,
                ..
            } => mask.count_ones(),
        }
    }
}

/// 业务作用：构建期把一批 CIDR 字符串解析成 [`Cidr`],任一非法即整体 `Err`(坏配置不上线)。
pub fn parse_cidrs(specs: &[String]) -> Result<Vec<Cidr>> {
    specs.iter().map(|s| Cidr::parse(s)).collect()
}

/// 业务作用：`ip` 是否落在任一网段内。**空列表 = 不匹配(安全默认:未配 = 谁都不信任)**。
pub fn any_contains(cidrs: &[Cidr], ip: IpAddr) -> bool {
    cidrs.iter().any(|c| c.contains(ip))
}
