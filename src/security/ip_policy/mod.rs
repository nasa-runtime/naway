//! 配置快照内的全局访问与真实来源判定。

mod forwarded;
mod segments;

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use http::request::Parts;
use serde::Serialize;

use crate::config::ip_policy::{AccessCfg, AccessMode, ClientIpCfg, ClientIpMode, ForwardedHeader};
use crate::io::net::Cidr;

/// 已验证的静态网段和来源预算，与业务路由在同一快照中发布。
#[derive(Clone)]
pub struct Plan {
    declared: bool,
    mode: AccessMode,
    entries: Arc<[Cidr]>,
    client_ip: Option<ClientIpCfg>,
}

/// 来源链未提供完整且无歧义的地址证明。
#[derive(Clone, Copy, Debug)]
pub struct InvalidSource;

/// 只有已编译来源策略可以要求上游重建来源头，客户端不能通过 HTTP 字段生成此标记。
#[derive(Clone, Copy)]
pub(crate) struct CanonicalSourceHeaders;

/// 不包含地址原文的配置读面摘要。
#[derive(Clone, Serialize)]
pub struct Summary {
    pub acl_declared: bool,
    pub acl_mode: AccessMode,
    pub acl_entries: usize,
    pub client_ip_mode: Option<ClientIpMode>,
    pub forwarded_header: Option<ForwardedHeader>,
    pub max_forwarded_hops: Option<usize>,
}

impl Plan {
    /// 业务作用：在候选构建阶段固定全局访问集合和来源预算，非法策略不能进入数据面。
    ///
    /// 参数说明：
    /// - `access`：静态 ACL 模式和地址声明。
    /// - `client_ip`：受信来源模式与元素预算，不包含代理信任列表。
    ///
    /// 返回：合法时返回只读计划；模式、网段或预算不合法时拒绝完整候选。
    pub fn build(access: Option<&AccessCfg>, client_ip: Option<&ClientIpCfg>) -> Result<Self> {
        let declared = access.is_some();
        let fallback = AccessCfg::default();
        let access = access.unwrap_or(&fallback);
        ensure!(
            access.entries.len() <= 4096,
            "acl.entries must contain at most 4096 addresses"
        );
        if let Some(client_ip) = client_ip {
            ensure!(
                (1..=64).contains(&client_ip.max_forwarded_hops),
                "client_ip_policy.max_forwarded_hops must be 1..=64"
            );
        }
        let mut entries = Vec::with_capacity(access.entries.len());
        for address in &access.entries {
            ensure!(
                address.len() <= 128,
                "acl.entries address exceeds 128 bytes"
            );
            entries.push(Cidr::parse(address).context("invalid acl.entries address")?);
        }
        entries.sort_unstable();
        entries.dedup();
        Ok(Self {
            declared,
            mode: access.mode,
            entries: entries.into(),
            client_ip: client_ip.copied(),
        })
    }

    /// 业务作用：在路由匹配前按同一真实客户端地址裁决静态 ACL。
    ///
    /// 参数说明：
    /// - `ip`：已由连接与受信来源策略确定的真实地址。
    ///
    /// 返回：off 放行；whitelist 只允许命中集合；blacklist 拒绝集合命中，不改变动态封禁。
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        match self.mode {
            AccessMode::Off => true,
            AccessMode::Whitelist => self.entries.iter().any(|entry| entry.contains(ip)),
            AccessMode::Blacklist => !self.entries.iter().any(|entry| entry.contains(ip)),
        }
    }

    /// 业务作用：仅为已经可信的代理连接解析来源链，避免客户端伪造或歧义链获取地址权威。
    ///
    /// 参数说明：
    /// - `parts`：保留原始来源头的请求。
    /// - `trusted`：当前入口构建期冻结的代理网段。
    ///
    /// 返回：有效链返回最近非可信地址；socket_addr 或兼容配置可返回 None；显式来源证据缺失、坏链或超限必须拒绝请求。
    pub fn forwarded_ip(
        &self,
        parts: &Parts,
        trusted: &[Cidr],
    ) -> Result<Option<IpAddr>, InvalidSource> {
        let Some(policy) = self.client_ip else {
            // 既有声明只授予 XFF 信任；不能因制品升级而开始信任代理未维护的 Forwarded。
            return Ok(forwarded::legacy_xff(parts, trusted));
        };
        if policy.mode == ClientIpMode::SocketAddr {
            return Ok(None);
        }
        forwarded::resolve(parts, trusted, policy.max_forwarded_hops, policy.header)
            .map_err(|_| InvalidSource)
    }

    /// 业务作用：冻结显式来源策略的转发约束，认证仍读取原始头，上游发送时再撤去客户端来源声明。
    ///
    /// 参数说明：
    /// - `parts`：当前请求的进程内 head，不修改原始 HTTP 来源字段。
    ///
    /// 返回：显式策略存在时登记不可伪造标记；兼容配置不改变既有转发合同。
    pub(crate) fn bind_request(&self, parts: &mut Parts) {
        if self.client_ip.is_some() {
            parts.extensions.insert(CanonicalSourceHeaders);
        }
    }

    /// 业务作用：比较全局访问与来源的实际声明，用于候选审阅而不按原文顺序偶然判定。
    ///
    /// 参数说明：
    /// - `other`：待比较的候选计划。
    ///
    /// 返回：模式、规范化网段与来源预算均相同才为 true，不比较请求运行事实。
    pub fn same_policy(&self, other: &Self) -> bool {
        self.same_access(other) && self.client_ip == other.client_ip
    }

    /// 业务作用：比较所有数据面共用的静态访问声明，保持 HTTP 来源头策略与不透明流量分离。
    ///
    /// 参数说明：
    /// - `other`：待比较的候选计划。
    ///
    /// 返回：声明存在性、模式和规范化网段都相同时为 true。
    pub fn same_access(&self, other: &Self) -> bool {
        self.declared == other.declared && self.mode == other.mode && self.entries == other.entries
    }

    /// 业务作用：为管理读面提供当前已发布模式和容量，不暴露地址或伪装为集群收敛证明。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回同代的模式与容量；来源配置缺席时三个对应字段为 None，表示兼容原有 XFF 行为。
    pub fn summary(&self) -> Summary {
        Summary {
            acl_declared: self.declared,
            acl_mode: self.mode,
            acl_entries: self.entries.len(),
            client_ip_mode: self.client_ip.map(|policy| policy.mode),
            forwarded_header: self.client_ip.map(|policy| policy.header),
            max_forwarded_hops: self.client_ip.map(|policy| policy.max_forwarded_hops),
        }
    }
}
