//! 受控动态正向代理:CONNECT 目标策略与 SSRF/DNS rebinding 门。
//!
//! 正向代理与反向代理的威胁模型完全相反。反向代理的上游是运维写死的;正向代理的上游
//! **由请求方指定**,等于把网关的网络位置借给了调用方。网关通常部署在能访问内网、
//! 云厂商元数据服务和管理面的位置,一个不设防的 CONNECT 就是一把万能内网钥匙。
//!
//! 因此这里的默认立场是 fail-closed:
//! - 没有显式 allowlist 就**什么都不允许**,不存在"默认放行公网"的形态;
//! - 目标先解析、**逐个**校验解析结果,再**按已校验的 IP 直连**。
//!
//! 最后一条是 DNS rebinding 防御的关键。先校验域名再调用按主机名连接的接口,
//! 系统会**再解析一次**;攻击者只要让两次解析返回不同结果,校验就完全落空。
//! 只有"校验哪个 IP 就连哪个 IP"才能关掉这个时间差。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// 单次 CONNECT 允许解析出的最大地址数,防御超大 DNS 应答放大解析成本。
const MAX_RESOLVED_ADDRS: usize = 16;
/// 目标 authority 的最大长度,避免超长输入进入解析路径。
const MAX_AUTHORITY_LEN: usize = 255;

/// 目标被拒绝的原因。分类是为了让审计日志能区分"配置没放行"和"命中安全禁区",
/// 前者是运维问题,后者往往是攻击尝试,两者的响应完全不同。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DenyReason {
    /// authority 语法非法。
    MalformedAuthority,
    /// 端口不在 allowlist。
    PortNotAllowed,
    /// 域名不在 allowlist。
    HostNotAllowed,
    /// 解析结果落在被禁地址类(环回/链路本地/元数据/内网等)。
    BlockedAddressClass,
    /// 解析结果指向网关自身监听地址或管理面。
    SelfOrAdmin,
    /// DNS 解析失败或未返回任何可用地址。
    ResolutionFailed,
    /// DNS 应答包含过多地址，无法证明后续连接仍在本次校验集合内。
    TooManyAddresses,
    /// 解析结果超出允许的 CIDR allowlist。
    CidrNotAllowed,
}

impl DenyReason {
    /// 业务作用：给出可写入审计日志的稳定原因串。
    ///
    /// 参数说明：无。
    ///
    /// 返回：低基数原因标签,可安全用作指标维度。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedAuthority => "malformed_authority",
            Self::PortNotAllowed => "port_not_allowed",
            Self::HostNotAllowed => "host_not_allowed",
            Self::BlockedAddressClass => "blocked_address_class",
            Self::SelfOrAdmin => "self_or_admin",
            Self::ResolutionFailed => "resolution_failed",
            Self::TooManyAddresses => "too_many_addresses",
            Self::CidrNotAllowed => "cidr_not_allowed",
        }
    }
}

/// CONNECT 目标 authority。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectTarget {
    /// 主机部分;可能是域名或字面量 IP。
    pub host: String,
    /// 端口。
    pub port: u16,
}

impl ConnectTarget {
    /// 业务作用：解析 CONNECT 请求行的 `host:port` authority。
    ///
    /// CONNECT 的 authority **必须**显式带端口(RFC 9110);不补默认端口是有意的——
    /// 猜一个默认端口等于替调用方决定要连什么,而端口正是 allowlist 的判据之一。
    ///
    /// 参数说明：`raw` 是请求行中的 authority 原文。
    ///
    /// 返回：解析成功返回目标;语法非法返回 `MalformedAuthority`。
    pub fn parse(raw: &str) -> Result<Self, DenyReason> {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > MAX_AUTHORITY_LEN {
            return Err(DenyReason::MalformedAuthority);
        }
        // authority 里出现凭据、路径或 scheme 都说明客户端在尝试非 CONNECT 语义,
        // 直接拒绝而不是尝试"宽容解析"——宽容解析正是绕过 allowlist 的常见入口。
        if raw.contains('@') || raw.contains('/') || raw.contains("://") || raw.contains('\\') {
            return Err(DenyReason::MalformedAuthority);
        }
        let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
            // IPv6 字面量形式 [::1]:443。
            let (inside, tail) = rest.split_once(']').ok_or(DenyReason::MalformedAuthority)?;
            let port = tail
                .strip_prefix(':')
                .ok_or(DenyReason::MalformedAuthority)?;
            if inside.parse::<Ipv6Addr>().is_err() {
                return Err(DenyReason::MalformedAuthority);
            }
            (inside.to_string(), port)
        } else {
            let (host, port) = raw.rsplit_once(':').ok_or(DenyReason::MalformedAuthority)?;
            if host.is_empty() || host.contains(':') {
                // 裸 IPv6 未加方括号,无法与 host:port 区分,按语法错误处理。
                return Err(DenyReason::MalformedAuthority);
            }
            (host.to_string(), port)
        };
        let port: u16 = port.parse().map_err(|_| DenyReason::MalformedAuthority)?;
        if port == 0 {
            return Err(DenyReason::MalformedAuthority);
        }
        if host.parse::<IpAddr>().is_err() && !valid_dns_name(host.trim_end_matches('.')) {
            return Err(DenyReason::MalformedAuthority);
        }
        Ok(Self { host, port })
    }
}

/// CIDR 前缀。
#[derive(Clone, Copy, Debug)]
pub struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// 业务作用：解析 `a.b.c.d/len` 或 `addr::/len` 形式的 CIDR。
    ///
    /// 参数说明：`raw` 为配置中的 CIDR 字符串。
    ///
    /// 返回：解析成功返回 CIDR;语法或前缀长度非法时返回错误。
    pub fn parse(raw: &str) -> Result<Self> {
        let (addr, prefix) = raw
            .trim()
            .split_once('/')
            .with_context(|| format!("CIDR `{raw}` 缺少前缀长度"))?;
        let base: IpAddr = addr
            .parse()
            .with_context(|| format!("CIDR `{raw}` 地址非法"))?;
        let prefix: u8 = prefix
            .parse()
            .with_context(|| format!("CIDR `{raw}` 前缀长度非法"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            bail!("CIDR `{raw}` 前缀长度超出上限 {max}");
        }
        Ok(Self { base, prefix })
    }

    /// 业务作用：判断地址是否落在该前缀内。
    ///
    /// 参数说明：`addr` 为已归一化的地址。
    ///
    /// 返回：命中返回 true。
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(base), IpAddr::V4(addr)) => {
                prefix_match(&base.octets(), &addr.octets(), self.prefix)
            }
            (IpAddr::V6(base), IpAddr::V6(addr)) => {
                prefix_match(&base.octets(), &addr.octets(), self.prefix)
            }
            // 协议族不同一律不匹配:把 IPv4 悄悄折进 IPv6 前缀比较会让
            // allowlist 覆盖到运维没预期的地址。
            _ => false,
        }
    }
}

/// 业务作用：按位比较地址与 CIDR 基址的前缀，避免字符串比较产生等价地址旁路。
///
/// 参数说明：`base` 是 CIDR 基址字节；`addr` 是目标地址字节；`prefix` 是前缀位数。
///
/// 返回：协议族内前 `prefix` 位相同时返回 `true`。
fn prefix_match(base: &[u8], addr: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if base[..full] != addr[..full] {
        return false;
    }
    let rest = prefix % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    base[full] & mask == addr[full] & mask
}

/// 主机 allowlist 条目。
#[derive(Clone, Debug)]
enum HostRule {
    /// 精确域名(大小写无关)。
    Exact(String),
    /// 通配后缀 `*.example.com`;只匹配子域,不匹配裸域。
    Suffix(String),
}

/// 正向代理目标策略。
#[derive(Clone, Debug, Default)]
pub struct ForwardProxyPolicy {
    /// 允许的端口集合。空集表示**不允许任何端口**。
    allowed_ports: Vec<u16>,
    /// 允许的域名规则。
    host_rules: Vec<HostRule>,
    /// 允许的目标 CIDR。空集表示不按 CIDR 放行。
    allowed_cidrs: Vec<Cidr>,
    /// 是否允许目标解析到私网地址。默认 false。
    allow_private: bool,
    /// 网关自身监听地址与管理面地址,任何解析结果命中都拒绝。
    self_addrs: Vec<SocketAddr>,
    /// 隧道空闲上限(ms);0 表示不限制。
    pub idle_timeout_ms: u64,
    /// 隧道绝对寿命上限(ms);0 表示不限制。
    pub max_lifetime_ms: u64,
    /// 单条隧道允许搬运的最大字节数;0 表示不限制。
    pub max_bytes: u64,
    /// 建连超时(ms)。
    pub connect_timeout_ms: u64,
}

impl ForwardProxyPolicy {
    /// 业务作用：从配置构建目标策略,并在构建期就拒绝"等于没设防"的组合。
    ///
    /// # 参数
    /// - `ports`: 允许端口。
    /// - `hosts`: 允许域名(支持 `*.` 前缀)。
    /// - `cidrs`: 允许目标 CIDR。
    /// - `allow_private`: 是否允许私网目标。
    ///
    /// 返回：构建成功返回策略;端口与主机/CIDR 任一为空时返回错误——
    /// 空 allowlist 若被解释成"全放行",这个 route 就是一个开放中继,
    /// 会被立刻拿去打内网和第三方,所以必须在配置期挡住。
    pub fn build(
        ports: &[u16],
        hosts: &[String],
        cidrs: &[String],
        allow_private: bool,
    ) -> Result<Self> {
        if ports.is_empty() {
            bail!("forward_proxy.allowed_ports 不能为空:空集会让该 route 变成开放中继");
        }
        if hosts.is_empty() && cidrs.is_empty() {
            bail!("forward_proxy 必须至少配置 allowed_hosts 或 allowed_cidrs 之一");
        }
        let mut host_rules = Vec::with_capacity(hosts.len());
        for host in hosts {
            let trimmed = host.trim().trim_end_matches('.').to_ascii_lowercase();
            if trimmed.is_empty() {
                bail!("forward_proxy.allowed_hosts 含空条目");
            }
            // 裸 `*` 会放行任意域名,与"受控"正向代理的前提直接冲突。
            if trimmed == "*" {
                bail!("forward_proxy.allowed_hosts 不允许裸 `*`:那等同于开放中继");
            }
            if let Some(suffix) = trimmed.strip_prefix("*.") {
                if suffix.is_empty() || !suffix.contains('.') || !valid_dns_name(suffix) {
                    bail!("forward_proxy.allowed_hosts 通配条目 `{host}` 过宽");
                }
                host_rules.push(HostRule::Suffix(suffix.to_string()));
            } else {
                if !valid_dns_name(trimmed.trim_end_matches('.')) {
                    bail!("forward_proxy.allowed_hosts 条目 `{host}` 不是合法 DNS 名称");
                }
                host_rules.push(HostRule::Exact(trimmed));
            }
        }
        let allowed_cidrs = cidrs
            .iter()
            .map(|raw| Cidr::parse(raw))
            .collect::<Result<Vec<_>>>()
            .context("forward_proxy.allowed_cidrs")?;
        Ok(Self {
            allowed_ports: ports.to_vec(),
            host_rules,
            allowed_cidrs,
            allow_private,
            self_addrs: Vec::new(),
            idle_timeout_ms: 0,
            max_lifetime_ms: 0,
            max_bytes: 0,
            connect_timeout_ms: 5_000,
        })
    }

    /// 业务作用：登记网关自身监听地址与管理面地址。
    ///
    /// 参数说明：`addrs` 为需要屏蔽的本机监听地址。
    ///
    /// 返回：无返回值。
    pub fn set_self_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.self_addrs = addrs;
    }

    /// 业务作用：判定目标 authority 在**解析之前**是否已经不可能被允许。
    ///
    /// 先做无 I/O 的判定是为了让绝大多数攻击尝试连一次 DNS 都触发不了,
    /// 顺带避免把网关变成任意域名的 DNS 探测器。
    ///
    /// 参数说明：`target` 是已解析的 authority。
    ///
    /// 返回：通过返回 `Ok`;否则返回拒绝原因。
    pub fn check_authority(&self, target: &ConnectTarget) -> Result<(), DenyReason> {
        if !self.allowed_ports.contains(&target.port) {
            return Err(DenyReason::PortNotAllowed);
        }
        // 字面量 IP 没有域名身份，必须由显式 CIDR 授权。仅配置域名白名单时若直接
        // 放过 IP，会让调用方绕开域名边界访问任意公网目标。
        if let Ok(addr) = target.host.parse::<IpAddr>() {
            let addr = normalize_ip(addr);
            return if self.allowed_cidrs.iter().any(|cidr| cidr.contains(addr)) {
                Ok(())
            } else {
                Err(DenyReason::CidrNotAllowed)
            };
        }
        let host = target.host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return Err(DenyReason::MalformedAuthority);
        }
        let matched = self.host_rules.iter().any(|rule| match rule {
            HostRule::Exact(exact) => *exact == host,
            // 只匹配真正的子域:`evil-example.com` 不能被 `*.example.com` 放行。
            HostRule::Suffix(suffix) => host
                .strip_suffix(suffix)
                .is_some_and(|head| head.ends_with('.')),
        });
        if matched {
            Ok(())
        } else {
            Err(DenyReason::HostNotAllowed)
        }
    }

    /// 业务作用：判定单个**已解析**地址是否允许连接。
    ///
    /// 参数说明：`addr` 是解析结果中的一个地址；`port` 是目标端口，用于比对网关自身监听。
    ///
    /// 返回：允许返回 `Ok`;否则返回拒绝原因。
    pub fn check_resolved(&self, addr: IpAddr, port: u16) -> Result<(), DenyReason> {
        // 归一化必须在所有判定之前:`::ffff:127.0.0.1` 与 `127.0.0.1` 是同一台机器,
        // 只按原始形态判断等于给攻击者留了一种写法就能绕过全部规则。
        let addr = normalize_ip(addr);
        if is_blocked_class(addr, self.allow_private) {
            return Err(DenyReason::BlockedAddressClass);
        }
        // 网关自身与管理面永远不是合法 CONNECT 目标:允许了就等于把管理面
        // 通过数据面端口暴露出去,还能绕过管理面自身的监听绑定限制。
        if self.self_addrs.iter().any(|own| {
            if own.port() != port {
                return false;
            }
            if own.ip().is_unspecified() {
                // 通配监听覆盖本机所有接口。临时绑定目标 IP 的随机端口只用于判断该 IP
                // 是否属于本机；不枚举接口可避免热更新期间依赖易过期的地址快照。
                std::net::TcpListener::bind(SocketAddr::new(addr, 0)).is_ok()
            } else {
                normalize_ip(own.ip()) == addr
            }
        }) {
            return Err(DenyReason::SelfOrAdmin);
        }
        if !self.allowed_cidrs.is_empty()
            && !self.allowed_cidrs.iter().any(|cidr| cidr.contains(addr))
            && self.host_rules.is_empty()
        {
            return Err(DenyReason::CidrNotAllowed);
        }
        Ok(())
    }

    /// 业务作用：解析目标并返回**全部通过校验**的地址。
    ///
    /// 这是 DNS rebinding 防御的落点,三条规则缺一不可:
    /// 1. **每次连接都重新解析**,不复用上一次的结论;
    /// 2. **逐个校验**解析出的每个地址,而不是只看第一个——多 A 记录里混一个内网地址
    ///    是最省事的绕过手法;
    /// 3. 只要有**任意一个**地址被禁就整体拒绝,不做"挑一个能用的"回退。
    ///    回退等于让攻击者用一条合法记录换来一次内网连接。
    ///
    /// 参数说明：`target` 是已通过 authority 预检的目标。
    ///
    /// 返回：全部校验通过的地址列表;任一环节失败返回拒绝原因。
    pub async fn resolve_checked(
        &self,
        target: &ConnectTarget,
    ) -> Result<Vec<SocketAddr>, DenyReason> {
        let host = target.host.clone();
        let port = target.port;
        let raw_resolved = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| DenyReason::ResolutionFailed)?
            .take(MAX_RESOLVED_ADDRS.saturating_add(1))
            .collect::<Vec<_>>();
        if raw_resolved.is_empty() {
            return Err(DenyReason::ResolutionFailed);
        }
        let mut resolved = Vec::with_capacity(raw_resolved.len());
        for addr in raw_resolved {
            let normalized = SocketAddr::new(normalize_ip(addr.ip()), addr.port());
            if !resolved.contains(&normalized) {
                resolved.push(normalized);
            }
        }
        // 静默截断会留下未校验的 DNS 结果；连接库一旦重新选择那些结果，DNS rebinding
        // 门就失效。超过预算必须整体拒绝，不能只校验前缀集合。
        if resolved.len() > MAX_RESOLVED_ADDRS {
            return Err(DenyReason::TooManyAddresses);
        }
        for addr in &resolved {
            self.check_resolved(addr.ip(), addr.port())?;
        }
        // 后续必须按这些已归一化的 IP 直连，不能再按主机名解析一次。
        Ok(resolved)
    }

    /// 业务作用：把配置的建连预算转换成运行期时长，并保证不会产生零时长竞态。
    ///
    /// 参数说明：无。
    ///
    /// 返回：至少 1ms 的 CONNECT 建连超时。
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms.max(1))
    }
}

/// 业务作用：把 IPv4-mapped / IPv4-compatible IPv6 归一化成 IPv4。
///
/// `::ffff:169.254.169.254` 和 `169.254.169.254` 指向同一目标,若只按字面形态判断,
/// 换一种写法就能绕过全部地址类检查。归一化必须发生在任何判定之前。
///
/// 参数说明：`addr` 是原始地址。
///
/// 返回：归一化后的地址。
pub fn normalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => match v6.to_ipv4() {
                // `::a.b.c.d`(IPv4-compatible)同样要还原;它已废弃但仍可被构造出来。
                Some(v4) if !v6.is_loopback() => IpAddr::V4(v4),
                _ => addr,
            },
        },
    }
}

/// 业务作用：判定地址是否落在**永远不得作为正向代理目标**的地址类。
///
/// 这里列的每一类都对应一种真实的越权路径:环回与未指定地址指向网关自身,
/// 链路本地含云厂商元数据服务(凭据泄露的经典入口),ULA/私网是内网横移,
/// CGNAT 常见于运营商内网,多播/广播会把请求放大到一片主机。
///
/// 参数说明：`addr` 是已归一化的地址；`allow_private` 表示是否显式允许私网目标。
///
/// 返回：属于禁区返回 true。
pub fn is_blocked_class(addr: IpAddr, allow_private: bool) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // 0.0.0.0/8 与 240.0.0.0/4 保留段。
                || v4.octets()[0] == 0
                || v4.octets()[0] >= 240
                // 100.64.0.0/10 CGNAT。
                || is_cgnat(v4)
            {
                return true;
            }
            if v4.is_private() && !allow_private {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            let segments = v6.segments();
            // fe80::/10 链路本地。
            if segments[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // 2001:db8::/32 文档段。
            if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                return true;
            }
            // fc00::/7 唯一本地地址(IPv6 的"私网")。
            if segments[0] & 0xfe00 == 0xfc00 {
                return !allow_private;
            }
            false
        }
    }
}

/// 业务作用：识别运营商 CGNAT 地址，防止正向代理成为运营商内网探测入口。
///
/// 参数说明：`addr` 是待判定 IPv4 地址。
///
/// 返回：地址位于 `100.64.0.0/10` 时返回 `true`。
fn is_cgnat(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..128).contains(&octets[1])
}

/// 业务作用：校验 allowlist 与 CONNECT authority 中的 ASCII DNS 名称语法，避免
/// 空 label、控制字符和畸形后缀进入宽松的字符串匹配路径。
///
/// 参数说明：`name` 是已去除尾点的 DNS 名称。
///
/// 返回：名称长度与每个 label 均满足 DNS 主机名边界时返回 `true`。
fn valid_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}
