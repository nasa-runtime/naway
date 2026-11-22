//! 独立 Sentinel 规则的请求路径与属性值索引。

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use anyhow::{ensure, Context, Result};
use http::{request::Parts, HeaderName};

use crate::config::model::SentinelValueMatch;
use crate::routing::{self, CircuitBreakerPolicy, LimitConnPolicy, LimitReqKey, LimitReqPolicy};

const MAX_RULES: usize = 4096;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_INDEX_BYTES: usize = 1024 * 1024;

#[derive(Default)]
struct Trie<T> {
    nodes: Vec<Node<T>>,
}

struct Node<T> {
    children: BTreeMap<u8, usize>,
    exact: Option<T>,
    prefix: Option<T>,
}

impl<T> Default for Node<T> {
    /// 业务作用：创建未获得匹配资格的字节节点，只有配置编译可以登记终点。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有边及终点的节点。
    fn default() -> Self {
        Self {
            children: BTreeMap::new(),
            exact: None,
            prefix: None,
        }
    }
}

struct Pattern<'a> {
    bytes: &'a [u8],
    prefix: bool,
}

impl<'a> Pattern<'a> {
    /// 业务作用：把单个尾随星号编译为前缀标志，阻止其它通配声明扩大保护范围。
    ///
    /// 参数说明：
    /// - `raw`：待校验的字面路径或属性值。
    ///
    /// 返回：字面字节及匹配方式。空精确值合法，空前缀或嵌入星号拒绝。
    fn parse(raw: &'a str) -> Result<Self> {
        let prefix = raw.ends_with('*');
        let literal = raw.strip_suffix('*').unwrap_or(raw);
        ensure!(
            raw.len() <= MAX_PATTERN_BYTES
                && !literal.contains('*')
                && (!prefix || !literal.is_empty())
                && !literal.chars().any(char::is_control),
            "invalid Sentinel pattern: expected a literal or a non-empty prefix followed by one *"
        );
        Ok(Self {
            bytes: literal.as_bytes(),
            prefix,
        })
    }
}

impl<T: Default> Trie<T> {
    /// 业务作用：编译 Trie 并复用共同的前缀边及同一终点的规则组。
    ///
    /// 参数说明：
    /// - `pattern`：已校验的字节路径及终点类型。
    ///
    /// 返回：只在构建阶段可变的终点。
    fn entry(&mut self, pattern: Pattern<'_>) -> &mut T {
        if self.nodes.is_empty() {
            self.nodes.push(Node::default());
        }
        let mut at = 0;
        for &byte in pattern.bytes {
            let next = self.nodes.len();
            let index = *self.nodes[at].children.entry(byte).or_insert(next);
            if index == next {
                self.nodes.push(Node::default());
            }
            at = index;
        }
        let node = &mut self.nodes[at];
        if pattern.prefix {
            node.prefix.get_or_insert_with(T::default)
        } else {
            node.exact.get_or_insert_with(T::default)
        }
    }

    /// 业务作用：沿实际请求值的一条路径枚举命中终点，不遍历其它模式分支。
    ///
    /// 参数说明：
    /// - `bytes`：原始或规范化后的请求属性值。
    /// - `found`：接收实际命中终点的函数。
    ///
    /// 返回：前缀在经过终点时匹配；精确模式只在请求值耗尽后匹配。
    fn lookup(&self, bytes: &[u8], mut found: impl FnMut(&T)) {
        let Some(mut node) = self.nodes.first() else {
            return;
        };
        for byte in bytes {
            let Some(&next) = node.children.get(byte) else {
                return;
            };
            node = &self.nodes[next];
            if let Some(prefix) = &node.prefix {
                found(prefix);
            }
        }
        if let Some(exact) = &node.exact {
            found(exact);
        }
    }
}

#[derive(Default)]
struct Target {
    unconditional: Vec<usize>,
    headers: HashMap<HeaderName, Trie<Vec<usize>>>,
    queries: HashMap<String, Trie<Vec<usize>>>,
    cookies: HashMap<String, Trie<Vec<usize>>>,
    attributes: HashMap<LimitReqKey, Trie<Vec<usize>>>,
    has_circuit: bool,
}

impl Target {
    /// 业务作用：把命名条件隔离在各自的字段目录，避免同名 Header、Query 和 Cookie 共享索引。
    ///
    /// 参数说明：
    /// - `key`：已解析的请求属性取值方式。
    ///
    /// 返回：对应属性的可编译 Trie。
    fn attribute(&mut self, key: LimitReqKey) -> &mut Trie<Vec<usize>> {
        match key {
            LimitReqKey::Header(name) => self.headers.entry(name).or_default(),
            LimitReqKey::Query(name) => self.queries.entry(name).or_default(),
            LimitReqKey::Cookie(name) => self.cookies.entry(name).or_default(),
            key => self.attributes.entry(key).or_default(),
        }
    }

    /// 业务作用：只查询请求中实际携带的命名属性，并保持首值语义。
    ///
    /// 参数说明：
    /// - `parts`：提供已通过头部预算的请求。
    /// - `route`：已经选择的路由标识。
    /// - `client_ip`：入口权威确认的客户端地址。
    /// - `indices`：收集实际命中的规则序号。
    ///
    /// 返回：追加实际匹配项；缺失字段和后续重复值不参与匹配。
    fn collect(&self, parts: &Parts, route: &str, client_ip: IpAddr, indices: &mut Vec<usize>) {
        indices.extend(self.unconditional.iter().copied());
        let mut found = |rules: &Vec<usize>| indices.extend(rules.iter().copied());
        if !self.headers.is_empty() {
            for name in parts.headers.keys() {
                if let Some(trie) = self.headers.get(name) {
                    trie.lookup(parts.headers[name].as_bytes(), &mut found);
                }
            }
        }
        if !self.queries.is_empty() {
            if let Some(query) = parts.uri.query() {
                lookup_named(&self.queries, query_pairs(query), &mut found);
            }
        }
        if !self.cookies.is_empty() {
            lookup_named(&self.cookies, cookie_pairs(parts), &mut found);
        }
        for (key, trie) in &self.attributes {
            if let Some(value) = value(parts, route, client_ip, key) {
                trie.lookup(&value, &mut found);
            }
        }
    }
}

/// 业务作用：用请求实际提供的字段查询对应 Trie，避免扫描规则及配置中缺失的字段。
///
/// 参数说明：
/// - `tries`：同一属性类型下按字段名分组的索引。
/// - `fields`：请求中按传输顺序到达的字段和值。
/// - `found`：接收确实匹配的规则集合。
///
/// 返回：只访问已配置字段的首值，并交付实际命中结果。
fn lookup_named<'a>(
    tries: &HashMap<String, Trie<Vec<usize>>>,
    fields: impl Iterator<Item = (&'a str, &'a str)>,
    mut found: impl FnMut(&Vec<usize>),
) {
    let mut seen = HashSet::new();
    for (name, value) in fields {
        if let Some(trie) = tries.get(name).filter(|_| seen.insert(name)) {
            trie.lookup(value.as_bytes(), &mut found);
        }
    }
}

pub(crate) enum Policy {
    Rate(LimitReqPolicy),
    Concurrency(LimitConnPolicy),
    Circuit(CircuitBreakerPolicy),
}

impl Policy {
    /// 业务作用：以编译后的属性标识流控计量字段，使等价配置共用状态、不同字段各自计量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：限速和并发策略的属性类型及规范字段名。熔断按规则统计，无计量字段。
    fn metering_field(&self) -> Option<(&'static str, &str)> {
        let key = match self {
            Self::Rate(policy) => &policy.key,
            Self::Concurrency(policy) => &policy.key,
            Self::Circuit(_) => return None,
        };
        Some(match key {
            LimitReqKey::Global => ("global", ""),
            LimitReqKey::Ip => ("ip", ""),
            LimitReqKey::Route => ("route", ""),
            LimitReqKey::Header(name) => ("header", name.as_str()),
            LimitReqKey::Query(name) => ("query", name.as_str()),
            LimitReqKey::Cookie(name) => ("cookie", name.as_str()),
            LimitReqKey::Host => ("host", ""),
            LimitReqKey::Path => ("path", ""),
        })
    }
}

pub(crate) struct Rule {
    pub(crate) identity: String,
    pub(crate) crosses_routes: bool,
    pub(crate) policy: Policy,
}

#[derive(Default)]
pub(crate) struct RequestRules {
    paths: Trie<Target>,
    routes: HashMap<String, Target>,
    rules: Vec<Rule>,
    index_bytes: usize,
}

/// 业务作用：识别显式路径前缀，把裸路由 ID 保留在原有精确绑定合同中。
///
/// 参数说明：
/// - `binding`：Sentinel 的 `route` 原文。
///
/// 返回：斜杠开头且包含星号时为真，具体合法性由 Trie 编译检查。
pub(crate) fn is_path(binding: &str) -> bool {
    binding.starts_with('/') && binding.contains('*')
}

impl RequestRules {
    /// 业务作用：编译路径与属性条件及业务动作，限定索引开销，按匹配范围和计量字段划分规则状态。
    ///
    /// 参数说明：
    /// - `binding`：精确路由 ID 或斜杠开头的尾随星号路径。
    /// - `id`：同一规则类型内的唯一 ID。
    /// - `selector`：可选的属性值条件。
    /// - `policy`：已经通过原生动作编译器的规则。
    ///
    /// 返回：校验成功后加入候选索引；任何模式、预算或属性错误阻止候选发布。
    pub(super) fn insert(
        &mut self,
        binding: &str,
        id: &str,
        selector: Option<&SentinelValueMatch>,
        policy: Policy,
    ) -> Result<()> {
        self.index_bytes += binding.len() + selector.map_or(0, |s| s.key.len() + s.value.len());
        ensure!(
            self.rules.len() < MAX_RULES && self.index_bytes <= MAX_INDEX_BYTES,
            "Sentinel request rule index exceeds its capacity"
        );
        let crosses_routes = is_path(binding);
        let target = if crosses_routes {
            ensure!(
                !binding.contains(['?', '#']),
                "Sentinel route path must not include a query or fragment"
            );
            self.paths.entry(Pattern::parse(binding)?)
        } else {
            self.routes.entry(binding.to_owned()).or_default()
        };
        target.has_circuit |= matches!(&policy, Policy::Circuit(_));
        let index = self.rules.len();
        if let Some(selector) = selector {
            let key =
                routing::parse_limit_key(&selector.key).context("invalid Sentinel match.key")?;
            ensure!(
                !matches!(key, LimitReqKey::Global),
                "Sentinel match.key cannot be global"
            );
            let pattern = if key == LimitReqKey::Host {
                Cow::Owned(selector.value.trim_end_matches('.').to_ascii_lowercase())
            } else {
                Cow::Borrowed(selector.value.as_str())
            };
            target
                .attribute(key)
                .entry(Pattern::parse(&pattern)?)
                .push(index);
        } else {
            target.unconditional.push(index);
        }
        let (field, pattern) = selector.map_or(("", ""), |s| (s.key.as_str(), s.value.as_str()));
        // 更换匹配范围或计量字段时使用独立状态，避免旧余额参与新规则裁决。
        // 运行中的请求持有原来的租约，归还时继续使用原作用域。
        let metering = policy
            .metering_field()
            .map(|(kind, name)| format!(":meter:{kind}:{}:{name}", name.len()))
            .unwrap_or_default();
        let identity = nasa::crypto::sha256(&format!(
            "{}:{id}{}:{binding}{}:{field}{}:{pattern}{metering}",
            id.len(),
            binding.len(),
            field.len(),
            pattern.len(),
        ));
        self.rules.push(Rule {
            identity,
            crosses_routes,
            policy,
        });
        Ok(())
    }

    /// 业务作用：识别绑定到精确路由的熔断规则，禁止在无上游结果的父层无声丢弃。
    ///
    /// 参数说明：
    /// - `route`：候选父层的路由标识。
    ///
    /// 返回：该路由存在精确绑定的请求条件熔断规则时为真。
    pub(in crate::config) fn has_route_circuit(&self, route: &str) -> bool {
        self.routes
            .get(route)
            .is_some_and(|target| target.has_circuit)
    }

    /// 业务作用：从原始请求头确定可执行的独立规则，重叠路径及属性条件按声明序生效。
    ///
    /// 参数说明：
    /// - `parts`：转发改写前的入口请求。
    /// - `route`：已选定的入口路由 ID。
    /// - `client_ip`：可信代理策略计算出的客户端地址。
    /// - `include_paths`：只有终端路由执行全局路径规则，分支只执行绑定给自己的规则。
    ///
    /// 返回：实际匹配的规则；缺失属性不命中任意模式，空属性仍可精确匹配。
    pub(crate) fn matching<'a>(
        &'a self,
        parts: &Parts,
        route: &str,
        client_ip: IpAddr,
        include_paths: bool,
    ) -> impl Iterator<Item = &'a Rule> {
        let mut indices = Vec::new();
        let mut lookup = |target: &Target| target.collect(parts, route, client_ip, &mut indices);
        if let Some(group) = self.routes.get(route) {
            lookup(group);
        }
        if include_paths {
            self.paths.lookup(parts.uri.path().as_bytes(), lookup);
        }
        indices.sort_unstable();
        indices.into_iter().map(move |index| &self.rules[index])
    }
}

/// 业务作用：统一读取模式和分桶所用的属性值，保留完整值并区分缺失和空值。
///
/// 参数说明：
/// - `parts`：提供请求路径和原始属性。
/// - `route`：已选出的路由身份。
/// - `client_ip`：网关固定的客户端地址。
/// - `key`：构建期解析的取值方式。
///
/// 返回：命中的首个属性原值，Host 规范化，Query 保留原有未解码口径。
pub(crate) fn value<'a>(
    parts: &'a Parts,
    route: &'a str,
    client_ip: IpAddr,
    key: &LimitReqKey,
) -> Option<Cow<'a, [u8]>> {
    match key {
        LimitReqKey::Global => Some(Cow::Borrowed(b"global")),
        LimitReqKey::Ip => Some(Cow::Owned(client_ip.to_string().into_bytes())),
        LimitReqKey::Route => Some(Cow::Borrowed(route.as_bytes())),
        LimitReqKey::Header(name) => parts
            .headers
            .get(name)
            .map(|value| Cow::Borrowed(value.as_bytes())),
        LimitReqKey::Query(name) => routing::query_param_raw(parts.uri.query()?, name)
            .map(|value| Cow::Borrowed(value.as_bytes())),
        LimitReqKey::Cookie(name) => cookie_pairs(parts)
            .find_map(|(key, value)| (key == name).then(|| Cow::Borrowed(value.as_bytes()))),
        LimitReqKey::Host => routing::request_host(parts).map(|host| Cow::Owned(host.into_bytes())),
        LimitReqKey::Path => Some(Cow::Borrowed(parts.uri.path().as_bytes())),
    }
}

/// 业务作用：按原始查询串顺序提取参数，匹配和分桶沿用网关的未解码语义。
///
/// 参数说明：
/// - `query`：不含问号的 URI 查询串。
///
/// 返回：参数和值的借用，只有名字的参数按空值处理。
fn query_pairs(query: &str) -> impl Iterator<Item = (&str, &str)> {
    query
        .split('&')
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
}

/// 业务作用：按 Cookie 字段的传输顺序提取具名值，保持选择与额度使用同一事实。
///
/// 参数说明：
/// - `parts`：可能具有一个或多个 Cookie 请求头。
///
/// 返回：借用有效的名值对，忽略无法作为 Cookie 读取的内容。
fn cookie_pairs(parts: &Parts) -> impl Iterator<Item = (&str, &str)> {
    parts
        .headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(';'))
        .filter_map(|item| item.trim().split_once('='))
}
