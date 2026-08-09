//! 路由断言 + DSL 解析。支持低成本 `Path`/`Host`/`Method` 组合,复杂正则默认不进入热路径。

use std::str::FromStr;

use anyhow::{bail, Context, Result};
use globset::{Glob, GlobMatcher};
use http::header::HeaderName;
use http::request::Parts;
use http::{header, Method};
use regex::Regex;

/// 路由断言:决定请求是否命中某条路由。
pub enum Predicate {
    /// `Path=/api/`:路径前缀匹配;`Path=/api/**` 会在解析期转成 glob。
    PathPrefix(String),
    /// `PathElementPrefix=/api`：按 `/` 分隔的完整 path element 前缀匹配。
    PathElementPrefix(String),
    /// `PathExact=/api/order`:路径精确匹配。
    PathExact(String),
    /// `PathGlob=/api/**`:预编译 glob 匹配。
    PathGlob {
        /// 用于冲突诊断和稳定签名的原始表达式。
        raw: String,
        /// 构建期生成、请求期只读的 glob matcher。
        matcher: GlobMatcher,
    },
    /// `PathTemplate=/pets/{id}`：OpenAPI segment 模板；变量只匹配一个非空 path segment。
    PathTemplate {
        /// 归一化模板签名，用于冲突检测。
        signature: String,
        /// 构建期拆分的 path segment 序列。
        segments: Vec<PathTemplateSegment>,
    },
    /// `Method=GET,POST`:方法命中其一。
    Method(Vec<Method>),
    /// `Host=api.example.com,*.example.com`:Host 精确或后缀匹配。
    Host(Vec<HostPattern>),
    /// `Header=<name>,<op>[,<value>]`:请求头断言(P0-1 gRPC L7 声明式分流)。
    ///
    /// 构建期把 header 名编译成 [`HeaderName`],请求期只做借用比较——不建 map、不分配、
    /// 热路径无 regex。多值语义显式定义在 [`HeaderOp`]。
    Header {
        /// 已归一化(小写)的 header 名。
        name: HeaderName,
        /// 比较算子与期望值。
        op: HeaderOp,
    },
    /// `Query=<name>,<op>,<value>`：解码后的 URI query 参数断言。
    ///
    /// 同名参数按“任一值命中”处理；名称和值都按 URL form 规则 percent-decode，
    /// 因此 Gateway API 的 HTTPQueryParamMatch 不会拿原始转义文本误判业务值。
    Query {
        /// 区分大小写的 query 参数名。
        name: Box<str>,
        /// 精确或正则比较算子。
        op: ValueOp,
    },
    /// `Weight=checkout,20`：同组、同一非权重断言集合中的加权灰度份额。
    ///
    /// 该断言由 [`Router`](super::Router) 成组选择；这里不自行取随机数，确保一个请求只做
    /// 一次稳定哈希，并避免每条候选 route 各自抽样造成“全部不命中/多条同时命中”。
    Weight {
        /// 互斥灰度候选组名。
        group: String,
        /// 相对于同组候选总权重的非负份额。
        weight: u32,
    },
}

/// Header 断言算子。
///
/// **多值语义(反 header smuggling)**:HTTP 允许同名 header 出现多次。`exact`/`prefix`
/// 采用"**任一值命中即命中**",与 `present` 一致;`absent` 则要求**一个都不存在**。
/// 绝不把多值拼接后再匹配——拼接会让 `a` + `b` 被 `a,b` 这样的表达式命中,
/// 是典型的 header smuggling 模糊面。
///
/// **大小写**:header 名按 HTTP 规范大小写不敏感(构建期归一化为小写);**值大小写敏感**,
/// 因为值是业务数据(如 tenant id、灰度标签),擅自忽略大小写会让 `A` 与 `a` 串路由。
pub enum HeaderOp {
    /// `exact`:任一值与期望值逐字节相等。
    Exact(Box<str>),
    /// `prefix`:任一值以期望值开头。
    Prefix(Box<str>),
    /// `regex`：构建期编译、请求期匹配任一 header 值。
    Regex {
        /// 稳定签名保留原始表达式。
        raw: Box<str>,
        /// 构建期编译结果。
        matcher: Regex,
    },
    /// `present`:该 header 至少出现一次(值任意,含空值)。
    Present,
    /// `absent`:该 header 一次都没出现。
    Absent,
}

/// query 参数值比较算子。
pub enum ValueOp {
    /// 解码后逐字节精确相等。
    Exact(Box<str>),
    /// 构建期编译的正则表达式。
    Regex {
        /// 稳定签名保留原始表达式。
        raw: Box<str>,
        /// 构建期编译结果。
        matcher: Regex,
    },
}

/// 已归一化的 Host 断言。
pub enum HostPattern {
    /// ASCII 大小写不敏感的精确主机名。
    Exact(String),
    /// 通配 `*.example.com` 编译得到的点边界后缀。
    Suffix(String),
}

impl Predicate {
    /// 业务作用：在请求热路径执行构建期已验证的单个路由断言。
    ///
    /// 参数说明：`parts` 是只读请求 head，不读取或聚合 body。
    ///
    /// 返回：请求满足该断言时为 true；不匹配或缺少所需字段时为 false，且不分配业务状态。
    pub(crate) fn matches(&self, parts: &Parts) -> bool {
        match self {
            Predicate::PathPrefix(p) => parts.uri.path().starts_with(p.as_str()),
            Predicate::PathElementPrefix(p) => path_element_prefix_matches(p, parts.uri.path()),
            Predicate::PathExact(p) => parts.uri.path() == p,
            Predicate::PathGlob { matcher, .. } => matcher.is_match(parts.uri.path()),
            Predicate::PathTemplate { segments, .. } => {
                path_template_matches(segments, parts.uri.path())
            }
            Predicate::Method(ms) => ms.contains(&parts.method),
            Predicate::Host(patterns) => request_host(parts)
                .map(|host| patterns.iter().any(|p| p.matches(&host)))
                .unwrap_or(false),
            // 只读 request head:借用 header 值切片比较,不 collect、不分配、不碰 body。
            Predicate::Header { name, op } => {
                let mut values = parts.headers.get_all(name).iter();
                match op {
                    HeaderOp::Present => values.next().is_some(),
                    HeaderOp::Absent => values.next().is_none(),
                    // 非 UTF-8(或含不可见字节)的值一律不算命中:路由不猜测二进制语义。
                    HeaderOp::Exact(expected) => {
                        values.any(|value| value.as_bytes() == expected.as_bytes())
                    }
                    HeaderOp::Prefix(expected) => {
                        values.any(|value| value.as_bytes().starts_with(expected.as_bytes()))
                    }
                    HeaderOp::Regex { matcher, .. } => values
                        .filter_map(|value| value.to_str().ok())
                        .any(|value| matcher.is_match(value)),
                }
            }
            Predicate::Query { name, op } => parts
                .uri
                .query()
                .into_iter()
                .flat_map(|query| form_urlencoded::parse(query.as_bytes()))
                .filter(|(actual, _)| actual.as_ref() == name.as_ref())
                .any(|(_, value)| match op {
                    ValueOp::Exact(expected) => value.as_ref() == expected.as_ref(),
                    ValueOp::Regex { matcher, .. } => matcher.is_match(value.as_ref()),
                }),
            // Weight 必须由 Router 在全部同组候选之间统一选择。普通 predicate 扫描把它视为
            // 已满足，避免为了跳过该枚举在每请求构造临时候选 predicate slice。
            Predicate::Weight { .. } => true,
        }
    }

    /// 业务作用：为冲突检测和带权路由分组生成规范化断言签名。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回稳定 DSL 字符串；相同运行语义得到相同签名。
    pub(crate) fn signature(&self) -> String {
        match self {
            Predicate::PathPrefix(p) => format!("Path={p}"),
            Predicate::PathElementPrefix(p) => format!("PathElementPrefix={p}"),
            Predicate::PathExact(p) => format!("PathExact={p}"),
            Predicate::PathGlob { raw, .. } => format!("PathGlob={raw}"),
            Predicate::PathTemplate { signature, .. } => {
                format!("PathTemplate={signature}")
            }
            Predicate::Method(ms) => {
                let mut methods = ms.iter().map(|m| m.as_str()).collect::<Vec<_>>();
                methods.sort_unstable();
                format!("Method={}", methods.join(","))
            }
            Predicate::Host(patterns) => {
                let mut hosts = patterns
                    .iter()
                    .map(HostPattern::signature)
                    .collect::<Vec<_>>();
                hosts.sort_unstable();
                format!("Host={}", hosts.join(","))
            }
            Predicate::Header { name, op } => match op {
                HeaderOp::Exact(value) => format!("Header={},exact,{value}", name.as_str()),
                HeaderOp::Prefix(value) => format!("Header={},prefix,{value}", name.as_str()),
                HeaderOp::Regex { raw, .. } => format!("Header={},regex,{raw}", name.as_str()),
                HeaderOp::Present => format!("Header={},present", name.as_str()),
                HeaderOp::Absent => format!("Header={},absent", name.as_str()),
            },
            Predicate::Query { name, op } => match op {
                ValueOp::Exact(value) => format!("Query={name},exact,{value}"),
                ValueOp::Regex { raw, .. } => format!("Query={name},regex,{raw}"),
            },
            Predicate::Weight { group, weight } => format!("Weight={group},{weight}"),
        }
    }
}

impl HostPattern {
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => host.eq_ignore_ascii_case(expected),
            Self::Suffix(suffix) => host.ends_with(suffix),
        }
    }

    fn signature(&self) -> String {
        match self {
            Self::Exact(host) => host.clone(),
            Self::Suffix(suffix) => format!("*{suffix}"),
        }
    }
}

/// 业务作用：把声明式路由断言编译成请求热路径可直接执行的只读匹配器。
///
/// 参数说明：`spec` 是配置或控制面生成的单条 predicate DSL。
///
/// 返回：语法和边界合法时返回编译结果；未知类型、非法名称或危险表达式返回错误并阻止发布快照。
pub(crate) fn parse_predicate(spec: &str) -> Result<Predicate> {
    let (name, args) = spec.split_once('=').unwrap_or((spec, ""));
    match name.trim() {
        "Path" => parse_path(args.trim()),
        "PathElementPrefix" => parse_path_element_prefix(args.trim()),
        "PathExact" => Ok(Predicate::PathExact(args.trim().to_string())),
        "PathGlob" => parse_path_glob(args.trim()),
        "PathTemplate" => parse_path_template(args.trim()),
        "Method" => {
            let ms = args
                .split(',')
                .map(|s| Method::from_str(s.trim()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .with_context(|| format!("invalid Method predicate `{args}`"))?;
            Ok(Predicate::Method(ms))
        }
        "Host" => {
            let patterns = args
                .split(',')
                .map(|s| parse_host_pattern(s.trim()))
                .collect::<Result<Vec<_>>>()?;
            if patterns.is_empty() {
                bail!("Host predicate requires at least one host");
            }
            Ok(Predicate::Host(patterns))
        }
        "Header" => parse_header(args),
        "Query" => parse_query(args),
        "Weight" => parse_weight(args.trim()),
        other => bail!("unsupported predicate `{other}` (supports Path / PathElementPrefix / PathExact / PathGlob / PathTemplate / Method / Host / Header / Query / Weight)"),
    }
}

/// 业务作用：执行 Gateway API/Kubernetes Ingress 的完整 path element 前缀语义，
/// 防止 `/v2` 意外匹配 `/v2example`。
///
/// 参数说明：`prefix` 是构建期已去除非根尾斜杠的绝对路径；`path` 是请求 URI path。
///
/// 返回：两者相等，或请求在 prefix 后紧接 `/` 时为 true；根前缀匹配所有绝对路径。
fn path_element_prefix_matches(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// header 名字节上限(HTTP/2 HPACK 场景下的合理上界;超长名多半是配置笔误或攻击面)。
const MAX_HEADER_NAME_BYTES: usize = 128;
/// header 期望值字节上限:断言值是路由标签,不是业务载荷。
const MAX_HEADER_VALUE_BYTES: usize = 256;

/// `Header=<name>,<op>[,<value>]` → Predicate。
///
/// 值里允许出现逗号(只按前两个逗号切分),因此 `Header=x-tag,exact,a,b` 的期望值是 `a,b`。
/// `present`/`absent` 不接受值参数——给了就是语义矛盾,构建期直接拒绝而不是静默忽略。
fn parse_header(raw: &str) -> Result<Predicate> {
    let (name, rest) = raw.split_once(',').with_context(|| {
        format!("Header predicate `{raw}` requires `Header=<name>,<op>[,<value>]`")
    })?;
    let name = name.trim();
    anyhow::ensure!(
        !name.is_empty() && name.len() <= MAX_HEADER_NAME_BYTES,
        "Header predicate name must be 1..={MAX_HEADER_NAME_BYTES} bytes"
    );
    // HeaderName 解析同时完成合法性校验与小写归一化(HTTP 名大小写不敏感)。
    let name = HeaderName::from_bytes(name.as_bytes())
        .with_context(|| format!("Header predicate `{name}` is not a valid HTTP header name"))?;
    let (op, value) = match rest.split_once(',') {
        Some((op, value)) => (op.trim(), Some(value)),
        None => (rest.trim(), None),
    };
    let require_value = |value: Option<&str>| -> Result<Box<str>> {
        let value = value.with_context(|| {
            format!(
                "Header predicate `{}` with op `{op}` requires a value",
                name.as_str()
            )
        })?;
        anyhow::ensure!(
            !value.is_empty() && value.len() <= MAX_HEADER_VALUE_BYTES,
            "Header predicate value must be 1..={MAX_HEADER_VALUE_BYTES} bytes"
        );
        // 值必须是可见 ASCII:控制字符/CR/LF 进断言等于给 header 注入留模糊面。
        anyhow::ensure!(
            value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
            "Header predicate value must be printable ASCII without control characters"
        );
        Ok(Box::from(value))
    };
    let op = match op {
        "exact" => HeaderOp::Exact(require_value(value)?),
        "prefix" => HeaderOp::Prefix(require_value(value)?),
        "regex" => {
            let raw = require_value(value)?;
            let matcher = Regex::new(raw.as_ref())
                .with_context(|| format!("Header predicate regex `{raw}` is invalid"))?;
            HeaderOp::Regex { raw, matcher }
        }
        "present" | "absent" => {
            anyhow::ensure!(
                value.is_none(),
                "Header predicate op `{op}` must not take a value"
            );
            if op == "present" {
                HeaderOp::Present
            } else {
                HeaderOp::Absent
            }
        }
        other => bail!(
            "unsupported Header predicate op `{other}` (supports exact / prefix / regex / present / absent)"
        ),
    };
    Ok(Predicate::Header { name, op })
}

/// 业务作用：编译 Gateway API 等控制面来源的 query 参数断言，并锁定解码后多值语义。
///
/// 参数说明：`raw` 使用 `<name>,exact|regex,<value>` 形态，值允许包含逗号。
///
/// 返回：名称、值与正则均合法时返回匹配器；空值、控制字符或超限输入返回错误。
fn parse_query(raw: &str) -> Result<Predicate> {
    let (name, rest) = raw
        .split_once(',')
        .with_context(|| format!("Query predicate `{raw}` requires `Query=<name>,<op>,<value>`"))?;
    let name = name.trim();
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= MAX_HEADER_NAME_BYTES
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
            }),
        "Query predicate name must be 1..={MAX_HEADER_NAME_BYTES} URL-safe bytes"
    );
    let (op, value) = rest
        .split_once(',')
        .with_context(|| format!("Query predicate `{raw}` requires `Query=<name>,<op>,<value>`"))?;
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= MAX_HEADER_VALUE_BYTES
            && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "Query predicate value must be 1..={MAX_HEADER_VALUE_BYTES} printable ASCII bytes"
    );
    let op = match op.trim() {
        "exact" => ValueOp::Exact(Box::from(value)),
        "regex" => ValueOp::Regex {
            raw: Box::from(value),
            matcher: Regex::new(value)
                .with_context(|| format!("Query predicate regex `{value}` is invalid"))?,
        },
        other => bail!("unsupported Query predicate op `{other}` (supports exact / regex)"),
    };
    Ok(Predicate::Query {
        name: Box::from(name),
        op,
    })
}

fn parse_weight(raw: &str) -> Result<Predicate> {
    let Some((group, weight)) = raw.split_once(',') else {
        bail!("Weight predicate requires `Weight=<group>,<weight>`");
    };
    let group = group.trim();
    anyhow::ensure!(
        !group.is_empty()
            && group.len() <= 64
            && group
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "Weight group must be 1..=64 safe ASCII bytes"
    );
    let weight = weight
        .trim()
        .parse::<u32>()
        .with_context(|| format!("invalid Weight value `{weight}`"))?;
    anyhow::ensure!(weight <= 1_000_000, "Weight value must be <= 1000000");
    Ok(Predicate::Weight {
        group: group.to_owned(),
        weight,
    })
}

/// 构建期拆分后的 OpenAPI path-template segment。
pub enum PathTemplateSegment {
    /// 必须逐字匹配的静态 segment。
    Literal(String),
    /// 匹配任意一个非空 segment 的变量占位符。
    Variable,
}

fn parse_path_template(raw: &str) -> Result<Predicate> {
    if raw == "/" {
        return Ok(Predicate::PathTemplate {
            signature: raw.to_owned(),
            segments: Vec::new(),
        });
    }
    let tail = raw
        .strip_prefix('/')
        .with_context(|| format!("path template `{raw}` must start with /"))?;
    if tail.is_empty() || tail.ends_with('/') {
        bail!("path template `{raw}` must not contain an empty trailing segment");
    }
    let mut segments = Vec::new();
    let mut signature = String::with_capacity(raw.len());
    for segment in tail.split('/') {
        if segment.is_empty() {
            bail!("path template `{raw}` must not contain empty segments");
        }
        signature.push('/');
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            {
                bail!("path template `{raw}` contains invalid parameter `{name}`");
            }
            signature.push_str("{}");
            segments.push(PathTemplateSegment::Variable);
        } else {
            if segment
                .chars()
                .any(|character| matches!(character, '{' | '}' | '*' | '?'))
            {
                bail!("path template `{raw}` contains an invalid literal segment");
            }
            signature.push_str(segment);
            segments.push(PathTemplateSegment::Literal(segment.to_owned()));
        }
    }
    Ok(Predicate::PathTemplate {
        signature,
        segments,
    })
}

/// OpenAPI 模板匹配直接借用 URI path 分段，不构造参数 map；参数提取只在显式
/// request-validation 慢路径中进行。这样门户生成路由的常规匹配仍保持零分配。
fn path_template_matches(segments: &[PathTemplateSegment], path: &str) -> bool {
    if segments.is_empty() {
        return path == "/";
    }
    let Some(tail) = path.strip_prefix('/') else {
        return false;
    };
    let mut actual = tail.split('/');
    for expected in segments {
        let Some(segment) = actual.next() else {
            return false;
        };
        if segment.is_empty()
            || matches!(expected, PathTemplateSegment::Literal(value) if value != segment)
        {
            return false;
        }
    }
    actual.next().is_none()
}

fn parse_path(args: &str) -> Result<Predicate> {
    if args.contains('*') || args.contains('?') {
        parse_path_glob(args)
    } else {
        Ok(Predicate::PathPrefix(args.to_string()))
    }
}

/// 业务作用：把控制面生成的 element-prefix DSL 编译为无正则的边界匹配器。
///
/// 参数说明：`args` 是绝对 path prefix，非根路径允许尾斜杠并会被规范化。
///
/// 返回：合法、无 glob 元字符且不含 query/fragment 的前缀返回断言；非法配置阻止快照发布。
fn parse_path_element_prefix(args: &str) -> Result<Predicate> {
    anyhow::ensure!(
        args.starts_with('/')
            && args.len() <= 2048
            && !args.chars().any(|value| matches!(value, '*' | '?' | '#'))
            && !args.bytes().any(|byte| byte < 0x20),
        "PathElementPrefix must be an origin path without glob/query/fragment syntax"
    );
    let normalized = if args == "/" {
        "/"
    } else {
        args.trim_end_matches('/')
    };
    Ok(Predicate::PathElementPrefix(normalized.to_owned()))
}

fn parse_path_glob(args: &str) -> Result<Predicate> {
    let glob = Glob::new(args).with_context(|| format!("invalid path glob `{args}`"))?;
    Ok(Predicate::PathGlob {
        raw: args.to_string(),
        matcher: glob.compile_matcher(),
    })
}

fn parse_host_pattern(raw: &str) -> Result<HostPattern> {
    if raw.is_empty() {
        bail!("empty Host pattern");
    }
    let host = raw.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = host.strip_prefix("*.") {
        Ok(HostPattern::Suffix(format!(".{rest}")))
    } else if host.contains('*') || host.contains('?') {
        bail!("Host predicate only supports exact host or leading wildcard `*.example.com`");
    } else {
        Ok(HostPattern::Exact(host))
    }
}

fn request_host(parts: &Parts) -> Option<String> {
    let raw = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| parts.uri.authority().map(|a| a.as_str()))?;
    let host = raw
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(raw)
        .split(':')
        .next()
        .unwrap_or(raw)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    Some(host)
}

/// `"StripPrefix=2"` → Some(2);非 StripPrefix 过滤器返回 None(R1 暂只实现 StripPrefix)。
pub(crate) fn parse_strip_prefix(spec: &str) -> Result<Option<usize>> {
    let (name, args) = spec.split_once('=').unwrap_or((spec, ""));
    if name.trim() == "StripPrefix" {
        let n = args
            .trim()
            .parse::<usize>()
            .with_context(|| format!("invalid StripPrefix `{args}`"))?;
        Ok(Some(n))
    } else {
        Ok(None)
    }
}
