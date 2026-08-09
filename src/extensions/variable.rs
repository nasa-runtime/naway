//! V3 nginx `set` / `map` / 变量模板编译层。
//!
//! 配置发布期把 `${...}` 模板编译为 [`ValueTemplate`];数据面只执行已编译计划,
//! 不再逐请求解析表达式或做全串 `replace` 扫描。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use http::header::HeaderName;
use http::request::Parts;

use crate::config::model::{VariableMapCfg, VariablesCfg};
use crate::net::Cidr;

/// 整份快照的变量执行计划。
///
/// `GatewayConfig.variables` 在发布期编译成该结构;route/filter 运行时只调用已编译模板,
/// 避免每请求解析 `${...}` 表达式。header/query allowlist 在这里固化,防止配置误读高基数字段。
#[derive(Clone)]
pub struct VariablePlan {
    sets: HashMap<String, ValueTemplate>,
    maps: Vec<MapPlan>,
    map_index: HashMap<String, usize>,
    allow_any_header: bool,
    allowed_headers: HashSet<HeaderName>,
    allow_any_query: bool,
    allowed_queries: HashSet<String>,
}

/// 一个已编译的字符串模板。
///
/// 无变量的模板会保留 `static_literal`,运行期可以直接复用字面值;含变量的模板拆成
/// literal + var 序列,按 [`EvalContext`] 渲染。
#[derive(Clone)]
pub struct ValueTemplate {
    parts: Arc<[TemplatePart]>,
    static_literal: Option<Arc<str>>,
}

/// 模板片段:静态字面量或一个已校验变量引用。
#[derive(Clone)]
enum TemplatePart {
    Literal(Arc<str>),
    Var(Var),
}

/// Downstream/PostRoute 阶段当前已支持的变量。
#[derive(Clone)]
enum Var {
    RemoteAddr,
    Host,
    Method,
    Uri,
    Path,
    Args,
    Scheme,
    RequestId,
    RouteId,
    Header(HeaderName),
    Query(String),
    Set(String),
    Map(usize),
}

/// 单个 nginx `map` 的编译结果。
#[derive(Clone)]
struct MapPlan {
    source: ValueTemplate,
    table: MapTable,
    default: Arc<str>,
}

/// map 匹配表。所有分支都在构建期完成解析/预编译。
#[derive(Clone)]
enum MapTable {
    /// 精确字符串匹配,热路径 hash 查找。
    Exact(HashMap<String, Arc<str>>),
    /// 前缀匹配,按前缀长度倒序保存,保证先命中最长前缀。
    Prefix(Vec<(String, Arc<str>)>),
    /// glob 匹配,构建期预编译 GlobSet。
    Glob(Arc<GlobSet>, Arc<[Arc<str>]>),
    /// CIDR 匹配,用于 nginx `geo` 的 CIDR -> value 基础语义。
    Cidr(Vec<(Cidr, Arc<str>)>),
}

/// 模板求值上下文。
///
/// 字段全部来自当前请求已确定的 Downstream/PostRoute 信息;后续接 upstream/response 相位变量时,
/// 应扩展上下文并加相位校验,不能在请求头阶段读取响应信息。
pub struct EvalContext<'a> {
    /// 原始下游请求 parts。`proxy_set_header`/动态 upstream 渲染必须读它,避免被后续 Host 改写污染。
    pub parts: &'a Parts,
    /// 按 PROXY protocol / trusted XFF 算出的真实客户端 IP。
    pub client_ip: IpAddr,
    /// 下游协议 scheme,当前取 `http` / `https`。
    pub downstream_proto: &'static str,
    /// 网关生成的权威 request id。
    pub request_id: &'a str,
    /// 当前命中的 route id。
    pub route_id: &'a str,
}

/// 变量模板编译期上下文。
///
/// 用于校验变量名、map 引用、header/query allowlist;不是运行期数据结构。
struct CompileCtx {
    set_names: HashSet<String>,
    map_index: HashMap<String, usize>,
    allow_any_header: bool,
    allowed_headers: HashSet<HeaderName>,
    allow_any_query: bool,
    allowed_queries: HashSet<String>,
    allow_maps: bool,
}

impl VariablePlan {
    /// 从配置构建变量计划。
    ///
    /// # 参数
    /// - `cfg`: 顶层 `variables` 配置,包含 set/map 定义和 header/query allowlist。
    pub fn build(cfg: &VariablesCfg) -> Result<Arc<Self>> {
        let allow_any_header = cfg.allow_headers.iter().any(|h| h == "*");
        let allowed_headers = cfg
            .allow_headers
            .iter()
            .filter(|h| h.as_str() != "*")
            .map(|h| {
                h.parse::<HeaderName>()
                    .with_context(|| format!("variables.allow_headers invalid header `{h}`"))
            })
            .collect::<Result<HashSet<_>>>()?;
        let allow_any_query = cfg.allow_queries.iter().any(|q| q == "*");
        let allowed_queries = cfg
            .allow_queries
            .iter()
            .filter(|q| q.as_str() != "*")
            .map(|q| {
                validate_query_name(q)?;
                Ok(q.clone())
            })
            .collect::<Result<HashSet<_>>>()?;
        let set_names = cfg
            .set
            .keys()
            .map(|name| {
                validate_variable_name(name)?;
                Ok(name.clone())
            })
            .collect::<Result<HashSet<_>>>()?;
        let mut map_index = HashMap::new();
        for (idx, map) in cfg.maps.iter().enumerate() {
            validate_variable_name(&map.name)?;
            if map_index.insert(map.name.clone(), idx).is_some() {
                bail!("duplicate variables.maps name `{}`", map.name);
            }
        }
        let base_ctx = CompileCtx {
            set_names,
            map_index: map_index.clone(),
            allow_any_header,
            allowed_headers,
            allow_any_query,
            allowed_queries,
            allow_maps: true,
        };
        let sets = cfg
            .set
            .iter()
            .map(|(name, raw)| {
                Ok((
                    name.clone(),
                    compile_template(raw, &base_ctx)
                        .with_context(|| format!("variables.set `{name}`"))?,
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        validate_set_cycles(&sets)?;

        let mut source_ctx = base_ctx.clone();
        source_ctx.allow_maps = false;
        let maps = cfg
            .maps
            .iter()
            .map(|map| build_map(map, &source_ctx))
            .collect::<Result<Vec<_>>>()?;

        Ok(Arc::new(Self {
            sets,
            maps,
            map_index,
            allow_any_header: base_ctx.allow_any_header,
            allowed_headers: base_ctx.allowed_headers,
            allow_any_query: base_ctx.allow_any_query,
            allowed_queries: base_ctx.allowed_queries,
        }))
    }

    /// 构建一个空变量计划。
    ///
    /// 用于测试或未配置 `variables` 的默认快照。
    pub fn empty() -> Arc<Self> {
        Self::build(&VariablesCfg::default()).expect("default variable plan")
    }

    /// 编译一个可引用本计划变量的字符串模板。
    ///
    /// # 参数
    /// - `raw`: 原始模板字符串,例如 `"${remote_addr}-${map.tenant}"`。
    pub fn compile_template(&self, raw: &str) -> Result<ValueTemplate> {
        let ctx = CompileCtx {
            set_names: self.sets.keys().cloned().collect(),
            map_index: self.map_index.clone(),
            allow_any_header: self.allow_any_header,
            allowed_headers: self.allowed_headers.clone(),
            allow_any_query: self.allow_any_query,
            allowed_queries: self.allowed_queries.clone(),
            allow_maps: true,
        };
        compile_template(raw, &ctx)
    }
}

impl ValueTemplate {
    /// 业务作用：为经过外部协议校验的字面量构造不参与 `${...}` 展开的模板，避免控制面值
    /// 被误解释为 Naway 配置变量。
    ///
    /// 参数说明：`value` 是已按调用方协议边界验证的原始字面量。
    ///
    /// 返回：返回始终原样渲染且可走静态快路径的模板。
    pub(crate) fn literal(value: &str) -> Self {
        Self {
            parts: Arc::from([TemplatePart::Literal(Arc::from(value))]),
            static_literal: Some(Arc::from(value)),
        }
    }

    /// 按当前请求上下文渲染模板。
    ///
    /// # 参数
    /// - `ctx`: 当前请求的变量求值上下文。
    /// - `plan`: 模板所属的变量计划,用于解析 set/map 间接引用。
    pub fn render(&self, ctx: &EvalContext<'_>, plan: &VariablePlan) -> String {
        self.render_with_depth(ctx, plan, 0)
    }

    /// 若模板是纯字面量,返回该字面量。
    ///
    /// 静态 header/upstream 可借此跳过运行期渲染。
    pub fn static_literal(&self) -> Option<&str> {
        self.static_literal.as_deref()
    }

    /// 带递归深度保护的内部渲染入口。
    ///
    /// # 参数
    /// - `ctx`: 当前请求上下文。
    /// - `plan`: 当前变量计划。
    /// - `depth`: set/map 间接求值深度,防止异常递归拖垮请求。
    fn render_with_depth(
        &self,
        ctx: &EvalContext<'_>,
        plan: &VariablePlan,
        depth: usize,
    ) -> String {
        if let Some(value) = &self.static_literal {
            return value.to_string();
        }
        if depth > 16 {
            return String::new();
        }
        let mut out = String::new();
        for part in self.parts.iter() {
            match part {
                TemplatePart::Literal(value) => out.push_str(value),
                TemplatePart::Var(var) => render_var(var, ctx, plan, depth + 1, &mut out),
            }
        }
        out
    }

    /// 枚举该模板直接引用的 set 名称,用于构建期循环检测。
    fn set_deps(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().filter_map(|part| match part {
            TemplatePart::Var(Var::Set(name)) => Some(name.as_str()),
            _ => None,
        })
    }
}

impl Default for ValueTemplate {
    fn default() -> Self {
        Self {
            parts: Arc::from([]),
            static_literal: Some(Arc::from("")),
        }
    }
}

impl Clone for CompileCtx {
    fn clone(&self) -> Self {
        Self {
            set_names: self.set_names.clone(),
            map_index: self.map_index.clone(),
            allow_any_header: self.allow_any_header,
            allowed_headers: self.allowed_headers.clone(),
            allow_any_query: self.allow_any_query,
            allowed_queries: self.allowed_queries.clone(),
            allow_maps: self.allow_maps,
        }
    }
}

/// 编译原始模板为 [`ValueTemplate`]。
///
/// # 参数
/// - `raw`: 配置中的原始模板。
/// - `ctx`: 编译期变量上下文,负责校验可引用变量集合。
fn compile_template(raw: &str, ctx: &CompileCtx) -> Result<ValueTemplate> {
    if !raw.contains("${") {
        return Ok(ValueTemplate {
            parts: Arc::from([TemplatePart::Literal(Arc::from(raw))]),
            static_literal: Some(Arc::from(raw)),
        });
    }
    let mut parts = Vec::new();
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        if start > 0 {
            parts.push(TemplatePart::Literal(Arc::from(&rest[..start])));
        }
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            bail!("unclosed variable template in `{raw}`");
        };
        let name = after_start[..end].trim();
        if name.is_empty() {
            bail!("empty variable template in `{raw}`");
        }
        parts.push(TemplatePart::Var(parse_var(name, ctx)?));
        rest = &after_start[end + 1..];
    }
    if !rest.is_empty() {
        parts.push(TemplatePart::Literal(Arc::from(rest)));
    }
    Ok(ValueTemplate {
        parts: Arc::from(parts),
        static_literal: None,
    })
}

/// 把 `${name}` 解析成强类型变量。
///
/// # 参数
/// - `name`: 去掉 `${}` 后的变量名。
/// - `ctx`: 编译期上下文,用于校验 allowlist 和 map/set 存在性。
fn parse_var(name: &str, ctx: &CompileCtx) -> Result<Var> {
    match name {
        "remote_addr" => return Ok(Var::RemoteAddr),
        "host" => return Ok(Var::Host),
        "method" | "request_method" => return Ok(Var::Method),
        "uri" | "request_uri" => return Ok(Var::Uri),
        "path" => return Ok(Var::Path),
        "args" | "query_string" => return Ok(Var::Args),
        "scheme" => return Ok(Var::Scheme),
        "request_id" => return Ok(Var::RequestId),
        "route_id" => return Ok(Var::RouteId),
        _ => {}
    }
    if let Some(header) = name.strip_prefix("header.") {
        let header_name = header
            .parse::<HeaderName>()
            .with_context(|| format!("invalid header variable `{name}`"))?;
        if !ctx.allow_any_header && !ctx.allowed_headers.contains(&header_name) {
            bail!("header variable `{name}` is not in variables.allow_headers");
        }
        return Ok(Var::Header(header_name));
    }
    if let Some(query) = name.strip_prefix("query.") {
        validate_query_name(query)?;
        if !ctx.allow_any_query && !ctx.allowed_queries.contains(query) {
            bail!("query variable `{name}` is not in variables.allow_queries");
        }
        return Ok(Var::Query(query.to_string()));
    }
    if let Some(map) = name.strip_prefix("map.") {
        if !ctx.allow_maps {
            bail!("map source must not reference another map `{name}`");
        }
        let Some(idx) = ctx.map_index.get(map) else {
            bail!("unknown map variable `{name}`");
        };
        return Ok(Var::Map(*idx));
    }
    if ctx.set_names.contains(name) {
        return Ok(Var::Set(name.to_string()));
    }
    bail!("unknown variable `{name}`")
}

/// 将单个变量写入输出缓冲。
///
/// # 参数
/// - `var`: 已编译变量。
/// - `ctx`: 当前请求上下文。
/// - `plan`: 当前变量计划。
/// - `depth`: 递归深度,用于保护 set/map 间接引用。
/// - `out`: 渲染输出缓冲。
fn render_var(
    var: &Var,
    ctx: &EvalContext<'_>,
    plan: &VariablePlan,
    depth: usize,
    out: &mut String,
) {
    match var {
        Var::RemoteAddr => out.push_str(&ctx.client_ip.to_string()),
        Var::Host => out.push_str(
            ctx.parts
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
        ),
        Var::Method => out.push_str(ctx.parts.method.as_str()),
        Var::Uri => out.push_str(
            ctx.parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or_else(|| ctx.parts.uri.path()),
        ),
        Var::Path => out.push_str(ctx.parts.uri.path()),
        Var::Args => out.push_str(ctx.parts.uri.query().unwrap_or_default()),
        Var::Scheme => out.push_str(ctx.downstream_proto),
        Var::RequestId => out.push_str(ctx.request_id),
        Var::RouteId => out.push_str(ctx.route_id),
        Var::Header(name) => out.push_str(
            ctx.parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
        ),
        Var::Query(name) => out.push_str(
            query_param(ctx.parts.uri.query().unwrap_or_default(), name).unwrap_or_default(),
        ),
        Var::Set(name) => {
            if let Some(template) = plan.sets.get(name) {
                out.push_str(&template.render_with_depth(ctx, plan, depth));
            }
        }
        Var::Map(idx) => {
            if let Some(map) = plan.maps.get(*idx) {
                let key = map.source.render_with_depth(ctx, plan, depth);
                out.push_str(map.lookup(&key));
            }
        }
    }
}

impl MapPlan {
    /// 查找 map 输出值。
    ///
    /// # 参数
    /// - `key`: source 模板渲染出的匹配 key。
    fn lookup(&self, key: &str) -> &str {
        match &self.table {
            MapTable::Exact(entries) => entries
                .get(key)
                .map(|v| v.as_ref())
                .unwrap_or(self.default.as_ref()),
            MapTable::Prefix(entries) => entries
                .iter()
                .find(|(prefix, _)| key.starts_with(prefix))
                .map(|(_, value)| value.as_ref())
                .unwrap_or(self.default.as_ref()),
            MapTable::Glob(globset, values) => globset
                .matches(key)
                .into_iter()
                .next()
                .and_then(|idx| values.get(idx))
                .map(|value| value.as_ref())
                .unwrap_or(self.default.as_ref()),
            MapTable::Cidr(entries) => key
                .parse::<IpAddr>()
                .ok()
                .and_then(|ip| {
                    entries
                        .iter()
                        .find(|(cidr, _)| cidr.contains(ip))
                        .map(|(_, value)| value.as_ref())
                })
                .unwrap_or(self.default.as_ref()),
        }
    }
}

/// 构建单个 map 计划。
///
/// # 参数
/// - `cfg`: map 配置项。
/// - `ctx`: 编译期上下文;map source 当前不允许引用另一个 map。
fn build_map(cfg: &VariableMapCfg, ctx: &CompileCtx) -> Result<MapPlan> {
    if cfg.entries.is_empty() {
        bail!("variables.maps `{}` requires entries", cfg.name);
    }
    let source = compile_template(&cfg.source, ctx)
        .with_context(|| format!("variables.maps `{}` source", cfg.name))?;
    let table =
        match cfg.match_type.as_str() {
            "" | "exact" => MapTable::Exact(
                cfg.entries
                    .iter()
                    .map(|(k, v)| (k.clone(), Arc::from(v.as_str())))
                    .collect(),
            ),
            "prefix" => {
                let mut entries = cfg
                    .entries
                    .iter()
                    .map(|(k, v)| (k.clone(), Arc::from(v.as_str())))
                    .collect::<Vec<_>>();
                entries.sort_by(|left, right| {
                    right
                        .0
                        .len()
                        .cmp(&left.0.len())
                        .then_with(|| left.0.cmp(&right.0))
                });
                MapTable::Prefix(entries)
            }
            "glob" => {
                let mut builder = GlobSetBuilder::new();
                let mut values = Vec::with_capacity(cfg.entries.len());
                let mut entries = cfg.entries.iter().collect::<Vec<_>>();
                entries.sort_by_key(|(pattern, _)| *pattern);
                for (pattern, value) in entries {
                    builder.add(Glob::new(pattern).with_context(|| {
                        format!("variables.maps `{}` glob `{pattern}`", cfg.name)
                    })?);
                    values.push(Arc::from(value.as_str()));
                }
                MapTable::Glob(
                    Arc::new(
                        builder
                            .build()
                            .with_context(|| format!("variables.maps `{}` globset", cfg.name))?,
                    ),
                    Arc::from(values),
                )
            }
            "cidr" | "geo" => {
                let mut entries = Vec::with_capacity(cfg.entries.len());
                for (cidr, value) in &cfg.entries {
                    let parsed = Cidr::parse(cidr)
                        .with_context(|| format!("variables.maps `{}` cidr `{cidr}`", cfg.name))?;
                    if entries
                        .iter()
                        .any(|(existing, _): &(Cidr, Arc<str>)| existing == &parsed)
                    {
                        bail!(
                            "variables.maps `{}` duplicate normalized cidr `{cidr}`",
                            cfg.name
                        );
                    }
                    entries.push((parsed, Arc::from(value.as_str())));
                }
                // CIDR 规则存在重叠时必须稳定选择最长前缀,否则 HashMap 迭代顺序会让 geo 结果不可解释。
                entries.sort_by_key(|(cidr, _)| std::cmp::Reverse(cidr.prefix_bits()));
                MapTable::Cidr(entries)
            }
            "regex" => bail!("variables.maps `{}` regex match is not enabled", cfg.name),
            other => bail!(
                "variables.maps `{}` unsupported match_type `{other}` (exact|prefix|glob|cidr)",
                cfg.name
            ),
        };
    Ok(MapPlan {
        source,
        table,
        default: Arc::from(cfg.default.as_str()),
    })
}

/// 检查 `variables.set` 是否存在循环引用。
///
/// # 参数
/// - `sets`: 已编译的 set 模板表。
fn validate_set_cycles(sets: &HashMap<String, ValueTemplate>) -> Result<()> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        Visiting,
        Done,
    }
    fn visit(
        name: &str,
        sets: &HashMap<String, ValueTemplate>,
        marks: &mut HashMap<String, Mark>,
    ) -> Result<()> {
        match marks.get(name) {
            Some(Mark::Done) => return Ok(()),
            Some(Mark::Visiting) => bail!("variables.set cycle contains `{name}`"),
            None => {}
        }
        marks.insert(name.to_string(), Mark::Visiting);
        if let Some(template) = sets.get(name) {
            for dep in template.set_deps() {
                visit(dep, sets, marks)?;
            }
        }
        marks.insert(name.to_string(), Mark::Done);
        Ok(())
    }
    let mut marks = HashMap::new();
    for name in sets.keys() {
        visit(name, sets, &mut marks)?;
    }
    Ok(())
}

/// 校验变量名,避免奇怪字符进入模板命名空间。
///
/// # 参数
/// - `name`: 待校验变量名。
fn validate_variable_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        bail!("invalid variable name `{name}`");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("invalid variable name `{name}`");
    }
    Ok(())
}

/// 校验 query 变量名。
///
/// # 参数
/// - `name`: query 参数名。
fn validate_query_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        bail!("invalid query variable `{name}`");
    }
    if name.bytes().any(|b| b == b'&' || b == b'=' || b < 0x20) {
        bail!("invalid query variable `{name}`");
    }
    Ok(())
}

/// 从原始 query 字符串中取未解码参数值。
///
/// # 参数
/// - `query`: URI 中 `?` 后的原始 query。
/// - `name`: 待查找参数名。
fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            Some(v)
        } else {
            None
        }
    })
}

#[path = "../../tests/unit/variable.rs"]
#[cfg(test)]
mod tests;
