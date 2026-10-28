//! 严格来源模型只接受已定义的配置面，不把 Spring Bean、脚本或未知属性当作无害注释。
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    spring: Spring,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spring {
    cloud: Cloud,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cloud {
    gateway: Gateway,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Gateway {
    server: Option<Server>,
    routes: Option<Vec<Route>>,
    default_filters: Option<Vec<Factory>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Server {
    webflux: Routes,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Routes {
    routes: Vec<Route>,
    #[serde(default)]
    default_filters: Vec<Factory>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    id: String,
    uri: String,
    #[serde(default)]
    order: Value,
    #[serde(default)]
    predicates: Vec<Factory>,
    #[serde(default)]
    filters: Vec<Factory>,
}
#[derive(Deserialize, Clone)]
#[serde(untagged)]
pub(super) enum Factory {
    Shortcut(String),
    Expanded(Expanded),
}
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(super) struct Expanded {
    name: String,
    #[serde(default)]
    args: BTreeMap<String, Value>,
}

/// 业务作用：把显式支持的 WebFlux 配置变成普通 RouteCfg，后续仍由同一 Router 编译执行。
///
/// 参数说明：
/// - `document`：通过有界 YAML 或 Properties 解码得到的唯一文档。
///
/// 返回：最多 256 条原生路由；未知属性、表达式或无法无损映射的工厂拒绝整个来源。
pub(super) fn translate(document: Value) -> Result<Vec<crate::config::model::RouteCfg>> {
    let parsed: Document = serde_json::from_value(document).map_err(|_| {
        anyhow::anyhow!(
            "SCG document requires only spring.cloud.gateway routes/default-filters or server.webflux; move listener/security/Bean settings to native configuration"
        )
    })?;
    let gateway = parsed.spring.cloud.gateway;
    let source = if let Some(server) = gateway.server {
        ensure!(
            gateway.routes.is_none() && gateway.default_filters.is_none(),
            "SCG legacy and server.webflux namespaces cannot be mixed"
        );
        server.webflux
    } else {
        Routes {
            routes: gateway.routes.context("SCG routes missing")?,
            default_filters: gateway.default_filters.unwrap_or_default(),
        }
    };
    ensure!(
        !source.routes.is_empty()
            && source.routes.len() <= 256
            && source.default_filters.len() <= 16,
        "SCG source requires 1..256 routes and at most 16 default filters"
    );
    let mut ids = HashSet::new();
    let mut routes = Vec::new();
    for raw in source.routes {
        ensure!(
            !raw.id.is_empty()
                && raw.id.len() <= 128
                && raw
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "SCG route id must be 1..128 safe ASCII bytes"
        );
        ensure!(ids.insert(raw.id.clone()), "SCG route id is duplicated");
        ensure!(
            raw.predicates.len() <= 16 && raw.filters.len() <= 32,
            "SCG route exceeds predicate/filter budget"
        );
        let uri = origin(&raw.uri)?;
        let order = match raw.order {
            Value::Null => 0,
            Value::Number(n) => n
                .as_i64()
                .and_then(|v| i32::try_from(v).ok())
                .context("SCG order must fit i32")?,
            Value::String(s) => s.parse::<i32>().context("SCG order must fit i32")?,
            _ => anyhow::bail!("SCG order must be an integer"),
        };
        let mut route: crate::config::model::RouteCfg =
            serde_json::from_value(serde_json::json!({
                "id":raw.id,
                "uri":uri.as_str(),
                "order":order
            }))?;
        for factory in &raw.predicates {
            route.predicates.push(super::factories::predicate(factory)?);
        }
        let mut responses = Vec::new();
        let mut path_mutation = false;
        // Spring 的两组 filter 各自从 order=1 开始；同序号默认项先执行，响应链逆序返回。
        for index in 0..source.default_filters.len().max(raw.filters.len()) {
            for factory in [source.default_filters.get(index), raw.filters.get(index)]
                .into_iter()
                .flatten()
            {
                super::factories::filter(factory, &mut route, &mut responses, &mut path_mutation)?;
            }
        }
        route.filters.extend(responses.into_iter().rev());
        routes.push(route);
    }
    Ok(routes)
}

/// 业务作用：只接纳固定 HTTP(S) 源站，防止 URL 规范化隐藏原声明中的路径或 authority 变换。
///
/// 参数说明：
/// - `raw`：SCG 路由的 URI 原文，不执行占位符或应用容器求值。
///
/// 返回：可交给原生上游的无凭据源站；非空路径、查询、片段和有歧义的 authority 均拒绝。
fn origin(raw: &str) -> Result<reqwest::Url> {
    literal(raw)?;
    let uri = raw.parse::<http::Uri>().map_err(|_| {
        anyhow::anyhow!(
            "SCG uri must be a fixed HTTP(S) origin; use native upstreams for discovery"
        )
    })?;
    // 必须先检查保留原路径的 URI，再交给 URL 解析器；否则 /a/.. 会折叠为 /，改变来源含义。
    ensure!(
        raw.is_ascii()
            && matches!(uri.scheme_str(), Some("http" | "https"))
            && uri.authority().is_some_and(|authority| {
                authority
                    .as_str()
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-:[]".contains(&byte))
            })
            && uri.path_and_query().is_none_or(|path| matches!(path.as_str(), "" | "/")),
        "SCG uri must be a literal credential-free HTTP(S) origin without path/query; use native backend and rewrite for other forms"
    );
    let url: reqwest::Url = raw.parse().map_err(|_| {
        anyhow::anyhow!("SCG uri has an invalid HTTP(S) authority; use a fixed native upstream")
    })?;
    ensure!(
        url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "SCG uri must identify only a fixed HTTP(S) origin"
    );
    Ok(url)
}

impl Factory {
    /// 业务作用：读取有界工厂名称，只允许固定目录中的标识用于诊断。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法 ASCII 名称；表达式、控制字符或超长名称拒绝且不回显输入。
    pub(super) fn name(&self) -> Result<&str> {
        let name = match self {
            Self::Shortcut(s) => s
                .split_once('=')
                .map_or(s.as_str(), |(name, _)| name)
                .trim(),
            Self::Expanded(e) => e.name.as_str(),
        };
        ensure!(
            !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric()),
            "SCG factory name is invalid; use the declared factory catalog"
        );
        Ok(name)
    }
    /// 业务作用：按工厂字段顺序绑定短写或命名参数，不执行 SpEL、Bean 或配置占位符。
    ///
    /// 参数说明：
    /// - `keys`：工厂允许的字段，顺序决定短写位置。
    /// - `required`：必须存在的前缀字段数。
    ///
    /// 返回：逐项参数；多余、缺失、结构值或求值表达式均拒绝。
    pub(super) fn args(&self, keys: &[&str], required: usize) -> Result<Vec<Option<String>>> {
        let mut output = vec![None; keys.len()];
        match self {
            Self::Shortcut(raw) => {
                if let Some((_, args)) = raw.split_once('=') {
                    let values = args.split(',').map(str::trim).collect::<Vec<_>>();
                    ensure!(
                        values.len() <= keys.len(),
                        "SCG factory has extra shortcut arguments; use explicit name/args for values containing commas"
                    );
                    for (i, value) in values.into_iter().enumerate() {
                        output[i] = Some(value.to_owned());
                    }
                }
            }
            Self::Expanded(expanded) => {
                ensure!(
                    expanded.args.len() <= 32,
                    "SCG factory argument count exceeds 32"
                );
                for (key, value) in &expanded.args {
                    let index = keys.iter().position(|allowed| *allowed == key).context(
                        "SCG factory has an unsupported argument; use documented native equivalent",
                    )?;
                    output[index] = Some(scalar(value)?);
                }
            }
        }
        ensure!(
            output.iter().take(required).all(Option::is_some),
            "SCG factory is missing required arguments"
        );
        for value in output.iter().flatten() {
            literal(value)?;
        }
        Ok(output)
    }
    /// 业务作用：绑定列表型断言，保留输入顺序并拒绝稀疏索引与重复尾标志。
    ///
    /// 参数说明：
    /// - `key`：命名列表字段。
    /// - `tail`：可选布尔尾标志名称。
    ///
    /// 返回：1..16 个列表项和可选标志；不猜测未知命名参数。
    pub(super) fn list(
        &self,
        key: &str,
        tail: Option<&str>,
    ) -> Result<(Vec<String>, Option<bool>)> {
        let mut list = Vec::new();
        let mut flag = None;
        match self {
            Self::Shortcut(raw) => {
                let (_, args) = raw
                    .split_once('=')
                    .context("SCG list predicate requires arguments")?;
                list = args.split(',').map(|s| s.trim().to_owned()).collect();
                if tail.is_some()
                    && list
                        .last()
                        .is_some_and(|s| matches!(s.as_str(), "true" | "false"))
                {
                    flag = Some(list.pop().unwrap() == "true");
                }
            }
            Self::Expanded(e) => {
                let mut indexed = BTreeMap::new();
                for (name, value) in &e.args {
                    if Some(name.as_str()) == tail {
                        let v = scalar(value)?;
                        ensure!(
                            matches!(v.as_str(), "true" | "false"),
                            "SCG tail flag must be true/false"
                        );
                        flag = Some(v == "true");
                    } else {
                        let suffix = name
                            .strip_prefix(&format!("{key}."))
                            .context("SCG list requires indexed argument names")?;
                        let n = suffix
                            .parse::<usize>()
                            .context("SCG list index is invalid")?;
                        ensure!(
                            n < 16 && suffix == n.to_string(),
                            "SCG list index exceeds bounds or is noncanonical"
                        );
                        indexed.insert(n, scalar(value)?);
                    }
                }
                for (n, value) in indexed {
                    ensure!(n == list.len(), "SCG list indices must be contiguous");
                    list.push(value);
                }
            }
        }
        ensure!(
            !list.is_empty() && list.len() <= 16,
            "SCG list must have 1..16 items"
        );
        for value in &list {
            literal(value)?;
        }
        Ok((list, flag))
    }
}

/// 业务作用：仅接受 Spring 参数绑定中无歧义的标量，不把对象或数组格式化成可执行文本。
///
/// 参数说明：
/// - `value`：单个命名参数。
///
/// 返回：字符串、布尔值或数字的文本；其它形态拒绝。
fn scalar(value: &Value) -> Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(v) => Ok(v.to_string()),
        Value::Number(v) => Ok(v.to_string()),
        _ => anyhow::bail!("SCG argument must be scalar"),
    }
}

/// 业务作用：确保兼容输入只是字面量声明，不具有应用容器或环境求值能力。
///
/// 参数说明：
/// - `value`：工厂参数原文。
///
/// 返回：最多 4096 字节且没有控制字节或表达式标记时通过。
pub(super) fn literal(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 4096
            && !value.chars().any(char::is_control)
            && !value.contains("${")
            && !value.contains("#{"),
        "SCG argument must be a bounded literal; move expressions to explicit native variables or bounded extensions"
    );
    Ok(())
}
