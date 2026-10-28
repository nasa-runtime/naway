//! degraphql：把受限 REST GET 映射成固定 GraphQL POST。
//!
//! query 文档由配置提供并在 build-then-swap 阶段完成语法、深度、复杂度与 introspection
//! 检查。请求只能填充显式声明的 path/query/header variables，不能提交任意 GraphQL 文本。

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING, UPGRADE};
use http::request::Parts;
use http::{HeaderName, HeaderValue, Method, Uri};
use serde::Serialize;
use serde_json::{Map, Number, Value};

use crate::config::model::{
    DegraphqlCfg, DegraphqlVariableCfg, DegraphqlVariableKindCfg, DegraphqlVariableSourceCfg,
    GraphqlGuardCfg,
};
use crate::extensions::graphql::GraphqlGuardPolicy;
use crate::full_body;
use crate::proxy::forward::ForwardBody;
use crate::routing::predicate::Predicate;

const MAX_VARIABLES: usize = 64;
const MAX_GENERATED_BODY_BYTES: usize = 1024 * 1024;

/// 构建期编译后的 REST→GraphQL 计划。
pub(crate) struct DegraphqlPlan {
    cost: u64,
    query: Arc<str>,
    operation_name: Option<Arc<str>>,
    upstream_uri: Uri,
    path_template: Option<PathTemplate>,
    variables: Vec<(Arc<str>, VariablePlan)>,
    max_body_bytes: usize,
}

struct PathTemplate {
    signature: String,
    segments: Vec<PathSegment>,
}

enum PathSegment {
    Literal(Arc<str>),
    Variable(Arc<str>),
}

enum VariablePlan {
    Path {
        name: Arc<str>,
        kind: VariableKind,
        required: bool,
        max_bytes: usize,
    },
    Query {
        name: Arc<str>,
        kind: VariableKind,
        required: bool,
        max_bytes: usize,
    },
    Header {
        name: HeaderName,
        kind: VariableKind,
        required: bool,
        max_bytes: usize,
    },
    Literal(Value),
}

#[derive(Clone, Copy)]
enum VariableKind {
    String,
    Integer,
    Number,
    Boolean,
}

pub(crate) enum DegraphqlOutcome {
    Transformed(ForwardBody),
    Rejected {
        status: u16,
        message: &'static str,
    },
}

impl DegraphqlPlan {
    /// 业务作用：冻结受信查询与变量映射，拒绝任意查询注入和无界生成正文。
    ///
    /// 参数说明：
    /// - `cfg`：提供静态模板
    /// - `guard`：限定查询预算
    /// - `predicates`：定位受控入口。
    /// - `route_id`：定位受控入口。
    ///
    /// 返回：可复用计划和已验证成本；任何查询、变量或路由约束不一致时拒绝候选。
    pub(crate) fn build(
        cfg: &DegraphqlCfg,
        guard: Option<&GraphqlGuardPolicy>,
        predicates: &[Predicate],
        route_id: &str,
    ) -> Result<Self> {
        anyhow::ensure!(
            predicates.iter().any(|predicate| {
                matches!(predicate, Predicate::Method(methods) if methods.as_slice() == [Method::GET])
            }),
            "route `{route_id}` degraphql requires an exact Method=GET predicate"
        );
        anyhow::ensure!(
            (1024..=MAX_GENERATED_BODY_BYTES).contains(&cfg.max_body_bytes),
            "route `{route_id}` degraphql max_body_bytes must be within 1024..={MAX_GENERATED_BODY_BYTES}"
        );
        anyhow::ensure!(
            cfg.variables.len() <= MAX_VARIABLES,
            "route `{route_id}` degraphql supports at most {MAX_VARIABLES} variables"
        );
        let upstream_uri = build_upstream_uri(&cfg.upstream_path)
            .with_context(|| format!("route `{route_id}` degraphql upstream_path"))?;
        let query_guard;
        let guard = if let Some(guard) = guard {
            guard
        } else {
            query_guard = GraphqlGuardPolicy::build(&GraphqlGuardCfg::default(), route_id)?;
            &query_guard
        };
        let cost = guard
            .validate_static_query(&cfg.query, cfg.operation_name.as_deref())
            .with_context(|| format!("route `{route_id}` degraphql query"))?;

        let uses_path = cfg
            .variables
            .values()
            .any(|variable| variable.source == DegraphqlVariableSourceCfg::Path);
        let path_template = if uses_path {
            anyhow::ensure!(
                !cfg.rest_path_template.is_empty(),
                "route `{route_id}` degraphql path variables require rest_path_template"
            );
            let template = PathTemplate::parse(&cfg.rest_path_template)
                .with_context(|| format!("route `{route_id}` degraphql rest_path_template"))?;
            anyhow::ensure!(
                predicates.iter().any(|predicate| {
                    matches!(predicate, Predicate::PathTemplate {
                        signature, ..
                    } if signature == &template.signature)
                }),
                "route `{route_id}` degraphql rest_path_template must match its PathTemplate predicate"
            );
            Some(template)
        } else {
            anyhow::ensure!(
                cfg.rest_path_template.is_empty(),
                "route `{route_id}` degraphql rest_path_template is only valid with path variables"
            );
            None
        };

        let mut variables = cfg.variables.iter().collect::<Vec<_>>();
        variables.sort_unstable_by(|left, right| left.0.cmp(right.0));
        let variables = variables
            .into_iter()
            .map(|(graphql_name, cfg)| {
                validate_graphql_name(graphql_name, "GraphQL variable")?;
                compile_variable(cfg, path_template.as_ref())
                    .map(|plan| (Arc::<str>::from(graphql_name.as_str()), plan))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            cost,
            query: Arc::from(cfg.query.as_str()),
            operation_name: cfg.operation_name.as_deref().map(Arc::from),
            upstream_uri,
            path_template,
            variables,
            max_body_bytes: cfg.max_body_bytes,
        })
    }

    /// 业务作用：把当前 REST head 转为 GraphQL POST，并返回有界生成的 body。
    ///
    /// 原请求必须是 Hyper 已知的空 body；未知 chunked body 也拒绝，避免为“确认空”额外 poll
    /// 客户端流。生成 JSON 只有一个 `Vec`，完成后直接转 `Bytes` 交给上游。
    ///
    /// 参数说明：
    /// - `parts`：提供受控变量输入和计量上下文
    /// - `request_end_of_stream`：确认原请求没有正文。
    ///
    /// 返回：完整生成正文及修改后的 head，或失败闭合响应；通过时记录冻结查询成本。
    pub(crate) fn transform(
        &self,
        parts: &mut Parts,
        request_end_of_stream: bool,
    ) -> DegraphqlOutcome {
        if !request_end_of_stream
            || parts.headers.contains_key(TRANSFER_ENCODING)
            || parts.headers.contains_key(UPGRADE)
        {
            return DegraphqlOutcome::Rejected {
                status: 400,
                message: "degraphql REST request body/upgrade is not supported",
            };
        }
        let path_values = match self.path_template.as_ref() {
            Some(template) => match template.extract(parts.uri.path()) {
                Ok(values) => values,
                Err(()) => {
                    return DegraphqlOutcome::Rejected {
                        status: 400,
                        message: "degraphql path does not match template",
                    }
                }
            },
            None => HashMap::new(),
        };
        let mut query_values: Option<HashMap<String, Vec<String>>> = None;
        let mut values = Map::new();
        for (graphql_name, plan) in &self.variables {
            let value = match plan.value(parts, &path_values, &mut query_values) {
                Ok(value) => value,
                Err(message) => {
                    return DegraphqlOutcome::Rejected {
                        status: 400,
                        message,
                    }
                }
            };
            if let Some(value) = value {
                values.insert(graphql_name.to_string(), value);
            }
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Envelope<'a> {
            query: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            operation_name: Option<&'a str>,
            variables: Map<String, Value>,
        }
        let envelope = Envelope {
            query: self.query.as_ref(),
            operation_name: self.operation_name.as_deref(),
            variables: values,
        };
        let mut writer = BoundedWriter::new(self.max_body_bytes);
        if serde_json::to_writer(&mut writer, &envelope).is_err() {
            return DegraphqlOutcome::Rejected {
                status: 413,
                message: "degraphql generated body is too large",
            };
        }
        let bytes = Bytes::from(writer.finish());
        let content_length = match HeaderValue::from_str(&bytes.len().to_string()) {
            Ok(value) => value,
            Err(_) => {
                return DegraphqlOutcome::Rejected {
                    status: 500,
                    message: "degraphql content length is invalid",
                }
            }
        };
        parts.method = Method::POST;
        parts.uri = self.upstream_uri.clone();
        parts.headers.remove(TRANSFER_ENCODING);
        parts
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        parts.headers.insert(CONTENT_LENGTH, content_length);
        crate::extensions::graphql::record_cost(parts, self.cost);
        DegraphqlOutcome::Transformed(full_body(bytes))
    }
}

impl VariablePlan {
    /// 业务作用：把已验证的输入标量转换为 GraphQL variables 值，保留声明的数据类型。
    fn value(
        &self,
        parts: &Parts,
        path: &HashMap<String, String>,
        query_cache: &mut Option<HashMap<String, Vec<String>>>,
    ) -> std::result::Result<Option<Value>, &'static str> {
        let (raw, kind, required, max_bytes) = match self {
            Self::Literal(value) => return Ok(Some(value.clone())),
            Self::Path {
                name,
                kind,
                required,
                max_bytes,
            } => (
                path.get(name.as_ref()).map(String::as_str),
                *kind,
                *required,
                *max_bytes,
            ),
            Self::Query {
                name,
                kind,
                required,
                max_bytes,
            } => {
                let values = query_cache.get_or_insert_with(|| parse_query(parts));
                let raw = match values.get(name.as_ref()) {
                    Some(values) if values.len() == 1 => values.first().map(String::as_str),
                    Some(_) => return Err("degraphql query variable must be unique"),
                    None => None,
                };
                (raw, *kind, *required, *max_bytes)
            }
            Self::Header {
                name,
                kind,
                required,
                max_bytes,
            } => {
                let mut all = parts.headers.get_all(name).iter();
                let first = all.next();
                if all.next().is_some() {
                    return Err("degraphql header variable must be unique");
                }
                let raw = first
                    .map(|value| value.to_str())
                    .transpose()
                    .map_err(|_| "degraphql header variable is not UTF-8")?;
                (raw, *kind, *required, *max_bytes)
            }
        };
        let Some(raw) = raw else {
            return if required {
                Err("required degraphql variable is missing")
            } else {
                Ok(None)
            };
        };
        if raw.len() > max_bytes {
            return Err("degraphql variable exceeds max_value_bytes");
        }
        parse_scalar(raw, kind).map(Some)
    }
}

impl PathTemplate {
    /// 业务作用：编译变量来源的声明，使运行期只读取允许的 path、query 或 header 字段。
    fn parse(raw: &str) -> Result<Self> {
        let tail = raw
            .strip_prefix('/')
            .with_context(|| format!("path template `{raw}` must start with /"))?;
        anyhow::ensure!(!tail.is_empty(), "path template cannot be root/empty");
        let mut names = std::collections::HashSet::new();
        let mut segments = Vec::new();
        let mut signature = String::with_capacity(raw.len());
        for segment in tail.split('/') {
            anyhow::ensure!(!segment.is_empty(), "path template contains empty segment");
            signature.push('/');
            if let Some(name) = segment
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
            {
                validate_graphql_name(name, "path variable")?;
                anyhow::ensure!(names.insert(name), "duplicate path variable `{name}`");
                signature.push_str("{}");
                segments.push(PathSegment::Variable(Arc::from(name)));
            } else {
                anyhow::ensure!(
                    !segment
                        .chars()
                        .any(|character| matches!(character, '{' | '}')),
                    "path template contains partial braces"
                );
                signature.push_str(segment);
                segments.push(PathSegment::Literal(Arc::from(segment)));
            }
        }
        Ok(Self {
            signature,
            segments,
        })
    }

    /// 业务作用：从当前请求提取固定来源的变量值，不允许调用方改写变量来源或 GraphQL 文档。
    fn extract(&self, path: &str) -> std::result::Result<HashMap<String, String>, ()> {
        let mut actual = path.strip_prefix('/').ok_or(())?.split('/');
        let mut values = HashMap::new();
        for expected in &self.segments {
            let value = actual.next().ok_or(())?;
            if value.is_empty() {
                return Err(());
            }
            match expected {
                PathSegment::Literal(literal) if literal.as_ref() != value => return Err(()),
                PathSegment::Literal(_) => {}
                PathSegment::Variable(name) => {
                    let decoded = percent_encoding::percent_decode_str(value)
                        .decode_utf8()
                        .map_err(|_| ())?
                        .into_owned();
                    values.insert(name.to_string(), decoded);
                }
            }
        }
        if actual.next().is_some() {
            return Err(());
        }
        Ok(values)
    }
}

/// 业务作用：验证变量名称、来源和类型，把固定 REST 映射冻结为可执行计划。
fn compile_variable(
    cfg: &DegraphqlVariableCfg,
    path: Option<&PathTemplate>,
) -> Result<VariablePlan> {
    anyhow::ensure!(
        (1..=64 * 1024).contains(&cfg.max_value_bytes),
        "degraphql variable max_value_bytes must be within 1..=65536"
    );
    let kind = match cfg.kind {
        DegraphqlVariableKindCfg::String => VariableKind::String,
        DegraphqlVariableKindCfg::Integer => VariableKind::Integer,
        DegraphqlVariableKindCfg::Number => VariableKind::Number,
        DegraphqlVariableKindCfg::Boolean => VariableKind::Boolean,
    };
    match cfg.source {
        DegraphqlVariableSourceCfg::Literal => {
            anyhow::ensure!(
                cfg.name.is_empty(),
                "literal variable must not configure name"
            );
            cfg.value
                .clone()
                .map(VariablePlan::Literal)
                .context("literal variable requires value")
        }
        DegraphqlVariableSourceCfg::Path => {
            anyhow::ensure!(
                cfg.value.is_none(),
                "path variable must not configure value"
            );
            validate_graphql_name(&cfg.name, "path variable name")?;
            anyhow::ensure!(
                path.is_some_and(|path| path.segments.iter().any(
                    |segment| matches!(segment, PathSegment::Variable(name) if name.as_ref() == cfg.name)
                )),
                "path variable `{}` is absent from rest_path_template",
                cfg.name
            );
            Ok(VariablePlan::Path {
                name: Arc::from(cfg.name.as_str()),
                kind,
                required: cfg.required,
                max_bytes: cfg.max_value_bytes,
            })
        }
        DegraphqlVariableSourceCfg::Query => {
            validate_input_name(&cfg.name, "query variable name")?;
            anyhow::ensure!(
                cfg.value.is_none(),
                "query variable must not configure value"
            );
            Ok(VariablePlan::Query {
                name: Arc::from(cfg.name.as_str()),
                kind,
                required: cfg.required,
                max_bytes: cfg.max_value_bytes,
            })
        }
        DegraphqlVariableSourceCfg::Header => {
            anyhow::ensure!(
                cfg.value.is_none(),
                "header variable must not configure value"
            );
            let name = cfg
                .name
                .parse::<HeaderName>()
                .with_context(|| format!("invalid degraphql header `{}`", cfg.name))?;
            Ok(VariablePlan::Header {
                name,
                kind,
                required: cfg.required,
                max_bytes: cfg.max_value_bytes,
            })
        }
    }
}

/// 业务作用：构造固定 GraphQL 后端地址，不接受请求提供的外部调用目标。
fn build_upstream_uri(path: &str) -> Result<Uri> {
    anyhow::ensure!(
        path.starts_with('/')
            && path.len() <= 2048
            && !path.contains(['?', '#'])
            && !path.bytes().any(|byte| byte <= 0x20),
        "must be an absolute path without query/fragment/control bytes"
    );
    path.parse().context("invalid URI path")
}

/// 业务作用：校验 GraphQL 标识符语法，避免变量名改变查询文档结构。
fn validate_graphql_name(value: &str, label: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let first = bytes.next().context("name cannot be empty")?;
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || value.len() > 128
    {
        bail!("{label} `{value}` is invalid");
    }
    Ok(())
}

/// 业务作用：限制请求字段名称，使变量提取遵守明确的 HTTP 输入边界。
fn validate_input_name(value: &str, label: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 128
            && !value
                .bytes()
                .any(|byte| byte <= 0x20 || matches!(byte, b'&' | b'=' | b'?' | b'#')),
        "{label} `{value}` is invalid"
    );
    Ok(())
}

/// 业务作用：按表单查询串语义解析变量来源，保持百分号与加号的解码规则。
fn parse_query(parts: &Parts) -> HashMap<String, Vec<String>> {
    let mut values = HashMap::new();
    if let Some(query) = parts.uri.query() {
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            values
                .entry(name.into_owned())
                .or_insert_with(Vec::new)
                .push(value.into_owned());
        }
    }
    values
}

/// 业务作用：按声明类型解释变量值，拒绝不能无损转换的输入。
fn parse_scalar(raw: &str, kind: VariableKind) -> std::result::Result<Value, &'static str> {
    match kind {
        VariableKind::String => Ok(Value::String(raw.to_owned())),
        VariableKind::Integer => raw
            .parse::<i64>()
            .map(Number::from)
            .map(Value::Number)
            .map_err(|_| "degraphql integer variable is invalid"),
        VariableKind::Number => raw
            .parse::<f64>()
            .ok()
            .and_then(Number::from_f64)
            .map(Value::Number)
            .ok_or("degraphql number variable is invalid"),
        VariableKind::Boolean => match raw {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err("degraphql boolean variable is invalid"),
        },
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    max: usize,
}

impl BoundedWriter {
    /// 业务作用：创建带字节上限的变量编码器，在编码过程中执行容量限制。
    fn new(max: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max.min(16 * 1024)),
            max,
        }
    }

    /// 业务作用：取出已完成的变量编码结果，转移缓冲所有权而不重复复制。
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    /// 业务作用：在写入 JSON 编码字节之前检查容量，超限时中止变量生成。
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(next) = self.bytes.len().checked_add(bytes.len()) else {
            return Err(std::io::Error::other("degraphql body too large"));
        };
        if next > self.max {
            return Err(std::io::Error::other("degraphql body too large"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// 业务作用：完成内存编码器的刷新合同，不触发外部 I/O。
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
