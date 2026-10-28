//! 工厂目录同时决定翻译与拒绝提示；不按相似名称猜测 Spring 扩展或原生过滤器。
use super::compile::Factory;
use crate::config::model::RouteCfg;
use anyhow::{ensure, Context, Result};
use base64::Engine;

/// 业务作用：把受支持的只读断言变成原生 DSL，保持整串与多值语义。
///
/// 参数说明：
/// - `factory`：源文档中的单条工厂声明。
///
/// 返回：已验证的原生断言；不能无损映射时返回固定工厂名和明确迁移方向。
pub(super) fn predicate(factory: &Factory) -> Result<String> {
    let name = factory.name()?;
    let result = match name {
        "Path" => {
            let (paths, tail) = factory.list("patterns", Some("matchTrailingSlash"))?;
            format!("PathRegex={}", super::patterns::paths(&paths, tail)?)
        }
        "Method" => {
            let (methods, _) = factory.list("methods", None)?;
            ensure!(
                methods.iter().all(|method| {
                    !method.is_empty() && method.bytes().all(|byte| byte.is_ascii_uppercase())
                }),
                "SCG Method must contain uppercase HTTP tokens"
            );
            format!("Method={}", methods.join(","))
        }
        "Header" => {
            return unsupported(
                name,
                "use explicit native Header=<name>,regex,<expression>; Spring quoted comma-list tokenization differs from native per-field matching",
            );
        }
        "Host" => {
            let (hosts, _) = factory.list("patterns", None)?;
            ensure!(
                hosts.iter().all(|host| {
                    !host.is_empty()
                        && host.len() <= 253
                        && host.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte))
                }),
                "SCG Host Ant templates and wildcards require explicit native Host or Header regex; native Host is case-insensitive"
            );
            format!(
                "Header=host,regex,{}",
                super::patterns::header_regex(
                    &hosts
                        .iter()
                        .map(|host| regex::escape(host))
                        .collect::<Vec<_>>()
                        .join("|")
                )?
            )
        }
        "Query" => {
            let args = factory.args(&["param", "regexp"], 1)?;
            ensure!(
                args[1].is_none(),
                "SCG Query regex decoding is not losslessly portable; use native Query=<name>,regex,<expression> with its form-decoding semantics"
            );
            let param = args[0].as_deref().unwrap();
            ensure!(
                !param.is_empty()
                    && param.len() <= 128
                    && param
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte)),
                "SCG Query name must be a literal URL-safe token"
            );
            format!("Query={param},regex,(?s:.*)")
        }
        "After" | "Before" | "Between" => {
            return unsupported(
                name,
                "use native scheduled route publication; Java ZonedDateTime and local clocks are not imported",
            );
        }
        "Cookie" => {
            return unsupported(
                name,
                "use explicit native authentication or a bounded request-header extension; duplicate cookie and Java regex semantics are not guessed",
            );
        }
        "RemoteAddr" | "XForwardedRemoteAddr" => {
            return unsupported(
                name,
                "use native trusted_proxy and allow/deny policies; filters must not be substituted for route selection",
            );
        }
        "Weight" => {
            return unsupported(
                name,
                "use native Weight with a declared shared predicate set; deterministic affinity is not Spring independent random sampling",
            );
        }
        "ReadBody" => {
            return unsupported(
                name,
                "use native request_validation or script_plugins with explicit max_body_bytes; Java predicates cannot be imported",
            );
        }
        "Version" => {
            return unsupported(
                name,
                "use native Header/Query/Path and explicit version policy; configure the version resolver without Spring Bean state",
            );
        }
        "CloudFoundryRouteService" => {
            return unsupported(
                name,
                "use native fixed upstream and trusted identity headers; Cloud Foundry signed route-service context has no implicit equivalent",
            );
        }
        _ => {
            return unsupported(
                "unknown predicate",
                "use the documented native predicates; custom Java factories are not executable declarations",
            );
        }
    };
    crate::routing::predicate::parse_predicate(&result)
        .context("SCG predicate failed native validation")?;
    Ok(result)
}

/// 业务作用：只生成现有原生过滤操作，分别保存请求正序和响应逆序的执行合同。
///
/// 参数说明：
/// - `factory`：有序工厂声明。
/// - `route`：待构建的原生路由。
/// - `responses`：响应操作暂存，最终按反向链展开。
/// - `path_mutation`：是否已经声明路径改写，阻止原生固定次序改变来源含义。
///
/// 返回：支持且权限明确的操作进入候选；不可映射、表达式或关键协议头修改拒绝。
pub(super) fn filter(
    factory: &Factory,
    route: &mut RouteCfg,
    responses: &mut Vec<String>,
    path_mutation: &mut bool,
) -> Result<()> {
    let name = factory.name()?;
    match name {
        "AddRequestHeader" | "SetRequestHeader" | "AddResponseHeader" | "SetResponseHeader" => {
            let keys = if name == "AddResponseHeader" {
                &["name", "value", "override"][..]
            } else {
                &["name", "value"][..]
            };
            let args = factory.args(keys, 2)?;
            if args.len() == 3 {
                ensure!(
                    args[2].as_deref().is_none_or(|v| v == "true"),
                    "SCG AddResponseHeader override=false requires native conditional header logic"
                );
            }
            let header = mutable_header(args[0].as_deref().unwrap())?;
            let value = args[1].as_deref().unwrap();
            literal_header(value)?;
            let direction = if name.contains("Response") {
                "response"
            } else {
                "request"
            };
            let op = if name.starts_with("Add") {
                "add"
            } else {
                "set"
            };
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
            let command = format!("gateway_{direction}_header_{op}_b64 {header} {encoded}");
            if direction == "response" {
                responses.push(command);
            } else {
                route.filters.push(command);
            }
        }
        "RemoveRequestHeader" | "RemoveResponseHeader" => {
            let args = factory.args(&["name"], 1)?;
            let header = mutable_header(args[0].as_deref().unwrap())?;
            if name == "RemoveRequestHeader" {
                route
                    .filters
                    .push(format!("gateway_request_header_remove {header}"));
            } else {
                responses.push(format!("gateway_response_header_remove {header}"));
            }
        }
        "PreserveHostHeader" => {
            factory.args(&[], 0)?;
            route.preserve_host = true;
        }
        "StripPrefix" => {
            let args = factory.args(&["parts"], 1)?;
            let count = args[0]
                .as_deref()
                .unwrap()
                .parse::<usize>()
                .context("SCG StripPrefix parts must be an integer")?;
            ensure!(
                count <= 128 && !*path_mutation,
                "SCG supports one path mutation with at most 128 parts; combine rewrites explicitly in native configuration"
            );
            *path_mutation = true;
            route.filters.push(format!("StripPrefix={count}"));
        }
        "SetPath" => {
            let args = factory.args(&["template"], 1)?;
            let path = args[0].as_deref().unwrap();
            ensure!(
                !*path_mutation
                    && path.starts_with('/')
                    && !path.contains("//")
                    && !path.split('/').any(|segment| matches!(segment, "." | ".."))
                    && path.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"/._~-".contains(&byte)),
                "SCG SetPath requires one literal absolute path; URI-template expansion needs native variables and explicit rewrite"
            );
            *path_mutation = true;
            route
                .filters
                .push(format!("gateway_rewrite_full_path {path}"));
        }
        _ => return unsupported_filter(name),
    }
    Ok(())
}

/// 业务作用：对内置但无法直接翻译的过滤器提供原生迁移方向，拒绝比近似执行更早发生。
///
/// 参数说明：
/// - `name`：已经验证为有界 ASCII 的工厂名。
///
/// 返回：始终拒绝；正文与重试提示保留硬预算和幂等约束。
fn unsupported_filter<T>(name: &str) -> Result<T> {
    let hint = match name {
        "AddRequestHeadersIfNotPresent" | "MapRequestHeader" => {
            "use explicit native variables and gateway_request_header_set; conditional/append behavior must be declared"
        },
        "AddRequestParameter" | "RemoveRequestParameter" | "RewriteRequestParameter" => {
            "no native query mutation equivalent; construct query parameters in the client/backend, since native request_transform changes only the body"
        },
        "CircuitBreaker" => {
            "use native circuit_breaker and error_page with explicit limits; Java fallback handlers are not imported"
        },
        "CacheRequestBody"
        | "ModifyRequestBody"
        | "ModifyResponseBody"
        | "RemoveJsonAttributesResponseBody" => {
            "use native request_transform/response_transform or script_plugins with explicit max_body_bytes; Java classes and lambdas are not imported"
        },
        "DedupeResponseHeader" => {
            "use native DedupeResponseHeader after explicitly reconciling response operation ordering"
        },
        "FallbackHeaders" => {
            "use native FallbackHeaders with a native circuit/error policy; Java exception names are not disclosed"
        },
        "JsonToGrpc" => {
            "use native grpc_transcoding with an explicit descriptor, method and body limit"
        },
        "LocalResponseCache" => {
            "use native proxy_cache with explicit key, capacity, freshness and authorization semantics"
        },
        "PrefixPath" | "RewritePath" => {
            "use native rewrite or gateway_rewrite_full_path; Java capture replacement and filter ordering must be explicit"
        },
        "RedirectTo" => {
            "use native gateway_redirect with explicit status, authority, path and query policy"
        },
        "RequestHeaderSize" => {
            "use native listener max_header_bytes; rejection status and per-field versus total limits differ"
        },
        "RequestHeaderToRequestUri" | "SetRequestUri" => {
            "use fixed native upstreams or forward_proxy with explicit destination allowlist; client-controlled backend selection is forbidden"
        },
        "RequestRateLimiter" => {
            "use native limit_req/Sentinel with explicit key, state capacity and dependency failure mode"
        },
        "RewriteLocationResponseHeader" | "RewriteResponseHeader" => {
            "use native proxy_redirect or a bounded response-header extension; Java regex replacement is not guessed"
        },
        "SaveSession" | "TokenRelay" => {
            "use native oidc_rp or upstream_credentials with explicit owner and backend allowlist; Spring session state cannot be imported"
        },
        "SecureHeaders" => {
            "use native listener security_headers and explicit policy values"
        },
        "SetStatus" => {
            "no generic native post-upstream status rewrite; use native return only for terminal local responses, or change the backend response contract"
        },
        "Retry" => {
            "use native retry policy and retry budget; non-idempotent requests carrying bodies cannot be automatically retried"
        },
        "RequestSize" => {
            "use native client body limits; unknown Content-Length, rejection headers and streaming bounds must be explicit"
        },
        "SetRequestHostHeader" => {
            "use native preserve_host and an explicit trusted Host policy; do not infer authority changes"
        },
        _ => {
            return unsupported(
                "unknown filter",
                "use the documented native filter catalog; custom Java factories are not executable declarations",
            );
        },
    };
    unsupported(name, hint)
}

/// 业务作用：返回固定目录名与迁移方向，不把配置参数、请求或凭据原文拼入错误。
///
/// 参数说明：
/// - `name`：固定已知工厂名或低敏 unknown 类别。
/// - `hint`：原生配置迁移提示。
///
/// 返回：失败关闭的候选构建错误。
fn unsupported<T>(name: &str, hint: &str) -> Result<T> {
    anyhow::bail!("SCG {name} cannot be translated losslessly: {hint}")
}

/// 业务作用：在 DSL 拼接前验证头名，阻止分隔符改变原生命令结构。
///
/// 参数说明：
/// - `name`：来源头名。
///
/// 返回：规范化名称；非法 token 或超长名称拒绝。
fn header_name(name: &str) -> Result<String> {
    ensure!(name.len() <= 128, "SCG header name exceeds 128 bytes");
    Ok(name
        .parse::<http::HeaderName>()
        .map_err(|_| anyhow::anyhow!("SCG header name is invalid"))?
        .as_str()
        .to_owned())
}

/// 业务作用：兼容翻译不得修改认证、来源、framing 或宿主安全字段，即使源框架允许也需显式原生策略。
///
/// 参数说明：
/// - `name`：来源请求或响应头名。
///
/// 返回：业务头名称；保留字段拒绝并要求原生安全配置。
fn mutable_header(name: &str) -> Result<String> {
    let name = header_name(name)?;
    ensure!(
        !matches!(
            name.as_str(),
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "set-cookie"
                | "host"
                | "connection"
                | "content-length"
                | "transfer-encoding"
                | "upgrade"
                | "trailer"
                | "te"
                | "forwarded"
                | "content-encoding"
                | "content-range"
                | "strict-transport-security"
                | "content-security-policy"
        ) && !name.starts_with("x-naway-")
            && !name.starts_with("x-forwarded-")
            && !name.starts_with("access-control-"),
        "SCG cannot mutate protocol/security/identity headers; use explicit native security policy"
    );
    Ok(name)
}

/// 业务作用：只接受不会触发 URI 模板展开的非空字面量字段值。
///
/// 参数说明：
/// - `value`：头部值原文。
///
/// 返回：合法且有界的 HTTP 值；模板、空值或控制字符拒绝。
fn literal_header(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && !value.contains(['{', '}']),
        "SCG header templates or empty values require explicit native header configuration"
    );
    http::HeaderValue::from_str(value)
        .map_err(|_| anyhow::anyhow!("SCG header value is invalid"))?;
    Ok(())
}
