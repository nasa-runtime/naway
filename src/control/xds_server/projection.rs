//! 将已通过原生构建的纯 HTTP 路由投影为固定 Envoy 资源，任何私有执行策略均拒绝。

use super::{proto as p, security};
use crate::config::model::{ProxyCfg, RouteCfg};
use anyhow::{ensure, Context, Result};
use prost::Message;
use prost_types::Any;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

/// 只在控制面持有的不可变资源；避免 Debug 意外暴露 SDS 私钥。
#[derive(Clone)]
pub(crate) struct Entry {
    pub value: Any,
    pub version: String,
}

pub(crate) type Resources = BTreeMap<&'static str, BTreeMap<String, Entry>>;

/// 业务作用：把一个已构建 proxy 的标准 HTTP 路由与静态 TLS 身份编译成 ADS 资源集合。
///
/// 参数说明：
/// - `proxy`：原生候选的入口声明，排序和后端仍由该声明唯一决定。
/// - `root`：用于读取已授权静态 TLS 文件的配置根。
/// - `allow_sds`：节点是否获准接收该入口的私钥。
///
/// 返回：全部投影资源；不能精确表达的路由执行策略、监听模式或身份策略使整个候选失败。
pub(crate) fn proxy(proxy: &ProxyCfg, root: &Path, allow_sds: bool) -> Result<Resources> {
    security::identifier(&proxy.id)?;
    ensure!(
        proxy.limits == crate::config::model::ServerLimitsCfg::default()
            && proxy.timeouts == crate::config::model::TimeoutCfg::default(),
        "xDS HTTP routing profile does not project customized native process limits or timeouts"
    );
    // 这些模式含独立权威或请求安全语义；省略它们会把受保护入口变成公开代理。
    ensure!(
        !proxy.http3.enabled
            && proxy.server_names.is_empty()
            && proxy.gateway_listeners.is_empty()
            && proxy.trusted_proxies.is_empty()
            && !proxy.proxy_protocol.enabled
            && !proxy.redirect_https
            && proxy.hsts_max_age == 0,
        "xDS HTTP projection rejects specialized listener policies"
    );
    ensure!(
        proxy.routes.len() <= 256,
        "xDS proxy route capacity exceeded"
    );
    let prefix = format!("proxy/{}/", proxy.id);
    let table = format!("{prefix}routes");
    let mut resources = Resources::new();
    let mut native: Vec<_> = proxy.routes.iter().collect();
    native.sort_by_key(|r| r.order);
    let mut routes = Vec::new();
    for route in native {
        validate_route(route)?;
        let cluster = format!("{prefix}upstream/{}", route.id);
        let uri: http::Uri = route
            .uri
            .parse()
            .context("xDS route requires a fixed HTTP origin")?;
        ensure!(
            uri.scheme_str() == Some("http")
                && uri
                    .path_and_query()
                    .is_none_or(|p| p.as_str().is_empty() || p.as_str() == "/"),
            "xDS projection accepts only HTTP origin without path or query"
        );
        let authority = uri.authority().context("xDS origin needs authority")?;
        ensure!(
            !authority.as_str().contains('@'),
            "xDS origin cannot embed credentials"
        );
        let ip: IpAddr = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .context("xDS EDS projection requires an explicit IP origin")?;
        let port = authority.port_u16().unwrap_or(80);
        ensure!(
            port != 0 && !ip.is_unspecified() && !ip.is_multicast(),
            "xDS origin address is invalid"
        );
        insert(
            &mut resources,
            p::CDS,
            &cluster,
            &p::Cluster {
                name: cluster.clone(),
                discovery_type: 3,
                eds_cluster_config: Some(p::EdsConfig {
                    eds_config: Some(p::ads()),
                    service_name: cluster.clone(),
                }),
                connect_timeout: Some(p::duration(5000)),
            },
        )?;
        insert(
            &mut resources,
            p::EDS,
            &cluster,
            &p::Assignment {
                cluster_name: cluster.clone(),
                endpoints: vec![p::LocalityEndpoints {
                    lb_endpoints: vec![p::LbEndpoint {
                        endpoint: Some(p::Endpoint {
                            address: Some(address(SocketAddr::new(ip, port))),
                        }),
                        health_status: 1,
                    }],
                }],
            },
        )?;
        routes.push(p::Route {
            name: route.id.clone(),
            r#match: Some(route_match(route)?),
            route: Some(p::RouteAction {
                cluster,
                host_rewrite_literal: if route.preserve_host {
                    String::new()
                } else {
                    authority.to_string()
                },
                // 原生没有默认完整响应期限；显式关闭 Envoy 默认的 15 秒 route timeout，保留流式响应。
                timeout: Some(p::duration(0)),
            }),
        });
    }
    insert(
        &mut resources,
        p::RDS,
        &table,
        &p::RouteConfiguration {
            name: table.clone(),
            virtual_hosts: vec![p::VirtualHost {
                name: proxy.id.clone(),
                domains: vec!["*".into()],
                routes,
                // 请求方不能通过 Envoy 控制头启用重试、改变截止期或自行声明内部来源。
                request_headers_to_remove: [
                    "x-envoy-retry-on",
                    "x-envoy-retry-grpc-on",
                    "x-envoy-max-retries",
                    "x-envoy-retriable-status-codes",
                    "x-envoy-retriable-header-names",
                    "x-envoy-upstream-rq-timeout-ms",
                    "x-envoy-upstream-rq-per-try-timeout-ms",
                    "x-envoy-hedge-on-per-try-timeout",
                    "x-envoy-upstream-rq-timeout-alt-response",
                    "x-envoy-upstream-rq-expected-timeout-ms",
                    "x-envoy-internal",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            }],
        },
    )?;
    let hcm = p::HttpConnectionManager {
        stat_prefix: "naway_projection".into(),
        rds: Some(p::Rds {
            config_source: Some(p::ads()),
            route_config_name: table,
        }),
        http_filters: vec![p::NetworkFilter {
            name: "envoy.filters.http.router".into(),
            typed_config: Some(p::pack(
                "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
                &p::Empty {},
            )),
        }],
        max_request_headers_kb: Some(64),
        // 私网源地址也不等于可信内部调用；禁止通过 XFF 或默认网段获得额外控制头权限。
        use_remote_address: Some(true),
        internal_address_config: Some(p::Empty {}),
        normalize_path: Some(false),
        merge_slashes: false,
        path_with_escaped_slashes_action: 1,
        stream_idle_timeout: Some(p::duration(proxy.timeouts.stream_idle_timeout_ms)),
    };
    if proxy.plain_enabled {
        listener(
            &mut resources,
            &format!("{prefix}listener/http"),
            &proxy.listen,
            &hcm,
            None,
        )?;
    }
    if let Some(tls) = &proxy.tls {
        ensure!(
            allow_sds,
            "xDS TLS projection requires explicit node allow_sds"
        );
        // 外部 signer、SPIRE、ACME 和 SNI 自有轮换权威，不能通过读取某个文件快照伪装等价身份。
        ensure!(
            tls.private_key_provider.is_none()
                && tls.spire.is_none()
                && tls.keypair_manifest_file.is_none()
                && tls.certs.is_empty()
                && tls.ocsp_stapling.is_none()
                && tls.session_tickets.is_none()
                && tls.acme.is_none(),
            "xDS projection requires a static single TLS identity"
        );
        let certificate = security::pem(root, &tls.cert_file)?;
        let key = security::pem(root, &tls.key_file)?;
        let certificate_name = format!("{prefix}certificate");
        let mut ca = None;
        if let Some(auth) = &tls.client_auth {
            ensure!(
                auth.mode == "require"
                    && auth.crl_files.is_empty()
                    && auth.revocation_mode == "off"
                    && auth.ocsp.is_none()
                    && auth.allowed_spiffe_ids.is_empty()
                    && auth.allowed_spiffe_trust_domains.is_empty(),
                "xDS projection supports only strict static CA client authentication"
            );
            ca = Some(security::pem(root, &auth.ca_file)?);
        }
        let material = crate::config::InMemoryTlsMaterial {
            certificate_chain: certificate.clone().into(),
            private_key: key.clone().into(),
            client_ca: ca.clone().map(Into::into),
            require_client_certificate: ca.is_some(),
        };
        crate::tls::build_in_memory_server_config(&material)?;
        insert(
            &mut resources,
            p::SDS,
            &certificate_name,
            &p::Secret {
                name: certificate_name.clone(),
                tls_certificate: Some(p::TlsCertificate {
                    certificate_chain: Some(p::DataSource {
                        inline_bytes: certificate,
                    }),
                    private_key: Some(p::DataSource {
                        inline_bytes: key,
                    }),
                }),
                validation_context: None,
            },
        )?;
        let validation = if let Some(ca) = ca {
            let name = format!("{prefix}validation");
            insert(
                &mut resources,
                p::SDS,
                &name,
                &p::Secret {
                    name: name.clone(),
                    tls_certificate: None,
                    validation_context: Some(p::ValidationContext {
                        trusted_ca: Some(p::DataSource {
                            inline_bytes: ca,
                        }),
                    }),
                },
            )?;
            Some(p::SdsConfig {
                name,
                sds_config: Some(p::ads()),
            })
        } else {
            None
        };
        let downstream = p::DownstreamTlsContext {
            require_client_certificate: Some(validation.is_some()),
            common_tls_context: Some(p::CommonTlsContext {
                alpn_protocols: vec!["h2".into(), "http/1.1".into()],
                tls_certificate_sds_secret_configs: vec![p::SdsConfig {
                    name: certificate_name,
                    sds_config: Some(p::ads()),
                }],
                validation_context_sds_secret_config: validation,
            }),
        };
        listener(&mut resources, &format!("{prefix}listener/tls"), &tls.listen, &hcm, Some(p::TransportSocket {
            name: "envoy.transport_sockets.tls".into(),
                typed_config: Some(p::pack("type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext", &downstream)),
        }))?;
    }
    Ok(resources)
}

/// 业务作用：拒绝无法生成标准 Envoy 执行语义的全部原生路由字段，防止安全策略被静默遗漏。
///
/// 参数说明：
/// - `route`：已经完成原生 Router 校验的完整声明。
///
/// 返回：仅固定 HTTP 后端、受支持断言与 Host 策略时成功；未来新增字段必须在穷尽解构中显式评估。
fn validate_route(route: &RouteCfg) -> Result<()> {
    let RouteCfg {
        id,
        layer,
        cgi,
        webdav,
        media,
        uri: _,
        serve,
        predicates: _,
        filters,
        resolved_snippets,
        #[cfg(feature = "config-providers")]
        provider_deadline,
        upstream_credentials,
        resolved_upstream_credentials,
        preserve_host: _,
        gateway_redirect,
        hedge,
        request_validation,
        request_transform,
        response_transform,
        response_contract,
        waf,
        geoip,
        bot,
        csrf,
        dlp,
        graphql_guard,
        degraphql,
        opa_authorization,
        casbin_authorization,
        wasm_plugins,
        script_plugins,
        external_plugins,
        ext_proc,
        inference_pool,
        bff_aggregation,
        dubbo,
        mock_response,
        fault_injection,
        usage_plan,
        traffic_limit,
        forward_proxy,
        webtransport,
        early_data,
        ws_frame,
        llm,
        agent,
        grpc_edge,
        grpc_transcoding,
        long_stream_idle_timeout_ms,
        request_timeout_ms,
        backend_request_timeout_ms,
        long_stream_max_lifetime_ms,
        order: _,
    } = route;
    security::identifier(id)?;
    ensure!(
        layer.is_none()
            && cgi.is_none()
            && webdav.is_none()
            && media.is_none()
            && serve.is_none()
            && filters.is_empty()
            && resolved_snippets.is_empty()
            && upstream_credentials.is_empty()
            && resolved_upstream_credentials.is_empty()
            && gateway_redirect.is_none()
            && hedge.is_none()
            && request_validation.is_none()
            && request_transform.is_none()
            && response_transform.is_none()
            && response_contract.is_none()
            && waf.is_none()
            && geoip.is_none()
            && bot.is_none()
            && csrf.is_none()
            && dlp.is_none()
            && graphql_guard.is_none()
            && degraphql.is_none()
            && opa_authorization.is_none()
            && casbin_authorization.is_none()
            && wasm_plugins.is_empty()
            && script_plugins.is_empty()
            && external_plugins.is_empty()
            && ext_proc.is_none()
            && inference_pool.is_none()
            && bff_aggregation.is_none()
            && dubbo.is_none()
            && mock_response.is_none()
            && fault_injection.is_none()
            && usage_plan.is_none()
            && traffic_limit.is_none()
            && forward_proxy.is_none()
            && webtransport.is_none()
            && early_data.is_none()
            && ws_frame.is_none()
            && llm.is_none()
            && agent.is_none()
            && grpc_edge.is_none()
            && grpc_transcoding.is_none()
            && long_stream_idle_timeout_ms.is_none()
            && request_timeout_ms.is_none()
            && backend_request_timeout_ms.is_none()
            && *long_stream_max_lifetime_ms == 0,
        "xDS HTTP projection rejects native-only route policies"
    );
    #[cfg(feature = "config-providers")]
    ensure!(
        provider_deadline.is_none(),
        "xDS projection cannot detach provider authority expiry"
    );
    Ok(())
}

/// 业务作用：生成严格大小写路径与单方法匹配，不解释正则、变量或复合原生断言。
///
/// 参数说明：
/// - `route`：固定断言列表。
///
/// 返回：唯一显式 Path/PathExact 加可选单个 Method 的标准匹配；其他组合拒绝候选。
fn route_match(route: &RouteCfg) -> Result<p::RouteMatch> {
    let mut path = None;
    let mut method = None;
    for predicate in &route.predicates {
        let (kind, value) = predicate
            .split_once('=')
            .context("xDS predicate needs a literal value")?;
        match kind {
            "Path" | "PathExact" => {
                ensure!(
                    path.is_none()
                        && value.starts_with('/')
                        && value.len() <= 2048
                        && !value.split('/').any(|part| part == "." || part == "..")
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"/._-~".contains(&b)),
                    "xDS path projection needs one literal path"
                );
                path = Some(if kind == "Path" {
                    p::PathMatch::Prefix(value.into())
                } else {
                    p::PathMatch::Exact(value.into())
                });
            }
            "Method" => {
                ensure!(
                    method.is_none()
                        && matches!(
                            value,
                            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
                        ),
                    "xDS Method projection requires one standard method"
                );
                method = Some(p::HeaderMatcher {
                    name: ":method".into(),
                    exact_match: value.into(),
                });
            }
            _ => anyhow::bail!(
                "xDS HTTP projection supports only literal Path, PathExact and one Method"
            ),
        }
    }
    ensure!(
        path.is_some(),
        "xDS HTTP projection requires an explicit path"
    );
    Ok(p::RouteMatch {
        path,
        case_sensitive: Some(true),
        headers: method.into_iter().collect(),
    })
}

/// 业务作用：用同一强类型地址编码 listener 和 endpoint，避免默认协议或端口推断产生歧义。
///
/// 参数说明：
/// - `socket`：已校验的 TCP 地址和非零端口。
///
/// 返回：固定 TCP SocketAddress。
fn address(socket: SocketAddr) -> p::Address {
    p::Address {
        socket_address: Some(p::SocketAddress {
            address: socket.ip().to_string(),
            port_value: u32::from(socket.port()),
        }),
    }
}

/// 业务作用：为已授权入口发布固定 HCM 和可选 SDS 引用，不接受任意网络过滤器。
///
/// 参数说明：
/// - `resources`：当前节点候选集合。
/// - `name`：当前 proxy 下的唯一 listener 名称。
/// - `listen`：原生声明的监听地址。
/// - `hcm`：同 proxy 的固定路由引用。
/// - `transport_socket`：已经完整构建的 TLS 引用，或显式明文入口。
///
/// 返回：资源在数量和字节上限内时加入候选；非法地址或预算不足使候选失败。
fn listener(
    resources: &mut Resources,
    name: &str,
    listen: &str,
    hcm: &p::HttpConnectionManager,
    transport_socket: Option<p::TransportSocket>,
) -> Result<()> {
    let socket: SocketAddr = listen
        .parse()
        .context("xDS listener needs an IP socket address")?;
    ensure!(
        socket.port() != 0,
        "xDS listener cannot use an ephemeral port"
    );
    insert(resources, p::LDS, name, &p::Listener {
        name: name.to_owned(),
            address: Some(address(socket)),
            per_connection_buffer_limit_bytes: Some(64 * 1024),
        filter_chains: vec![p::FilterChain { filters: vec![p::NetworkFilter {
            name: "envoy.filters.network.http_connection_manager".into(),
            typed_config: Some(p::pack("type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", hcm)),
        }], transport_socket }],
    })
}

/// 业务作用：统一限制投影资源大小并给内容分配稳定版本，语义回滚仍由外层单调快照版本记录。
///
/// 参数说明：
/// - `resources`：当前候选目录。
/// - `kind`：固定资源类型。
/// - `name`：规范资源名称。
/// - `value`：由本地投影生成的消息。
///
/// 返回：合法、唯一且单资源不超过 512KiB 时插入；否则拒绝候选。
fn insert(
    resources: &mut Resources,
    kind: &'static str,
    name: &str,
    value: &impl Message,
) -> Result<()> {
    ensure!(
        value.encoded_len() <= 512 * 1024,
        "xDS projected resource exceeds byte budget"
    );
    let value = p::pack(kind, value);
    let version = format!("{:x}", Sha256::digest(&value.value));
    ensure!(
        resources
            .entry(kind)
            .or_default()
            .insert(
                name.to_owned(),
                Entry {
                    value,
                    version
                }
            )
            .is_none(),
        "duplicate xDS projected resource"
    );
    Ok(())
}
