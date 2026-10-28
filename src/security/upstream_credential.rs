//! 上游凭据引用解析、backend 归属门禁与请求期注入。
//!
//! SecretSource 只在候选构建期解析。请求热路径只读取已冻结的 HeaderValue/String，并在任何
//! 上游 I/O 前删除客户端同名值，再写入绑定到当前 route/backend 的凭据。

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use http::header::{HeaderName, HeaderValue};
use http::request::Parts;
use http::Uri;

use crate::config::model::{GatewayConfig, UpstreamCredentialCfg, UpstreamTlsCfg};
use crate::routing::RequestHeaderOp;

const MAX_CREDENTIALS: usize = 256;
const MAX_CREDENTIAL_REFS: usize = 16;
const MAX_ALLOWED_BACKENDS: usize = 64;
const MAX_QUERY_NAME_BYTES: usize = 128;

/// route 快照内的已解析凭据注入计划。
pub(crate) struct UpstreamCredentialPlan {
    headers: Vec<(HeaderName, HeaderValue)>,
    query: Vec<(String, String)>,
    not_after: Option<std::time::Instant>,
}

impl UpstreamCredentialPlan {
    /// 业务作用：把已通过引用和 backend 归属校验的凭据编译成请求期不可变注入计划。
    ///
    /// 参数说明：
    /// - `cfgs`：是 route 已解析引用
    /// - `config_dir`：是 SecretSource 路径基准
    /// - `request_headers`：是 route 自身 mutation
    /// - `route_id`：用于不含 secret 的错误定位。
    ///
    /// 返回：凭据类型、目标、SecretSource 和 mutation 冲突均合法时返回计划，否则拒绝候选。
    pub(crate) fn build(
        cfgs: &[UpstreamCredentialCfg],
        config_dir: &Path,
        request_headers: &[RequestHeaderOp],
        route_id: &str,
    ) -> Result<Option<Arc<Self>>> {
        if cfgs.is_empty() {
            return Ok(None);
        }
        let mut headers = Vec::new();
        let mut query = Vec::new();
        let mut header_targets = HashSet::new();
        let mut query_targets = HashSet::new();
        let mut not_after = None;
        for cfg in cfgs {
            let overwrite = cfg.overwrite.with_context(|| {
                format!(
                    "route `{route_id}` upstream credential `{}` must declare overwrite",
                    cfg.name
                )
            })?;
            let value = resolved_value(cfg, config_dir)?;
            if value.is_empty() {
                bail!(
                    "upstream credential `{}` resolves to an empty value",
                    cfg.name
                );
            }
            match cfg.kind.as_str() {
                "api_key" | "header" | "bearer" | "basic" => {
                    let name = credential_header_name(cfg)?;
                    if !header_targets.insert(name.clone()) {
                        bail!(
                            "route `{route_id}` has multiple upstream credentials for header `{name}`"
                        );
                    }
                    if !overwrite
                        && request_headers
                            .iter()
                            .any(|operation| request_header_name(operation) == name)
                    {
                        bail!(
                            "route `{route_id}` upstream credential `{}` overwrite=false conflicts with a route header mutation",
                            cfg.name
                        );
                    }
                    let rendered = credential_header_value(cfg, value.as_str())?;
                    headers.push((name, rendered));
                }
                "query" => {
                    validate_query_name(cfg.target.as_str())?;
                    if !query_targets.insert(cfg.target.clone()) {
                        bail!(
                            "route `{route_id}` has multiple upstream credentials for query `{}`",
                            cfg.target
                        );
                    }
                    query.push((cfg.target.clone(), value));
                }
                "tls_client_identity" => {
                    bail!(
                        "route `{route_id}` cannot attach TLS client identity `{}`; bind it to upstreams.services.<name>.upstream_credentials",
                        cfg.name
                    );
                }
                _ => bail!("upstream credential `{}` has unknown kind", cfg.name),
            }
            not_after = earliest_deadline(not_after, cfg.resolved_not_after);
        }
        Ok(Some(Arc::new(Self {
            headers,
            query,
            not_after,
        })))
    }

    /// 业务作用：在最终上游 head 发送前删除同名客户端值并注入当前 backend 专属凭据。
    ///
    /// 参数说明：
    /// - `parts`：已完成普通 route mutation，尚未执行任何上游 I/O。
    ///
    /// 返回：header/query 均可安全重建时成功；URI 构造失败时拒绝本次上游请求。
    pub(crate) fn apply(&self, parts: &mut Parts) -> Result<()> {
        if self
            .not_after
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            // 远程值超过 lease 或最大陈旧期后必须在任何上游 I/O 前停止使用；继续发送会把
            // 已失权的身份当作有效凭据，并绕过 provider 的撤权边界。
            bail!("upstream credential is no longer within its remote validity window");
        }
        for (name, value) in &self.headers {
            // 凭据写入是安全边界的最后一步；先删客户端或普通 filter 的同名值，避免重复头在
            // 不同上游框架中产生 first/last-wins 歧义。
            parts.headers.remove(name);
            parts.headers.insert(name.clone(), value.clone());
        }
        if self.query.is_empty() {
            return Ok(());
        }
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        if let Some(existing) = parts.uri.query() {
            for (name, value) in form_urlencoded::parse(existing.as_bytes()) {
                if !self
                    .query
                    .iter()
                    .any(|(secret_name, _)| secret_name == name.as_ref())
                {
                    serializer.append_pair(name.as_ref(), value.as_ref());
                }
            }
        }
        for (name, value) in &self.query {
            serializer.append_pair(name, value);
        }
        let query = serializer.finish();
        let mut uri = parts.uri.clone().into_parts();
        uri.path_and_query = Some(
            format!("{}?{query}", parts.uri.path())
                .parse()
                .context("build upstream credential query")?,
        );
        parts.uri = Uri::from_parts(uri).context("build upstream credential URI")?;
        Ok(())
    }
}

/// 业务作用：解析全局凭据引用，复验 backend allowlist，并把 TLS identity 注入所属 service 候选。
///
/// 参数说明：
/// - `cfg`：是尚未构建路由与上游目录的完整候选
/// - `config_dir`：是 SecretSource 路径基准
/// - `crypto_catalog`：提供远程 secret envelope 解密所需的共享密码 provider。
///
/// 返回：所有定义恰有消费者、类型与归属一致时返回可选远程刷新周期；未知引用、错 backend、
/// provider 或 secret 错误拒绝候选。
pub(crate) fn resolve_references(
    cfg: &mut GatewayConfig,
    config_dir: &Path,
    crypto_catalog: &crate::security::external_crypto::ExternalCryptoCatalog,
) -> Result<Option<u64>> {
    if cfg.upstream_credentials.len() > MAX_CREDENTIALS {
        bail!("upstream_credentials supports at most {MAX_CREDENTIALS} entries");
    }
    let mut remote_references = cfg
        .upstream_credentials
        .iter()
        .flat_map(|credential| {
            [
                credential.value.clone(),
                credential.client_certificate.clone(),
                credential.client_private_key.clone(),
            ]
        })
        .collect::<Vec<_>>();
    for route in cfg
        .routes
        .iter()
        .chain(cfg.proxies.iter().flat_map(|proxy| proxy.routes.iter()))
    {
        if let Some(llm) = &route.llm {
            remote_references.extend(llm.models.iter().flat_map(|model| {
                [
                    model.api_key.clone(),
                    model.aws_access_key_id.clone(),
                    model.aws_secret_access_key.clone(),
                    model.aws_session_token.clone(),
                ]
            }));
        }
    }
    let remote = crate::security::remote_secret::resolve_all(
        cfg.secret_providers.as_slice(),
        remote_references,
        config_dir,
        crypto_catalog,
    )?;
    for credential in &mut cfg.upstream_credentials {
        resolve_remote_fields(credential, &remote)?;
    }
    for route in cfg.routes.iter_mut().chain(
        cfg.proxies
            .iter_mut()
            .flat_map(|proxy| proxy.routes.iter_mut()),
    ) {
        if let Some(llm) = &mut route.llm {
            for model in &mut llm.models {
                resolve_llm_remote_fields(model, &remote)?;
            }
        }
    }
    let mut definitions = HashMap::with_capacity(cfg.upstream_credentials.len());
    for credential in &cfg.upstream_credentials {
        validate_definition(credential, config_dir)?;
        if definitions
            .insert(credential.name.clone(), credential.clone())
            .is_some()
        {
            bail!("duplicate upstream credential name `{}`", credential.name);
        }
    }
    let mut used = HashSet::new();
    for route in cfg.routes.iter_mut().chain(
        cfg.proxies
            .iter_mut()
            .flat_map(|proxy| proxy.routes.iter_mut()),
    ) {
        validate_references(
            route.upstream_credentials.as_slice(),
            "route",
            route.id.as_str(),
        )?;
        if route.upstream_credentials.is_empty() {
            continue;
        }
        let backend = normalize_backend(route.uri.as_str())
            .with_context(|| format!("route `{}` upstream credential backend", route.id))?;
        for reference in &route.upstream_credentials {
            let credential = definitions.get(reference).with_context(|| {
                format!(
                    "route `{}` references unknown upstream credential",
                    route.id
                )
            })?;
            if credential.kind == "tls_client_identity" {
                bail!(
                    "route `{}` cannot attach TLS client identity `{reference}` directly",
                    route.id
                );
            }
            ensure_backend_allowed(credential, backend.as_str())?;
            if credential.kind == "query"
                && credential.overwrite == Some(false)
                && route_query_contains(route.uri.as_str(), credential.target.as_str())?
            {
                bail!(
                    "route `{}` upstream credential `{reference}` overwrite=false conflicts with a fixed route query",
                    route.id
                );
            }
            route.resolved_upstream_credentials.push(credential.clone());
            used.insert(reference.clone());
        }
    }
    for (service_name, service) in &mut cfg.upstreams.services {
        validate_references(
            service.upstream_credentials.as_slice(),
            "service",
            service_name.as_str(),
        )?;
        if service.upstream_credentials.len() > 1 {
            bail!("service `{service_name}` may bind at most one TLS client identity");
        }
        let backend = format!("lb://{service_name}");
        for reference in &service.upstream_credentials {
            let credential = definitions.get(reference).with_context(|| {
                format!("service `{service_name}` references unknown upstream credential")
            })?;
            if credential.kind != "tls_client_identity" {
                bail!(
                    "service `{service_name}` credential `{reference}` must be tls_client_identity"
                );
            }
            ensure_backend_allowed(credential, backend.as_str())?;
            attach_tls_identity(
                service_name,
                service.tls.get_or_insert_with(Default::default),
                credential,
                config_dir,
            )?;
            used.insert(reference.clone());
        }
    }
    if let Some(unused) = definitions.keys().find(|name| !used.contains(*name)) {
        bail!("upstream credential `{unused}` is not referenced by any route or service");
    }
    Ok(remote.refresh_interval_ms())
}

/// 业务作用：收集凭据定义中的文件型 SecretSource，使内容轮换进入统一配置 watcher。
///
/// 参数说明：
/// - `cfg`：是完整候选
/// - `config_dir`：是相对路径基准。
///
/// 返回：返回 value、client certificate 和 private key 的本地文件依赖，不包含 secret 内容。
pub(crate) fn dependency_paths(cfg: &GatewayConfig, config_dir: &Path) -> Vec<std::path::PathBuf> {
    let mut paths = cfg
        .upstream_credentials
        .iter()
        .flat_map(|credential| {
            [
                credential.value.as_str(),
                credential.client_certificate.as_str(),
                credential.client_private_key.as_str(),
            ]
            .into_iter()
            .filter_map(|value| crate::security::secret::dependency_path(value, config_dir))
        })
        .collect::<Vec<_>>();
    for route in cfg
        .routes
        .iter()
        .chain(cfg.proxies.iter().flat_map(|proxy| proxy.routes.iter()))
    {
        if let Some(llm) = &route.llm {
            paths.extend(llm.models.iter().flat_map(|model| {
                [
                    model.api_key.as_str(),
                    model.aws_access_key_id.as_str(),
                    model.aws_secret_access_key.as_str(),
                    model.aws_session_token.as_str(),
                ]
                .into_iter()
                .filter_map(|value| crate::security::secret::dependency_path(value, config_dir))
            }));
        }
    }
    paths.extend(crate::security::remote_secret::dependency_paths(
        cfg.secret_providers.as_slice(),
        config_dir,
    ));
    paths
}

/// 业务作用：把模型 provider 的远程 API key 与云签名材料物化到同一候选，并合并最早失效时间。
///
/// 参数说明：
/// - `model`：是尚未编译的模型声明
/// - `resolution`：是本轮 provider prepare 的完整结果。
///
/// 返回：远程引用都存在时成功；任一材料缺失时拒绝整个候选，避免发布半套云身份。
fn resolve_llm_remote_fields(
    model: &mut crate::config::model::LlmModelCfg,
    resolution: &crate::security::remote_secret::RemoteSecretResolution,
) -> Result<()> {
    if crate::security::remote_secret::is_remote_reference(model.api_key.as_str()) {
        let resolved = resolution.get(model.api_key.as_str())?;
        model.resolved_api_key = Some(resolved.value());
        model.resolved_not_after =
            earliest_deadline(model.resolved_not_after, Some(resolved.not_after()));
    }
    if crate::security::remote_secret::is_remote_reference(model.aws_access_key_id.as_str()) {
        let resolved = resolution.get(model.aws_access_key_id.as_str())?;
        model.resolved_aws_access_key_id = Some(resolved.value());
        model.resolved_not_after =
            earliest_deadline(model.resolved_not_after, Some(resolved.not_after()));
    }
    if crate::security::remote_secret::is_remote_reference(model.aws_secret_access_key.as_str()) {
        let resolved = resolution.get(model.aws_secret_access_key.as_str())?;
        model.resolved_aws_secret_access_key = Some(resolved.value());
        model.resolved_not_after =
            earliest_deadline(model.resolved_not_after, Some(resolved.not_after()));
    }
    if crate::security::remote_secret::is_remote_reference(model.aws_session_token.as_str()) {
        let resolved = resolution.get(model.aws_session_token.as_str())?;
        model.resolved_aws_session_token = Some(resolved.value());
        model.resolved_not_after =
            earliest_deadline(model.resolved_not_after, Some(resolved.not_after()));
    }
    Ok(())
}

/// 业务作用：把凭据中的远程引用替换为仅驻留候选内存的值，并合并最早失效时间。
///
/// 参数说明：
/// - `credential`：是待物化定义
/// - `resolution`：是同一次 provider prepare 的完整结果。
///
/// 返回：全部远程引用存在时成功；缺失映射拒绝候选且不保留半物化定义。
fn resolve_remote_fields(
    credential: &mut UpstreamCredentialCfg,
    resolution: &crate::security::remote_secret::RemoteSecretResolution,
) -> Result<()> {
    if crate::security::remote_secret::is_remote_reference(credential.value.as_str()) {
        let resolved = resolution.get(credential.value.as_str())?;
        credential.resolved_value = Some(resolved.value());
        credential.resolved_not_after =
            earliest_deadline(credential.resolved_not_after, Some(resolved.not_after()));
    }
    if crate::security::remote_secret::is_remote_reference(credential.client_certificate.as_str()) {
        let resolved = resolution.get(credential.client_certificate.as_str())?;
        credential.resolved_client_certificate = Some(resolved.value());
        credential.resolved_not_after =
            earliest_deadline(credential.resolved_not_after, Some(resolved.not_after()));
    }
    if crate::security::remote_secret::is_remote_reference(credential.client_private_key.as_str()) {
        let resolved = resolution.get(credential.client_private_key.as_str())?;
        credential.resolved_client_private_key = Some(resolved.value());
        credential.resolved_not_after =
            earliest_deadline(credential.resolved_not_after, Some(resolved.not_after()));
    }
    Ok(())
}

/// 业务作用：合并多个远程字段的有效期，确保组合凭据按最早失效材料失败闭合。
///
/// 参数说明：
/// - `left`：是可选单调时钟截止点。
/// - `right`：是可选单调时钟截止点。
///
/// 返回：返回两个截止点中更早者；仅一侧存在时返回该侧。
fn earliest_deadline(
    left: Option<std::time::Instant>,
    right: Option<std::time::Instant>,
) -> Option<std::time::Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// 业务作用：读取普通 credential 值，优先使用本轮远程 prepare 的内存结果。
///
/// 参数说明：
/// - `cfg`：是凭据定义
/// - `config_dir`：是本地来源路径基准。
///
/// 返回：远程或本地 SecretSource 成功时返回值；未物化远程引用和本地读取错误拒绝候选。
fn resolved_value(cfg: &UpstreamCredentialCfg, config_dir: &Path) -> Result<String> {
    if let Some(value) = &cfg.resolved_value {
        return Ok(value.clone());
    }
    if crate::security::remote_secret::is_remote_reference(cfg.value.as_str()) {
        bail!("upstream credential remote value was not prepared");
    }
    crate::security::secret::resolve_text(
        cfg.value.as_str(),
        config_dir,
        &format!("upstream credential `{}` value", cfg.name),
    )
}

/// 业务作用：读取 TLS identity 单项材料，禁止把未解析远程引用交给 PEM parser。
///
/// 参数说明：
/// - `resolved`：是可选远程值
/// - `raw`：是原始来源
/// - `config_dir`：是本地路径基准
/// - `field`：是不含 secret 的错误标签。
///
/// 返回：返回已解析 PEM 文本；来源缺失或读取失败时拒绝候选。
fn resolved_tls_material(
    resolved: Option<&String>,
    raw: &str,
    config_dir: &Path,
    field: &str,
) -> Result<String> {
    if let Some(value) = resolved {
        return Ok(value.clone());
    }
    if crate::security::remote_secret::is_remote_reference(raw) {
        bail!("{field} remote value was not prepared");
    }
    crate::security::secret::resolve_text(raw, config_dir, field)
}

/// 业务作用：验证一个凭据定义的类型专属字段、SecretSource 和 backend 边界。
///
/// 参数说明：
/// - `cfg`：是单一凭据
/// - `config_dir`：是 SecretSource 路径基准。
///
/// 返回：声明自洽且所有本地 secret 可读取时成功，否则返回错误。
fn validate_definition(cfg: &UpstreamCredentialCfg, config_dir: &Path) -> Result<()> {
    validate_name(cfg.name.as_str())?;
    if cfg.allowed_backends.is_empty() || cfg.allowed_backends.len() > MAX_ALLOWED_BACKENDS {
        bail!(
            "upstream credential `{}` allowed_backends must be in 1..={MAX_ALLOWED_BACKENDS}",
            cfg.name
        );
    }
    let mut allowed = HashSet::new();
    for backend in &cfg.allowed_backends {
        let backend = normalize_allowed_backend(backend)
            .with_context(|| format!("upstream credential `{}` allowed backend", cfg.name))?;
        if !allowed.insert(backend) {
            bail!(
                "upstream credential `{}` has duplicate allowed backend",
                cfg.name
            );
        }
    }
    match cfg.kind.as_str() {
        "api_key" | "header" | "query" => {
            if cfg.overwrite.is_none()
                || cfg.value.is_empty()
                || !cfg.username.is_empty()
                || !cfg.client_certificate.is_empty()
                || !cfg.client_private_key.is_empty()
            {
                bail!(
                    "upstream credential `{}` fields do not match its kind",
                    cfg.name
                );
            }
            if cfg.kind == "query" {
                validate_query_name(cfg.target.as_str())?;
            } else {
                let _ = credential_header_name(cfg)?;
            }
            let _ = resolved_value(cfg, config_dir)?;
        }
        "bearer" => {
            if cfg.overwrite.is_none()
                || cfg.value.is_empty()
                || !cfg.username.is_empty()
                || !cfg.target.is_empty()
                || !cfg.client_certificate.is_empty()
                || !cfg.client_private_key.is_empty()
            {
                bail!(
                    "upstream credential `{}` fields do not match bearer",
                    cfg.name
                );
            }
            let _ = resolved_value(cfg, config_dir)?;
        }
        "basic" => {
            if cfg.overwrite.is_none()
                || cfg.value.is_empty()
                || cfg.username.is_empty()
                || !cfg.target.is_empty()
                || !cfg.client_certificate.is_empty()
                || !cfg.client_private_key.is_empty()
            {
                bail!(
                    "upstream credential `{}` fields do not match basic",
                    cfg.name
                );
            }
            if cfg.username.len() > 256
                || cfg.username.contains(':')
                || cfg.username.bytes().any(|byte| byte.is_ascii_control())
            {
                bail!(
                    "upstream credential `{}` Basic username is invalid",
                    cfg.name
                );
            }
            let _ = resolved_value(cfg, config_dir)?;
        }
        "tls_client_identity" => {
            if cfg.overwrite.is_some()
                || !cfg.value.is_empty()
                || !cfg.username.is_empty()
                || !cfg.target.is_empty()
                || cfg.client_certificate.is_empty()
                || cfg.client_private_key.is_empty()
            {
                bail!(
                    "upstream credential `{}` fields do not match TLS identity",
                    cfg.name
                );
            }
            for (resolved, value, field) in [
                (
                    cfg.resolved_client_certificate.as_ref(),
                    &cfg.client_certificate,
                    "client certificate",
                ),
                (
                    cfg.resolved_client_private_key.as_ref(),
                    &cfg.client_private_key,
                    "client private key",
                ),
            ] {
                let _ = resolved_tls_material(
                    resolved,
                    value.as_str(),
                    config_dir,
                    &format!("upstream credential `{}` {field}", cfg.name),
                )?;
            }
        }
        _ => bail!("upstream credential `{}` has unknown kind", cfg.name),
    }
    Ok(())
}

/// 业务作用：把 TLS identity 的已解析 PEM 写入所属 service 候选，禁止覆盖另一身份。
///
/// 参数说明：
/// - `service_name`：标识连接池
/// - `tls`：是候选 TLS
/// - `credential`：提供 PEM SecretSource
/// - `config_dir`：是相对路径基准。
///
/// 返回：service 尚无其它 client identity 且 PEM 可读取时成功，否则拒绝候选。
fn attach_tls_identity(
    service_name: &str,
    tls: &mut UpstreamTlsCfg,
    credential: &UpstreamCredentialCfg,
    config_dir: &Path,
) -> Result<()> {
    if tls.client_cert_file.is_some()
        || tls.client_key_file.is_some()
        || tls.client_cert_pem.is_some()
        || tls.client_key_pem.is_some()
    {
        bail!("service `{service_name}` already declares an upstream TLS client identity");
    }
    tls.client_cert_pem = Some(resolved_tls_material(
        credential.resolved_client_certificate.as_ref(),
        credential.client_certificate.as_str(),
        config_dir,
        &format!(
            "upstream credential `{}` client certificate",
            credential.name
        ),
    )?);
    tls.client_key_pem = Some(resolved_tls_material(
        credential.resolved_client_private_key.as_ref(),
        credential.client_private_key.as_str(),
        config_dir,
        &format!(
            "upstream credential `{}` client private key",
            credential.name
        ),
    )?);
    tls.client_identity_not_after = credential.resolved_not_after;
    Ok(())
}

/// 业务作用：把凭据类型映射到唯一安全 header 名，并拒绝 framing/routing header。
///
/// 参数说明：
/// - `cfg`：是已通过类型字段初检的凭据。
///
/// 返回：Bearer/Basic 返回 Authorization，API key/custom header 返回验证后的名称。
fn credential_header_name(cfg: &UpstreamCredentialCfg) -> Result<HeaderName> {
    let name = match cfg.kind.as_str() {
        "bearer" | "basic" => HeaderName::from_static("authorization"),
        "api_key" => {
            let target = if cfg.target.is_empty() {
                "x-api-key"
            } else {
                cfg.target.as_str()
            };
            target.parse().context("invalid upstream API-key header")?
        }
        "header" => cfg
            .target
            .parse()
            .context("invalid upstream credential header")?,
        _ => bail!("upstream credential kind does not use a header"),
    };
    if matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "upgrade"
            | "te"
            | "trailer"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "forwarded"
            | "x-client-cert-verified"
    ) {
        bail!("upstream credential cannot target routing, framing or trusted proxy header");
    }
    Ok(name)
}

/// 业务作用：构造最终敏感 HeaderValue，并让协议栈在调试输出中保持敏感标记。
///
/// 参数说明：
/// - `cfg`：决定格式
/// - `value`：是已解析 secret。
///
/// 返回：值可编码为合法 header 时返回 sensitive HeaderValue，否则拒绝候选。
fn credential_header_value(cfg: &UpstreamCredentialCfg, value: &str) -> Result<HeaderValue> {
    let value = match cfg.kind.as_str() {
        "bearer" => format!("Bearer {value}"),
        "basic" => format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{value}", cfg.username).as_bytes())
        ),
        _ => value.to_owned(),
    };
    let mut value = HeaderValue::from_str(value.as_str())
        .context("upstream credential is not a valid header value")?;
    value.set_sensitive(true);
    Ok(value)
}

/// 业务作用：验证 query 凭据名可被稳定 form 编码且不会制造无界 key。
///
/// 参数说明：
/// - `name`：是 query 参数名。
///
/// 返回：ASCII 字母数字、点、下划线或连字符组成的非空有界名称成功，否则返回错误。
fn validate_query_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_QUERY_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("upstream query credential target is invalid");
    }
    Ok(())
}

/// 业务作用：验证凭据和引用名称为稳定、低敏标识符。
///
/// 参数说明：
/// - `name`：是全局凭据名称。
///
/// 返回：1..=128 字节的安全 ASCII 名称成功，否则返回错误。
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("upstream credential name is invalid");
    }
    Ok(())
}

/// 业务作用：验证单个 route/service 引用列表有界、无重复且名称合法。
///
/// 参数说明：
/// - `references`：是名称列表
/// - `owner_kind`：用于错误定位。
/// - `owner_id`：用于错误定位。
///
/// 返回：列表合法时成功，否则拒绝候选。
fn validate_references(references: &[String], owner_kind: &str, owner_id: &str) -> Result<()> {
    if references.len() > MAX_CREDENTIAL_REFS {
        bail!("{owner_kind} `{owner_id}` has too many upstream credential references");
    }
    let mut seen = HashSet::with_capacity(references.len());
    for reference in references {
        validate_name(reference)?;
        if !seen.insert(reference) {
            bail!("{owner_kind} `{owner_id}` repeats an upstream credential reference");
        }
    }
    Ok(())
}

/// 业务作用：把 backend 声明规范化为 origin 或 `lb://service`，防 path/大小写差异绕过归属门。
///
/// 参数说明：
/// - `raw`：是 route URI 或 allowed_backends 条目。
///
/// 返回：固定 HTTP(S) origin 或合法逻辑服务名；变量、凭据和其它 scheme 返回错误。
fn normalize_backend(raw: &str) -> Result<String> {
    if raw.contains("${") {
        bail!("dynamic upstream cannot receive a statically bound credential");
    }
    if let Some(service) = raw.strip_prefix("lb://") {
        if service.is_empty()
            || service.contains(['/', '?', '#', '@'])
            || service.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            bail!("invalid credential lb backend");
        }
        return Ok(format!("lb://{service}"));
    }
    let uri: Uri = raw.parse().context("invalid credential HTTP backend")?;
    let scheme = uri
        .scheme_str()
        .context("credential backend requires scheme")?;
    if !matches!(scheme, "http" | "https") {
        bail!("credential backend must use HTTP(S)");
    }
    let authority = uri
        .authority()
        .context("credential backend requires authority")?;
    if authority.as_str().contains('@') {
        bail!("credential backend authority must not contain userinfo");
    }
    let host = authority.host().to_ascii_lowercase();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let port = authority.port_u16();
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => unreachable!("scheme checked above"),
    };
    Ok(match port {
        Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    })
}

/// 业务作用：复验 allowlist 条目确实是 origin，而不是会被静默截断的具体 path/query。
///
/// 参数说明：
/// - `raw`：是 `allowed_backends` 单项。
///
/// 返回：根路径 HTTP(S) origin 或 `lb://service` 返回规范身份；其它形态拒绝候选。
fn normalize_allowed_backend(raw: &str) -> Result<String> {
    if raw.starts_with("lb://") {
        return normalize_backend(raw);
    }
    let uri: Uri = raw.parse().context("invalid credential allowed backend")?;
    if uri.query().is_some() || !matches!(uri.path(), "" | "/") {
        bail!("credential allowed backend must be an origin without path or query");
    }
    normalize_backend(raw)
}

/// 业务作用：检测 route 固定 URI 是否已产生同名 query，供 overwrite=false 冲突门禁使用。
///
/// 参数说明：
/// - `uri`：是已禁止动态凭据路由的目标
/// - `target`：是凭据 query 名。
///
/// 返回：解析成功时返回是否存在同名参数；非法 URI 返回错误并拒绝候选。
fn route_query_contains(uri: &str, target: &str) -> Result<bool> {
    let uri: Uri = uri.parse().context("invalid credential route URI")?;
    Ok(uri.query().is_some_and(|query| {
        form_urlencoded::parse(query.as_bytes()).any(|(name, _)| name == target)
    }))
}

/// 业务作用：复验凭据只会到达定义时声明的 backend。
///
/// 参数说明：
/// - `credential`：是全局定义
/// - `backend`：是 route/service 规范身份。
///
/// 返回：allowlist 精确命中时成功，未命中拒绝候选。
fn ensure_backend_allowed(credential: &UpstreamCredentialCfg, backend: &str) -> Result<()> {
    let allowed = credential
        .allowed_backends
        .iter()
        .map(|candidate| normalize_allowed_backend(candidate))
        .collect::<Result<Vec<_>>>()?;
    if !allowed.iter().any(|candidate| candidate == backend) {
        bail!(
            "upstream credential `{}` is not allowed for backend `{backend}`",
            credential.name
        );
    }
    Ok(())
}

/// 业务作用：提取 route header mutation 的目标名，供 overwrite=false 构建期冲突门禁。
///
/// 参数说明：
/// - `operation`：是已编译 mutation。
///
/// 返回：返回该操作会修改的 header 名。
fn request_header_name(operation: &RequestHeaderOp) -> &HeaderName {
    match operation {
        RequestHeaderOp::Set(value) | RequestHeaderOp::Add(value) => &value.name,
        RequestHeaderOp::Remove(name) => name,
    }
}
