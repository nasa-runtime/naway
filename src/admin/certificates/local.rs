//! 本机证书材料查询与手工条件安装；此入口不代表集群持久交付。

use crate::admin::{
    approval_required, authenticate_admin_request, collect_bounded_admin_body, finish_config_write,
    json, plain, prepare_config_write, reject_untrusted_admin_browser_origin, request_content_type,
    submit_approval_change, AdminAction, AdminRequest, AdminRequestParts, AdminResource,
    AdminState, ApprovalPayload, BoxBody,
};
use anyhow::Context;
use http::{Response, StatusCode};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// 业务作用：枚举所有 TLS listener 的域名、证书到期时间、原子 manifest 与 ACME 策略状态。
///
/// 参数说明：
/// - `state`：提供当前不可变 TLS 计划与有界证书读取路径。
///
/// 返回：返回 200 和逐证书状态；单个证书缺失/损坏仅将该项标记 `ok=false`，不读取或返回私钥。
pub(in crate::admin) fn read_certificates(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load();
    let mut certificates = Vec::new();
    for proxy in snapshot.proxies.iter() {
        let Some(tls) = &proxy.tls else {
            continue;
        };
        let source = if tls.in_memory.is_some() {
            "sds"
        } else if tls.keypair_manifest_file.is_some() {
            "manifest"
        } else if tls.acme.is_some() {
            "acme"
        } else {
            "static"
        };
        let default_status = if let Some(material) = &tls.in_memory {
            certificate_status(material.certificate_chain.as_ref())
        } else {
            crate::tls::active_keypair_paths(tls)
                .and_then(|(cert, _)| {
                    crate::io::bounded_io::read_file(&cert, 1024 * 1024, "admin TLS certificate")
                })
                .and_then(|bytes| certificate_status(&bytes))
        };
        certificates.push(certificate_json(
            &proxy.id,
            "default",
            proxy.server_names.as_ref(),
            source,
            tls,
            default_status,
        ));
        for (index, sni) in tls.certs.iter().enumerate() {
            let status = crate::io::bounded_io::read_file(
                &sni.cert_file,
                1024 * 1024,
                "admin SNI TLS certificate",
            )
            .and_then(|bytes| certificate_status(&bytes));
            certificates.push(certificate_json(
                &proxy.id,
                &format!("sni-{index}"),
                sni.server_names.as_ref(),
                "static",
                tls,
                status,
            ));
        }
    }
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "certificates": certificates
        }),
    )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateUploadInput {
    proxy: String,
    certificate_pem: String,
    private_key_pem: String,
}

/// 与原配置和提交主体绑定的完整材料；不能被序列化进入列表或审计。
pub(in crate::admin) struct Installation {
    pub tls: crate::config::TlsRuntimeCfg,
    pub expected: String,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub version: u64,
    pub fingerprint: u64,
    pub initiator: Arc<str>,
}

/// 业务作用：以配置集 CAS 和证书事实 CAS 双重保护手工证书轮换，并与 ACME 安装共享互斥与 pair
/// 校验，防止覆盖并发续期或发布不匹配私钥。
///
/// 参数说明：
/// - `req`：必须带配置 `If-Match`、`X-Naway-Certificate-If-Match` 和有界 JSON PEM
/// - `state`：提供当前 TLS 计划、RBAC 与审计。
///
/// 返回：两个基线均未变化且 pair 安装成功时返回 200；并发轮换返回 412；无 listener、SDS、非法
/// PEM、超限或权限错误返回 4xx，I/O 故障返回 5xx。
pub(in crate::admin) async fn upload_certificate(
    req: AdminRequest,
    state: Arc<AdminState>,
) -> Response<BoxBody> {
    const MAX_CERT_UPLOAD_BYTES: usize = 2 * 1024 * 1024;

    let (parts, body) = req.into_parts();
    let prepared = match prepare_config_write(&parts, &state, AdminResource::Certs).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let expected_certificate = parts
        .headers
        .get("x-naway-certificate-if-match")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let response = if !request_content_type(&parts, "application/json") {
        json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            serde_json::json!({
                "ok": false,
                "error": "Content-Type must be application/json"
            }),
        )
    } else if expected_certificate.is_none() {
        json(
            StatusCode::PRECONDITION_REQUIRED,
            serde_json::json!({
                "ok": false,
                "error": "X-Naway-Certificate-If-Match is required; read GET /api/certs",
            }),
        )
    } else {
        match collect_bounded_admin_body(&parts, body, MAX_CERT_UPLOAD_BYTES).await {
            Err(response) => *response,
            Ok(body) => match serde_json::from_slice::<CertificateUploadInput>(&body) {
                Err(_) => json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "ok": false,
                        "error": "invalid certificate JSON"
                    }),
                ),
                Ok(input)
                    if input
                        .certificate_pem
                        .len()
                        .saturating_add(input.private_key_pem.len())
                        > MAX_CERT_UPLOAD_BYTES =>
                {
                    json(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        serde_json::json!({
                            "ok": false,
                            "error": "certificate pair exceeds 2 MiB"
                        }),
                    )
                }
                Ok(input) => {
                    // 读取正文可能跨越权限换代；旧认证不得为新配置创建待审批材料。
                    if let Err(response) = authorize(
                        &state,
                        &parts,
                        prepared.base_version,
                        prepared.base_fingerprint,
                        &prepared.identity.principal_id,
                    ) {
                        return finish_config_write(
                            &state,
                            &prepared.identity,
                            &parts,
                            AdminResource::Certs,
                            *response,
                        )
                        .await;
                    }
                    let tls = {
                        let snapshot = state.snap.load();
                        snapshot
                            .proxies
                            .iter()
                            .find(|proxy| proxy.id == input.proxy)
                            .and_then(|proxy| proxy.tls.clone())
                    };
                    match tls {
                        None => json(
                            StatusCode::NOT_FOUND,
                            serde_json::json!({
                                "ok": false,
                                "error": "TLS proxy not found"
                            }),
                        ),
                        Some(tls) if !manual_target(&tls) => json(
                            StatusCode::CONFLICT,
                            serde_json::json!({
                                "ok": false,
                                "error": "certificate identity source does not allow file upload"
                            }),
                        ),
                        Some(tls) => {
                            let expected = expected_certificate
                                .as_deref()
                                .expect("presence checked")
                                .to_string();
                            let certificate = input.certificate_pem.into_bytes();
                            let private_key = input.private_key_pem.into_bytes();
                            if approval_required(&state, AdminResource::Certs) {
                                submit_approval_change(
                                    &state,
                                    &prepared,
                                    AdminResource::Certs,
                                    ApprovalPayload::Certificate {
                                        tls: Box::new(tls),
                                        expected_etag: expected,
                                        certificate_pem: certificate,
                                        private_key_pem: private_key,
                                    },
                                )
                            } else {
                                install_uploaded_certificate(
                                    &state,
                                    &parts,
                                    Installation {
                                        tls,
                                        expected,
                                        certificate,
                                        private_key,
                                        version: prepared.base_version,
                                        fingerprint: prepared.base_fingerprint,
                                        initiator: prepared.identity.principal_id.clone(),
                                    },
                                )
                                .await
                            }
                        }
                    }
                }
            },
        }
    };
    finish_config_write(
        &state,
        &prepared.identity,
        &parts,
        AdminResource::Certs,
        response,
    )
    .await
}

/// 业务作用：持有配置发布权复验权限、源文档和证书 CAS，防止等待期间失权的材料写入旧目标。
///
/// 参数说明：
/// - `state`：与全部配置发布者共享协调器和文件事务的管理状态。
/// - `request`：当前请求凭据和浏览器来源，等待之后重新认证。
/// - `input`：原配置、提交主体、目标材料和 PEM 基线。
///
/// 返回：文件安装成功返回200；权限失败401/403、基线变化412、繁忙429，非法材料400或worker错误500。
/// HTTP 取消不释放实际任务仍持有的发布权；文件成功不代表所有监听协议已经完成热换。
pub(in crate::admin) async fn install_uploaded_certificate(
    state: &Arc<AdminState>,
    request: &AdminRequestParts,
    input: Installation,
) -> Response<BoxBody> {
    let Ok(permit) = state.certificates.installs.clone().try_acquire_owned() else {
        return plain(
            StatusCode::TOO_MANY_REQUESTS,
            "certificate installers exhausted\n",
        );
    };
    let Ok(publication) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.apply_coordinator.lock_owned(),
    )
    .await
    else {
        return plain(StatusCode::TOO_MANY_REQUESTS, "configuration writer busy\n");
    };
    // 先取得共享配置发布权再复验认证；该权威必须随真正的阻塞工作存活，不能随HTTP等待者提前释放。
    let snapshot = match authorize(
        state,
        request,
        input.version,
        input.fingerprint,
        &input.initiator,
    ) {
        Ok(snapshot) => snapshot,
        Err(response) => return *response,
    };
    if !manual_target(&input.tls)
        || !snapshot
            .proxies
            .iter()
            .any(|proxy| proxy.tls.as_ref() == Some(&input.tls))
    {
        return plain(
            StatusCode::CONFLICT,
            "certificate target authority changed\n",
        );
    }
    let state = state.clone();
    let installed = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _publication = publication;
        // 锁顺序固定为配置发布权、配置文件读事务、证书安装锁；受管写者不能在复验与写入之间换权限或原文。
        state.config_history.with_stable_local_files(|| {
            if !Arc::ptr_eq(&snapshot, &state.snap.load_full())
                || crate::config::config_fingerprint(&snapshot.source_config_path).ok()
                    != Some(input.fingerprint)
            {
                return None;
            }
            Some(crate::tls::keypair::install_keypair_atomically_if_match(
                &input.tls,
                &input.expected,
                &input.certificate,
                &input.private_key,
            ))
        })
    })
    .await;
    match installed {
        Ok(Some(crate::tls::keypair::KeypairCasInstallOutcome::Installed)) => json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "status": "installed"
            }),
        ),
        Ok(Some(crate::tls::keypair::KeypairCasInstallOutcome::Changed(etag))) => {
            let mut response = json(
                StatusCode::PRECONDITION_FAILED,
                serde_json::json!({
                    "ok": false,
                    "error": "certificate changed since it was read",
                    "certificate_etag": etag,
                }),
            );
            if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
                response.headers_mut().insert(hyper::header::ETAG, value);
            }
            response
        }
        Ok(None) => plain(
            StatusCode::PRECONDITION_FAILED,
            "certificate configuration baseline changed\n",
        ),
        Ok(Some(crate::tls::keypair::KeypairCasInstallOutcome::Invalid)) => {
            installation_failure(StatusCode::BAD_REQUEST, "invalid_certificate_material")
        }
        Ok(Some(crate::tls::keypair::KeypairCasInstallOutcome::Unavailable)) => {
            installation_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "certificate_storage_unavailable",
            )
        }
        Ok(Some(crate::tls::keypair::KeypairCasInstallOutcome::OutcomeUnknown)) | Err(_) => {
            installation_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "certificate_installation_outcome_unknown",
            )
        }
    }
}

/// 业务作用：向材料写入调用者交付固定失败分类，禁止底层文件路径、解析输入或私钥进入响应。
///
/// 参数说明：
/// - `status`：与候选拒绝、存储不可用或结果未知对应的 HTTP 状态。
/// - `code`：固定业务错误码，不接受底层异常文本。
///
/// 返回：不含秘密的 JSON；结果未知明确要求按原目标回读，不能据此重放。
fn installation_failure(status: StatusCode, code: &'static str) -> Response<BoxBody> {
    json(
        status,
        serde_json::json!({
            "ok": false,
            "error": code
        }),
    )
}

/// 业务作用：拒绝向外部身份所有者的占位文件写材料，避免将无效上传描述为成功换证。
///
/// 参数说明：
/// - `tls`：当前材料来源计划。
///
/// 返回：仅文件或 manifest 持有私钥时为真；SDS、SPIRE 和外部 signer 为假。
fn manual_target(tls: &crate::config::TlsRuntimeCfg) -> bool {
    tls.in_memory.is_none() && tls.spire.is_none() && tls.private_key_provider.is_none()
}

/// 业务作用：让当前请求和原提交者在同一配置代内仍有证书写权，正文接收及排队不能固化旧权限。
///
/// 参数说明：
/// - `state`：当前管理认证与配置状态。
/// - `request`：真实凭据及来源头，不从主体名推断当前请求已认证。
/// - `version`：提交时固定的配置代。
/// - `fingerprint`：同一代配置及依赖身份。
/// - `initiator`：原材料提交者。
///
/// 返回：身份、来源、双主体写权和配置代都成立时返回共享快照；否则交付固定拒绝响应。
fn authorize(
    state: &AdminState,
    request: &AdminRequestParts,
    version: u64,
    fingerprint: u64,
    initiator: &str,
) -> Result<Arc<crate::config::GatewaySnapshot>, Box<Response<BoxBody>>> {
    let snapshot = state.snap.load_full();
    let identity = authenticate_admin_request(request, state)?;
    if let Some(response) = reject_untrusted_admin_browser_origin(request, state) {
        return Err(Box::new(response));
    }
    if !identity.allows(AdminResource::Certs, AdminAction::Write)
        || (snapshot.admin_auth.rbac_enabled
            && !snapshot.admin_auth.principals.iter().any(|principal| {
                principal.id.as_ref() == initiator
                    && principal.allows(AdminResource::Certs, AdminAction::Write)
            }))
    {
        // 审阅者仍有权限不能替代原提交者的当前权限，撤权后的旧候选必须重新提交。
        return Err(Box::new(plain(
            StatusCode::FORBIDDEN,
            "certificate write permission required\n",
        )));
    }
    if snapshot.version != version
        || snapshot.config_fingerprint != Some(fingerprint)
        || !Arc::ptr_eq(&snapshot, &state.snap.load_full())
    {
        return Err(Box::new(plain(
            StatusCode::PRECONDITION_FAILED,
            "certificate configuration baseline changed\n",
        )));
    }
    Ok(snapshot)
}

/// 业务作用：将一张可见证书的有效期解析成 Console 可用状态，不接触私钥。
///
/// 参数说明：
/// - `pem`：是经 1 MiB 上限保护的 PEM 证书链。
///
/// 返回：有 leaf 且 X.509 可解析时返回 notBefore/notAfter Unix 时间与剩余天数；空链或非法证书失败。
fn certificate_status(pem: &[u8]) -> anyhow::Result<serde_json::Value> {
    let mut reader = std::io::Cursor::new(pem);
    let leaf = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .context("parse TLS certificate PEM")?
        .ok_or_else(|| anyhow::anyhow!("certificate PEM contains no certificate"))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| anyhow::anyhow!("parse X.509 certificate: {error}"))?;
    let not_before = certificate.validity().not_before.timestamp();
    let not_after = certificate.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64;
    Ok(serde_json::json!({
        "etag": crate::tls::acme::certificate_etag(pem),
        "not_before_unix": not_before,
        "not_after_unix": not_after,
        "days_remaining": not_after.saturating_sub(now) / 86_400,
        "expired": not_after <= now,
        "subject": certificate.subject().to_string(),
    }))
}

/// 业务作用：组装一条不含路径和私钥的 TLS/ACME 管理读模型。
///
/// 参数说明：
/// - `proxy`：证书所属 proxy 标识。
/// - `entry`：该 proxy 内证书条目标识。
/// - `domains`：证书覆盖的域名集合。
/// - `source`：证书来源类型。
/// - `tls`：TLS 交付策略。
/// - `status`：有界 X.509 解析结果。
///
/// 返回：解析成功时合并有效期；失败时返回 `ok=false` 和低敏原因。
fn certificate_json(
    proxy: &str,
    entry: &str,
    domains: &[String],
    source: &str,
    tls: &crate::config::TlsRuntimeCfg,
    status: anyhow::Result<serde_json::Value>,
) -> serde_json::Value {
    let acme = tls.acme.as_ref().map(|acme| {
        serde_json::json!({
            "domains": acme.domains.as_ref(),
            "challenge": match acme.challenge {
                crate::config::AcmeChallenge::Http01 => "http-01",
                crate::config::AcmeChallenge::Dns01 => "dns-01",
            },
            "renew_before_days": acme.renew_before_days,
            "storage_mode": acme.storage_mode,
            "lock_backend": acme.lock_backend,
        })
    });
    match status {
        Ok(status) => serde_json::json!({
            "proxy": proxy,
            "entry": entry,
            "domains": domains,
            "source": source,
            "manifest": tls.keypair_manifest_file.is_some(),
            "acme": acme,
            "ok": true,
            "status": status,
        }),
        Err(error) => serde_json::json!({
            "proxy": proxy,
            "entry": entry,
            "domains": domains,
            "source": source,
            "manifest": tls.keypair_manifest_file.is_some(),
            "acme": acme,
            "ok": false,
            "reason": error.to_string(),
        }),
    }
}
