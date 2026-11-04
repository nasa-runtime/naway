//! 本机文件材料与逻辑安装目标；读取结果不能代替实际 listener 安装事实。

use crate::admin::{json, AdminState, BoxBody};
use crate::config::TlsRuntimeCfg;
use crate::tls::targets::{self, Kind, Target};
use anyhow::Context;
use http::{Response, StatusCode};
use std::time::{SystemTime, UNIX_EPOCH};

/// 业务作用：枚举 HTTP 与 TCP TLS 的默认及 SNI 文件身份，提供不含路径的精确材料目标。
///
/// 参数说明：
/// - `state`：当前已发布的完整监听计划。
///
/// 返回：逐身份的公开材料条件；单项失败保留固定低敏状态，旧 pair journal 仍先恢复。
pub(in crate::admin) fn read_certificates(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load();
    let mut certificates = Vec::new();
    for proxy in snapshot.proxies.iter() {
        if let Some(tls) = &proxy.tls {
            append(
                &mut certificates,
                Kind::Proxy,
                &proxy.id,
                proxy.server_names.as_ref(),
                tls,
            );
        }
    }
    for listener in snapshot.stream_listeners.iter() {
        if let Some(tls) = &listener.tls {
            append(&mut certificates, Kind::Stream, &listener.id, &[], tls);
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

/// 业务作用：把每个声明的真实材料来源投影为逻辑条目，SNI 不继承默认身份的安装权限。
///
/// 参数说明：
/// - `output`：本次本机读取的条目集合。
/// - `kind`：HTTP proxy 或 TCP stream 命名空间。
/// - `listener`：已发布入口标识。
/// - `domains`：默认身份的入口名称。
/// - `tls`：包含默认及 SNI 声明的完整计划。
///
/// 返回：追加所有声明，材料错误只影响对应条目，不将文件路径或解析文本交给调用者。
fn append(
    output: &mut Vec<serde_json::Value>,
    kind: Kind,
    listener: &str,
    domains: &[String],
    tls: &TlsRuntimeCfg,
) {
    output.push(certificate_json(
        Target {
            kind,
            listener: listener.to_owned(),
            entry: "default".into(),
        },
        domains,
        tls,
        status(tls),
    ));
    for (index, sni) in tls.certs.iter().enumerate() {
        let source = targets::sni_source(tls, sni);
        output.push(certificate_json(
            Target {
                kind,
                listener: listener.to_owned(),
                entry: format!("sni-{index}"),
            },
            &sni.server_names,
            &source,
            status(&source),
        ));
    }
}

/// 业务作用：取得同一身份的公开证书条件和受管材料代，外部身份不得展示可手工写入的代。
///
/// 参数说明：
/// - `tls`：默认或单个 SNI 来源。
///
/// 返回：公开材料状态；不返回私钥，必要的未完成 pair 恢复仍核对完整材料。
fn status(tls: &TlsRuntimeCfg) -> anyhow::Result<serde_json::Value> {
    if let Some(material) = &tls.in_memory {
        return certificate_status(material.certificate_chain.as_ref());
    }
    let (certificate, _) = crate::tls::active_keypair_paths(tls)?;
    let bytes =
        crate::io::bounded_io::read_file(&certificate, 1024 * 1024, "admin TLS certificate")?;
    let mut status = certificate_status(&bytes)?;
    status["material_generation"] = if targets::writable(tls) {
        crate::tls::keypair::material_generation(tls, &bytes)?
            .map_or(serde_json::Value::Null, serde_json::Value::String)
    } else {
        serde_json::Value::Null
    };
    Ok(status)
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
/// - `target`：冻结在当前配置代内的逻辑入口与证书声明。
/// - `domains`：证书覆盖的域名集合。
/// - `tls`：TLS 交付策略。
/// - `status`：有界 X.509 解析结果。
///
/// 返回：解析成功时合并有效期；失败时返回 `ok=false` 和低敏原因。
fn certificate_json(
    target: Target,
    domains: &[String],
    tls: &crate::config::TlsRuntimeCfg,
    status: anyhow::Result<serde_json::Value>,
) -> serde_json::Value {
    let source = if tls.in_memory.is_some() {
        "sds"
    } else if tls.spire.is_some() {
        "spire"
    } else if tls.private_key_provider.is_some() {
        "external_signer"
    } else if tls.keypair_manifest_file.is_some() {
        "manifest"
    } else if tls.acme.is_some() {
        "acme"
    } else {
        "static"
    };
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
            "proxy": (target.kind == Kind::Proxy).then_some(&target.listener),
            "entry": target.entry,
            "target": target,
            "manual_upload": targets::writable(tls),
            "domains": domains,
            "source": source,
            "manifest": tls.keypair_manifest_file.is_some(),
            "acme": acme,
            "ok": true,
            "status": status,
        }),
        Err(_) => serde_json::json!({
            "proxy": (target.kind == Kind::Proxy).then_some(&target.listener),
            "entry": target.entry,
            "target": target,
            "manual_upload": targets::writable(tls),
            "domains": domains,
            "source": source,
            "manifest": tls.keypair_manifest_file.is_some(),
            "acme": acme,
            "ok": false,
            "reason": "certificate_material_unavailable",
        }),
    }
}
