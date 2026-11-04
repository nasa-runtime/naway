use super::{CertificateObservation, ServerMaterial};
use crate::config::InMemoryTlsMaterial;
use crate::tls::*;

/// 业务作用：用一次材料加载同时构建握手配置和公开证书事实，供监听器安装后原子发布。
///
/// 参数说明：
/// - `tls`：包含默认、SNI、SDS 或 SPIRE 材料计划及客户端认证策略。
///
/// 返回：身份校验成功后返回同源构建产物；材料错误拒绝候选，观察容量不足只影响事实可见性。
pub fn build_server_material(tls: &TlsRuntimeCfg) -> Result<ServerMaterial> {
    if let Some(material) = &tls.in_memory {
        anyhow::ensure!(
            tls.keypair_manifest_file.is_none()
                && tls.certs.is_empty()
                && tls.client_auth.is_none()
                && tls.acme.is_none(),
            "in-memory TLS material cannot be combined with file, SNI, client_auth, or ACME sources"
        );
        return build_in_memory_material(material);
    }
    let builder = ServerConfig::builder();
    let builder = match &tls.client_auth {
        Some(ca) => match &tls.spire {
            Some(source) => {
                builder.with_client_cert_verifier(build_spire_client_verifier(source, ca)?)
            }
            None => builder.with_client_cert_verifier(build_client_verifier(ca)?),
        },
        None => builder.with_no_client_auth(),
    };
    let (resolver, observation): (Arc<dyn ResolvesServerCert>, _) = match &tls.spire {
        Some(source) => {
            anyhow::ensure!(
                source.current().is_some(),
                "SPIRE identity is not currently authorized or has expired"
            );
            (
                Arc::new(crate::tls::spire::SpireServerCertResolver::new(
                    source.clone(),
                )),
                CertificateObservation::Spire(source.clone()),
            )
        }
        None => {
            let resolver = build_sni_resolver(tls)?;
            let observation = super::certificate::observe_resolver(&resolver, tls);
            (Arc::new(resolver), observation)
        }
    };
    // 选证 resolver 在每次握手执行 OCSP 或 SPIRE 到期门禁；任何身份失权都不能沿用已构建配置绕过。
    let mut cfg = builder.with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    if let Some(tickets) = &tls.session_tickets {
        cfg.ticketer = build_session_ticket_producer(tickets)?;
    }
    Ok(ServerMaterial {
        config: Arc::new(cfg),
        observation,
    })
}

/// 业务作用：把快照持有的内存 PEM 构造成独立 rustls 配置，整个过程不创建临时文件或日志字段。
///
/// 参数说明：
/// - `material`：持有证书链、私钥与可选客户端 CA；其生命周期绑定当前 Snapshot。
///
/// 返回：证书/私钥/CA 完整且彼此匹配时返回服务端配置；任何解析或身份错误拒绝候选 generation。
pub(crate) fn build_in_memory_material(material: &InMemoryTlsMaterial) -> Result<ServerMaterial> {
    let builder = ServerConfig::builder();
    let builder = match material.client_ca.as_deref() {
        Some(ca) => {
            let certs = load_certs_from_bytes(ca, "SDS trusted CA")?;
            let mut roots = RootCertStore::empty();
            for cert in certs {
                roots.add(cert).context("add SDS client CA certificate")?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots));
            let verifier = if material.require_client_certificate {
                verifier.build()
            } else {
                verifier.allow_unauthenticated().build()
            }
            .context("build SDS client certificate verifier")?;
            builder.with_client_cert_verifier(verifier)
        }
        None => {
            anyhow::ensure!(
                !material.require_client_certificate,
                "SDS require_client_certificate needs a validation-context secret"
            );
            builder.with_no_client_auth()
        }
    };
    let certs = load_certs_from_bytes(&material.certificate_chain, "SDS certificate chain")?;
    let observation = CertificateObservation::Static(super::certificate::single_certificate(
        certs[0].as_ref(),
        super::CertificateSource::Sds,
    ));
    let key = load_private_key_from_bytes(&material.private_key, "SDS private key")?;
    let mut config = builder
        .with_single_cert(certs, key)
        .context("build SDS TLS certificate identity")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(ServerMaterial {
        config: Arc::new(config),
        observation,
    })
}
