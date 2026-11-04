//! 默认与 SNI 签名身份采用一致的证书匹配和 OCSP 安全门。

use super::*;

/// 业务作用：从默认证书 + `certs[]` 构建 SNI resolver。任一证书/私钥读不了即整体失败(坏证书不上线)。
///
/// 参数说明：
/// - `tls`：当前默认和 SNI 材料来源及各自的 OCSP 策略。
///
/// 返回：全部身份可加载时返回选证目录；任一身份不满足策略时拒绝整个候选。
pub(super) fn build_sni_resolver(tls: &TlsRuntimeCfg) -> Result<SniCertResolver> {
    build_sni_resolver_with(tls, |source| {
        // 默认与 SNI 文件均先结算原 pair journal，不能把崩溃遗留的半份身份交给选证器。
        let (certificate, private_key) = active_keypair_paths(source)?;
        certified_identity(
            &certificate,
            &private_key,
            source.private_key_provider.as_ref(),
            source.ocsp_stapling.as_ref(),
        )
    })
}

/// 业务作用：让磁盘加载与候选覆盖共用同一选证顺序，预检不能采用另一套 SNI 匹配规则。
///
/// 参数说明：
/// - `tls`：完整默认及 SNI 声明。
/// - `load`：按单个身份来源取得已经验证的签名材料。
///
/// 返回：完整解析器；任一来源拒绝时不返回半份选证目录。
pub(super) fn build_sni_resolver_with(
    tls: &TlsRuntimeCfg,
    mut load: impl FnMut(&TlsRuntimeCfg) -> Result<CertifiedIdentity>,
) -> Result<SniCertResolver> {
    let default = load(tls).context("build default tls certificate")?;
    let mut exact: HashMap<String, Arc<CertifiedIdentity>> = HashMap::new();
    let mut wildcards: Vec<(String, Arc<CertifiedIdentity>)> = Vec::new();
    for cert in &tls.certs {
        let source = targets::sni_source(tls, cert);
        let key = Arc::new(load(&source).context("build sni tls certificate")?);
        for name in &cert.server_names {
            if let Some(suffix) = name.strip_prefix("*.") {
                // 通配 `*.foo.com` → 匹配 SNI 以 `.foo.com` 结尾。
                wildcards.push((format!(".{suffix}"), key.clone()));
            } else {
                exact.insert(name.clone(), key.clone());
            }
        }
    }
    Ok(SniCertResolver {
        exact,
        wildcards,
        default: Arc::new(default),
    })
}

/// 业务作用：从 PEM 身份构建 rustls 签名身份，并绑定经过密码学与 freshness 校验的 OCSP staple。
///
/// 参数说明：
/// - `cert_file`：当前身份的公开证书链 PEM 路径。
/// - `key_file`：本地私钥路径；使用外部 signer 时不读取。
/// - `private_key_provider`：可选受控签名来源，与本地私钥来源互斥。
/// - `ocsp`：是该证书专属的可选响应策略。
///
/// 返回：证书、私钥和 OCSP 响应自洽时返回握手身份；must-staple 缺响应或任何材料无效时失败。
pub(super) fn certified_identity(
    cert_file: &Path,
    key_file: &Path,
    private_key_provider: Option<&crate::security::external_crypto::ExternalPrivateKeyPlan>,
    ocsp: Option<&OcspStaplingRuntime>,
) -> Result<CertifiedIdentity> {
    let certs = load_certs_from(cert_file)?;
    let signing_key = if let Some(private_key_provider) = private_key_provider {
        let leaf = x509_cert::Certificate::from_der(certs[0].as_ref())
            .with_context(|| format!("parse TLS leaf certificate {}", cert_file.display()))?;
        let public_key = leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .context("encode TLS leaf certificate SPKI")?;
        private_key_provider
            .signing_key(SubjectPublicKeyInfoDer::from(public_key))
            .context("build external TLS signing key")?
    } else {
        let key = load_private_key_from(key_file)?;
        // 本地身份只在候选构建期解析私钥，握手路径只持有不可变 signing key。
        tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
            .with_context(|| format!("load signing key from {}", key_file.display()))?
    };
    let certified = CertifiedKey::new(certs, signing_key);
    // 公开密钥与签名密钥必须先匹配，OCSP 成功不能替代身份一致性。
    certified
        .keys_match()
        .context("TLS certificate and signing key do not match")?;
    apply_ocsp_policy(certified, ocsp)
}

/// 业务作用：为已匹配的签名身份统一执行 must-staple 和 OCSP 门，材料写入与实际加载不能采用不同标准。
///
/// 参数说明：
/// - `certified`：同一份证书链与已解析且匹配的签名密钥；消费所有权以复用解析产物。
/// - `ocsp`：当前默认或 SNI 身份专属的响应来源与有效期策略。
///
/// 返回：可用于当前握手策略的身份；缺少必需响应或 OCSP 验证失败拒绝候选。
pub(super) fn apply_ocsp_policy(
    mut certified: CertifiedKey,
    ocsp: Option<&OcspStaplingRuntime>,
) -> Result<CertifiedIdentity> {
    let must_staple = certificate_requires_ocsp_staple(&certified.cert[0])?;
    let Some(ocsp) = ocsp else {
        anyhow::ensure!(
            !must_staple,
            "TLS certificate declares must-staple but has no ocsp_stapling config"
        );
        return Ok(CertifiedIdentity {
            active: Arc::new(certified),
            expired_fallback: None,
            ocsp_valid_until: None,
        });
    };
    let (staple, valid_until) = validate_ocsp_staple(&certified.cert, ocsp)?;
    let fallback = if ocsp.required || must_staple {
        None
    } else {
        Some(Arc::new(CertifiedKey::new(
            certified.cert.clone(),
            certified.key.clone(),
        )))
    };
    // 验证与发布必须使用同一份字节，避免 response_file 在两次读取之间被替换形成 TOCTOU。
    certified.ocsp = Some(staple);
    Ok(CertifiedIdentity {
        active: Arc::new(certified),
        expired_fallback: fallback,
        ocsp_valid_until: Some(valid_until),
    })
}
