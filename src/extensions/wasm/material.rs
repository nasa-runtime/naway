//! 模块来源的实际凭据、信任和证明只在候选构建期解析，比较不重新读取秘密或编码完整配置。

use super::*;

pub(super) struct LoadedModule {
    pub(super) bytes: Vec<u8>,
    pub(super) label: String,
    pub(super) remote: Option<RemotePolicy>,
}

#[derive(PartialEq, Eq)]
pub(super) struct RemotePolicy {
    reference: String,
    digest: String,
    manifest_digest: Option<String>,
    cache_directory: String,
    timeout_ms: u64,
    authorization: Option<HeaderValue>,
    ca_identity: Option<[u8; 32]>,
    proof: ProofIdentity,
}

#[derive(PartialEq, Eq)]
pub(super) struct ProofIdentity {
    pub(super) signer: Option<[u8; 32]>,
    pub(super) attestation: Option<AttestationIdentity>,
}

#[derive(PartialEq, Eq)]
pub(super) struct AttestationIdentity {
    pub(super) statement: [u8; 32],
    pub(super) signer: [u8; 32],
    pub(super) predicate_type: String,
    pub(super) builder_id: String,
    pub(super) subject_name: String,
}

pub(super) struct RemoteTransport {
    pub(super) authorization: Option<HeaderValue>,
    pub(super) certificate: Option<reqwest::Certificate>,
    ca_identity: Option<[u8; 32]>,
}

impl RemoteTransport {
    /// 业务作用：在选择缓存或网络之前验证当前来源凭据与 TLS 信任，缓存不能掩盖无效的当前材料。
    ///
    /// 参数说明：
    /// - `source`：已经通过固定引用与声明预算校验的远程来源。
    /// - `directory`：解析文件 SecretSource 的受控目录。
    ///
    /// 返回：与材料身份共享同一次解析的传输参数；凭据或 CA 无效时拒绝整个候选。
    pub(super) fn resolve(source: &WasmModuleSourceCfg, directory: &Path) -> Result<Self> {
        let authorization = resolve_wasm_authorization(source, directory)?;
        let (certificate, ca_identity) = if source.ca_certificate.trim().is_empty() {
            (None, None)
        } else {
            let pem = crate::security::secret::resolve_text(
                &source.ca_certificate,
                directory,
                "Proxy-Wasm source CA certificate",
            )?;
            let certificate = crate::tls::trust::http_ca(pem.as_bytes())
                .context("parse Proxy-Wasm source CA certificate")?;
            (
                Some(certificate),
                Some(Sha256::digest(pem.as_bytes()).into()),
            )
        };
        Ok(Self {
            authorization,
            certificate,
            ca_identity,
        })
    }

    /// 业务作用：在模块和证明验证成功后移交实际传输身份，控制面无需保留证书解析器或重复秘密副本。
    ///
    /// 参数说明：
    /// - `source`：本次构建已经验证的固定来源声明。
    /// - `digest`：规范化的模块固定摘要。
    /// - `proof`：实际验证成功的 signer 与 provenance 身份。
    ///
    /// 返回：只含冻结声明和实际材料身份的比较计划；OCI 引用不一致时仍拒绝候选。
    pub(super) fn policy(
        self,
        source: &WasmModuleSourceCfg,
        digest: String,
        proof: ProofIdentity,
    ) -> Result<RemotePolicy> {
        let manifest_digest = if source.reference.starts_with("oci://") {
            Some(parse_oci_reference(source)?.manifest_digest)
        } else {
            None
        };
        Ok(RemotePolicy {
            reference: source.reference.clone(),
            digest,
            manifest_digest,
            cache_directory: source.cache_dir.clone(),
            timeout_ms: source.timeout_ms,
            authorization: self.authorization,
            ca_identity: self.ca_identity,
            proof,
        })
    }
}
