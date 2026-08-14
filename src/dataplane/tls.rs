//! TLS 监听配置加载 + 证书热换。
//!
//! ★据 review:证书**只在启动期与文件变更时**加载一次到 `ArcSwap<ServerConfig>`,accept 循环只做
//! 廉价的 `Arc` clone(不再每条 TLS 连接开盘读证书 + 解析——那既阻塞异步 accept 线程,又是 DoS 放大面)。
//! 证书文件内容变更由 notify watcher 捕获并重建(热换证不断连,§7.5/§19)。

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::{Cursor, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use sha2::Digest as _;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName,
    SubjectPublicKeyInfoDer, UnixTime,
};
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::server::{
    ClientHello, ProducesTickets, ResolvesServerCert, WebPkiClientVerifier,
};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
};
use x509_cert::der::{Decode, Encode};

use crate::config::{
    ClientAuthRuntime, ClientCertificateOcspMode, ClientCertificateOcspRuntime,
    ClientOcspCacheRecord, InMemoryTlsMaterial, OcspStaplingRuntime, SessionTicketRuntime,
    TlsRuntimeCfg,
};

const KEYPAIR_MANIFEST_MAX_BYTES: usize = 64 * 1024;
/// 单个证书链、私钥或 CA PEM 的控制面硬上限。PEM 只在启动/reload 读取，但仍必须防止
/// 错挂载的大文件在配置构建期造成 OOM；4 MiB 足以容纳远超常规规模的证书链。
const TLS_PEM_MAX_BYTES: usize = 4 * 1024 * 1024;
const OCSP_RESPONSE_MAX_BYTES: usize = 256 * 1024;
const MAX_SESSION_TICKET_PLAINTEXT_BYTES: usize = 64 * 1024;
const SESSION_TICKET_PREFIX: &[u8; 5] = b"NWTK1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeypairManifest {
    schema_version: u32,
    directory: String,
}

struct SessionTicketKey {
    id: [u8; 8],
    cipher: Aes256Gcm,
}

struct SharedSessionTickets {
    keys: Vec<SessionTicketKey>,
    lifetime_seconds: u32,
}

/// 单张服务端证书及其 OCSP 运行门禁。
struct CertifiedIdentity {
    active: Arc<CertifiedKey>,
    expired_fallback: Option<Arc<CertifiedKey>>,
    ocsp_valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone)]
enum OcspCertificateSource {
    Default(Arc<TlsRuntimeCfg>),
    File(PathBuf),
}

impl OcspCertificateSource {
    /// 业务作用：在每轮 OCSP 获取前解析当前证书路径，使 manifest 身份轮换不会继续查询旧证书。
    ///
    /// 参数说明：无。
    ///
    /// 返回：普通 SNI 返回固定路径；默认 manifest 身份返回当前原子指针指向的证书路径。
    fn certificate_file(&self) -> Result<PathBuf> {
        match self {
            Self::Default(tls) => active_keypair_paths(tls).map(|(cert, _)| cert),
            Self::File(path) => Ok(path.clone()),
        }
    }
}

impl CertifiedIdentity {
    /// 业务作用：在每次握手选证时复验 OCSP freshness，阻止已加载响应在进程内无限陈旧。
    ///
    /// 参数说明：无。
    ///
    /// 返回：响应仍有效时返回带 staple 的身份；optional 响应过期后返回无 staple 身份；
    /// required 或 must-staple 响应过期后返回空并中止握手。
    fn resolve(&self) -> Option<Arc<CertifiedKey>> {
        if self
            .ocsp_valid_until
            .is_some_and(|deadline| chrono::Utc::now() > deadline)
        {
            return self.expired_fallback.clone();
        }
        Some(self.active.clone())
    }
}

impl std::fmt::Debug for SharedSessionTickets {
    /// 业务作用：提供不含 ticket key、摘要或密文的低敏 TLS 运行态诊断。
    ///
    /// 参数说明：`formatter` 是标准格式化目标。
    ///
    /// 返回：只输出重叠 key 数量与公开 lifetime，不暴露可用于解密 session 的材料。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedSessionTickets")
            .field("key_count", &self.keys.len())
            .field("lifetime_seconds", &self.lifetime_seconds)
            .finish()
    }
}

impl ProducesTickets for SharedSessionTickets {
    /// 业务作用：声明显式 ticket key 计划可签发和恢复无状态 TLS session。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：构建器已保证至少有一个 key，因此始终为 true。
    fn enabled(&self) -> bool {
        true
    }

    /// 业务作用：把配置的轮换窗口作为客户端 ticket lifetime hint。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回构建期限制在 60 秒到 7 天的 lifetime。
    fn lifetime(&self) -> u32 {
        self.lifetime_seconds
    }

    /// 业务作用：用当前首 key 认证加密 rustls session 状态，并写入非敏感 key id 供重叠代选择。
    ///
    /// 参数说明：`plain` 是 rustls 生成的内部 session 状态，不含应用请求 body。
    ///
    /// 返回：随机数、大小或 AEAD 失败时不签发 ticket；成功返回带格式版本、key id 和 nonce 的密文。
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        if plain.len() > MAX_SESSION_TICKET_PLAINTEXT_BYTES {
            return None;
        }
        let key = self.keys.first()?;
        let mut nonce = [0_u8; 12];
        getrandom::getrandom(&mut nonce).ok()?;
        let mut aad = [0_u8; 13];
        aad[..5].copy_from_slice(SESSION_TICKET_PREFIX);
        aad[5..].copy_from_slice(&key.id);
        let encrypted = key
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .ok()?;
        let mut ticket = Vec::with_capacity(SESSION_TICKET_PREFIX.len() + 8 + 12 + encrypted.len());
        ticket.extend_from_slice(SESSION_TICKET_PREFIX);
        ticket.extend_from_slice(&key.id);
        ticket.extend_from_slice(&nonce);
        ticket.extend_from_slice(&encrypted);
        Some(ticket)
    }

    /// 业务作用：仅用 key id 命中的当前或重叠旧 key 认证解密 ticket，篡改和撤销 key 一律失败。
    ///
    /// 参数说明：`ciphertext` 完全由客户端控制，解析必须有界且不 panic。
    ///
    /// 返回：格式、key id 或 GCM tag 非法时为空；成功时返回 rustls session 状态。
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        const HEADER_BYTES: usize = 5 + 8 + 12;
        if ciphertext.len() < HEADER_BYTES + 16
            || ciphertext.len() > HEADER_BYTES + MAX_SESSION_TICKET_PLAINTEXT_BYTES + 16
            || &ciphertext[..5] != SESSION_TICKET_PREFIX
        {
            return None;
        }
        let id: [u8; 8] = ciphertext[5..13].try_into().ok()?;
        let nonce = &ciphertext[13..HEADER_BYTES];
        let mut aad = [0_u8; 13];
        aad[..5].copy_from_slice(SESSION_TICKET_PREFIX);
        aad[5..].copy_from_slice(&id);
        let key = self.keys.iter().find(|key| key.id == id)?;
        key.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &ciphertext[HEADER_BYTES..],
                    aad: &aad,
                },
            )
            .ok()
    }
}

/// 进程内共享的 TLS 服务端配置:启动期构建一次,证书文件变更时原子换新。
pub type SharedServerConfig = Arc<ArcSwap<ServerConfig>>;

/// HTTP 上游 TLS profile：已在配置构建期解析并校验证书材料。
///
/// `key` 只包含非敏感指纹,供常驻连接池按 profile 复用;`client_config` 不带 ALPN,创建 connector 时再由
/// hyper-rustls 按 h1/h2 能力设置。
#[derive(Clone)]
pub struct UpstreamTlsProfile {
    /// 不含密钥明文的稳定配置指纹，用作连接池身份。
    pub key: Arc<str>,
    /// 可选显式 SNI/证书主机名；为空时使用上游 URI host。
    pub server_name: Option<Arc<str>>,
    /// 已加载 CA、客户端证书和校验策略的 rustls client 配置。
    pub client_config: Arc<ClientConfig>,
    /// 远程客户端身份允许建立新请求的单调时钟截止点；本地身份为空。
    pub(crate) client_identity_not_after: Option<std::time::Instant>,
    /// 可选动态 SPIRE 身份来源；存在时新请求与握手都复验当前授权和到期状态。
    pub(crate) spire: Option<Arc<crate::spire::SpireTlsSource>>,
}

impl UpstreamTlsProfile {
    /// 业务作用：在使用远程 mTLS 身份创建新上游请求前复验 lease 与最大陈旧期。
    ///
    /// 参数说明：无。
    ///
    /// 返回：本地身份，或仍获授权且未到期的远程身份返回 true；否则禁止创建新请求，既有连接可自然 drain。
    pub(crate) fn allows_new_requests(&self) -> bool {
        if let Some(source) = &self.spire {
            source.ensure_upstream_watcher();
        }
        self.client_identity_not_after
            .is_none_or(|deadline| std::time::Instant::now() < deadline)
            && self
                .spire
                .as_ref()
                .is_none_or(|source| source.current().is_some())
    }
}

struct SubjectAltNameVerifier {
    signature_verifier: Arc<WebPkiServerVerifier>,
    roots: Arc<RootCertStore>,
    dns_names: Vec<String>,
    uris: Vec<String>,
}

struct EncryptionOnlyServerVerifier {
    signature_algorithms: tokio_rustls::rustls::crypto::WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for EncryptionOnlyServerVerifier {
    /// 业务作用：为仅加密的上游 TLS 策略提供不含证书材料的诊断视图。
    ///
    /// 参数说明：`formatter` 是标准格式化目标。
    ///
    /// 返回：只标识 verifier 类型，不输出握手证书或密钥材料。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptionOnlyServerVerifier")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for EncryptionOnlyServerVerifier {
    /// 业务作用：允许受控发现边界内的动态自签名服务端建立加密通道，不把未知证书当作远程身份。
    ///
    /// 参数说明：证书链、握手名称与时间均由 rustls 提供，本策略不会据此授予业务身份。
    ///
    /// 返回：始终接受证书声明；目标授权必须在进入 TLS 前由服务发现和路由门禁完成。
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// 业务作用：校验 TLS 1.2 握手仍由本次证书对应私钥签署，避免仅加密模式退化为无密钥证明。
    ///
    /// 参数说明：消息、证书和签名结构由 rustls 状态机提供。
    ///
    /// 返回：签名与当前 provider 算法一致时接受，否则终止握手。
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.signature_algorithms,
        )
    }

    /// 业务作用：校验 TLS 1.3 握手仍由本次证书对应私钥签署，保持通道完整性。
    ///
    /// 参数说明：消息、证书和签名结构由 rustls 状态机提供。
    ///
    /// 返回：签名有效时接受，否则终止握手。
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.signature_algorithms,
        )
    }

    /// 业务作用：声明当前密码 provider 可验证的握手签名算法集合。
    ///
    /// 参数说明：无。
    ///
    /// 返回：按 provider 优先级返回标准 SignatureScheme 列表。
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_algorithms.supported_schemes()
    }
}

struct InsecureFallbackClientCertVerifier {
    signature_verifier: Arc<dyn ClientCertVerifier>,
    root_hints: Vec<tokio_rustls::rustls::DistinguishedName>,
}

impl std::fmt::Debug for InsecureFallbackClientCertVerifier {
    /// 业务作用：输出不含客户端 CA 和证书材料的 fallback verifier 诊断视图。
    ///
    /// 参数说明：`formatter` 是标准格式化目标。
    ///
    /// 返回：仅标识 verifier 类型，不泄露握手身份或信任材料。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InsecureFallbackClientCertVerifier")
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for InsecureFallbackClientCertVerifier {
    /// 业务作用：要求服务端发送 `CertificateRequest`，使有证书的客户端实际出示身份。
    ///
    /// 参数说明：无。
    ///
    /// 返回：始终返回 true；fallback 的兼容性只放宽信任判定，不省略证书请求。
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// 业务作用：允许没有客户端证书的连接继续，用于显式启用的不安全兼容模式。
    ///
    /// 参数说明：无。
    ///
    /// 返回：始终返回 false，使无证书客户端不会因握手缺少身份而失败。
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    /// 业务作用：不限制客户端证书颁发者，确保不受配置 CA 信任的证书也会被出示。
    ///
    /// 参数说明：无。
    ///
    /// 返回：空 CA 提示列表，表示客户端可选择任意已有证书。
    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &self.root_hints
    }

    /// 业务作用：在 fallback 模式忽略证书链信任结果，把身份授权交给后续业务策略。
    ///
    /// 参数说明：`end_entity`、`intermediates` 和 `now` 是客户端证书链及握手时间。
    ///
    /// 返回：对任何已出示证书链确认通过；后续握手签名仍必须证明对应私钥持有。
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, tokio_rustls::rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    /// 业务作用：校验 TLS 1.2 客户端对握手消息的签名，避免伪造任意公开证书。
    ///
    /// 参数说明：`message` 是握手消息，`cert` 是叶证书，`dss` 是签名及算法。
    ///
    /// 返回：签名与证书公钥匹配时通过，否则终止握手。
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.signature_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    /// 业务作用：校验 TLS 1.3 客户端对握手消息的签名，保留私钥持有证明。
    ///
    /// 参数说明：`message` 是握手消息，`cert` 是叶证书，`dss` 是签名及算法。
    ///
    /// 返回：签名与证书公钥及算法约束匹配时通过，否则终止握手。
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.signature_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    /// 业务作用：复用标准 verifier 的握手签名算法集合，保持协议协商兼容性。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回当前 rustls provider 支持的客户端证书签名算法，按优先级排序。
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

impl std::fmt::Debug for SubjectAltNameVerifier {
    /// 业务作用：输出不含证书材料的 SAN verifier 诊断视图，供配置构建错误定位。
    ///
    /// 参数说明：`formatter` 是标准格式化目标。
    ///
    /// 返回：仅写入公开身份 allowlist，绝不输出 CA 或握手证书内容。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubjectAltNameVerifier")
            .field("dns_names", &self.dns_names)
            .field("uris", &self.uris)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for SubjectAltNameVerifier {
    /// 业务作用：在 BackendTLSPolicy 显式 SAN 模式下把证书链校验与名称校验分离，
    /// 避免把仅用于 SNI 选择的 hostname 错当成认证身份。
    ///
    /// 参数说明：证书链、握手名称与时间均由 rustls 提供；OCSP 当前不改变静态 CA 判定。
    ///
    /// 返回：证书链、serverAuth 用途和至少一个声明 SAN 均有效时放行；否则终止 TLS 握手。
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let end_entity_cert = webpki::EndEntityCert::try_from(end_entity).map_err(|error| {
            tokio_rustls::rustls::Error::General(format!(
                "parse BackendTLSPolicy end-entity certificate: {error}"
            ))
        })?;
        end_entity_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &self.roots.roots,
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|error| {
                tokio_rustls::rustls::Error::General(format!(
                    "verify BackendTLSPolicy certificate chain: {error}"
                ))
            })?;
        let (_, certificate) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|error| {
                tokio_rustls::rustls::Error::General(format!(
                    "parse BackendTLSPolicy certificate SAN: {error}"
                ))
            })?;
        let mut matched = false;
        for extension in certificate.extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                extension.parsed_extension()
            {
                matched |= san.general_names.iter().any(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(name) => self
                        .dns_names
                        .iter()
                        .any(|expected| expected.eq_ignore_ascii_case(name.trim_end_matches('.'))),
                    x509_parser::extensions::GeneralName::URI(uri) => {
                        self.uris.iter().any(|expected| expected == uri)
                    }
                    _ => false,
                });
            }
        }
        if !matched {
            return Err(tokio_rustls::rustls::Error::General(
                "BackendTLSPolicy certificate does not match any required subjectAltName"
                    .to_owned(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    /// 业务作用：复用 rustls WebPKI 的 TLS 1.2 握手签名校验，防止自定义 SAN 门禁削弱密钥证明。
    ///
    /// 参数说明：消息、证书和签名结构由 rustls 状态机提供。
    ///
    /// 返回：底层 WebPKI 验签结论原样返回。
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.signature_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    /// 业务作用：复用 rustls WebPKI 的 TLS 1.3 握手签名校验，保持算法与曲线约束完整。
    ///
    /// 参数说明：消息、证书和签名结构由 rustls 状态机提供。
    ///
    /// 返回：底层 WebPKI 验签结论原样返回。
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.signature_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    /// 业务作用：公开自定义 verifier 实际支持的握手签名算法集合。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回底层 WebPKI verifier 的稳定算法优先级。
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

/// edge relay 双向 TLS profile。服务端与客户端共用同一节点身份，并使用独立 CA 信任域。
///
/// `server_name` 是所有 relay 节点证书必须覆盖的固定 DNS 身份；peer 地址仍可使用 IP，避免把
/// 服务发现地址误当成证书身份。`key` 只含材料指纹，可安全用于拓扑变更比较与日志。
#[derive(Clone)]
pub struct EdgeRelayTlsProfile {
    /// 不含私钥明文的稳定配置指纹。
    pub key: Arc<str>,
    /// relay TLS 握手使用的固定服务端名称。
    pub server_name: ServerName<'static>,
    /// 入站 relay 强制客户端证书校验的服务端配置。
    pub server_config: SharedServerConfig,
    /// 出站 relay 同时携带节点证书的客户端配置。
    pub client_config: Arc<ArcSwap<ClientConfig>>,
    ca_file: Arc<PathBuf>,
    cert_file: Arc<PathBuf>,
    key_file: Arc<PathBuf>,
}

impl std::fmt::Debug for EdgeRelayTlsProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeRelayTlsProfile")
            .field("key", &self.key)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl EdgeRelayTlsProfile {
    /// 判断两个 profile 是否引用同一组 relay TLS 配置源。
    ///
    /// 文件内容变化属于证书轮换，由 watcher 原子热换，不应被误判为 socket/peer 拓扑变化。
    pub fn same_material_source(&self, other: &Self) -> bool {
        self.server_name == other.server_name
            && self.ca_file == other.ca_file
            && self.cert_file == other.cert_file
            && self.key_file == other.key_file
    }
}

/// 构建 edge relay 的强制 mTLS profile。
///
/// # 参数
/// - `server_name`: relay 证书统一 DNS 身份，出站连接不使用 peer IP 做证书校验。
/// - `ca_file`: 只信任该 CA 签发的 relay 节点证书。
/// - `cert_file`/`key_file`: 本节点证书链与私钥，同时用于入站和出站握手。
pub fn build_edge_relay_tls_profile(
    server_name: &str,
    ca_file: &Path,
    cert_file: &Path,
    key_file: &Path,
) -> Result<EdgeRelayTlsProfile> {
    let normalized = server_name
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    anyhow::ensure!(
        !normalized.is_empty(),
        "edge relay tls server_name must not be empty"
    );
    let server_name = ServerName::try_from(normalized.clone())
        .with_context(|| format!("invalid edge relay tls server_name `{normalized}`"))?;

    let mut key_hasher = DefaultHasher::new();
    normalized.hash(&mut key_hasher);
    for path in [ca_file, cert_file, key_file] {
        path.hash(&mut key_hasher);
        hash_file_contents(path, &mut key_hasher)?;
    }

    let roots = root_store_from_ca_file(ca_file)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots.clone()))
        .build()
        .with_context(|| {
            format!(
                "build edge relay client certificate verifier from {}",
                ca_file.display()
            )
        })?;
    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            load_certs_from(cert_file)?,
            load_private_key_from(key_file)?,
        )
        .with_context(|| {
            format!(
                "build edge relay server certificate cert={} key={}",
                cert_file.display(),
                key_file.display()
            )
        })?;
    server_config.alpn_protocols = vec![b"naway-edge/1".to_vec()];

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            load_certs_from(cert_file)?,
            load_private_key_from(key_file)?,
        )
        .with_context(|| {
            format!(
                "build edge relay client certificate cert={} key={}",
                cert_file.display(),
                key_file.display()
            )
        })?;
    client_config.alpn_protocols = vec![b"naway-edge/1".to_vec()];

    Ok(EdgeRelayTlsProfile {
        key: Arc::from(format!("edge-relay-tls-{:016x}", key_hasher.finish())),
        server_name,
        server_config: Arc::new(ArcSwap::from_pointee(server_config)),
        client_config: Arc::new(ArcSwap::from_pointee(client_config)),
        ca_file: Arc::new(ca_file.to_path_buf()),
        cert_file: Arc::new(cert_file.to_path_buf()),
        key_file: Arc::new(key_file.to_path_buf()),
    })
}

/// 监听 edge relay CA/证书/私钥并原子热换服务端与客户端 rustls 配置。
///
/// 任一材料损坏都只记录告警并保留旧配置。现有 TLS 连接继续使用握手时的配置，新 accept/dial
/// 自动读取最新指针；这与普通 listener 的证书热换语义一致。
pub fn spawn_edge_relay_tls_watcher(profile: EdgeRelayTlsProfile) {
    let mut files = vec![
        profile.ca_file.as_ref().clone(),
        profile.cert_file.as_ref().clone(),
        profile.key_file.as_ref().clone(),
    ];
    files = files
        .into_iter()
        .map(|path| {
            path.parent()
                .and_then(|parent| std::fs::canonicalize(parent).ok())
                .and_then(|parent| path.file_name().map(|name| parent.join(name)))
                .unwrap_or(path)
        })
        .collect();
    files.sort();
    files.dedup();
    let mut dirs = files
        .iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect::<Vec<_>>();
    dirs.sort();
    dirs.dedup();

    tokio::spawn(async move {
        let watched_files = files;
        let reload_profile = profile.clone();
        let mut watcher = match RecommendedWatcher::new(
            move |result: notify::Result<notify::Event>| {
                let Ok(event) = result else { return };
                if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
                    || !event
                        .paths
                        .iter()
                        .any(|changed| watched_files.iter().any(|target| changed == target))
                {
                    return;
                }
                let server_name = reload_profile.server_name.to_str();
                match build_edge_relay_tls_profile(
                    server_name.as_ref(),
                    &reload_profile.ca_file,
                    &reload_profile.cert_file,
                    &reload_profile.key_file,
                ) {
                    Ok(next) => {
                        reload_profile
                            .server_config
                            .store(next.server_config.load_full());
                        reload_profile
                            .client_config
                            .store(next.client_config.load_full());
                        tracing::info!("edge relay TLS identity reloaded (hot swap)");
                    }
                    Err(error) => tracing::warn!(
                        error = %format!("{error:#}"),
                        "edge relay TLS identity reload failed; keeping previous config"
                    ),
                }
            },
            notify::Config::default(),
        ) {
            Ok(watcher) => watcher,
            Err(error) => {
                tracing::error!(error = %error, "edge relay TLS watcher init failed");
                return;
            }
        };
        for dir in &dirs {
            if let Err(error) = watcher.watch(dir, RecursiveMode::NonRecursive) {
                tracing::error!(dir = %dir.display(), error = %error, "watch edge relay TLS dir failed");
            }
        }
        let _keep_alive = watcher;
        std::future::pending::<()>().await;
    });
}

impl std::fmt::Debug for UpstreamTlsProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTlsProfile")
            .field("key", &self.key)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl PartialEq for UpstreamTlsProfile {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for UpstreamTlsProfile {}

impl Hash for UpstreamTlsProfile {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

/// 业务作用：使用文件型信任材料构建 HTTP 上游 TLS profile，并兼容既有静态配置入口。
///
/// 参数说明：`server_name` 是可选 SNI 与默认认证名；`ca_file` 是可选自定义 CA；
/// `client_cert_file` 与 `client_key_file` 是必须成对出现的上游 mTLS 身份。
///
/// 返回：材料完整且 TLS 策略可构建时返回可复用 profile；路径、PEM 或身份配置非法时失败。
pub fn build_upstream_tls_profile(
    server_name: Option<&str>,
    ca_file: Option<&Path>,
    client_cert_file: Option<&Path>,
    client_key_file: Option<&Path>,
) -> Result<UpstreamTlsProfile> {
    build_upstream_tls_profile_with_material(
        server_name,
        ca_file,
        None,
        &[],
        client_cert_file,
        client_key_file,
        None,
        None,
    )
}

/// 业务作用：把动态发现得到的内联 CA 与显式 SAN 门禁原子编译进 HTTP 上游 TLS profile。
///
/// 参数说明：`server_name` 只在 `subject_alt_names` 非空时作为 SNI；`ca_file` 与 `ca_pem`
/// 互斥；`subject_alt_names` 使用 `dns:` 或 `uri:` 前缀；客户端证书和私钥必须选择一组成对的
/// 文件或内联来源。
///
/// 返回：信任根、SAN 与客户端身份全部有效时返回 profile；任何歧义或非法材料都会拒绝候选配置。
#[allow(clippy::too_many_arguments)]
pub fn build_upstream_tls_profile_with_material(
    server_name: Option<&str>,
    ca_file: Option<&Path>,
    ca_pem: Option<&str>,
    subject_alt_names: &[String],
    client_cert_file: Option<&Path>,
    client_key_file: Option<&Path>,
    client_cert_pem: Option<&str>,
    client_key_pem: Option<&str>,
) -> Result<UpstreamTlsProfile> {
    build_upstream_tls_profile_inner(
        server_name,
        ca_file,
        ca_pem,
        subject_alt_names,
        client_cert_file,
        client_key_file,
        client_cert_pem,
        client_key_pem,
        None,
    )
}

/// 业务作用：为目标已由受控发现边界授权、但证书每次启动动态自签的上游建立仅加密 TLS profile。
///
/// 参数说明：`server_name` 是可选 SNI；它不参与远程身份认证。
///
/// 返回：名称合法且密码 provider 可用时返回 profile；非法名称会拒绝候选配置。
pub(crate) fn build_encryption_only_upstream_tls_profile(
    server_name: Option<&str>,
) -> Result<UpstreamTlsProfile> {
    let server_name = server_name
        .map(|name| {
            let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
            anyhow::ensure!(
                !normalized.is_empty(),
                "upstream tls server_name must not be empty"
            );
            ServerName::try_from(normalized.clone())
                .with_context(|| format!("invalid upstream tls server_name `{normalized}`"))?;
            Ok::<_, anyhow::Error>(normalized)
        })
        .transpose()?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let signature_algorithms = provider.signature_verification_algorithms;
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("select encryption-only upstream TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(EncryptionOnlyServerVerifier {
            signature_algorithms,
        }))
        .with_no_client_auth();
    let mut key_hasher = DefaultHasher::new();
    "encryption-only".hash(&mut key_hasher);
    server_name.hash(&mut key_hasher);
    Ok(UpstreamTlsProfile {
        key: Arc::from(format!("tls-{:016x}", key_hasher.finish())),
        server_name: server_name.map(Arc::from),
        client_config: Arc::new(client_config),
        client_identity_not_after: None,
        spire: None,
    })
}

/// 业务作用：把 SPIRE 动态客户端身份与静态上游服务端信任策略编译为可复用 TLS profile。
///
/// 参数说明：服务端名称、CA 与 SAN 参数保持现有含义；`spire` 是已取得首个有效 SVID 的来源。
///
/// 返回：服务端信任和动态客户端身份都有效时返回 profile；材料冲突或策略无效时拒绝。
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_upstream_tls_profile_with_spire(
    server_name: Option<&str>,
    ca_file: Option<&Path>,
    ca_pem: Option<&str>,
    subject_alt_names: &[String],
    client_cert_file: Option<&Path>,
    client_key_file: Option<&Path>,
    client_cert_pem: Option<&str>,
    client_key_pem: Option<&str>,
    spire: Arc<crate::spire::SpireTlsSource>,
) -> Result<UpstreamTlsProfile> {
    build_upstream_tls_profile_inner(
        server_name,
        ca_file,
        ca_pem,
        subject_alt_names,
        client_cert_file,
        client_key_file,
        client_cert_pem,
        client_key_pem,
        Some(spire),
    )
}

/// 业务作用：收敛文件、内联与 SPIRE 三类上游客户端身份，保证任一 profile 只有一个身份来源。
///
/// 参数说明：CA/SAN 参数约束上游服务端；三类客户端证书参数与 `spire` 必须互斥。
///
/// 返回：全部信任与身份材料可编译时返回 profile；来源歧义、坏材料或无效名称失败。
#[allow(clippy::too_many_arguments)]
fn build_upstream_tls_profile_inner(
    server_name: Option<&str>,
    ca_file: Option<&Path>,
    ca_pem: Option<&str>,
    subject_alt_names: &[String],
    client_cert_file: Option<&Path>,
    client_key_file: Option<&Path>,
    client_cert_pem: Option<&str>,
    client_key_pem: Option<&str>,
    spire: Option<Arc<crate::spire::SpireTlsSource>>,
) -> Result<UpstreamTlsProfile> {
    anyhow::ensure!(
        ca_file.is_none() || ca_pem.is_none(),
        "upstream tls ca_file and ca_pem cannot be configured together"
    );
    anyhow::ensure!(
        subject_alt_names.len() <= 5,
        "upstream tls subject_alt_names exceeds the limit of 5"
    );
    anyhow::ensure!(
        client_cert_file.is_none() || client_cert_pem.is_none(),
        "upstream TLS client certificate file and inline sources cannot be combined"
    );
    anyhow::ensure!(
        client_key_file.is_none() || client_key_pem.is_none(),
        "upstream TLS client key file and inline sources cannot be combined"
    );
    anyhow::ensure!(
        spire.is_none()
            || client_cert_file.is_none()
                && client_key_file.is_none()
                && client_cert_pem.is_none()
                && client_key_pem.is_none(),
        "upstream SPIRE identity cannot be combined with file or inline client identity"
    );
    let server_name = server_name
        .map(|name| {
            let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
            if normalized.is_empty() {
                anyhow::bail!("upstream tls server_name must not be empty");
            }
            ServerName::try_from(normalized.clone())
                .with_context(|| format!("invalid upstream tls server_name `{normalized}`"))?;
            Ok::<_, anyhow::Error>(normalized)
        })
        .transpose()?;

    let mut key_hasher = DefaultHasher::new();
    server_name.hash(&mut key_hasher);

    let roots = match (ca_file, ca_pem) {
        (Some(path), None) => {
            path.hash(&mut key_hasher);
            hash_file_contents(path, &mut key_hasher)?;
            root_store_from_ca_file(path)?
        }
        (None, Some(pem)) => {
            anyhow::ensure!(
                pem.len() <= TLS_PEM_MAX_BYTES,
                "upstream inline CA exceeds {} bytes",
                TLS_PEM_MAX_BYTES
            );
            pem.hash(&mut key_hasher);
            root_store_from_ca_bytes(pem.as_bytes(), "inline upstream CA")?
        }
        (None, None) => {
            "native-roots".hash(&mut key_hasher);
            native_root_store()?
        }
        (Some(_), Some(_)) => unreachable!("CA source exclusivity checked above"),
    };

    let (dns_names, uris) = parse_subject_alt_names(subject_alt_names)?;
    subject_alt_names.hash(&mut key_hasher);
    if let Some(source) = &spire {
        source.identity_key().hash(&mut key_hasher);
    }

    let roots = Arc::new(roots);
    let builder = if dns_names.is_empty() && uris.is_empty() {
        ClientConfig::builder().with_root_certificates((*roots).clone())
    } else {
        let signature_verifier = WebPkiServerVerifier::builder(roots.clone())
            .build()
            .context("build upstream WebPKI verifier")?;
        // 显式 SAN 模式仍先执行标准证书链和握手签名校验，只替换名称认证步骤。
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SubjectAltNameVerifier {
                signature_verifier,
                roots,
                dns_names,
                uris,
            }))
    };

    let mut client_config = match (
        client_cert_file,
        client_key_file,
        client_cert_pem,
        client_key_pem,
    ) {
        (None, None, None, None) => match &spire {
            Some(source) => builder.with_client_cert_resolver(Arc::new(
                crate::spire::SpireClientCertResolver::new(source.clone()),
            )),
            None => builder.with_no_client_auth(),
        },
        (Some(cert), Some(key), None, None) => {
            cert.hash(&mut key_hasher);
            key.hash(&mut key_hasher);
            hash_file_contents(cert, &mut key_hasher)?;
            hash_file_contents(key, &mut key_hasher)?;
            let certs = load_certs_from(cert)?;
            let key = load_private_key_from(key)?;
            builder
                .with_client_auth_cert(certs, key)
                .with_context(|| format!("build upstream client certificate {}", cert.display()))?
        }
        (None, None, Some(cert), Some(key)) => {
            anyhow::ensure!(
                cert.len() <= TLS_PEM_MAX_BYTES && key.len() <= TLS_PEM_MAX_BYTES,
                "inline upstream client identity exceeds TLS material limit"
            );
            cert.hash(&mut key_hasher);
            key.hash(&mut key_hasher);
            builder
                .with_client_auth_cert(
                    load_certs_from_bytes(cert.as_bytes(), "inline upstream client certificate")?,
                    load_private_key_from_bytes(key.as_bytes(), "inline upstream client key")?,
                )
                .context("build inline upstream client certificate")?
        }
        _ => anyhow::bail!("upstream TLS client certificate and key must use one paired source"),
    };
    if spire.is_some() {
        // TLS resumption 会复用旧握手的客户端认证事实而不重新调用动态 resolver；关闭后每条新
        // 连接都必须出示当前 SVID，身份轮换和撤权才能即时约束新连接。
        client_config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    }

    Ok(UpstreamTlsProfile {
        key: Arc::from(format!("tls-{:016x}", key_hasher.finish())),
        server_name: server_name.map(Arc::from),
        client_config: Arc::new(client_config),
        client_identity_not_after: None,
        spire,
    })
}

/// 业务作用：用 PEM CA 文件构造上游信任根，确保坏证书不会进入连接池。
///
/// 参数说明：`ca_file` 是受配置边界约束的 PEM bundle 路径。
///
/// 返回：至少包含一张合法 CA 时返回信任根；读取、解析或导入失败时拒绝配置。
fn root_store_from_ca_file(ca_file: &Path) -> Result<RootCertStore> {
    let bytes = crate::bounded_io::read_file(ca_file, TLS_PEM_MAX_BYTES, "upstream CA")?;
    root_store_from_ca_bytes(&bytes, &ca_file.display().to_string())
}

/// 业务作用：从有界内存 PEM 构造上游信任根，供动态控制面避免临时落盘。
///
/// 参数说明：`bytes` 是 CA PEM；`label` 只用于低敏错误上下文，不能包含 PEM 内容。
///
/// 返回：全部证书可导入且集合非空时返回信任根；否则失败。
fn root_store_from_ca_bytes(bytes: &[u8], label: &str) -> Result<RootCertStore> {
    let certs = load_certs_from_bytes(bytes, label)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .with_context(|| format!("add upstream CA cert from {label}"))?;
    }
    Ok(roots)
}

/// 业务作用：加载操作系统根证书供 `wellKnownCACertificates: System` 与默认 HTTPS 共用。
///
/// 参数说明: 无。
///
/// 返回：系统至少提供一张可用根证书时返回信任库；完全不可用时拒绝 TLS profile。
fn native_root_store() -> Result<RootCertStore> {
    let result = rustls_native_certs::load_native_certs();
    anyhow::ensure!(
        !result.certs.is_empty(),
        "native TLS root store did not provide any certificates: {:?}",
        result.errors
    );
    let mut roots = RootCertStore::empty();
    for cert in result.certs {
        roots.add(cert).context("add native upstream CA cert")?;
    }
    Ok(roots)
}

/// 业务作用：规范化 BackendTLSPolicy 显式 SAN allowlist，避免歧义类型或相对 URI 绕过身份门禁。
///
/// 参数说明：`values` 中每项必须是 `dns:<name>` 或 `uri:<absolute-uri>`。
///
/// 返回：返回分离的 DNS 与 URI 集合；空值、未知类型和非法身份失败。
fn parse_subject_alt_names(values: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let mut dns_names = Vec::new();
    let mut uris = Vec::new();
    for value in values {
        if let Some(name) = value.strip_prefix("dns:") {
            let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
            anyhow::ensure!(
                !normalized.is_empty(),
                "upstream TLS DNS subjectAltName must not be empty"
            );
            ServerName::try_from(normalized.clone()).with_context(|| {
                format!("invalid upstream TLS DNS subjectAltName `{normalized}`")
            })?;
            dns_names.push(normalized);
        } else if let Some(uri) = value.strip_prefix("uri:") {
            let parsed = uri
                .parse::<http::Uri>()
                .with_context(|| format!("invalid upstream TLS URI subjectAltName `{uri}`"))?;
            anyhow::ensure!(
                parsed.scheme().is_some() && parsed.authority().is_some(),
                "upstream TLS URI subjectAltName must be absolute"
            );
            uris.push(uri.to_owned());
        } else {
            anyhow::bail!("upstream TLS subjectAltName `{value}` must use dns: or uri: prefix");
        }
    }
    Ok((dns_names, uris))
}

/// 把文件内容纳入 profile key,使同路径证书变更后 reload 可切到新的连接池。
fn hash_file_contents(path: &Path, hasher: &mut DefaultHasher) -> Result<()> {
    let bytes = crate::bounded_io::read_file(path, TLS_PEM_MAX_BYTES, "TLS material")?;
    bytes.hash(hasher);
    Ok(())
}

/// 解析当前生效的默认证书 pair。
///
/// 配置了 manifest 且文件存在时，cert/key 必须来自其指向的同一不可变版本目录；manifest 本身
/// 损坏或目标不完整会拒绝 reload，绝不回退并拼出混合 pair。manifest 尚不存在时才使用旧
/// `cert_file`/`key_file`，支持 seed 迁移和无 seed ACME 首签。
pub(crate) fn active_keypair_paths(tls: &TlsRuntimeCfg) -> Result<(PathBuf, PathBuf)> {
    if tls.private_key_provider.is_none() && tls.keypair_manifest_file.is_none() {
        // 旧双文件模式可能在断电时停在两个 rename 之间；任何 loader 读 pair 前先在安装锁内
        // 完成恢复，避免一次启动把跨代材料发布成新的 ServerConfig。
        crate::acme::recover_legacy_keypair_transaction(tls)?;
    }
    active_keypair_paths_unrecovered(tls)
}

/// 业务作用：在证书安装锁持有期间解析 pair 路径，避免恢复入口递归获取同一互斥锁。
///
/// 参数说明：`tls` 是当前 listener 的固定材料计划；调用方必须已处理旧式事务恢复。
///
/// 返回：manifest 当前指向的同代路径，或兼容 cert/key 路径；指针损坏时失败闭合。
pub(crate) fn active_keypair_paths_unrecovered(tls: &TlsRuntimeCfg) -> Result<(PathBuf, PathBuf)> {
    let Some(manifest_file) = &tls.keypair_manifest_file else {
        return Ok((tls.cert_file.clone(), tls.key_file.clone()));
    };
    let bytes = match crate::bounded_io::read_optional_file(
        manifest_file,
        KEYPAIR_MANIFEST_MAX_BYTES,
        "TLS keypair manifest",
    )? {
        Some(bytes) => bytes,
        None => return Ok((tls.cert_file.clone(), tls.key_file.clone())),
    };
    let manifest: KeypairManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse TLS keypair manifest {}", manifest_file.display()))?;
    anyhow::ensure!(
        manifest.schema_version == 1,
        "TLS keypair manifest {} uses unsupported schema_version {}",
        manifest_file.display(),
        manifest.schema_version
    );
    let relative = Path::new(&manifest.directory);
    anyhow::ensure!(
        !relative.as_os_str().is_empty()
            && !relative.is_absolute()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "TLS keypair manifest {} directory must be a non-empty relative path without traversal",
        manifest_file.display()
    );
    let parent = manifest_file.parent().unwrap_or_else(|| Path::new("."));
    let directory = parent.join(relative);
    Ok((directory.join("cert.pem"), directory.join("key.pem")))
}

/// 起证书热换 watcher:监听 cert/key 文件所在目录,内容变更即重建 `ServerConfig` 并原子换入 `shared`。
///
/// 坏证书**保留旧配置**(只告警,不让在线 TLS 中断);与数据面配置热更「坏配置不上线」同哲学。
///
/// # 参数
/// - `tls`: TLS 运行期配置(cert/key 路径),watcher 据此定位要监听的文件与重建来源。
/// - `shared`: accept 循环读取的原子 `ServerConfig` 指针,重建成功后 `store` 换新。
pub fn spawn_cert_watcher(tls: TlsRuntimeCfg, shared: SharedServerConfig) {
    spawn_cert_material_watcher(tls, move |config| {
        shared.store(config);
        Ok(())
    });
}

/// 业务作用：启动受 listener generation 停止权约束的 TCP TLS 证书 watcher，防止热换后遗留旧材料任务。
///
/// 参数说明：`tls` 定位证书材料；`shared` 是本代 acceptor 的配置指针；`shutdown` 表示本代已失权。
///
/// 返回：无同步返回值；收到停止事实后注销文件监听并终止发布，坏证书仍保留本代 LKG。
pub fn spawn_cert_watcher_until(
    tls: TlsRuntimeCfg,
    shared: SharedServerConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    spawn_cert_material_watcher_until(
        tls,
        move |config| {
            shared.store(config);
            Ok(())
        },
        shutdown,
    );
}

/// 监听 TLS 材料并把成功构建的新配置交给调用方原子发布。
///
/// 业务作用：让 TCP TLS、QUIC 等不同 transport 复用完全相同的文件/manifest/SNI/mTLS 监控
/// 纪律；回调失败时保留 transport 旧配置，不能发布半构建证书身份。
///
/// 参数说明：`tls` 描述全部受监控材料；`publish` 只在完整 `ServerConfig` 构建成功后调用，
/// 可继续执行 transport 专属转换并决定是否发布。
///
/// 返回：无同步返回值；watcher 在后台 task 中常驻，初始化或目录监控失败会记录错误。
pub fn spawn_cert_material_watcher<F>(tls: TlsRuntimeCfg, publish: F)
where
    F: Fn(Arc<ServerConfig>) -> Result<()> + Send + 'static,
{
    spawn_cert_material_watcher_inner(tls, publish, None);
}

/// 启动随 listener generation 停止的 TLS 材料 watcher。
///
/// 业务作用：为 QUIC 等会被 watcher 间接持有的 transport 提供明确生命周期；generation 停收
/// 后立即 Drop watcher/发布回调，避免旧 endpoint 被证书事件重新激活或长期泄漏。
///
/// 参数说明：`tls`/`publish` 与 [`spawn_cert_material_watcher`] 相同；`shutdown` 是 listener
/// generation 的停收广播。
///
/// 返回：无同步返回值；停机广播关闭或变为 true 时后台 task 结束。
pub fn spawn_cert_material_watcher_until<F>(
    tls: TlsRuntimeCfg,
    publish: F,
    shutdown: tokio::sync::watch::Receiver<bool>,
) where
    F: Fn(Arc<ServerConfig>) -> Result<()> + Send + 'static,
{
    spawn_cert_material_watcher_inner(tls, publish, Some(shutdown));
}

/// 装配可选 generation 生命周期的证书 watcher 共用实现。
///
/// 业务作用：保证常驻 TCP watcher 与可停止 QUIC watcher 使用同一文件筛选和坏证书保旧策略。
///
/// 参数说明：`tls` 是材料来源；`publish` 原子发布新配置；`shutdown` 为 None 时随进程常驻。
///
/// 返回：无同步返回值；初始化与监控结果通过日志暴露。
fn spawn_cert_material_watcher_inner<F>(
    tls: TlsRuntimeCfg,
    publish: F,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) where
    F: Fn(Arc<ServerConfig>) -> Result<()> + Send + 'static,
{
    if let Some(source) = tls.spire.clone() {
        let reload_tls = tls.clone();
        crate::spire::spawn_listener_watcher(source, shutdown, move || {
            // 身份快照先在来源内原子替换，随后才重建含动态 trust bundle 的完整配置；
            // 明确失权时 resolver 已返回空，不会在重建窗口继续接受旧身份握手。
            if reload_tls
                .spire
                .as_ref()
                .and_then(|source| source.current())
                .is_none()
            {
                return;
            }
            match build_server_config(&reload_tls) {
                Ok(config) => match publish(config) {
                    Ok(()) => tracing::info!("SPIRE TLS identity and trust bundles updated"),
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), "SPIRE TLS transport publish failed")
                    }
                },
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "SPIRE TLS candidate rejected")
                }
            }
        });
        return;
    }
    // 去重 cert/key 的父目录(常同目录);notify 监听目录而非文件,兼容编辑器「写临时文件+rename」。
    // 默认证书与所有 SNI 证书的目录都要监听，任一身份材料变化都必须热换整份 ServerConfig。
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = vec![tls.cert_file.clone()];
    if !tls.key_file.as_os_str().is_empty() {
        files.push(tls.key_file.clone());
    }
    if let Some(manifest) = &tls.keypair_manifest_file {
        files.push(manifest.clone());
    }
    for cert in &tls.certs {
        files.push(cert.cert_file.clone());
        if !cert.key_file.as_os_str().is_empty() {
            files.push(cert.key_file.clone());
        }
    }
    if let Some(ca) = &tls.client_auth {
        files.push(ca.ca_file.clone()); // mTLS CA 决定客户端授权边界，变化后必须与证书材料一起原子热换。
        files.extend(ca.crl_files.iter().cloned());
    }
    for ocsp in tls.ocsp_stapling.iter().chain(
        tls.certs
            .iter()
            .filter_map(|cert| cert.ocsp_stapling.as_ref()),
    ) {
        files.push(ocsp.response_file.clone());
        if let Some(issuer) = &ocsp.issuer_file {
            files.push(issuer.clone());
        }
    }
    // macOS notify 可能把 `/var/...` 事件规范化成 `/private/var/...`；只做裸 PathBuf
    // 相等会漏掉真实目标。规范化父目录但保留文件名，兼容尚不存在的 manifest 和 rename 写法。
    files = files
        .into_iter()
        .map(|path| {
            path.parent()
                .and_then(|parent| std::fs::canonicalize(parent).ok())
                .and_then(|parent| path.file_name().map(|name| parent.join(name)))
                .unwrap_or(path)
        })
        .collect();
    files.sort();
    files.dedup();
    for f in &files {
        if let Some(dir) = f.parent() {
            let dir = dir.to_path_buf();
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }
    tokio::spawn(async move {
        let watched_files = files;
        let reload_tls = tls.clone();
        let mut watcher = match RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                let Ok(ev) = res else { return };
                if !matches!(ev.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    return;
                }
                // notify 必须监听父目录才能兼容 temp+rename，但同目录其它文件不应触发昂贵的
                // PEM 解析和全量 ServerConfig 重建（证书目录常与其它控制面文件共存）。
                if !ev
                    .paths
                    .iter()
                    .any(|changed| watched_files.iter().any(|target| changed == target))
                {
                    return;
                }
                match build_server_config(&reload_tls) {
                    Ok(cfg) => match publish(cfg) {
                        Ok(()) => tracing::info!("tls certificate reloaded (hot swap)"),
                        Err(error) => tracing::warn!(
                            error = %format!("{error:#}"),
                            "tls certificate transport publish failed; keeping previous config"
                        ),
                    },
                    Err(e) => {
                        tracing::warn!(error = %format!("{e:#}"), "tls certificate reload failed; keeping previous config")
                    }
                }
            },
            notify::Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "tls cert watcher init failed; hot cert reload disabled");
                return;
            }
        };
        for dir in &dirs {
            if let Err(e) = watcher.watch(dir, RecursiveMode::NonRecursive) {
                tracing::error!(dir = %dir.display(), error = %e, "watch tls cert dir failed");
            }
        }
        tracing::info!("watching tls certificate files for changes");
        // 只有文件 watcher 已就绪后才启动主动获取，保证原子替换产生的首个事件不会落在监听空窗。
        spawn_ocsp_refreshers(tls.clone(), shutdown.clone());
        // 持有 watcher 到进程退出或 listener generation 停止(drop 即停止监听)。
        let _keep_alive = watcher;
        if let Some(mut shutdown) = shutdown {
            loop {
                if *shutdown.borrow() {
                    return;
                }
                if shutdown.changed().await.is_err() {
                    return;
                }
            }
        } else {
            std::future::pending::<()>().await;
        }
    });
}

/// 从 `TlsRuntimeCfg` 构建一份 `ServerConfig`(ALPN 广告 h2 + http/1.1)。启动期与证书热换时各调用一次。
///
/// - 无 SNI 证书(`certs` 空):走 `with_single_cert`,保留 rustls 的 key↔cert 匹配校验(常见单域名)。
/// - 有 SNI 证书(§19):装一个 `SniCertResolver`,按 ClientHello 的 server_name 选证,默认证书兜底。
pub fn build_server_config(tls: &TlsRuntimeCfg) -> Result<Arc<ServerConfig>> {
    if let Some(material) = &tls.in_memory {
        anyhow::ensure!(
            tls.keypair_manifest_file.is_none()
                && tls.certs.is_empty()
                && tls.client_auth.is_none()
                && tls.acme.is_none(),
            "in-memory TLS material cannot be combined with file, SNI, client_auth, or ACME sources"
        );
        return build_in_memory_server_config(material);
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
    let resolver: Arc<dyn ResolvesServerCert> = match &tls.spire {
        Some(source) => {
            anyhow::ensure!(
                source.current().is_some(),
                "SPIRE identity is not currently authorized or has expired"
            );
            Arc::new(crate::spire::SpireServerCertResolver::new(source.clone()))
        }
        None => Arc::new(build_sni_resolver(tls)?),
    };
    // 选证 resolver 在每次握手执行 OCSP 或 SPIRE 到期门禁；任何身份失权都不能沿用已构建配置绕过。
    let mut cfg = builder.with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    if let Some(tickets) = &tls.session_tickets {
        cfg.ticketer = build_session_ticket_producer(tickets)?;
    }
    Ok(Arc::new(cfg))
}

struct SpireClientCertVerifier {
    source: Arc<crate::spire::SpireTlsSource>,
    material: Arc<crate::spire::SpireMaterial>,
    by_domain: HashMap<String, Arc<dyn ClientCertVerifier>>,
    signature_verifier: Arc<dyn ClientCertVerifier>,
    root_hints: Vec<tokio_rustls::rustls::DistinguishedName>,
    require: bool,
    allowed_ids: Arc<[String]>,
    allowed_domains: Arc<[String]>,
}

impl std::fmt::Debug for SpireClientCertVerifier {
    /// 业务作用：输出不含 bundle 与证书内容的 SPIRE 客户端验证器摘要。
    ///
    /// 参数说明：`formatter` 是标准格式化目标。
    ///
    /// 返回：只记录已授权 trust domain 数和是否强制客户端身份。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpireClientCertVerifier")
            .field("trust_domain_count", &self.by_domain.len())
            .field("require", &self.require)
            .finish()
    }
}

impl ClientCertVerifier for SpireClientCertVerifier {
    /// 业务作用：要求服务端发送 CertificateRequest，确保配置的 SPIFFE 授权实际进入握手。
    ///
    /// 参数说明：无。
    ///
    /// 返回：始终为 true。
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// 业务作用：落实 require 与 optional 的客户端身份存在性门禁。
    ///
    /// 参数说明：无。
    ///
    /// 返回：require 模式为 true，optional 模式为 false。
    fn client_auth_mandatory(&self) -> bool {
        self.require
    }

    /// 业务作用：向客户端提供所有获授权 trust domain 的 CA subject 提示，不泄露额外信任域。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回构建期合并去重的 root hints。
    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &self.root_hints
    }

    /// 业务作用：先按唯一 SPIFFE URI SAN 选择同域 bundle，再执行链、用途、时间与 CRL 验证。
    ///
    /// 参数说明：`end_entity` 是客户端叶证书；`intermediates` 是其链；`now` 是握手验证时刻。
    ///
    /// 返回：身份 allowlist 与对应 trust-domain verifier 都通过时成功；跨域 CA、越权或吊销均拒绝。
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, tokio_rustls::rustls::Error> {
        if self
            .source
            .current()
            .is_none_or(|current| !Arc::ptr_eq(&current, &self.material))
        {
            // bundle 换代必须和服务端身份发布为同一份配置；旧 verifier 在发布窗口只拒绝，
            // 不能继续用已撤销 trust bundle 接受客户端。
            return Err(tokio_rustls::rustls::Error::General(
                "SPIRE client trust bundle generation is no longer authoritative".to_owned(),
            ));
        }
        let (identity, domain) = certificate_spiffe_identity(end_entity)
            .map_err(|error| tokio_rustls::rustls::Error::General(error.to_string()))?;
        let authorized = self
            .allowed_ids
            .binary_search_by(|allowed| allowed.as_str().cmp(identity.as_str()))
            .is_ok()
            || self
                .allowed_domains
                .binary_search_by(|allowed| allowed.as_str().cmp(domain.as_str()))
                .is_ok();
        if !authorized {
            return Err(tokio_rustls::rustls::Error::General(
                "SPIFFE client identity is not authorized for this listener".to_owned(),
            ));
        }
        self.by_domain
            .get(&domain)
            .ok_or_else(|| {
                tokio_rustls::rustls::Error::General(
                    "SPIFFE client trust domain has no authorized bundle".to_owned(),
                )
            })?
            .verify_client_cert(end_entity, intermediates, now)
    }

    /// 业务作用：校验 TLS 1.2 客户端握手签名，证明证书对应私钥由对端持有。
    ///
    /// 参数说明：`message` 是握手消息；`cert` 是叶证书；`dss` 是协商的签名值。
    ///
    /// 返回：标准 rustls 签名验证成功时通过，否则终止握手。
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.signature_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    /// 业务作用：校验 TLS 1.3 客户端握手签名，证明证书对应私钥由对端持有。
    ///
    /// 参数说明：`message` 是握手消息；`cert` 是叶证书；`dss` 是协商的签名值。
    ///
    /// 返回：标准 rustls 签名验证成功时通过，否则终止握手。
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.signature_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    /// 业务作用：公开标准验证器支持的握手签名算法集合，避免动态 bundle 改变密码套件边界。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回当前 rustls crypto provider 的客户端证书签名算法。
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

/// 业务作用：从当前 SPIRE 完整快照构建按 trust domain 隔离的客户端证书验证器。
///
/// 参数说明：`source` 提供动态 bundle 与 CRL；`auth` 提供精确身份、domain allowlist 和认证模式。
///
/// 返回：每个授权域都有独立可用 bundle 时返回验证器；缺 bundle、坏 CRL 或空授权集合拒绝候选。
fn build_spire_client_verifier(
    source: &Arc<crate::spire::SpireTlsSource>,
    auth: &ClientAuthRuntime,
) -> Result<Arc<dyn ClientCertVerifier>> {
    let material = source
        .current()
        .context("SPIRE client trust is unavailable or expired")?;
    let mut required_domains = auth.allowed_spiffe_trust_domains.to_vec();
    for identity in auth.allowed_spiffe_ids.iter() {
        let (_, domain) = crate::config::normalize_spiffe_id(identity)?;
        required_domains.push(domain);
    }
    required_domains.sort();
    required_domains.dedup();
    anyhow::ensure!(
        !required_domains.is_empty(),
        "SPIRE client trust requires an explicit identity allowlist"
    );

    let mut by_domain = HashMap::<String, Arc<dyn ClientCertVerifier>>::new();
    let mut signature_verifier = None;
    let mut root_hints = Vec::new();
    for domain in required_domains {
        let bundle = material.trust_bundles.get(&domain).with_context(|| {
            format!("SPIRE response has no authorized bundle for trust domain `{domain}`")
        })?;
        let mut roots = RootCertStore::empty();
        for cert in bundle.iter() {
            roots
                .add(cert.clone())
                .context("add SPIRE client trust anchor")?;
        }
        let mut builder = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()),
        );
        if !material.crls.is_empty() {
            builder = builder
                .with_crls(material.crls.iter().cloned())
                .allow_unknown_revocation_status();
            if auth.enforce_crl_expiration {
                builder = builder.enforce_revocation_expiration();
            }
        }
        let verifier: Arc<dyn ClientCertVerifier> = if auth.require {
            builder.build()
        } else {
            builder.allow_unauthenticated().build()
        }
        .with_context(|| format!("build SPIRE client verifier for trust domain `{domain}`"))?;
        root_hints.extend(verifier.root_hint_subjects().iter().cloned());
        signature_verifier.get_or_insert_with(|| verifier.clone());
        by_domain.insert(domain, verifier);
    }
    root_hints.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
    root_hints.dedup_by(|left, right| left.as_ref() == right.as_ref());
    Ok(Arc::new(SpireClientCertVerifier {
        source: source.clone(),
        material,
        by_domain,
        signature_verifier: signature_verifier
            .context("SPIRE client verifier has no trust domain")?,
        root_hints,
        require: auth.require,
        allowed_ids: auth.allowed_spiffe_ids.clone(),
        allowed_domains: auth.allowed_spiffe_trust_domains.clone(),
    }))
}

/// 业务作用：从客户端叶证书提取唯一规范 SPIFFE ID，供握手期选择同域 trust bundle。
///
/// 参数说明：`certificate` 是尚未完成信任链验证的客户端叶证书。
///
/// 返回：仅有一个 URI SAN 且语法无歧义时返回身份与 trust domain；其它 SAN 形态拒绝。
fn certificate_spiffe_identity(certificate: &CertificateDer<'_>) -> Result<(String, String)> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    let (_, leaf) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|error| anyhow::anyhow!("parse SPIFFE client certificate: {error}"))?;
    let san = leaf
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(names) => Some(names),
            _ => None,
        })
        .context("SPIFFE client certificate has no subjectAltName")?;
    anyhow::ensure!(
        san.general_names.len() == 1,
        "SPIFFE client certificate must contain exactly one SAN"
    );
    let GeneralName::URI(uri) = san.general_names[0] else {
        anyhow::bail!("SPIFFE client certificate SAN must be a URI");
    };
    crate::config::normalize_spiffe_id(uri)
}

/// 业务作用：把已解析共享 key 编译成固定当前代和重叠旧代的 AES-256-GCM ticket producer。
///
/// 参数说明：`runtime` 按配置顺序携带 1..=4 个 256-bit key 与 lifetime。
///
/// 返回：key id 唯一且 AEAD 可构造时返回 rustls producer；冲突或内部构造失败拒绝 TLS 候选。
fn build_session_ticket_producer(
    runtime: &SessionTicketRuntime,
) -> Result<Arc<dyn ProducesTickets>> {
    let mut ids = std::collections::HashSet::new();
    let mut keys = Vec::with_capacity(runtime.keys.len());
    for raw in runtime.keys.iter() {
        let digest = sha2::Sha256::digest(raw);
        let id: [u8; 8] = digest[..8]
            .try_into()
            .expect("SHA-256 prefix has a fixed length");
        anyhow::ensure!(
            ids.insert(id),
            "TLS session ticket key id collision; rotate one key before publishing"
        );
        keys.push(SessionTicketKey {
            id,
            cipher: Aes256Gcm::new_from_slice(raw)
                .map_err(|_| anyhow::anyhow!("build TLS session ticket AEAD"))?,
        });
    }
    Ok(Arc::new(SharedSessionTickets {
        keys,
        lifetime_seconds: runtime.lifetime_seconds,
    }))
}

/// 业务作用：把 SDS 已验证的内联 PEM 构造成独立 rustls 配置，整个过程不创建临时文件或日志字段。
///
/// 参数说明：`material` 持有证书链、私钥与可选客户端 CA；其生命周期绑定当前 Snapshot。
///
/// 返回：证书/私钥/CA 完整且彼此匹配时返回服务端配置；任何解析或身份错误拒绝候选 generation。
fn build_in_memory_server_config(material: &InMemoryTlsMaterial) -> Result<Arc<ServerConfig>> {
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
    let key = load_private_key_from_bytes(&material.private_key, "SDS private key")?;
    let mut config = builder
        .with_single_cert(certs, key)
        .context("build SDS TLS certificate identity")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 业务作用：从 CA PEM 构建客户端证书 verifier，并准确落实严格、可选或不安全兼容模式。
///
/// 参数说明：`ca` 包含已解析的认证模式和受信 CA 文件。
///
/// 返回：严格模式校验信任链且要求证书；可选模式允许无证书但校验已出示证书；
/// 不安全兼容模式接受任意证书或无证书，但仍校验已出示证书的握手签名。
fn build_client_verifier(
    ca: &ClientAuthRuntime,
) -> Result<Arc<dyn tokio_rustls::rustls::server::danger::ClientCertVerifier>> {
    let ca_certs = load_certs_from(&ca.ca_file)?;
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots
            .add(cert)
            .with_context(|| format!("add client CA cert from {}", ca.ca_file.display()))?;
    }
    let mut builder = WebPkiClientVerifier::builder(Arc::new(roots));
    if !ca.crl_files.is_empty() {
        let mut crls = Vec::new();
        for path in &ca.crl_files {
            crls.extend(load_crls_from(path)?);
        }
        builder = builder.with_crls(crls);
        if ca.allow_unknown_revocation_status {
            builder = builder.allow_unknown_revocation_status();
        }
        if ca.enforce_crl_expiration {
            builder = builder.enforce_revocation_expiration();
        }
    }
    let verifier = if ca.require {
        builder.build()
    } else {
        builder.allow_unauthenticated().build()
    }
    .with_context(|| format!("build client cert verifier from {}", ca.ca_file.display()))?;
    if ca.allow_untrusted {
        // 兼容模式仍发送 CertificateRequest 并复用标准签名校验，只放宽 CA 信任门禁。
        Ok(Arc::new(InsecureFallbackClientCertVerifier {
            signature_verifier: verifier,
            root_hints: Vec::new(),
        }))
    } else {
        Ok(verifier)
    }
}

/// 业务作用：有界读取一个 PEM CRL bundle，供客户端证书握手期执行离线吊销复验。
///
/// 参数说明：`path` 是构建期规范化的 CRL 文件。
///
/// 返回：至少一张合法 DER CRL 时返回集合；空文件、超限、读取或 PEM 解析错误拒绝 TLS 候选。
fn load_crls_from(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let bytes = crate::bounded_io::read_file(path, TLS_PEM_MAX_BYTES, "client certificate CRL")?;
    let crls = rustls_pemfile::crls(&mut Cursor::new(bytes))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse client certificate CRL {}", path.display()))?;
    anyhow::ensure!(
        !crls.is_empty(),
        "client certificate CRL {} contains no CRL entries",
        path.display()
    );
    Ok(crls)
}

/// 从默认证书 + `certs[]` 构建 SNI resolver(§19)。任一证书/私钥读不了即整体失败(坏证书不上线)。
fn build_sni_resolver(tls: &TlsRuntimeCfg) -> Result<SniCertResolver> {
    let (default_cert_file, default_key_file) = active_keypair_paths(tls)?;
    let default = certified_identity(
        &default_cert_file,
        &default_key_file,
        tls.private_key_provider.as_ref(),
        tls.ocsp_stapling.as_ref(),
    )
    .context("build default tls certificate")?;
    let mut exact: HashMap<String, Arc<CertifiedIdentity>> = HashMap::new();
    let mut wildcards: Vec<(String, Arc<CertifiedIdentity>)> = Vec::new();
    for cert in &tls.certs {
        let key = Arc::new(
            certified_identity(
                &cert.cert_file,
                &cert.key_file,
                cert.private_key_provider.as_ref(),
                cert.ocsp_stapling.as_ref(),
            )
            .with_context(|| format!("build sni tls certificate for {:?}", cert.server_names))?,
        );
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
/// 参数说明：`cert_file` 是公开证书链；`key_file` 与 `private_key_provider` 恰有一个有效；
/// `ocsp` 是该证书专属的可选响应策略。
///
/// 返回：证书、私钥和 OCSP 响应自洽时返回握手身份；must-staple 缺响应或任何材料无效时失败。
fn certified_identity(
    cert_file: &Path,
    key_file: &Path,
    private_key_provider: Option<&crate::external_crypto::ExternalPrivateKeyPlan>,
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
    let mut certified = CertifiedKey::new(certs, signing_key);
    // 发布前复验证书公开身份与 signing key，避免双文件更新或 signer 配置错位形成半完成身份。
    certified.keys_match().with_context(|| {
        format!(
            "TLS certificate {} and signing key do not match",
            cert_file.display()
        )
    })?;
    let must_staple = certificate_requires_ocsp_staple(&certified.cert[0])?;
    let Some(ocsp) = ocsp else {
        anyhow::ensure!(
            !must_staple,
            "TLS certificate {} declares must-staple but has no ocsp_stapling config",
            cert_file.display()
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

/// 业务作用：完整验证 OCSPResponse 可被当前服务端证书安全 stapling，并计算握手截止时刻。
///
/// 参数说明：`chain` 的首项是叶证书；`runtime` 固定响应、issuer 和 freshness 策略。
///
/// 返回：响应签名、issuer、CertID、good 状态和时间窗口全部成立时返回同一份 DER 与截止时刻；
/// revoked、unknown、弱签名、未来响应、陈旧响应或 delegated responder 未闭环时失败。
fn validate_ocsp_staple(
    chain: &[CertificateDer<'static>],
    runtime: &OcspStaplingRuntime,
) -> Result<(Vec<u8>, chrono::DateTime<chrono::Utc>)> {
    let response = crate::bounded_io::read_file(
        &runtime.response_file,
        OCSP_RESPONSE_MAX_BYTES,
        "OCSP response",
    )?;
    let valid_until = validate_ocsp_staple_bytes(chain, runtime, &response, None)?;
    Ok((response, valid_until))
}

/// 业务作用：验证内存中的 OCSP 响应，供文件加载和主动 AIA 获取复用同一信任与时间语义。
///
/// 参数说明：`chain` 和 `runtime` 固定证书及策略；`response` 是待验 DER；`nonce` 来自主动请求。
///
/// 返回：响应只对当前叶证书报告 good 且 freshness 有效时返回截止时刻，否则失败。
fn validate_ocsp_staple_bytes(
    chain: &[CertificateDer<'static>],
    runtime: &OcspStaplingRuntime,
    response: &[u8],
    nonce: Option<&[u8]>,
) -> Result<chrono::DateTime<chrono::Utc>> {
    let leaf_der = chain.first().context("TLS certificate chain is empty")?;
    let leaf = x509_cert::Certificate::from_der(leaf_der.as_ref())
        .context("parse TLS leaf certificate for OCSP")?;
    let issuer = load_ocsp_issuer(chain, runtime)?;
    let signature_policy = tsp_ltv::crypto::verify::SignaturePolicy::strict();
    // issuer 必须确实签发叶证书，不能仅凭响应中的同 serial 记录把无关 CA 绑定到当前身份。
    tsp_ltv::crypto::verify::verify_certificate_signature_with_policy(
        &leaf,
        &issuer,
        &signature_policy,
    )
    .context("OCSP issuer did not sign TLS leaf certificate")?;
    let max_age = i64::try_from(runtime.max_age_without_next_update_seconds)
        .context("OCSP max age exceeds signed duration")?;
    let skew = i64::try_from(runtime.clock_skew_seconds)
        .context("OCSP clock skew exceeds signed duration")?;
    let freshness = tsp_ltv::ltv::OcspFreshness {
        clock_skew: chrono::Duration::seconds(skew),
        max_age_without_next_update: chrono::Duration::seconds(max_age),
    };
    let now = chrono::Utc::now();
    let outcome = tsp_ltv::ltv::ocsp_check_revocation_detailed(
        response,
        &leaf,
        &issuer,
        nonce,
        Some(now),
        &signature_policy,
        &freshness,
    )
    .context("validate OCSP response")?;
    anyhow::ensure!(
        outcome.delegated_responder.is_none(),
        "OCSP delegated responder requires its own revocation evidence"
    );
    anyhow::ensure!(
        outcome.status.is_valid(),
        "OCSP response does not report the TLS certificate as good"
    );
    let parsed = tsp_ltv::ltv::parse_ocsp_response(response)
        .context("parse validated OCSP response window")?;
    let latest_allowed = now + freshness.clock_skew;
    anyhow::ensure!(
        parsed.produced_at <= latest_allowed,
        "OCSP response producedAt is beyond the allowed clock skew"
    );
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .context("encode OCSP issuer subject")?;
    let expected_name_hash = sha1::Sha1::digest(&issuer_name_der);
    let expected_key_hash = sha1::Sha1::digest(
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    );
    let serial =
        tsp_ltv::der_utils::parse_integer_body(leaf.tbs_certificate.serial_number.as_bytes());
    let matches = parsed
        .responses
        .iter()
        .filter(|single| {
            single.issuer_name_hash == expected_name_hash.as_slice()
                && single.issuer_key_hash == expected_key_hash.as_slice()
                && tsp_ltv::der_utils::integer_bodies_equal(&single.serial_number, &serial)
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        matches.len() == 1,
        "OCSP response must contain exactly one status for the TLS certificate"
    );
    let single = matches[0];
    anyhow::ensure!(
        single.this_update <= latest_allowed,
        "OCSP response thisUpdate is beyond the allowed clock skew"
    );
    anyhow::ensure!(
        parsed.produced_at + freshness.clock_skew >= single.this_update,
        "OCSP response producedAt precedes thisUpdate beyond the allowed clock skew"
    );
    let valid_until = single.next_update.map_or_else(
        || single.this_update + freshness.max_age_without_next_update + freshness.clock_skew,
        |next_update| next_update + freshness.clock_skew,
    );
    Ok(valid_until)
}

/// 业务作用：为所有开启 AIA 获取的证书启动独立有界刷新循环，刷新失败不覆盖最后有效响应。
///
/// 参数说明：`tls` 包含默认及 SNI 证书；`shutdown` 绑定 listener generation 生命周期。
///
/// 返回：无同步返回值；没有启用主动获取时不创建后台任务。
fn spawn_ocsp_refreshers(tls: TlsRuntimeCfg, shutdown: Option<tokio::sync::watch::Receiver<bool>>) {
    let mut response_files = std::collections::HashSet::new();
    let shared_tls = Arc::new(tls.clone());
    if let Some(runtime) = tls
        .ocsp_stapling
        .as_ref()
        .filter(|runtime| runtime.fetch_from_aia)
    {
        response_files.insert(runtime.response_file.clone());
        spawn_ocsp_refresher(
            OcspCertificateSource::Default(shared_tls),
            runtime.clone(),
            shutdown.clone(),
        );
    }
    for cert in &tls.certs {
        let Some(runtime) = cert
            .ocsp_stapling
            .as_ref()
            .filter(|runtime| runtime.fetch_from_aia)
        else {
            continue;
        };
        if !response_files.insert(runtime.response_file.clone()) {
            tracing::warn!(
                response_file = %runtime.response_file.display(),
                "duplicate OCSP refresh target skipped"
            );
            continue;
        }
        spawn_ocsp_refresher(
            OcspCertificateSource::File(cert.cert_file.clone()),
            runtime.clone(),
            shutdown.clone(),
        );
    }
}

/// 业务作用：按固定上限周期获取一张证书的 OCSP 响应，只有完整验证后才原子替换材料文件。
///
/// 参数说明：`source` 每轮解析当前叶证书；`runtime` 固定 responder 策略；`shutdown` 可停止任务。
///
/// 返回：无同步返回值；网络、验证或落盘失败仅记录低敏错误并保留最后有效响应。
fn spawn_ocsp_refresher(
    source: OcspCertificateSource,
    runtime: OcspStaplingRuntime,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) {
    tokio::spawn(async move {
        let mut shutdown = shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            runtime.refresh_interval_seconds,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match fetch_and_store_ocsp_response(&source, &runtime).await {
                        Ok(true) => tracing::info!(
                            response_file = %runtime.response_file.display(),
                            "OCSP response refreshed"
                        ),
                        Ok(false) => {}
                        Err(error) => tracing::warn!(
                            error = %format!("{error:#}"),
                            "OCSP refresh failed; keeping last-known-good response"
                        ),
                    }
                }
                _ = async {
                    match shutdown.as_mut() {
                        Some(receiver) => {
                            while !*receiver.borrow() {
                                if receiver.changed().await.is_err() {
                                    break;
                                }
                            }
                        }
                        None => std::future::pending::<()>().await,
                    }
                } => return,
            }
        }
    });
}

/// 业务作用：从叶证书 AIA 获取带 nonce 的响应，复验后以 rename 原子发布给 TLS watcher。
///
/// 参数说明：`source` 提供当前证书路径；`runtime` 提供响应文件、issuer、deadline 与 freshness。
///
/// 返回：发布新字节返回 true；响应未变化返回 false；所有依赖和验证失败均返回错误。
async fn fetch_and_store_ocsp_response(
    source: &OcspCertificateSource,
    runtime: &OcspStaplingRuntime,
) -> Result<bool> {
    use futures::StreamExt as _;

    let cert_file = source.certificate_file()?;
    let chain = load_certs_from(&cert_file)?;
    let leaf_der = chain.first().context("TLS certificate chain is empty")?;
    let leaf = x509_cert::Certificate::from_der(leaf_der.as_ref())
        .context("parse TLS leaf certificate for OCSP fetch")?;
    let issuer = load_ocsp_issuer(&chain, runtime)?;
    let urls = tsp_ltv::ltv::OcspClient::extract_ocsp_urls(&leaf);
    anyhow::ensure!(
        !urls.is_empty(),
        "TLS certificate has no OCSP AIA responder"
    );
    anyhow::ensure!(
        urls.len() <= 4,
        "TLS certificate has too many OCSP AIA responders"
    );
    let (request, nonce) = tsp_ltv::ltv::build_ocsp_request_with_nonce(&leaf, &issuer)
        .context("build OCSP request")?;
    let timeout = std::time::Duration::from_millis(runtime.request_timeout_ms);
    let mut last_error = None;
    for url in urls {
        let result = async {
            let client =
                build_pinned_ocsp_client(&url, timeout, runtime.allowed_responder_cidrs.as_slice())
                    .await?;
            let response = client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/ocsp-request")
                .header(reqwest::header::ACCEPT, "application/ocsp-response")
                .body(request.clone())
                .send()
                .await
                .context("send OCSP request")?;
            anyhow::ensure!(
                response.status().is_success(),
                "OCSP responder returned failure"
            );
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_ascii_lowercase();
            anyhow::ensure!(
                content_type
                    .split(';')
                    .next()
                    .is_some_and(|value| value.trim() == "application/ocsp-response"),
                "OCSP responder returned an unexpected content type"
            );
            if let Some(length) = response.content_length() {
                anyhow::ensure!(
                    length <= OCSP_RESPONSE_MAX_BYTES as u64,
                    "OCSP response exceeds byte limit"
                );
            }
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("read OCSP response")?;
                anyhow::ensure!(
                    body.len().saturating_add(chunk.len()) <= OCSP_RESPONSE_MAX_BYTES,
                    "OCSP response exceeds byte limit"
                );
                body.extend_from_slice(&chunk);
            }
            anyhow::ensure!(!body.is_empty(), "OCSP responder returned an empty body");
            validate_ocsp_staple_bytes(&chain, runtime, &body, Some(&nonce))?;
            Result::<Vec<u8>>::Ok(body)
        }
        .await;
        match result {
            Ok(body) => {
                if crate::bounded_io::read_file(
                    &runtime.response_file,
                    OCSP_RESPONSE_MAX_BYTES,
                    "OCSP response",
                )
                .is_ok_and(|current| current == body)
                {
                    return Ok(false);
                }
                let path = runtime.response_file.clone();
                tokio::task::spawn_blocking(move || atomic_write_ocsp_response(&path, &body))
                    .await
                    .context("join OCSP response writer")??;
                return Ok(true);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("all OCSP responders failed")))
}

/// 业务作用：解析并钉住 OCSP responder 的公开目标地址，避免校验后再次解析造成 DNS rebinding。
///
/// 参数说明：`url` 来自当前受信叶证书 AIA；`timeout` 同时约束 DNS 与 HTTP 请求。
///
/// 返回：scheme、凭据、地址类别均安全时返回禁重定向且使用固定地址集的 client，否则失败。
async fn build_pinned_ocsp_client(
    url: &str,
    timeout: std::time::Duration,
    allowed_responder_cidrs: &[crate::net::Cidr],
) -> Result<reqwest::Client> {
    let parsed = reqwest::Url::parse(url).context("parse OCSP responder URL")?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "OCSP responder URL scheme is not allowed"
    );
    anyhow::ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "OCSP responder URL must not contain credentials"
    );
    anyhow::ensure!(
        parsed.fragment().is_none(),
        "OCSP responder URL must not contain a fragment"
    );
    let host = parsed
        .host_str()
        .context("OCSP responder URL has no host")?;
    let port = parsed
        .port_or_known_default()
        .context("OCSP responder URL has no port")?;
    let addresses = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![std::net::SocketAddr::new(ip, port)]
    } else {
        tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
            .await
            .context("OCSP DNS resolution timed out")??
            .collect::<Vec<_>>()
    };
    anyhow::ensure!(
        !addresses.is_empty(),
        "OCSP responder resolved to no addresses"
    );
    anyhow::ensure!(
        addresses.iter().all(|address| {
            !tsp_ltv::net::is_disallowed_ip(address.ip())
                || crate::net::any_contains(allowed_responder_cidrs, address.ip())
        }),
        "OCSP responder resolved to a non-public address"
    );
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout);
    let builder = if host.parse::<std::net::IpAddr>().is_ok() {
        builder
    } else {
        builder.resolve_to_addrs(host, &addresses)
    };
    builder.build().context("build pinned OCSP HTTP client")
}

/// 业务作用：从显式 issuer 文件或叶证书链读取 OCSP issuer，统一验证与主动获取的选择规则。
///
/// 参数说明：`chain` 是当前服务端证书链；`runtime` 可指定独立 issuer 文件。
///
/// 返回：返回可解析 issuer 证书；材料缺失或畸形时失败。
fn load_ocsp_issuer(
    chain: &[CertificateDer<'static>],
    runtime: &OcspStaplingRuntime,
) -> Result<x509_cert::Certificate> {
    let issuer_der = match &runtime.issuer_file {
        Some(path) => load_certs_from(path)?
            .into_iter()
            .next()
            .with_context(|| format!("OCSP issuer file {} is empty", path.display()))?,
        None => chain
            .get(1)
            .cloned()
            .context("OCSP validation needs issuer_file or a second certificate in the chain")?,
    };
    x509_cert::Certificate::from_der(issuer_der.as_ref()).context("parse OCSP issuer certificate")
}

/// 业务作用：把已验证 OCSP 响应写入同目录临时文件并原子替换，避免 watcher 读取半文件。
///
/// 参数说明：`target` 是声明的响应文件；`body` 是已完成签名与 freshness 校验的 DER。
///
/// 返回：文件写入、sync 或 rename 任一步失败时返回错误，原目标保持不变。
fn atomic_write_ocsp_response(target: &Path, body: &[u8]) -> Result<()> {
    anyhow::ensure!(
        !body.is_empty() && body.len() <= OCSP_RESPONSE_MAX_BYTES,
        "OCSP response write exceeds byte limit"
    );
    let parent = target
        .parent()
        .context("OCSP response path has no parent")?;
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .context("OCSP response filename is not valid UTF-8")?;
    let mut nonce = [0_u8; 8];
    getrandom::getrandom(&mut nonce).context("generate OCSP temporary filename")?;
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = parent.join(format!(".{name}.naway-{suffix}.tmp"));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create OCSP temporary file in {}", parent.display()))?;
        file.write_all(body).context("write OCSP temporary file")?;
        file.sync_all().context("sync OCSP temporary file")?;
        std::fs::rename(&temporary, target).context("publish OCSP response")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

enum ClientOcspError {
    Dependency(anyhow::Error),
    Rejected(anyhow::Error),
}

impl std::fmt::Display for ClientOcspError {
    /// 业务作用：输出不含客户端证书主体、serial、AIA URL 或响应内容的错误类别。
    ///
    /// 参数说明：`formatter` 是标准格式化目标。
    ///
    /// 返回：仅暴露低敏失败原因，供握手拒绝日志定位依赖或证据错误。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dependency(error) => write!(formatter, "OCSP dependency unavailable: {error}"),
            Self::Rejected(error) => write!(formatter, "OCSP evidence rejected: {error}"),
        }
    }
}

/// 业务作用：在客户端证书链已通过 rustls 校验后、开放 HTTP 或 stream 业务数据前执行在线吊销门。
///
/// 参数说明：`peer_certificates` 来自当前 TLS session；`auth` 是同 listener 的认证与 OCSP 策略。
///
/// 返回：未启用、未出示可选证书、缓存 good 或在线 good 时成功；明确吊销/坏证据始终失败，
/// 依赖故障只在显式 soft-fail 下放行。
pub async fn verify_client_certificate_ocsp(
    peer_certificates: Option<&[CertificateDer<'_>]>,
    auth: Option<&ClientAuthRuntime>,
) -> Result<()> {
    let Some(policy) = auth.and_then(|auth| auth.client_ocsp.as_ref()) else {
        return Ok(());
    };
    let Some(certificates) = peer_certificates.filter(|certs| !certs.is_empty()) else {
        return Ok(());
    };
    let fingerprint: [u8; 32] = sha2::Sha256::digest(certificates[0].as_ref()).into();
    let now = chrono::Utc::now();
    if policy
        .cache
        .get(&fingerprint)
        .is_some_and(|entry| now <= entry.valid_until)
    {
        return Ok(());
    }
    let timeout = std::time::Duration::from_millis(policy.timeout_ms);
    let permit = tokio::time::timeout(timeout, policy.concurrency.clone().acquire_owned())
        .await
        .context("client certificate OCSP concurrency wait timed out")?
        .context("client certificate OCSP concurrency gate closed")?;
    let now = chrono::Utc::now();
    if policy
        .cache
        .get(&fingerprint)
        .is_some_and(|entry| now <= entry.valid_until)
    {
        drop(permit);
        return Ok(());
    }
    let stale = policy.cache.get(&fingerprint).map(|entry| entry.clone());
    let checked =
        fetch_client_certificate_ocsp(certificates, auth.expect("policy implies auth"), policy)
            .await;
    drop(permit);
    match checked {
        Ok(valid_until) => {
            let stale_seconds = i64::try_from(policy.max_stale_seconds)
                .context("client certificate OCSP max stale exceeds signed duration")?;
            let record = ClientOcspCacheRecord {
                valid_until,
                stale_until: valid_until + chrono::Duration::seconds(stale_seconds),
            };
            if policy.cache.contains_key(&fingerprint)
                || policy.cache.len() < policy.max_cache_entries
            {
                policy.cache.insert(fingerprint, record);
            }
            Ok(())
        }
        Err(ClientOcspError::Rejected(error)) => Err(error),
        Err(ClientOcspError::Dependency(error)) => {
            let dependency_may_fail_open = stale
                .as_ref()
                .is_none_or(|entry| chrono::Utc::now() <= entry.stale_until);
            if policy.mode == ClientCertificateOcspMode::SoftFail && dependency_may_fail_open {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

/// 业务作用：在 TLS 链校验后按精确 SPIFFE ID 或 trust domain 授权客户端 workload 身份。
///
/// 参数说明：`peer_certificates` 来自当前 session；`auth` 持有构建期规范化的身份 allowlist。
///
/// 返回：未配置 SPIFFE 门时返回空；唯一 URI SAN 合法且获授权时返回规范 ID；缺失、多值、
/// 路径歧义或越权身份均拒绝连接。
pub fn verify_client_certificate_spiffe(
    peer_certificates: Option<&[CertificateDer<'_>]>,
    auth: Option<&ClientAuthRuntime>,
) -> Result<Option<Arc<str>>> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    let Some(auth) = auth.filter(|auth| {
        !auth.allowed_spiffe_ids.is_empty() || !auth.allowed_spiffe_trust_domains.is_empty()
    }) else {
        return Ok(None);
    };
    let certificates = peer_certificates
        .filter(|certificates| !certificates.is_empty())
        .context("SPIFFE authorization requires a client certificate")?;
    let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
        .map_err(|error| anyhow::anyhow!("parse client certificate for SPIFFE: {error}"))?;
    let san = leaf
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(names) => Some(names),
            _ => None,
        })
        .context("SPIFFE client certificate has no subjectAltName")?;
    let uris = san
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        uris.len() == 1,
        "SPIFFE client certificate must contain exactly one URI SAN"
    );
    let (identity, domain) = crate::config::normalize_spiffe_id(uris[0])?;
    anyhow::ensure!(
        auth.allowed_spiffe_ids
            .binary_search_by(|allowed| allowed.as_str().cmp(identity.as_str()))
            .is_ok()
            || auth
                .allowed_spiffe_trust_domains
                .binary_search_by(|allowed| allowed.as_str().cmp(domain.as_str()))
                .is_ok(),
        "SPIFFE client identity is not authorized for this listener"
    );
    Ok(Some(Arc::from(identity)))
}

/// 业务作用：为一张已验证客户端证书获取并验证在线 OCSP 状态，不把网络错误与坏证据混为一类。
///
/// 参数说明：`certificates` 是 peer 链；`auth` 提供信任根；`policy` 提供 deadline 与 freshness。
///
/// 返回：good 响应返回截止时刻；网络/AIA 故障返回 Dependency；密码学、绑定或状态错误返回 Rejected。
async fn fetch_client_certificate_ocsp(
    certificates: &[CertificateDer<'_>],
    auth: &ClientAuthRuntime,
    policy: &ClientCertificateOcspRuntime,
) -> std::result::Result<chrono::DateTime<chrono::Utc>, ClientOcspError> {
    let leaf = x509_cert::Certificate::from_der(certificates[0].as_ref())
        .context("parse client leaf certificate")
        .map_err(ClientOcspError::Rejected)?;
    let issuer = find_client_certificate_issuer(certificates, auth, &leaf)
        .map_err(ClientOcspError::Rejected)?;
    let urls = tsp_ltv::ltv::OcspClient::extract_ocsp_urls(&leaf);
    if urls.is_empty() {
        return Err(ClientOcspError::Dependency(anyhow::anyhow!(
            "client certificate has no OCSP AIA responder"
        )));
    }
    if urls.len() > 4 {
        return Err(ClientOcspError::Rejected(anyhow::anyhow!(
            "client certificate has too many OCSP AIA responders"
        )));
    }
    let (request, nonce) = tsp_ltv::ltv::build_ocsp_request_with_nonce(&leaf, &issuer)
        .context("build client certificate OCSP request")
        .map_err(ClientOcspError::Rejected)?;
    let timeout = std::time::Duration::from_millis(policy.timeout_ms);
    let response = request_ocsp_response(
        &urls,
        &request,
        timeout,
        policy.allowed_responder_cidrs.as_slice(),
    )
    .await
    .map_err(ClientOcspError::Dependency)?;
    validate_client_ocsp_evidence(&response, &nonce, &leaf, &issuer, policy)
        .map_err(ClientOcspError::Rejected)
}

/// 业务作用：在 peer chain 与配置 CA 中定位确实签发客户端叶证书的 issuer，避免信任同名无关证书。
///
/// 参数说明：`certificates` 是客户端提交链；`auth` 指向已信任 CA bundle；`leaf` 是解析后的叶证书。
///
/// 返回：首个 subject 与签名都匹配的 issuer；没有匹配项时拒绝在线状态检查。
fn find_client_certificate_issuer(
    certificates: &[CertificateDer<'_>],
    auth: &ClientAuthRuntime,
    leaf: &x509_cert::Certificate,
) -> Result<x509_cert::Certificate> {
    let mut candidates = certificates
        .iter()
        .skip(1)
        .map(|certificate| CertificateDer::from(certificate.as_ref().to_vec()))
        .collect::<Vec<_>>();
    candidates.extend(load_certs_from(&auth.ca_file)?);
    anyhow::ensure!(
        candidates.len() <= 32,
        "client certificate issuer candidates exceed 32"
    );
    let signature_policy = tsp_ltv::crypto::verify::SignaturePolicy::strict();
    for candidate in candidates {
        let Ok(issuer) = x509_cert::Certificate::from_der(candidate.as_ref()) else {
            continue;
        };
        if leaf.tbs_certificate.issuer == issuer.tbs_certificate.subject
            && tsp_ltv::crypto::verify::verify_certificate_signature_with_policy(
                leaf,
                &issuer,
                &signature_policy,
            )
            .is_ok()
        {
            return Ok(issuer);
        }
    }
    anyhow::bail!("no trusted issuer matches the client certificate")
}

/// 业务作用：向已钉住公开地址的 responder 发送有界 OCSP 请求，所有 URL 共用一个总 deadline。
///
/// 参数说明：`urls` 来自证书 AIA；`request` 是 DER 请求；`timeout` 是整个尝试序列的上限。
///
/// 返回：首个成功且 content-type/大小合法的 DER；所有依赖失败时返回低敏错误。
async fn request_ocsp_response(
    urls: &[String],
    request: &[u8],
    timeout: std::time::Duration,
    allowed_responder_cidrs: &[crate::net::Cidr],
) -> Result<Vec<u8>> {
    use futures::StreamExt as _;

    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error = None;
    for url in urls {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let result = async {
            let client = build_pinned_ocsp_client(url, remaining, allowed_responder_cidrs).await?;
            let response = client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/ocsp-request")
                .header(reqwest::header::ACCEPT, "application/ocsp-response")
                .body(request.to_vec())
                .send()
                .await
                .context("send OCSP request")?;
            anyhow::ensure!(
                response.status().is_success(),
                "OCSP responder returned failure"
            );
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_ascii_lowercase();
            anyhow::ensure!(
                content_type
                    .split(';')
                    .next()
                    .is_some_and(|value| value.trim() == "application/ocsp-response"),
                "OCSP responder returned an unexpected content type"
            );
            if let Some(length) = response.content_length() {
                anyhow::ensure!(
                    length <= OCSP_RESPONSE_MAX_BYTES as u64,
                    "OCSP response exceeds byte limit"
                );
            }
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("read OCSP response")?;
                anyhow::ensure!(
                    body.len().saturating_add(chunk.len()) <= OCSP_RESPONSE_MAX_BYTES,
                    "OCSP response exceeds byte limit"
                );
                body.extend_from_slice(&chunk);
            }
            anyhow::ensure!(!body.is_empty(), "OCSP responder returned an empty body");
            Result::<Vec<u8>>::Ok(body)
        }
        .await;
        match result {
            Ok(body) => return Ok(body),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("all OCSP responders failed")))
}

/// 业务作用：验证客户端证书 OCSP 响应的签名、issuer/CertID、nonce、good 状态与实时 freshness。
///
/// 参数说明：`response`、`nonce` 是同次请求证据；`leaf`、`issuer` 固定身份；`policy` 固定时间门。
///
/// 返回：证据只对应当前证书且仍有效时返回截止时刻；任何明确不可信状态均返回错误。
fn validate_client_ocsp_evidence(
    response: &[u8],
    nonce: &[u8],
    leaf: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
    policy: &ClientCertificateOcspRuntime,
) -> Result<chrono::DateTime<chrono::Utc>> {
    let signature_policy = tsp_ltv::crypto::verify::SignaturePolicy::strict();
    let freshness = tsp_ltv::ltv::OcspFreshness {
        clock_skew: chrono::Duration::seconds(i64::try_from(policy.clock_skew_seconds)?),
        max_age_without_next_update: chrono::Duration::seconds(i64::try_from(
            policy.max_age_without_next_update_seconds,
        )?),
    };
    let now = chrono::Utc::now();
    let outcome = tsp_ltv::ltv::ocsp_check_revocation_detailed(
        response,
        leaf,
        issuer,
        Some(nonce),
        Some(now),
        &signature_policy,
        &freshness,
    )
    .context("validate client certificate OCSP response")?;
    anyhow::ensure!(
        outcome.delegated_responder.is_none(),
        "client OCSP delegated responder requires its own revocation evidence"
    );
    anyhow::ensure!(
        outcome.status.is_valid(),
        "client certificate OCSP status is not good"
    );
    let parsed = tsp_ltv::ltv::parse_ocsp_response(response)
        .context("parse client certificate OCSP response window")?;
    let latest_allowed = now + freshness.clock_skew;
    anyhow::ensure!(
        parsed.produced_at <= latest_allowed,
        "client OCSP producedAt is beyond allowed clock skew"
    );
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .context("encode client OCSP issuer subject")?;
    let expected_name_hash = sha1::Sha1::digest(&issuer_name_der);
    let expected_key_hash = sha1::Sha1::digest(
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    );
    let serial =
        tsp_ltv::der_utils::parse_integer_body(leaf.tbs_certificate.serial_number.as_bytes());
    let matches = parsed
        .responses
        .iter()
        .filter(|single| {
            single.issuer_name_hash == expected_name_hash.as_slice()
                && single.issuer_key_hash == expected_key_hash.as_slice()
                && tsp_ltv::der_utils::integer_bodies_equal(&single.serial_number, &serial)
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        matches.len() == 1,
        "client OCSP response must contain exactly one matching status"
    );
    let single = matches[0];
    anyhow::ensure!(
        single.this_update <= latest_allowed,
        "client OCSP thisUpdate is beyond allowed clock skew"
    );
    anyhow::ensure!(
        parsed.produced_at + freshness.clock_skew >= single.this_update,
        "client OCSP producedAt precedes thisUpdate beyond allowed clock skew"
    );
    Ok(single.next_update.map_or_else(
        || single.this_update + freshness.max_age_without_next_update + freshness.clock_skew,
        |next_update| next_update + freshness.clock_skew,
    ))
}

/// 业务作用：识别叶证书 TLS Feature 扩展中的 status_request，落实 must-staple 不可降级语义。
///
/// 参数说明：`certificate` 是待发布的 DER 叶证书。
///
/// 返回：扩展合法时返回是否要求 OCSP staple；扩展 DER 畸形时拒绝证书身份。
fn certificate_requires_ocsp_staple(certificate: &CertificateDer<'_>) -> Result<bool> {
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|error| anyhow::anyhow!("parse TLS certificate extensions: {error}"))?;
    let Some(extension) = parsed
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.24")
    else {
        return Ok(false);
    };
    parse_tls_feature_status_request(extension.value)
}

/// 业务作用：以有界 DER 解析 TLS Feature 整数序列，拒绝畸形扩展绕过 must-staple 门禁。
///
/// 参数说明：`der` 是扩展 OCTET STRING 解包后的 DER SEQUENCE。
///
/// 返回：序列包含 status_request(5) 时为 true；长度、tag 或整数编码非法时返回错误。
fn parse_tls_feature_status_request(der: &[u8]) -> Result<bool> {
    let mut cursor = 0_usize;
    anyhow::ensure!(
        der.get(cursor) == Some(&0x30),
        "TLS Feature must be a DER SEQUENCE"
    );
    cursor += 1;
    let sequence_len = read_der_length(der, &mut cursor)?;
    anyhow::ensure!(
        cursor.checked_add(sequence_len) == Some(der.len()),
        "TLS Feature SEQUENCE length mismatch"
    );
    let end = der.len();
    let mut must_staple = false;
    while cursor < end {
        anyhow::ensure!(
            der.get(cursor) == Some(&0x02),
            "TLS Feature entry must be INTEGER"
        );
        cursor += 1;
        let integer_len = read_der_length(der, &mut cursor)?;
        anyhow::ensure!(
            (1..=4).contains(&integer_len) && cursor + integer_len <= end,
            "TLS Feature INTEGER length is invalid"
        );
        let bytes = &der[cursor..cursor + integer_len];
        anyhow::ensure!(
            bytes[0] & 0x80 == 0,
            "TLS Feature INTEGER must be non-negative"
        );
        anyhow::ensure!(
            integer_len == 1 || bytes[0] != 0 || bytes[1] & 0x80 != 0,
            "TLS Feature INTEGER is not minimally encoded"
        );
        let value = bytes
            .iter()
            .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
        must_staple |= value == 5;
        cursor += integer_len;
    }
    Ok(must_staple)
}

/// 业务作用：读取 DER definite length，限制长度字段规模并拒绝非最短编码。
///
/// 参数说明：`input` 是完整扩展；`cursor` 指向 length 首字节并在成功后前移。
///
/// 返回：返回经边界检查的内容长度；indefinite、超长或截断编码返回错误。
fn read_der_length(input: &[u8], cursor: &mut usize) -> Result<usize> {
    let first = *input.get(*cursor).context("DER length is truncated")?;
    *cursor += 1;
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let count = usize::from(first & 0x7f);
    anyhow::ensure!((1..=4).contains(&count), "DER length field is unsupported");
    anyhow::ensure!(
        *cursor + count <= input.len(),
        "DER length field is truncated"
    );
    anyhow::ensure!(input[*cursor] != 0, "DER length is not minimally encoded");
    let mut length = 0_usize;
    for byte in &input[*cursor..*cursor + count] {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .context("DER length overflows platform size")?;
    }
    *cursor += count;
    anyhow::ensure!(length >= 128, "DER long-form length is not minimal");
    Ok(length)
}

/// 按 ClientHello SNI 选证书的 resolver(§19):精确 server_name > `*.` 通配 > 默认证书兜底。
struct SniCertResolver {
    exact: HashMap<String, Arc<CertifiedIdentity>>,
    wildcards: Vec<(String, Arc<CertifiedIdentity>)>,
    default: Arc<CertifiedIdentity>,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCertResolver")
            .field("exact", &self.exact.keys().collect::<Vec<_>>())
            .field(
                "wildcards",
                &self.wildcards.iter().map(|(s, _)| s).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ResolvesServerCert for SniCertResolver {
    /// 业务作用：选择 SNI 身份并在返回前执行该身份的 OCSP 到期策略。
    ///
    /// 参数说明：`client_hello` 提供未经信任的 SNI；只用于已冻结映射查找。
    ///
    /// 返回：命中身份且 OCSP 策略允许新握手时返回证书；required 响应到期时返回空。
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        client_hello
            .server_name()
            .and_then(|sni| select_by_sni(&self.exact, &self.wildcards, sni))
            // 无 SNI 或不匹配任何配置证书时使用显式默认身份，不能借未知 SNI 绕开其 OCSP 门禁。
            .unwrap_or(&self.default)
            .resolve()
    }
}

/// SNI 选证的纯匹配逻辑(可单测):精确 server_name 优先,其次 `*.` 通配后缀;都不中返回 `None`(调用方兜底默认)。
fn select_by_sni<'a, T>(
    exact: &'a HashMap<String, T>,
    wildcards: &'a [(String, T)],
    sni: &str,
) -> Option<&'a T> {
    let sni = sni.to_ascii_lowercase();
    if let Some(value) = exact.get(&sni) {
        return Some(value);
    }
    wildcards
        .iter()
        .find(|(suffix, _)| sni.ends_with(suffix.as_str()))
        .map(|(_, value)| value)
}

fn load_certs_from(cert_file: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = crate::bounded_io::read_file(cert_file, TLS_PEM_MAX_BYTES, "TLS certificate")?;
    let mut reader = Cursor::new(bytes);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse tls cert {}", cert_file.display()))?;
    if certs.is_empty() {
        anyhow::bail!("tls cert {} has no certificates", cert_file.display());
    }
    Ok(certs)
}

/// 业务作用：解析有界内存 PEM 证书链，供 SDS 构建路径复用文件证书的同一 rustls 类型。
///
/// 参数说明：`bytes` 是已经过 xDS resource 大小门的 PEM；`label` 仅用于低敏错误定位。
///
/// 返回：至少一张合法证书时成功；空链或 PEM 语法错误时失败且不回显材料。
fn load_certs_from_bytes(bytes: &[u8], label: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = Cursor::new(bytes);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse {label}"))?;
    anyhow::ensure!(!certs.is_empty(), "{label} has no certificates");
    Ok(certs)
}

fn load_private_key_from(key_file: &Path) -> Result<PrivateKeyDer<'static>> {
    let bytes = crate::bounded_io::read_file(key_file, TLS_PEM_MAX_BYTES, "TLS private key")?;
    let mut reader = Cursor::new(bytes);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse tls key {}", key_file.display()))?
        .with_context(|| {
            format!(
                "tls key {} has no supported private key",
                key_file.display()
            )
        })
}

/// 业务作用：解析有界内存 PEM 私钥，避免 SDS 私钥为适配文件型 TLS 路径而落盘。
///
/// 参数说明：`bytes` 是已经过 xDS resource 大小门的 PEM；`label` 仅用于低敏错误定位。
///
/// 返回：包含一个 rustls 支持的私钥时成功；空值或不支持编码时失败且不回显材料。
fn load_private_key_from_bytes(bytes: &[u8], label: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = Cursor::new(bytes);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse {label}"))?
        .with_context(|| format!("{label} has no supported private key"))
}

/// 业务作用：复验 Kubernetes Gateway certificateRef 的 PEM 身份，防止把无法握手或
/// 证书与私钥不匹配的 Secret 标记为已就绪。
///
/// 参数说明：`certificate_chain` 与 `private_key` 是已经 Kubernetes 响应大小门限约束的
/// PEM 字节；调用方不得将它们加入日志或 status。
///
/// 返回：证书链可解析、私钥可解析且二者匹配时成功；任一条件不满足时返回
/// 不含密钥材料的低敏错误。
pub(crate) fn validate_server_identity_bytes(
    certificate_chain: &[u8],
    private_key: &[u8],
) -> Result<()> {
    let certs = load_certs_from_bytes(certificate_chain, "Gateway certificate chain")?;
    let key = load_private_key_from_bytes(private_key, "Gateway private key")?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("validate Gateway TLS certificate identity")?;
    Ok(())
}
