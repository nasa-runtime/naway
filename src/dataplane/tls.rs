//! TLS 监听配置加载 + 证书热换。
//!
//! ★据 review:证书**只在启动期与文件变更时**加载一次到 `ArcSwap<ServerConfig>`,accept 循环只做
//! 廉价的 `Arc` clone(不再每条 TLS 连接开盘读证书 + 解析——那既阻塞异步 accept 线程,又是 DoS 放大面)。
//! 证书文件内容变更由 notify watcher 捕获并重建(热换证不断连,§7.5/§19)。

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
};

use crate::config::{ClientAuthRuntime, InMemoryTlsMaterial, TlsRuntimeCfg};

const KEYPAIR_MANIFEST_MAX_BYTES: usize = 64 * 1024;
/// 单个证书链、私钥或 CA PEM 的控制面硬上限。PEM 只在启动/reload 读取，但仍必须防止
/// 错挂载的大文件在配置构建期造成 OOM；4 MiB 足以容纳远超常规规模的证书链。
const TLS_PEM_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeypairManifest {
    schema_version: u32,
    directory: String,
}

/// 进程内共享的 TLS 服务端配置:启动期构建一次,证书文件变更时原子换新。
pub type SharedServerConfig = Arc<ArcSwap<ServerConfig>>;

/// HTTP 上游 TLS profile(§36 `proxy_ssl_*`):已在配置构建期解析并校验证书材料。
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
}

struct SubjectAltNameVerifier {
    signature_verifier: Arc<WebPkiServerVerifier>,
    roots: Arc<RootCertStore>,
    dns_names: Vec<String>,
    uris: Vec<String>,
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

    let client_config = match (
        client_cert_file,
        client_key_file,
        client_cert_pem,
        client_key_pem,
    ) {
        (None, None, None, None) => builder.with_no_client_auth(),
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

    Ok(UpstreamTlsProfile {
        key: Arc::from(format!("tls-{:016x}", key_hasher.finish())),
        server_name: server_name.map(Arc::from),
        client_config: Arc::new(client_config),
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
    if tls.keypair_manifest_file.is_none() {
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
    // 去重 cert/key 的父目录(常同目录);notify 监听目录而非文件,兼容编辑器「写临时文件+rename」。
    // 默认证书 + 所有 SNI 证书(§19)的目录都要监听,任一证书文件变更都热换整份 ServerConfig。
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = vec![tls.cert_file.clone(), tls.key_file.clone()];
    if let Some(manifest) = &tls.keypair_manifest_file {
        files.push(manifest.clone());
    }
    for cert in &tls.certs {
        files.push(cert.cert_file.clone());
        files.push(cert.key_file.clone());
    }
    if let Some(ca) = &tls.client_auth {
        files.push(ca.ca_file.clone()); // mTLS CA 变更也热换(§19)
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
                match build_server_config(&tls) {
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
    // mTLS(§19):配了 client_auth 就装客户端证书 verifier(require 拒无证书握手,optional 放行未出示的);否则不校验。
    let builder = ServerConfig::builder();
    let builder = match &tls.client_auth {
        Some(ca) => builder.with_client_cert_verifier(build_client_verifier(ca)?),
        None => builder.with_no_client_auth(),
    };
    let (default_cert_file, default_key_file) = active_keypair_paths(tls)?;
    let mut cfg = if tls.certs.is_empty() {
        let certs = load_certs_from(&default_cert_file)?;
        let key = load_private_key_from(&default_key_file)?;
        builder.with_single_cert(certs, key).with_context(|| {
            format!(
                "build tls config cert={} key={}",
                default_cert_file.display(),
                default_key_file.display()
            )
        })?
    } else {
        builder.with_cert_resolver(Arc::new(build_sni_resolver(tls)?))
    };
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
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
    let builder = WebPkiClientVerifier::builder(Arc::new(roots));
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

/// 从默认证书 + `certs[]` 构建 SNI resolver(§19)。任一证书/私钥读不了即整体失败(坏证书不上线)。
fn build_sni_resolver(tls: &TlsRuntimeCfg) -> Result<SniCertResolver> {
    let (default_cert_file, default_key_file) = active_keypair_paths(tls)?;
    let default = certified_key(&default_cert_file, &default_key_file)
        .context("build default tls certificate")?;
    let mut exact: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut wildcards: Vec<(String, Arc<CertifiedKey>)> = Vec::new();
    for cert in &tls.certs {
        let key = certified_key(&cert.cert_file, &cert.key_file)
            .with_context(|| format!("build sni tls certificate for {:?}", cert.server_names))?;
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
        default,
    })
}

/// 从 cert/key PEM 文件构建一个 rustls `CertifiedKey`(证书链 + 签名私钥),供 SNI resolver 装载。
fn certified_key(cert_file: &Path, key_file: &Path) -> Result<Arc<CertifiedKey>> {
    let certs = load_certs_from(cert_file)?;
    let key = load_private_key_from(key_file)?;
    // 用进程默认 crypto provider(aws-lc-rs)把私钥变成签名 key;与 ServerConfig::builder() 同一 provider。
    let signing_key = tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .with_context(|| format!("load signing key from {}", key_file.display()))?;
    let certified = CertifiedKey::new(certs, signing_key);
    // 校验 cert↔key 匹配(与 with_single_cert 的隐式校验对齐)。WHY:legacy 双 rename 续期(先写 key
    // 再写 cert)存在「新 key + 旧 cert」的短暂窗口,若 watcher 在此刻重建 SNI resolver,不校验就会装上
    // 不匹配的默认证书,导致握手签名失败直到下一次事件自愈。装载前拒绝不匹配 pair,保留旧配置更安全。
    certified.keys_match().with_context(|| {
        format!(
            "tls cert {} and key {} do not match",
            cert_file.display(),
            key_file.display()
        )
    })?;
    Ok(Arc::new(certified))
}

/// 按 ClientHello SNI 选证书的 resolver(§19):精确 server_name > `*.` 通配 > 默认证书兜底。
struct SniCertResolver {
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcards: Vec<(String, Arc<CertifiedKey>)>,
    default: Arc<CertifiedKey>,
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
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        client_hello
            .server_name()
            .and_then(|sni| select_by_sni(&self.exact, &self.wildcards, sni))
            .cloned()
            // 无 SNI 或不匹配任何配置证书 → 默认证书兜底(对齐 nginx default_server 的证书)。
            .or_else(|| Some(self.default.clone()))
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

#[path = "../../tests/unit/tls.rs"]
#[cfg(test)]
mod tests;
