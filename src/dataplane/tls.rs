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
use hyper_rustls::ConfigBuilderExt;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::config::{ClientAuthRuntime, TlsRuntimeCfg};

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

/// 构建 HTTP 上游 TLS profile(§36 `proxy_ssl_*`)。
///
/// # 参数
/// - `server_name`: 可选 SNI/证书校验名覆盖(`proxy_ssl_name`)。
/// - `ca_file`: 可选自定义上游 CA;为空使用系统根证书。
/// - `client_cert_file`/`client_key_file`: 上游 mTLS 客户端证书与私钥,必须成对出现。
pub fn build_upstream_tls_profile(
    server_name: Option<&str>,
    ca_file: Option<&Path>,
    client_cert_file: Option<&Path>,
    client_key_file: Option<&Path>,
) -> Result<UpstreamTlsProfile> {
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

    let roots = match ca_file {
        Some(path) => {
            path.hash(&mut key_hasher);
            hash_file_contents(path, &mut key_hasher)?;
            Some(root_store_from_ca_file(path)?)
        }
        None => {
            "native-roots".hash(&mut key_hasher);
            None
        }
    };

    let builder = match roots {
        Some(roots) => ClientConfig::builder().with_root_certificates(roots),
        None => ClientConfig::builder()
            .with_native_roots()
            .context("load native TLS roots for upstream")?,
    };

    let client_config = match (client_cert_file, client_key_file) {
        (None, None) => builder.with_no_client_auth(),
        (Some(cert), Some(key)) => {
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
        _ => anyhow::bail!(
            "upstream tls client_cert_file and client_key_file must be configured together"
        ),
    };

    Ok(UpstreamTlsProfile {
        key: Arc::from(format!("tls-{:016x}", key_hasher.finish())),
        server_name: server_name.map(Arc::from),
        client_config: Arc::new(client_config),
    })
}

/// 用 PEM CA 文件构造 RootCertStore。任一证书非法即坏配置拒上线。
fn root_store_from_ca_file(ca_file: &Path) -> Result<RootCertStore> {
    let certs = load_certs_from(ca_file)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .with_context(|| format!("add upstream CA cert from {}", ca_file.display()))?;
    }
    Ok(roots)
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
                    Ok(cfg) => {
                        shared.store(cfg);
                        tracing::info!("tls certificate reloaded (hot swap)");
                    }
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
        // 持有 watcher 直到进程退出(drop 即停止监听)。
        let _keep_alive = watcher;
        std::future::pending::<()>().await;
    });
}

/// 从 `TlsRuntimeCfg` 构建一份 `ServerConfig`(ALPN 广告 h2 + http/1.1)。启动期与证书热换时各调用一次。
///
/// - 无 SNI 证书(`certs` 空):走 `with_single_cert`,保留 rustls 的 key↔cert 匹配校验(常见单域名)。
/// - 有 SNI 证书(§19):装一个 `SniCertResolver`,按 ClientHello 的 server_name 选证,默认证书兜底。
pub fn build_server_config(tls: &TlsRuntimeCfg) -> Result<Arc<ServerConfig>> {
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

/// 从 CA PEM 构建客户端证书 verifier(§19)。require → 无合法客户端证书即拒绝握手;optional → 未出示也放行。
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
    Ok(verifier)
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

#[path = "../../tests/unit/tls.rs"]
#[cfg(test)]
mod tests;
