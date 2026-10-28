//! 管理端传输身份和可导出密钥的受限文件读取。

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// 管理端 TLS 信任链和证书内容摘要；不存在明文监听配置。
pub(crate) struct TransportIdentity {
    pub config: Arc<tokio_rustls::rustls::ServerConfig>,
    pub digest: [u8; 32],
}

/// 业务作用：把管理端信任与私钥冻结进候选，保证握手不读取未发布文件内容。
///
/// 参数说明：
/// - `cfg`：三份显式 PEM 路径。
/// - `root`：已经确定的主配置根。
///
/// 返回：CA、证书和密钥一致时返回强制 mTLS 的 h2 配置；任何读取或密码学校验失败拒绝候选。
pub(crate) fn transport(
    cfg: &crate::config::xds_server::TlsCfg,
    root: &Path,
) -> Result<TransportIdentity> {
    let ca = pem(root, &cfg.ca_file)?;
    let cert = pem(root, &cfg.cert_file)?;
    let key = pem(root, &cfg.key_file)?;
    let mut hash = Sha256::new();
    for content in [&ca, &cert, &key] {
        hash.update((content.len() as u64).to_be_bytes());
        hash.update(content);
    }
    let material = crate::config::InMemoryTlsMaterial {
        certificate_chain: cert.into(),
        private_key: key.into(),
        client_ca: Some(ca.into()),
        require_client_certificate: true,
    };
    let mut config = crate::tls::build_in_memory_server_config(&material)?
        .as_ref()
        .clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TransportIdentity {
        config: Arc::new(config),
        digest: hash.finalize().into(),
    })
}

/// 业务作用：在配置根能力范围内读取有界 PEM，防止密钥下发借绝对路径或最终符号链接扩权。
///
/// 参数说明：
/// - `root`：允许读取的主配置目录。
/// - `raw`：相对于根的文件名。
///
/// 返回：最多 256KiB 的普通文件内容；越根、非普通文件或超限均失败且不回显内容。
pub(crate) fn pem(root: &Path, raw: &str) -> Result<Vec<u8>> {
    ensure!(
        !raw.is_empty() && raw.len() <= 1024,
        "xDS PEM path is missing or oversized"
    );
    let root = root
        .canonicalize()
        .context("resolve xDS configuration root")?;
    let path = root
        .join(raw)
        .canonicalize()
        .context("resolve xDS PEM file")?;
    ensure!(
        path.starts_with(&root),
        "xDS PEM file escapes configuration root"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    // 先锁定文件句柄再检查类型和长度，规范路径被换为链接或 FIFO 时不能读入其它权威的内容。
    let file = options.open(&path).context("open xDS PEM file")?;
    crate::io::bounded_io::read_open_file(file, &path, 256 * 1024, "xDS PEM")
}

/// 业务作用：把已通过 mTLS 验签的叶证书绑定到静态 node 授权，不采信请求里的自报身份。
///
/// 参数说明：
/// - `der`：TLS 会话提供的完整叶证书 DER。
///
/// 返回：用于精确比较的 SHA-256 小写十六进制摘要。
pub(crate) fn certificate_digest(der: &[u8]) -> String {
    format!("{:x}", Sha256::digest(der))
}

/// 业务作用：限制资源命名片段，避免节点授权前缀被分隔符或过长标识绕过。
///
/// 参数说明：
/// - `name`：node、workspace、proxy 或 route 的单一标识。
///
/// 返回：非空、最多 128 字节且仅包含 ASCII 字母数字和点横线下划线时成功。
pub(crate) fn identifier(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "xDS projection identifier is invalid"
    );
    Ok(())
}

/// 业务作用：将管理端传输材料加入同一配置观察和指纹集合，轮换不得独立于快照发布。
///
/// 参数说明：
/// - `cfg`：可选管理端配置。
/// - `root`：主配置目录。
///
/// 返回：未开启时为空；开启时返回三份确定的 PEM 路径，不读取内容。
pub(crate) fn dependencies(
    cfg: Option<&crate::config::xds_server::ServerCfg>,
    root: &Path,
) -> Vec<PathBuf> {
    cfg.map(|c| {
        [&c.tls.ca_file, &c.tls.cert_file, &c.tls.key_file]
            .into_iter()
            .map(|p| root.join(p))
            .collect()
    })
    .unwrap_or_default()
}
