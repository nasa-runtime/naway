//! 证书材料安装与条件写入共用唯一事务门；签发来源不决定文件发布语义。

mod io;
mod legacy;
mod manifest;
mod validation;

use crate::config::TlsRuntimeCfg;
use anyhow::Result;
pub(crate) use io::atomic_write;
use io::sync_directory;
use legacy::{install_legacy_keypair_transaction, recover_legacy_keypair_transaction_locked};
use manifest::{gc_keypair_versions, prepare_keypair_version};
use validation::validate_keypair;

const MAX_KEYPAIR_BYTES: usize = 4 * 1024 * 1024;

/// 业务作用：串行化 ACME/自动续期的证书安装，避免同一进程内两个完整 pair 交错发布。
///
/// 参数说明：
/// - `tls`：定位事实源
/// - `certificate_pem`：是完整证书链
/// - `private_key_pem`：是匹配私钥。
///
/// 返回：pair 通过密码学校验并完整发布时成功；锁、校验或 I/O 失败时返回错误且不得宣告换版。
pub(crate) fn install_keypair_atomically(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<()> {
    let _guard = keypair_install_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("TLS keypair install lock is poisoned"))?;
    recover_legacy_keypair_transaction_locked(tls)?;
    install_keypair_atomically_locked(tls, certificate_pem, private_key_pem)
}

/// 手工证书 CAS 安装结果。
pub(crate) enum KeypairCasInstallOutcome {
    /// 比较基线仍一致，完整 pair 已发布。
    Installed,
    /// 安装前证书已变化，未写入任何文件。
    Changed(String),
}

/// 业务作用：在与 ACME 续期共享的进程锁内复验证书摘要并安装完整 pair，防止 Console 覆盖刚完成
/// 的自动续期。
///
/// 参数说明：
/// - `tls`：固定当前证书事实源的 TLS 策略。
/// - `expected_etag`：从证书读取接口取得的 CAS 基线 ETag。
/// - `certificate_pem`：有界上传的完整证书 PEM。
/// - `private_key_pem`：有界上传的完整私钥 PEM。
///
/// 返回：基线一致且 pair 合法时返回 Installed；摘要变化返回当前 ETag 且无副作用；读取、校验或落盘
/// 失败返回错误。
pub(crate) fn install_keypair_atomically_if_match(
    tls: &TlsRuntimeCfg,
    expected_etag: &str,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<KeypairCasInstallOutcome> {
    let _guard = keypair_install_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("TLS keypair install lock is poisoned"))?;
    recover_legacy_keypair_transaction_locked(tls)?;
    let (certificate_path, _) = crate::tls::active_keypair_paths_unrecovered(tls)?;
    let current = crate::io::bounded_io::read_file(
        &certificate_path,
        MAX_KEYPAIR_BYTES,
        "TLS certificate CAS baseline",
    )?;
    let current_etag = certificate_etag(&current);
    if expected_etag.trim() != current_etag {
        return Ok(KeypairCasInstallOutcome::Changed(current_etag));
    }
    install_keypair_atomically_locked(tls, certificate_pem, private_key_pem)?;
    Ok(KeypairCasInstallOutcome::Installed)
}

/// 业务作用：返回 ACME 与手工轮换共享的证书安装互斥锁，保证比较和 manifest/pair 发布不交错。
///
/// 参数说明: 无。
///
/// 返回：返回进程生命周期内唯一互斥锁。
fn keypair_install_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// 业务作用：在任何旧双文件 pair 读取前完成上次崩溃事务恢复，使 loader 只能看到恢复后的完整代。
///
/// 参数说明：
/// - `tls`：固定 cert/key 目标；manifest 模式没有双文件事务，直接成功。
///
/// 返回：无待恢复事务或已恢复/确认提交时成功；journal 损坏或 I/O 失败时拒绝加载证书。
pub(crate) fn recover_legacy_keypair_transaction(tls: &TlsRuntimeCfg) -> Result<()> {
    if tls.keypair_manifest_file.is_some() {
        return Ok(());
    }
    let _guard = keypair_install_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("TLS keypair install lock is poisoned"))?;
    recover_legacy_keypair_transaction_locked(tls)
}

/// 业务作用：为证书原始字节生成强 ETag，供读接口与手工轮换 CAS 使用同一比较语义。
///
/// 参数说明：
/// - `certificate_pem`：是有界读取或上传的完整证书链字节。
///
/// 返回：返回带引号的 `sha256-<hex>` 强 ETag。
pub(crate) fn certificate_etag(certificate_pem: &[u8]) -> String {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(certificate_pem);
    let mut encoded = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing SHA-256 hex to String cannot fail");
    }
    format!("\"sha256-{encoded}\"")
}

/// 业务作用：在调用方已持有证书安装锁时校验并发布 pair，集中维护 manifest 与兼容文件模式语义。
///
/// 参数说明：
/// - `tls`：固定安装事实源的 TLS 策略。
/// - `certificate_pem`：待校验和安装的完整证书 PEM。
/// - `private_key_pem`：待校验和安装的完整私钥 PEM。
///
/// 返回：pair 合法且事实源完整切换时成功；校验或任一步 I/O 失败时返回错误。
fn install_keypair_atomically_locked(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<()> {
    validate_keypair(certificate_pem, private_key_pem)?;
    if let Some(manifest_file) = &tls.keypair_manifest_file {
        let prepared = prepare_keypair_version(manifest_file, certificate_pem, private_key_pem)?;
        atomic_write(manifest_file, &prepared.manifest, false)?;
        tracing::info!(
            directory = %prepared.directory.display(),
            manifest = %manifest_file.display(),
            "activated immutable TLS keypair version"
        );
        let retention = tls
            .acme
            .as_ref()
            .map(|acme| acme.keypair_retention_generations)
            .unwrap_or(3);
        if let Err(error) = gc_keypair_versions(manifest_file, retention) {
            // 当前 manifest 已持久化；回收失败只留下额外历史，不能谎称激活失败并诱发重复签发。
            tracing::warn!(error = %format!("{error:#}"), "TLS keypair history cleanup failed");
        }
    } else {
        install_legacy_keypair_transaction(tls, certificate_pem, private_key_pem)?;
    }
    Ok(())
}
