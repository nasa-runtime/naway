//! 证书材料安装与条件写入共用唯一事务门；签发来源不决定文件发布语义。

pub(crate) mod conditions;
mod generation;
mod io;
mod legacy;
mod manifest;
mod preflight;
mod source;
mod validation;

use crate::config::TlsRuntimeCfg;
use anyhow::Result;
pub(crate) use generation::valid_token as valid_material_generation;
pub(crate) use io::atomic_write;
use io::sync_directory;
use legacy::{install_legacy_keypair_transaction, recover_legacy_keypair_transaction_locked};
pub(crate) use manifest::current_material_directory;
use manifest::{gc_keypair_versions, prepare_keypair_version};
pub(crate) use validation::validate_keypair;

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
    validate_installation(tls, certificate_pem, private_key_pem, None)?;
    generation::current(tls, certificate_pem, None)?;
    publish_keypair_locked(tls, certificate_pem, private_key_pem).map(|_| ())
}

/// 手工证书 CAS 安装结果。
pub(crate) enum KeypairCasInstallOutcome {
    /// 比较基线仍一致，完整 pair 已发布。
    Installed(String),
    /// 安装前证书已变化，未开始该候选的文件决定。
    Changed(String),
    /// 完整材料已不属于所给代；不因证书摘要重新相同而恢复旧写入资格。
    GenerationChanged,
    /// 材料或当前 OCSP 策略不允许安装，未开始该候选的文件决定。
    Invalid,
    /// 不能取得安装权或读取当前基线，未开始该候选的文件决定。
    Unavailable,
    /// 恢复或文件决定已经开始但未取得明确完成证据，必须重新读取事实。
    OutcomeUnknown,
}

/// 业务作用：在与 ACME 续期共享的进程锁内复验证书摘要并安装完整 pair，防止 Console 覆盖刚完成
/// 的自动续期。
///
/// 参数说明：
/// - `tls`：固定当前证书事实源的 TLS 策略。
/// - `expected_etag`：从证书读取接口取得的 CAS 基线 ETag。
/// - `expected_generation`：可选受管材料代，指定后还须证明完整 pair 仍属于该代。
/// - `certificate_pem`：有界上传的完整证书 PEM。
/// - `private_key_pem`：有界上传的完整私钥 PEM。
/// - `snapshot`：持有配置发布权时的完整监听计划；提供后同时预检所有共享来源。
///
/// 返回：基线及身份有效且文件提交完成时为 Installed；摘要变化携带当前 ETag；其它结果区分
/// 候选无效、存储不可用与提交未知，不附带材料或底层文件路径。
pub(crate) fn install_keypair_atomically_if_match(
    tls: &TlsRuntimeCfg,
    expected_etag: &str,
    expected_generation: Option<&str>,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    snapshot: Option<&crate::config::GatewaySnapshot>,
) -> KeypairCasInstallOutcome {
    let Ok(_guard) = keypair_install_lock().lock() else {
        return KeypairCasInstallOutcome::Unavailable;
    };
    // 旧事务恢复可能已经改变文件；没有明确结算证据时不能声称该请求毫无副作用。
    if recover_legacy_keypair_transaction_locked(tls).is_err() {
        return KeypairCasInstallOutcome::OutcomeUnknown;
    }
    let baseline = crate::tls::active_keypair_paths_unrecovered(tls).and_then(|(path, _)| {
        crate::io::bounded_io::read_file(&path, MAX_KEYPAIR_BYTES, "TLS certificate CAS baseline")
    });
    let Ok(current) = baseline else {
        return KeypairCasInstallOutcome::Unavailable;
    };
    let current_etag = certificate_etag(&current);
    if expected_etag.trim() != current_etag {
        return KeypairCasInstallOutcome::Changed(current_etag);
    }
    let current_generation = if expected_generation.is_some() {
        // 材料代与完整 pair 在同一锁内复验；A→B→A 或私钥单独改变不能复活旧动作的所有权。
        crate::tls::active_keypair_paths_unrecovered(tls).and_then(|(_, key)| {
            let private_key = crate::io::bounded_io::read_file(
                &key,
                MAX_KEYPAIR_BYTES,
                "TLS material ownership private key",
            )?;
            generation::current(tls, &current, Some(&private_key))
        })
    } else {
        generation::current(tls, &current, None)
    };
    let Ok(current_generation) = current_generation else {
        return KeypairCasInstallOutcome::Unavailable;
    };
    if let Some(expected) = expected_generation {
        if !valid_material_generation(expected) || current_generation.as_deref() != Some(expected) {
            return KeypairCasInstallOutcome::GenerationChanged;
        }
    }
    // 候选身份与当前 staple 必须在任何准备写入之前自洽，不能先破坏磁盘材料再依赖 listener 的 LKG。
    if validate_installation(tls, certificate_pem, private_key_pem, snapshot).is_err() {
        return KeypairCasInstallOutcome::Invalid;
    }
    match publish_keypair_locked(tls, certificate_pem, private_key_pem) {
        Ok(generation) => KeypairCasInstallOutcome::Installed(generation),
        // rename 或 fsync 的失败不证明提交未发生；调用者只能回读原目标，不能无条件重放。
        Err(_) => KeypairCasInstallOutcome::OutcomeUnknown,
    }
}

/// 业务作用：为本机材料读面提供已记录的随机代，读取不创建或收养外部材料所有权。
///
/// 参数说明：
/// - `tls`：当前默认或 SNI 文件身份来源。
/// - `certificate`：本次已读取的公开证书原文，仍须与归属记录一致。
///
/// 返回：受管代、未受管空值或不可证明错误；普通投影不读取私钥，旧 journal 的必要恢复仍核对完整 pair。
pub(crate) fn material_generation(
    tls: &TlsRuntimeCfg,
    certificate: &[u8],
) -> Result<Option<String>> {
    let _guard = keypair_install_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("TLS keypair install lock is poisoned"))?;
    recover_legacy_keypair_transaction_locked(tls)?;
    generation::current(tls, certificate, None)
}

/// 业务作用：把材料目标绑定到审批摘要，不能把同一 pair 的批准令牌用于另一来源计划。
///
/// 参数说明：
/// - `tls`：审批记录冻结的材料来源。
///
/// 返回：不含可逆文件路径的目标摘要，不触发磁盘读取或秘密解析。
pub(crate) fn material_target_fingerprint(tls: &TlsRuntimeCfg) -> [u8; 32] {
    generation::declared_target(tls)
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

/// 业务作用：在材料写入前复验所选身份及可选共享监听策略，复用实际握手加载的校验门。
///
/// 参数说明：
/// - `tls`：当前所选身份的来源和专属 OCSP 策略。
/// - `certificate_pem`：待安装的有界完整证书链。
/// - `private_key_pem`：待安装的有界私钥。
/// - `snapshot`：可选的完整已发布监听计划，由外层配置发布权冻结。
///
/// 返回：本地文件身份满足密钥匹配和 OCSP 约束时成功；失败不创建材料目录或切换文件。
fn validate_installation(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    snapshot: Option<&crate::config::GatewaySnapshot>,
) -> Result<()> {
    anyhow::ensure!(
        tls.in_memory.is_none() && tls.spire.is_none() && tls.private_key_provider.is_none(),
        "TLS identity is owned by an external source"
    );
    anyhow::ensure!(
        certificate_pem.len() <= MAX_KEYPAIR_BYTES && private_key_pem.len() <= MAX_KEYPAIR_BYTES,
        "TLS keypair material exceeds installation budget"
    );
    let certified = validate_keypair(certificate_pem, private_key_pem)?;
    if let Some(snapshot) = snapshot {
        preflight::validate(snapshot, tls, &certified)?;
    } else {
        crate::tls::identity::apply_ocsp_policy(certified, tls.ocsp_stapling.as_ref())?;
    }
    Ok(())
}

/// 业务作用：在调用方持有证书安装锁且完成身份验证后发布 pair，集中维护 manifest 与兼容文件模式语义。
///
/// 参数说明：
/// - `tls`：固定安装事实源的 TLS 策略。
/// - `certificate_pem`：已通过当前身份策略校验的完整证书 PEM。
/// - `private_key_pem`：与已验证证书匹配的完整私钥 PEM。
///
/// 返回：事实源完整切换时返回新材料代；任一步 I/O 失败时返回错误，调用者不能据此推断未提交。
fn publish_keypair_locked(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<String> {
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
        Ok(prepared.generation)
    } else {
        install_legacy_keypair_transaction(tls, certificate_pem, private_key_pem)
    }
}
