//! 兼容双文件材料的持久决定与崩溃恢复，部分写入不能成为完整身份。

use super::{atomic_write, sync_directory, validate_keypair, MAX_KEYPAIR_BYTES};
use crate::config::TlsRuntimeCfg;
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// 业务作用：以持久 journal 发布旧式 cert/key 双文件，并在任一步失败时恢复安装前事实。
///
/// 参数说明：
/// - `tls`：固定证书与私钥目标路径的 TLS 策略。
/// - `certificate_pem`：已经完成密钥对密码学校验的证书 PEM。
/// - `private_key_pem`：已经完成密钥对密码学校验的私钥 PEM。
///
/// 返回：两个目标均成为新代且 journal 已结算时成功；失败时先恢复旧代再返回原错误。
pub(super) fn install_legacy_keypair_transaction(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<()> {
    recover_legacy_keypair_transaction_locked(tls)?;
    let transaction = legacy_keypair_transaction_dir(tls)?;
    let parent = transaction
        .parent()
        .context("legacy keypair transaction has no parent")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "create legacy keypair transaction parent {}",
            parent.display()
        )
    })?;
    let mut random = [0_u8; 8];
    getrandom::getrandom(&mut random).context("generate legacy keypair transaction suffix")?;
    let temporary = parent.join(format!(
        ".naway-keypair-prepare-{:016x}",
        u64::from_le_bytes(random)
    ));
    fs::create_dir(&temporary)
        .with_context(|| format!("create legacy keypair transaction {}", temporary.display()))?;
    let prepared = (|| -> Result<()> {
        let old_cert = crate::io::bounded_io::read_optional_file(
            &tls.cert_file,
            MAX_KEYPAIR_BYTES,
            "legacy TLS certificate backup",
        )?;
        let old_key = crate::io::bounded_io::read_optional_file(
            &tls.key_file,
            MAX_KEYPAIR_BYTES,
            "legacy TLS private key backup",
        )?;
        if let Some(bytes) = &old_cert {
            atomic_write(&temporary.join("old-cert.pem"), bytes, false)?;
        }
        if let Some(bytes) = &old_key {
            atomic_write(&temporary.join("old-key.pem"), bytes, true)?;
        }
        atomic_write(&temporary.join("new-cert.pem"), certificate_pem, false)?;
        atomic_write(&temporary.join("new-key.pem"), private_key_pem, true)?;
        atomic_write(
            &temporary.join("state.json"),
            &serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "old_cert_present": old_cert.is_some(),
                "old_key_present": old_key.is_some(),
            }))?,
            false,
        )?;
        sync_directory(&temporary)?;
        fs::rename(&temporary, &transaction).with_context(|| {
            format!(
                "publish legacy keypair transaction {}",
                transaction.display()
            )
        })?;
        sync_directory(parent)
    })();
    if let Err(error) = prepared {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }

    let publish = (|| -> Result<()> {
        // journal 已经持久化，两个 rename 之间即使崩溃也能在下一次读取前恢复旧代或确认新代。
        atomic_write(&tls.key_file, private_key_pem, true)?;
        atomic_write(&tls.cert_file, certificate_pem, false)?;
        Ok(())
    })();
    if let Err(error) = publish {
        recover_legacy_keypair_transaction_locked(tls)
            .context("restore legacy TLS pair after failed publish")?;
        return Err(error);
    }
    finish_legacy_keypair_transaction(&transaction)?;
    Ok(())
}

/// 业务作用：检查旧式 pair journal；完整新代已落盘则提交，否则按备份恢复安装前状态。
///
/// 参数说明：
/// - `tls`：固定 journal 身份和两个目标；调用方持有全局安装锁。
///
/// 返回：journal 不存在、确认提交或恢复完成时成功；任何不可信 journal/材料拒绝继续读取。
pub(super) fn recover_legacy_keypair_transaction_locked(tls: &TlsRuntimeCfg) -> Result<()> {
    if tls.keypair_manifest_file.is_some() {
        return Ok(());
    }
    let transaction = legacy_keypair_transaction_dir(tls)?;
    let metadata = match fs::symlink_metadata(&transaction) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("stat legacy keypair transaction"),
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "legacy keypair transaction path is not a directory"
    );
    let state_bytes = crate::io::bounded_io::read_file(
        &transaction.join("state.json"),
        64 * 1024,
        "legacy keypair transaction state",
    )?;
    let state: serde_json::Value =
        serde_json::from_slice(&state_bytes).context("parse legacy keypair transaction state")?;
    anyhow::ensure!(
        state
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            == Some(1),
        "legacy keypair transaction schema is invalid"
    );
    let old_cert_present = state
        .get("old_cert_present")
        .and_then(serde_json::Value::as_bool)
        .context("legacy keypair transaction old_cert_present is missing")?;
    let old_key_present = state
        .get("old_key_present")
        .and_then(serde_json::Value::as_bool)
        .context("legacy keypair transaction old_key_present is missing")?;
    let new_cert = crate::io::bounded_io::read_file(
        &transaction.join("new-cert.pem"),
        MAX_KEYPAIR_BYTES,
        "legacy keypair transaction new certificate",
    )?;
    let new_key = crate::io::bounded_io::read_file(
        &transaction.join("new-key.pem"),
        MAX_KEYPAIR_BYTES,
        "legacy keypair transaction new key",
    )?;
    validate_keypair(&new_cert, &new_key)?;
    let live_cert = crate::io::bounded_io::read_optional_file(
        &tls.cert_file,
        MAX_KEYPAIR_BYTES,
        "legacy TLS live certificate",
    )?;
    let live_key = crate::io::bounded_io::read_optional_file(
        &tls.key_file,
        MAX_KEYPAIR_BYTES,
        "legacy TLS live key",
    )?;
    if live_cert.as_deref() == Some(new_cert.as_slice())
        && live_key.as_deref() == Some(new_key.as_slice())
    {
        return finish_legacy_keypair_transaction(&transaction);
    }

    // 新代不完整就先恢复 secret key、再恢复证书；loader 持有同一安装锁，恢复期间不能发布中间态。
    restore_legacy_file(
        &tls.key_file,
        &transaction.join("old-key.pem"),
        old_key_present,
        true,
    )?;
    restore_legacy_file(
        &tls.cert_file,
        &transaction.join("old-cert.pem"),
        old_cert_present,
        false,
    )?;
    finish_legacy_keypair_transaction(&transaction)
}

/// 业务作用：在证书安装事务未完成时恢复单个旧文件，避免遗留新旧不配对的证书材料。
fn restore_legacy_file(target: &Path, backup: &Path, present: bool, secret: bool) -> Result<()> {
    if present {
        let bytes = crate::io::bounded_io::read_file(
            backup,
            MAX_KEYPAIR_BYTES,
            "legacy keypair transaction backup",
        )?;
        atomic_write(target, &bytes, secret)
    } else {
        match fs::remove_file(target) {
            Ok(()) => sync_directory(target.parent().unwrap_or_else(|| Path::new("."))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("remove partial TLS file {}", target.display()))
            }
        }
    }
}

/// 业务作用：为固定证书路径定位配对安装事务目录，恢复记录不能跨目标复用。
fn legacy_keypair_transaction_dir(tls: &TlsRuntimeCfg) -> Result<PathBuf> {
    use sha2::Digest as _;
    anyhow::ensure!(
        tls.cert_file != tls.key_file,
        "TLS cert_file and key_file must differ"
    );
    let parent = tls
        .cert_file
        .parent()
        .context("TLS cert_file has no parent")?;
    let mut digest = sha2::Sha256::new();
    digest.update(tls.cert_file.as_os_str().as_encoded_bytes());
    digest.update([0]);
    digest.update(tls.key_file.as_os_str().as_encoded_bytes());
    let encoded = digest.finalize();
    let mut suffix = String::with_capacity(24);
    use std::fmt::Write as _;
    for byte in &encoded[..12] {
        write!(&mut suffix, "{byte:02x}").expect("writing digest to String cannot fail");
    }
    Ok(parent.join(format!(".naway-keypair-transaction-{suffix}")))
}

/// 业务作用：完成或恢复证书配对事务，并在一致性确认后清理对应事务状态。
fn finish_legacy_keypair_transaction(transaction: &Path) -> Result<()> {
    fs::remove_dir_all(transaction).with_context(|| {
        format!(
            "remove legacy keypair transaction {}",
            transaction.display()
        )
    })?;
    sync_directory(transaction.parent().unwrap_or_else(|| Path::new(".")))
}
