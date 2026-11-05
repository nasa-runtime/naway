//! 兼容双文件材料的持久决定与崩溃恢复，部分写入不能成为完整身份。

use super::{atomic_write, generation, sync_directory, MAX_KEYPAIR_BYTES};
use crate::config::TlsRuntimeCfg;
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

mod recovery;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionState {
    schema_version: u32,
    old_cert_present: bool,
    old_key_present: bool,
    #[serde(default)]
    old_generation_present: bool,
    #[serde(default)]
    generation: Option<generation::Record>,
}

/// 业务作用：以持久 journal 发布旧式 cert/key 双文件，并在任一步失败时恢复安装前事实。
///
/// 参数说明：
/// - `tls`：固定证书与私钥目标路径的 TLS 策略。
/// - `certificate_pem`：已经完成密钥对密码学校验的证书 PEM。
/// - `private_key_pem`：已经完成密钥对密码学校验的私钥 PEM。
/// - `next`：上层为该完整 pair 预分配的材料记录，不由文件事务重新生成。
///
/// 返回：两个目标及材料代均已提交且 journal 已结算时返回新代；失败时尝试恢复，不保证没有提交。
pub(super) fn install_legacy_keypair_transaction(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    next: generation::Record,
) -> Result<String> {
    // 准备身份必须先于恢复或写入复验；错来源或错正文不能借旧事务恢复取得副作用。
    let target = generation::target(tls)?;
    next.require_material(&target, certificate_pem, private_key_pem)?;
    recover_legacy_keypair_transaction_locked(tls)?;
    let generation_path = generation::legacy_path(tls)?;
    let old_generation = generation::read(&generation_path, &target)?;
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
    let prepared = (|| -> Result<generation::Record> {
        let old_cert = crate::io::bounded_io::read_optional_file(
            &tls.cert_file,
            MAX_KEYPAIR_BYTES,
            "legacy TLS certificate backup",
        )?;
        let old_key = crate::io::bounded_io::read_optional_file(
            &tls.key_file,
            MAX_KEYPAIR_BYTES,
            "legacy TLS private key backup",
        )?
        .map(zeroize::Zeroizing::new);
        if let Some(bytes) = &old_cert {
            atomic_write(&temporary.join("old-cert.pem"), bytes, false)?;
        }
        if let Some(bytes) = &old_key {
            atomic_write(&temporary.join("old-key.pem"), bytes, true)?;
        }
        atomic_write(&temporary.join("new-cert.pem"), certificate_pem, false)?;
        atomic_write(&temporary.join("new-key.pem"), private_key_pem, true)?;
        if let Some((bytes, _)) = &old_generation {
            atomic_write(&temporary.join("old-generation.json"), bytes, true)?;
        }
        let mut state = TransactionState {
            schema_version: 2,
            old_cert_present: old_cert.is_some(),
            old_key_present: old_key.is_some(),
            old_generation_present: old_generation.is_some(),
            generation: Some(next),
        };
        atomic_write(
            &temporary.join("state.json"),
            &serde_json::to_vec(&state)?,
            true,
        )?;
        sync_directory(&temporary)?;
        fs::rename(&temporary, &transaction).with_context(|| {
            format!(
                "publish legacy keypair transaction {}",
                transaction.display()
            )
        })?;
        sync_directory(parent)?;
        Ok(state
            .generation
            .take()
            .expect("new transaction owns a material generation"))
    })();
    let next = match prepared {
        Ok(next) => next,
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary);
            return Err(error);
        }
    };

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
    // 完整 pair 的持久决定先于材料代发布；原 journal 在代发布完成前始终可恢复。
    next.publish(&generation_path)?;
    finish_legacy_keypair_transaction(&transaction)?;
    Ok(next.generation)
}

/// 业务作用：检查旧式 pair journal，只确认完整新代或在原旧新边界成立时恢复原材料。
///
/// 参数说明：
/// - `tls`：固定 journal 身份和两个目标；调用方持有全局安装锁。
///
/// 返回：journal 不存在、确认提交或恢复完成时成功；任何不可信 journal/材料拒绝继续读取。
pub(super) fn recover_legacy_keypair_transaction_locked(tls: &TlsRuntimeCfg) -> Result<()> {
    if tls.keypair_manifest_file.is_some() {
        return Ok(());
    }
    let canonical = legacy_keypair_transaction_dir(tls)?;
    let previous = legacy_directory_for_paths(&tls.cert_file, &tls.key_file)?;
    let transaction = if previous != canonical && previous.try_exists()? {
        // 两份活动 journal 无法证明先后；保留原材料，不能按扫描顺序任选一份恢复。
        anyhow::ensure!(
            !canonical.try_exists()?,
            "multiple active TLS keypair journals"
        );
        previous
    } else {
        canonical
    };
    let metadata = match fs::symlink_metadata(&transaction) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("stat legacy keypair transaction"),
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "legacy keypair transaction path is not a directory"
    );
    let state = read_transaction_state(&transaction)?;
    recovery::settle(tls, &transaction, &state)
}

/// 业务作用：恢复前核对完整事务格式，未知或残缺材料代不能被解释为旧式无条件恢复。
///
/// 参数说明：
/// - `transaction`：当前 pair 唯一活动 journal 目录。
///
/// 返回：旧格式无材料代，或新格式具有完整新代时成功；不在读取失败后补造恢复事实。
fn read_transaction_state(transaction: &Path) -> Result<TransactionState> {
    let bytes = crate::io::bounded_io::read_file(
        &transaction.join("state.json"),
        64 * 1024,
        "legacy keypair transaction state",
    )?;
    let state: TransactionState =
        serde_json::from_slice(&bytes).context("parse legacy keypair transaction state")?;
    anyhow::ensure!(
        (state.schema_version == 1 && state.generation.is_none() && !state.old_generation_present)
            || (state.schema_version == 2 && state.generation.is_some()),
        "legacy keypair transaction schema is invalid"
    );
    Ok(state)
}

/// 业务作用：为固定证书路径定位配对安装事务目录，恢复记录不能跨目标复用。
///
/// 参数说明：
/// - `tls`：确定证书与私钥槽位的双文件计划。
///
/// 返回：按实际父目录计算的唯一活动 journal 路径；目录无法解析时拒绝定位。
fn legacy_keypair_transaction_dir(tls: &TlsRuntimeCfg) -> Result<PathBuf> {
    legacy_directory_for_paths(
        &generation::identity_path(&tls.cert_file)?,
        &generation::identity_path(&tls.key_file)?,
    )
}

/// 业务作用：按固定槽位计算活动 journal 名，旧声明路径仍可定位已存在的兼容恢复记录。
///
/// 参数说明：
/// - `certificate`：证书槽位路径，新事务已解析父目录别名。
/// - `private_key`：配对私钥槽位路径。
///
/// 返回：证书同目录的固定事务位置；证书和私钥不能共用同一槽位。
fn legacy_directory_for_paths(certificate: &Path, private_key: &Path) -> Result<PathBuf> {
    use sha2::Digest as _;
    anyhow::ensure!(
        certificate != private_key,
        "TLS cert_file and key_file must differ"
    );
    let parent = certificate
        .parent()
        .context("TLS cert_file has no parent")?;
    let mut digest = sha2::Sha256::new();
    digest.update(certificate.as_os_str().as_encoded_bytes());
    digest.update([0]);
    digest.update(private_key.as_os_str().as_encoded_bytes());
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
    let parent = transaction.parent().unwrap_or_else(|| Path::new("."));
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random).context("TLS journal retirement entropy unavailable")?;
    let retired = parent.join(format!(
        ".naway-keypair-retired-{:032x}",
        u128::from_le_bytes(random)
    ));
    // 先撤下恢复入口并同步目录，再删除已退休备份；崩溃不能留下一个会被恢复器误读的半删 journal。
    fs::rename(transaction, &retired).context("retire completed TLS keypair transaction")?;
    sync_directory(parent)?;
    fs::remove_dir_all(&retired).with_context(|| {
        format!(
            "remove retired legacy keypair transaction {}",
            retired.display()
        )
    })?;
    sync_directory(parent)
}
