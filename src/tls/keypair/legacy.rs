//! 兼容双文件材料的持久决定与崩溃恢复，部分写入不能成为完整身份。

use super::{generation, io, MAX_KEYPAIR_BYTES};
use crate::config::TlsRuntimeCfg;
use crate::io::file_target::Target;
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

mod bound;
mod recovery;

/// 整批材料决定冻结的原角色目录及旧完整归属，不能由底层事务重新选择目标。
pub(in crate::tls::keypair) struct Boundary<'a> {
    pub certificate: &'a crate::io::file_target::Location,
    pub private_key: &'a crate::io::file_target::Location,
    pub owner: &'a crate::io::file_target::Location,
    pub transaction: &'a crate::io::file_target::Location,
    pub previous: &'a generation::Record,
}

impl Boundary<'_> {
    /// 业务作用：在恢复或创建底层事务之前核对全部原父目录，缺失目录不能被重新创建成旧权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：四个原角色的父目录身份仍成立时成功，不创建目录或改写任何正文。
    fn require_locations(&self) -> Result<()> {
        for location in [
            self.certificate,
            self.private_key,
            self.owner,
            self.transaction,
        ] {
            location.open()?;
        }
        Ok(())
    }

    /// 业务作用：把底层实际打开能力与整批原位置配对，外部别名或父目录替换不能获得原决定写权。
    ///
    /// 参数说明：
    /// - `targets`：底层事务持有且后续读写一直沿用的四个目录能力。
    ///
    /// 返回：全部原角色位置精确相同才成功，拒绝时保持原活动材料。
    fn require_targets(&self, targets: &bound::Targets<'_>) -> Result<()> {
        use crate::io::file_target::Location;
        anyhow::ensure!(
            Location::capture(&targets.certificate)? == *self.certificate
                && Location::capture(&targets.private_key)? == *self.private_key
                && Location::capture(&targets.owner)? == *self.owner
                && Location::capture(&targets.transaction)? == *self.transaction,
            "TLS decided transaction locations differ"
        );
        Ok(())
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    locations: Option<bound::Locations>,
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
    install(tls, certificate_pem, private_key_pem, next, None)
}

/// 业务作用：按整批已提交的原边界执行同一双文件事务，不另造材料代或向后来目录写入。
///
/// 参数说明：
/// - `tls`：原本机文件声明，外层已验证配置证据并持有材料锁。
/// - `certificate`：该方向已验证完整证书借用。
/// - `private_key`：同一完整pair的私钥借用。
/// - `next`：整批决定之前持久预分配的材料归属。
/// - `boundary`：原四角色目录及该方向允许的旧owner。
///
/// 返回：原决定完整提交后的材料代；未知结果保留原事务，不声称未执行。
#[cfg(feature = "node-actions")]
pub(in crate::tls::keypair) fn install_decided(
    tls: &TlsRuntimeCfg,
    certificate: &[u8],
    private_key: &[u8],
    next: generation::Record,
    boundary: &Boundary<'_>,
) -> Result<String> {
    install(tls, certificate, private_key, next, Some(boundary))
}

/// 业务作用：共享双文件写入顺序，并在具有整批约束时将原目录和旧owner门加入实际副作用位置。
///
/// 参数说明：
/// - `tls`：本机文件计划，调用方持有材料安装锁。
/// - `certificate_pem`：完整目标证书链。
/// - `private_key_pem`：对应私钥原文。
/// - `next`：原预分配目标材料代。
/// - `boundary`：整批动作原边界；普通本机安装没有额外持久原位置。
///
/// 返回：完整事务确认后的目标代；失败沿用原恢复与未知结果语义。
fn install(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    next: generation::Record,
    boundary: Option<&Boundary<'_>>,
) -> Result<String> {
    // 准备身份必须先于恢复或写入复验；错来源或错正文不能借旧事务恢复取得副作用。
    let target = generation::target(tls)?;
    next.require_material(&target, certificate_pem, private_key_pem)?;
    recover(tls, boundary, Some(&next))?;
    if let Some(boundary) = boundary {
        // 原批次只拥有已经存在的原目录，缺席后重新建目录会错误继承旧写权。
        boundary.require_locations()?;
    } else {
        for path in [&tls.cert_file, &tls.key_file] {
            fs::create_dir_all(path.parent().context("TLS material parent absent")?)?;
        }
    }
    let transaction = legacy_keypair_transaction_dir(tls)?;
    let targets = bound::Targets::capture(tls, &transaction)?;
    if let Some(boundary) = boundary {
        boundary.require_targets(&targets)?;
    }
    // 打开父目录后复验原材料身份，路径别名变化不能把此前预分配的代移到另一来源。
    next.require_material(&targets.source(), certificate_pem, private_key_pem)?;
    let locations = targets.locations()?;
    targets.require_current()?;
    let old_generation = bound::owner(&targets.owner, &target)?;
    if let Some(boundary) = boundary {
        anyhow::ensure!(
            old_generation.as_ref().map(|(_, owner)| owner) == Some(boundary.previous),
            "TLS decided previous ownership differs"
        );
    }
    let mut journal = bound::Journal::create(&targets.transaction)?;
    let prepared = (|| -> Result<generation::Record> {
        let old_cert = io::read(&targets.certificate, MAX_KEYPAIR_BYTES)?;
        let old_key = io::read(&targets.private_key, MAX_KEYPAIR_BYTES)?;
        // 原owner必须拥有完整备份，否则不能创建一个恢复时无法证明的受管旧边界。
        if let Some((_, owner)) = &old_generation {
            owner.require_material(
                &target,
                old_cert
                    .as_deref()
                    .context("TLS previous certificate absent")?,
                old_key
                    .as_deref()
                    .context("TLS previous private key absent")?,
            )?;
        }
        if let Some(bytes) = &old_cert {
            io::write(&journal.file("old-cert.pem")?, bytes, false)?;
        }
        if let Some(bytes) = &old_key {
            io::write(&journal.file("old-key.pem")?, bytes, true)?;
        }
        io::write(&journal.file("new-cert.pem")?, certificate_pem, false)?;
        io::write(&journal.file("new-key.pem")?, private_key_pem, true)?;
        if let Some((bytes, _)) = &old_generation {
            io::write(&journal.file("old-generation.json")?, bytes, true)?;
        }
        let mut state = TransactionState {
            schema_version: 3,
            old_cert_present: old_cert.is_some(),
            old_key_present: old_key.is_some(),
            old_generation_present: old_generation.is_some(),
            generation: Some(next),
            locations: Some(locations),
        };
        let bytes = serde_json::to_vec(&state)?;
        anyhow::ensure!(
            bytes.len() <= 64 * 1024,
            "TLS transaction state exceeds limit"
        );
        io::write(&journal.file("state.json")?, &bytes, true)?;
        targets.require_current()?;
        Ok(state
            .generation
            .take()
            .expect("transaction owns its prepared generation"))
    })();
    let next = match prepared {
        Ok(next) => next,
        Err(error) => {
            let _ = journal.discard();
            return Err(error);
        }
    };
    // 完整state及原目录证据先于活动入口；发布后的同步错误只能保留恢复责任，不能清理journal。
    journal.publish(&targets.transaction)?;
    let publish = (|| -> Result<()> {
        targets.require_current()?;
        journal.require_current()?;
        io::write(&targets.private_key, private_key_pem, true)?;
        io::write(&targets.certificate, certificate_pem, false)?;
        targets.require_current()
    })();
    if let Err(error) = publish {
        recover(tls, boundary, Some(&next))
            .context("restore legacy TLS pair after failed publish")?;
        return Err(error);
    }
    // 完整pair决定先于材料归属发布，原journal直到两者均确认后才退休。
    next.publish_to(&targets.owner)?;
    targets.require_current()?;
    journal.finish()?;
    Ok(next.generation)
}

/// 业务作用：检查旧式 pair journal，只确认完整新代或在原旧新边界成立时恢复原材料。
///
/// 参数说明：
/// - `tls`：固定 journal 身份和两个目标；调用方持有全局安装锁。
///
/// 返回：journal 不存在、确认提交或恢复完成时成功；任何不可信 journal/材料拒绝继续读取。
pub(super) fn recover_legacy_keypair_transaction_locked(tls: &TlsRuntimeCfg) -> Result<()> {
    recover(tls, None, None)
}

/// 业务作用：整批重放只结算同一预分配方向的原底层journal，后来事务不能借原计划被恢复。
///
/// 参数说明：
/// - `tls`：原本机双文件声明，调用方持有材料锁。
/// - `boundary`：原四角色目录及该方向的旧完整归属。
/// - `next`：全批方向决定的目标归属。
///
/// 返回：没有活动journal或同一原事务完成恢复时成功；错代、错目录或未知旧备份拒绝。
#[cfg(feature = "node-actions")]
pub(in crate::tls::keypair) fn recover_decided(
    tls: &TlsRuntimeCfg,
    boundary: &Boundary<'_>,
    next: &generation::Record,
) -> Result<()> {
    boundary.require_locations()?;
    recover(tls, Some(boundary), Some(next))
}

/// 业务作用：共用旧格式读取和严格整批恢复，原决定约束必须先于任何备份回放或owner发布。
///
/// 参数说明：
/// - `tls`：当前明确的本机声明。
/// - `boundary`：可选的整批原目录及旧owner证据。
/// - `next`：整批约束启用时唯一允许的目标代；普通独立恢复不额外选择目标。
///
/// 返回：原事务结算或明确缺失时成功；证据不符保留现场并阻止加载。
fn recover(
    tls: &TlsRuntimeCfg,
    boundary: Option<&Boundary<'_>>,
    next: Option<&generation::Record>,
) -> Result<()> {
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
    let journal = bound::Journal::open(Target::open(&transaction)?)?;
    let state = read_transaction_state(&journal)?;
    let targets = bound::Targets::capture(tls, &transaction)?;
    if let Some(boundary) = boundary {
        // 旧schema缺少本次整批原目录或预分配代，不能被自动提升为该方向的恢复权威。
        boundary.require_targets(&targets)?;
        anyhow::ensure!(
            state.schema_version == 3
                && state.generation.as_ref() == next
                && next.is_some()
                && state.old_cert_present
                && state.old_key_present
                && state.old_generation_present,
            "TLS decided journal ownership differs"
        );
        let previous = bound::owner(&journal.file("old-generation.json")?, &targets.source())?;
        anyhow::ensure!(
            previous.as_ref().map(|(_, owner)| owner) == Some(boundary.previous),
            "TLS decided journal original owner differs"
        );
    }
    // 新记录必须匹配原父目录；同字节备份和同名新目录也不能继承原事务写权。
    if let Some(expected) = &state.locations {
        anyhow::ensure!(
            targets.locations()? == *expected,
            "TLS transaction source locations changed"
        );
    }
    targets.require_current()?;
    journal.require_current()?;
    recovery::settle(&targets, &journal, &state)
}

/// 业务作用：恢复前核对完整事务格式，未知或残缺材料代不能被解释为旧式无条件恢复。
///
/// 参数说明：
/// - `transaction`：当前 pair 唯一活动 journal 目录。
///
/// 返回：旧格式无材料代，或新格式具有完整新代时成功；不在读取失败后补造恢复事实。
fn read_transaction_state(transaction: &bound::Journal) -> Result<TransactionState> {
    let bytes = io::read(&transaction.file("state.json")?, 64 * 1024)?
        .context("TLS transaction state absent")?;
    let state: TransactionState =
        serde_json::from_slice(&bytes).context("parse legacy keypair transaction state")?;
    anyhow::ensure!(
        (state.schema_version == 1
            && state.generation.is_none()
            && !state.old_generation_present
            && state.locations.is_none())
            || (state.schema_version == 2
                && state.generation.is_some()
                && state.locations.is_none())
            || (state.schema_version == 3
                && state.generation.is_some()
                && state.locations.is_some()),
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
pub(in crate::tls::keypair) fn legacy_directory_for_paths(
    certificate: &Path,
    private_key: &Path,
) -> Result<PathBuf> {
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
