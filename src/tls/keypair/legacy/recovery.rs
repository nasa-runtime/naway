//! 恢复仅处理原事务的完整新代或可证明旧新边界，材料接管不能被旧备份覆盖。

use super::{bound, io, TransactionState, MAX_KEYPAIR_BYTES};
use crate::{io::file_target::Target, tls::keypair::validate_keypair};
use anyhow::{ensure, Context, Result};
use zeroize::Zeroizing;

/// 业务作用：在完整材料与归属门成立后结算唯一双文件事务，第三方内容保留现场并阻止自动覆盖。
///
/// 参数说明：
/// - `targets`：已核对持久位置的原文件能力。
/// - `transaction`：已固定目录句柄的精确活动 journal。
/// - `state`：已经通过格式检查的原持久决定。
///
/// 返回：完整新代确认或原材料恢复并结算时成功；未知代、未知内容、必要备份缺失或 I/O 异常拒绝。
pub(super) fn settle(
    targets: &bound::Targets,
    transaction: &bound::Journal,
    state: &TransactionState,
) -> Result<()> {
    let target = targets.source();
    let current = bound::owner(&targets.owner, &target)?.map(|(_, record)| record);
    let next = state.generation.as_ref();
    let committed_owner = current
        .as_ref()
        .zip(next)
        .is_some_and(|(left, right)| left == right);
    let previous = if state.old_generation_present && !committed_owner {
        Some(
            bound::owner(&transaction.file("old-generation.json")?, &target)?
                .context("TLS previous material generation missing")?
                .1,
        )
    } else {
        None
    };
    // 相同 pair 也可能已被新动作接管；只有原备份代或本事务新代能够结算这个 journal。
    ensure!(
        committed_owner || current.as_ref() == previous.as_ref(),
        "TLS transaction no longer owns the material generation"
    );
    let new_cert = read_required(&transaction.file("new-cert.pem")?)?;
    let new_key = read_required(&transaction.file("new-key.pem")?)?;
    validate_keypair(&new_cert, &new_key)?;
    if let Some(next) = next {
        next.require_material(&target, &new_cert, &new_key)?;
    }
    let live_cert = read_optional(&targets.certificate)?;
    let live_key = read_optional(&targets.private_key)?;
    let cert_is_new = live_cert.as_deref().map(Vec::as_slice) == Some(new_cert.as_slice());
    let key_is_new = live_key.as_deref().map(Vec::as_slice) == Some(new_key.as_slice());
    // 候选比较完成后先清除缓冲，再读取旧备份；恢复不同时保留三份完整 pair。
    drop(new_cert);
    drop(new_key);
    if cert_is_new && key_is_new {
        // 完整候选已经落盘才能确认原新代；即使旧新字节相同，也不能沿用退休的旧材料代。
        targets.require_current()?;
        transaction.require_current()?;
        if let Some(next) = next {
            next.publish_to(&targets.owner)?;
        }
        targets.require_current()?;
        return transaction.finish();
    }
    // 新代发布意味着完整 pair 曾提交；之后出现不完整内容属于接管或损坏，不能退回更旧的所有权。
    ensure!(
        !committed_owner,
        "committed TLS material changed before journal settlement"
    );
    let old_cert = state
        .old_cert_present
        .then(|| read_required(&transaction.file("old-cert.pem")?))
        .transpose()?;
    let old_key = state
        .old_key_present
        .then(|| read_required(&transaction.file("old-key.pem")?))
        .transpose()?;
    if let Some(previous) = &previous {
        let certificate = old_cert
            .as_ref()
            .context("TLS previous certificate backup missing")?;
        let key = old_key
            .as_ref()
            .context("TLS previous private key backup missing")?;
        previous.require_material(&target, certificate, key)?;
    }
    if let (Some(certificate), Some(key)) = (&old_cert, &old_key) {
        validate_keypair(certificate, key)?;
    }
    // 先核对两个槽位的完整旧新边界，任何未知片段都不能触发第一个恢复写入。
    ensure!(
        (cert_is_new
            || live_cert.as_deref().map(Vec::as_slice) == old_cert.as_deref().map(Vec::as_slice))
            && (key_is_new
                || live_key.as_deref().map(Vec::as_slice) == old_key.as_deref().map(Vec::as_slice)),
        "TLS transaction encountered material outside its original boundary"
    );
    targets.require_current()?;
    transaction.require_current()?;
    restore(
        &targets.private_key,
        old_key.as_deref().map(Vec::as_slice),
        true,
    )?;
    restore(
        &targets.certificate,
        old_cert.as_deref().map(Vec::as_slice),
        false,
    )?;
    // pair 恢复与材料归属共同完成后才退休 journal；同步不确定仍保留原恢复责任。
    targets.require_current()?;
    if state.schema_version >= 2 {
        if let Some(previous) = previous {
            previous.publish_to(&targets.owner)?;
        } else {
            restore(&targets.owner, None, true)?;
        }
    }
    targets.require_current()?;
    transaction.finish()
}

/// 业务作用：有界读取恢复所需的确定材料，完整与部分读取失败均在清零容器内处理。
///
/// 参数说明：
/// - `path`：原事务已经固定的材料位置。
///
/// 返回：完整有限材料；缺失、超限或读取异常拒绝，不把缺失解释为空文件。
fn read_required(path: &Target) -> Result<Zeroizing<Vec<u8>>> {
    io::read(path, MAX_KEYPAIR_BYTES)?.context("TLS recovery material absent")
}

/// 业务作用：保留活动文件的真实缺席状态，使首次安装中断与外部删除按原事务边界分别裁决。
///
/// 参数说明：
/// - `path`：原证书或私钥槽位。
///
/// 返回：存在时为释放清零的有限原文，缺失为空；其它错误保留保护。
fn read_optional(path: &Target) -> Result<Option<Zeroizing<Vec<u8>>>> {
    io::read(path, MAX_KEYPAIR_BYTES)
}

/// 业务作用：只写入已完成全 pair 验证的原备份，不在两个恢复写入之间重新读取可变备份。
///
/// 参数说明：
/// - `target`：已经通过原旧新边界门的目标槽。
/// - `bytes`：同轮验证的原文借用；空表示原槽位确实缺失。
/// - `secret`：是否从暂存创建起限制为私有文件。
///
/// 返回：该槽恢复并同步时成功；失败保留活动 journal，不宣称整对恢复完成。
fn restore(target: &Target, bytes: Option<&[u8]>, secret: bool) -> Result<()> {
    if let Some(bytes) = bytes {
        io::write(target, bytes, secret)
    } else {
        io::remove(target)
    }
}
