//! NASA 认证加密绑定持久业务上下文；材料秘密只在有界阻塞任务中存在。

use super::{
    model::{self, Material, Summary},
    Error,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::{OwnedMutexGuard, Semaphore};
use zeroize::Zeroizing;

/// 全部字段来自冻结意图或同事务数据库权威，不从客户端接受密文上下文。
pub(super) struct Context {
    pub cluster: String,
    pub store_id: String,
    pub epoch: i64,
    pub id: String,
    pub key_id: String,
    pub creator: String,
    pub scope: String,
    pub intent: [u8; 32],
    pub created: i64,
    pub expires: i64,
}

impl Context {
    /// 业务作用：以独立域和长度帧认证密文归属，阻止跨集群、存储、提案或审阅期限搬移。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界 AAD；不含明文、私钥摘要或加密秘密。
    fn aad(&self) -> Vec<u8> {
        let mut bytes = b"naway-certificate-material\0".to_vec();
        for field in [
            self.cluster.as_bytes(),
            self.store_id.as_bytes(),
            &self.epoch.to_be_bytes(),
            self.id.as_bytes(),
            self.key_id.as_bytes(),
            self.creator.as_bytes(),
            self.scope.as_bytes(),
            &self.intent,
            &self.created.to_be_bytes(),
            &self.expires.to_be_bytes(),
        ] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        bytes
    }
}

pub(super) struct Sealed {
    pub ciphertext: String,
    pub summary: Vec<u8>,
}

/// 业务作用：在已获共享容量与配置权威后验证材料并封装为 NASA NC2 密文，不把秘密送入 SQL。
///
/// 参数说明：
/// - `material`：本次受理唯一材料帧，完成或失败后清零。
/// - `key`：当前配置明确指定的写钥。
/// - `context`：原事务冻结的认证上下文。
///
/// 返回：密文及有限公开摘要；任何密码学失败只返回固定错误。
pub(super) fn seal(material: Material, key: &str, context: &Context) -> Result<Sealed, Error> {
    let summary = serde_json::to_vec(&material.inspect().map_err(|_| Error::Invalid)?)
        .map_err(|_| Error::Invalid)?;
    let ciphertext = nasa::crypto::encrypt_modern_bytes_with_aad(&material.0, key, &context.aad())
        .map_err(|_| Error::Unavailable)?;
    if !ciphertext.starts_with("NC2.65536.3.4.")
        || ciphertext.len() > material.0.len() * 2 + 256
        || summary.len() > 1024
    {
        return Err(Error::Unavailable);
    }
    Ok(Sealed {
        ciphertext,
        summary,
    })
}

/// 业务作用：审阅前认证保存的密文和完整意图，缺旧钥或篡改时禁止批准，明文不离开阻塞任务。
///
/// 参数说明：
/// - `ciphertext`：数据库保存的 NC2 token。
/// - `key`：按原 key id 从当前钥环取得的秘密。
/// - `context`：原持久上下文与存储当前随机身份。
/// - `targets`：原目标编码。
/// - `authority`：原冻结权限摘要。
/// - `summary`：拟供审批者确认的公开证书投影。
///
/// 返回：认证、帧、全部意图与公开摘要一致才成功；不交付任何明文材料。
pub(super) fn verify(
    ciphertext: &str,
    key: &str,
    context: &Context,
    targets: &[u8],
    authority: &[u8; 32],
    summary: &[u8],
) -> Result<(), Error> {
    // 只接受本合同固定的有界 KDF 参数，数据库被篡改也不能扩大算法内存或退回无 AAD 格式。
    if !ciphertext.starts_with("NC2.65536.3.4.") || ciphertext.len() > 2 * (1024 * 1024 + 16) + 256
    {
        return Err(Error::Unavailable);
    }
    let material = Material(Zeroizing::new(
        nasa::crypto::decrypt_modern_bytes_with_aad(ciphertext, key, &context.aad())
            .map_err(|_| Error::Unavailable)?,
    ));
    let ttl_ms = context
        .expires
        .checked_sub(context.created)
        .ok_or(Error::Unavailable)?;
    let ttl = u32::try_from(ttl_ms / 1000).map_err(|_| Error::Unavailable)?;
    if ttl_ms % 1000 != 0
        || !(60..=86400).contains(&ttl)
        || model::fingerprint(&material, targets, context.epoch, ttl, authority) != context.intent
        || material.inspect().map_err(|_| Error::Unavailable)?
            != serde_json::from_slice::<Summary>(summary).map_err(|_| Error::Unavailable)?
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

/// 业务作用：把算法并发许可和配置发布权交给实际阻塞任务，HTTP 取消不能提前释放仍在运行的 KDF。
///
/// 参数说明：
/// - `workers`：该材料 owner 的两个实际算法名额。
/// - `publication`：当前请求已取得并复验的配置发布权。
/// - `work`：只做材料密码学处理，不在后台提交数据库或安装证书。
///
/// 返回：完整算法结果；排队超过两秒拒绝，任务异常不输出材料或底层诊断。
pub(super) async fn run<T: Send + 'static>(
    workers: &Arc<Semaphore>,
    publication: Arc<OwnedMutexGuard<()>>,
    work: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let permit = tokio::time::timeout(Duration::from_secs(2), workers.clone().acquire_owned())
        .await
        .map_err(|_| Error::Capacity)?
        .map_err(|_| Error::Unavailable)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _publication = publication;
        work()
    })
    .await
    .map_err(|_| Error::Unavailable)?
}
