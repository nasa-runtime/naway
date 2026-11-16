//! 通知先验证来源与原始字节，再登记有期限的业务消费证据。

use super::Event;
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 已验证传输来源的事件；构造不登记去重，不代表业务副作用已经完成。
pub struct VerifiedEvent {
    event: Event,
    expires_at: u64,
    valid_until_ms: u64,
}

/// 首次登记和拒绝登记必须区分；后者也可能是依赖或容量失败，不能断言消息已经处理。
#[derive(Debug)]
pub enum Admission {
    First(Event),
    NotAdmitted,
}

/// 业务作用：为精确JSON原文生成带协议域、投递时间和完整事件身份的HMAC，重试可更新投递时间。
///
/// 参数说明：
/// - `body`：有效事件的完整UTF-8 JSON原文字节。
/// - `delivery_unix_ms`：本次投递使用的规范十进制Unix毫秒。
/// - `key`：至少32字节的共享签名秘密。
///
/// 返回：小写十六进制HMAC；事件、时间或秘密不满足合同则拒绝。
pub fn sign_webhook(body: &[u8], delivery_unix_ms: &str, key: &str) -> Result<String> {
    ensure!(
        key.len() >= 32,
        "ACL webhook signing key must contain at least 32 bytes"
    );
    let event = Event::decode(body)?;
    super::event::unsigned(delivery_unix_ms)?;
    let body = std::str::from_utf8(body).context("ACL webhook body must be UTF-8")?;
    Ok(nasa::crypto::hmac_sha256(
        &format!(
            "naway.acl.v1\n{delivery_unix_ms}\n{}\n{body}",
            event.event_id
        ),
        key,
    ))
}

/// 业务作用：先验证通知完整性与新鲜性，再允许调用方进入消费登记，伪造事件不能占用去重键。
///
/// 参数说明：
/// - `body`：接收到的完整原文，不得重新序列化后验签。
/// - `delivery_unix_ms`：`x-naway-acl-timestamp`头的单个值。
/// - `event_id`：`x-naway-acl-event-id`头的单个值，必须等于原文身份。
/// - `signature`：`x-naway-acl-signature`头的单个小写十六进制值。
/// - `key`：当前接收出口的共享签名秘密。
/// - `max_age`：事件可消费期限，1至300秒；投递时间另允许5秒时钟偏差。
///
/// 返回：已验签且仍有效的事件；不改变ReplayGuard或业务状态。
pub fn verify_webhook(
    body: &[u8],
    delivery_unix_ms: &str,
    event_id: &str,
    signature: &str,
    key: &str,
    max_age: Duration,
) -> Result<VerifiedEvent> {
    ensure!(
        key.len() >= 32,
        "ACL webhook signing key must contain at least 32 bytes"
    );
    let event = Event::decode(body)?;
    ensure!(event.event_id == event_id, "ACL webhook identity mismatch");
    let delivery = super::event::unsigned(delivery_unix_ms)?;
    let now = now_ms()?;
    ensure!(
        now.abs_diff(delivery) <= 5_000,
        "ACL webhook delivery timestamp outside allowed window"
    );
    ensure!(
        signature.len() == 64
            && signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid ACL webhook signature encoding"
    );
    let text = std::str::from_utf8(body).context("ACL webhook body must be UTF-8")?;
    // 验签先于任何共享登记，攻击者不能用已知事件身份耗尽真实业务的消费资格。
    ensure!(
        nasa::crypto::hmac_sha256_verify(
            &format!("naway.acl.v1\n{delivery_unix_ms}\n{event_id}\n{text}"),
            key,
            signature
        ),
        "ACL webhook signature rejected"
    );
    VerifiedEvent::from_trusted_transport(event, max_age)
}

impl VerifiedEvent {
    /// 业务作用：为已经完成broker身份与主题授权验证的消息建立有限消费窗口。
    ///
    /// 参数说明：
    /// - `event`：来自受信MQ或受管DynamicStore的完整事件，调用方负责来源认证。
    /// - `max_age`：允许的事件年龄，1至300秒；原始事件时间不能通过重试延长。
    ///
    /// 返回：仍在原始事件有效窗内的待登记对象；不验证MQ凭据，也不读取或改变事实源。
    pub fn from_trusted_transport(event: Event, max_age: Duration) -> Result<Self> {
        event.validate()?;
        ensure!(
            max_age.subsec_nanos() == 0 && (1..=300).contains(&max_age.as_secs()),
            "ACL consumer max_age must contain 1..=300 whole seconds"
        );
        let timestamp = super::event::unsigned(&event.timestamp_unix_ms)?;
        let now = now_ms()?;
        ensure!(
            timestamp <= now.saturating_add(5_000),
            "ACL event timestamp is in the future"
        );
        let until = timestamp
            .checked_add(max_age.as_secs() * 1_000)
            .context("ACL event expiration overflow")?;
        ensure!(now < until, "ACL event consumption window expired");
        Ok(Self {
            event,
            expires_at: until / 1_000 + 1,
            valid_until_ms: until,
        })
    }

    /// 业务作用：按业务接收域和完整事件身份原子登记消费资格，失败不得软放行。
    ///
    /// 参数说明：
    /// - `guard`：接收业务选择的严格ReplayGuard；本地后端只保证本进程去重。
    /// - `scope`：业务订阅的稳定独立域，1至128字节，不能取自通知正文。
    ///
    /// 返回：只有严格首次登记成功才交付事件；重复、容量、依赖失败或不支持严格合同均为NotAdmitted。
    /// 登记与业务副作用并非同一事务，调用方仍需自己的事务收件箱处理崩溃及重试。
    pub async fn admit(
        self,
        guard: &dyn crate::runtime::state::ReplayGuard,
        scope: &str,
    ) -> Result<Admission> {
        ensure!(
            !scope.is_empty() && scope.len() <= 128 && !scope.chars().any(char::is_control),
            "invalid ACL consumer scope"
        );
        let now_ms = now_ms()?;
        let now = now_ms / 1_000;
        // 共享账本要求保留期覆盖凭证截止时间及一秒时钟余量；这不延长原事件的有效窗。
        let ttl = self
            .expires_at
            .checked_sub(now)
            .and_then(|remaining| remaining.checked_add(1))
            .filter(|seconds| *seconds <= 310);
        let Some(ttl) = ttl.filter(|_| now_ms < self.valid_until_ms) else {
            return Ok(Admission::NotAdmitted);
        };
        let Some(authority) = guard.strict_authority() else {
            // 空账本或不具备严格登记的后端没有放行业务消费的权力。
            return Ok(Admission::NotAdmitted);
        };
        let mut digest = Sha256::new();
        digest.update(b"naway.acl.consumer.v1\0");
        digest.update((scope.len() as u64).to_be_bytes());
        digest.update(scope.as_bytes());
        digest.update(self.event.event_id.as_bytes());
        let key = format!("{:x}", digest.finalize());
        let ttl = Duration::from_secs(ttl);
        if guard
            .check_and_set_strict(authority, self.expires_at, &key, ttl, None)
            .await
        {
            Ok(Admission::First(self.event))
        } else {
            Ok(Admission::NotAdmitted)
        }
    }
}

/// 业务作用：提供通知接收新鲜性使用的真实Unix毫秒，异常时拒绝消费。
///
/// 参数说明: 无。
///
/// 返回：当前毫秒；时钟早于epoch或超出协议范围时返回错误，不回退为零。
pub(super) fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("ACL notification clock precedes Unix epoch")?
        .as_millis()
        .try_into()
        .context("ACL notification timestamp exhausted")
}
