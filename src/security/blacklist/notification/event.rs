//! 通知描述已经确认的操作事实，不把消息顺序当作共享黑名单当前状态。

use anyhow::{ensure, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_EVENT_BYTES: usize = 2048;
const MAX_EVENT_ID_BYTES: usize = 64;
const MAX_ACTOR_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Ban,
    Unban,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Admin,
    AutoLimitReq,
    AutoWaf,
    AutoAuthentication,
    AutoAbnormal,
}

impl Source {
    /// 业务作用：把通知来源映射到既有审计合同的固定名称，不允许请求正文成为原因标签。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：低基数原生动作来源，与实际封禁信号一一对应。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::AutoLimitReq => "auto_limit_req",
            Self::AutoWaf => "auto_waf",
            Self::AutoAuthentication => "auto_authentication",
            Self::AutoAbnormal => "auto_abnormal",
        }
    }
}

/// 单个已确认操作的通知；整数使用规范十进制文本，接收方不能丢失雪花或时间精度。
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema_version: u32,
    pub event_id: String,
    pub timestamp_unix_ms: String,
    pub action: Action,
    pub ip: String,
    pub actor: String,
    pub source: Source,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_at_unix_ms: Option<String>,
}

/// 随机发送实例域与单机雪花序列共同组成完整事件身份，不依赖PID或重启后的墙钟唯一性。
pub struct EventFactory {
    instance: String,
    ids: nasa::base::Snowflake,
}

impl EventFactory {
    /// 业务作用：为一个通知发送实例建立独立事件域，防止重启或不同节点的雪花序号互相去重。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：安全随机源和雪花空间可用时返回工厂；失败不退回PID或可预测实例域。
    pub fn new() -> Result<Self> {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| anyhow::anyhow!("ACL event randomness unavailable"))?;
        Ok(Self {
            instance: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random),
            ids: nasa::base::Snowflake::with_default_bits(0)
                .context("initialize ACL event sequence")?,
        })
    }

    /// 业务作用：把已经确认的封禁或解封操作转为跨传输重试保持不变的事件。
    ///
    /// 参数说明：
    /// - `action`：事实源已经确认的期望操作。
    /// - `ip`：由真实连接或管理输入确定的客户端地址。
    /// - `actor`：当前动作主体，不含凭据或请求正文。
    /// - `source`：提供封禁证据的固定原生来源。
    /// - `expire_at_unix_ms`：原事实的绝对期限；永久封禁和解封不携带期限。
    ///
    /// 返回：规范地址和完整事件身份；非法主体、期限或不可用的时间/序列拒绝事件构造。
    pub fn create(
        &self,
        action: Action,
        ip: IpAddr,
        actor: &str,
        source: Source,
        expire_at_unix_ms: Option<i64>,
    ) -> Result<Event> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("ACL event clock precedes Unix epoch")?
            .as_millis();
        ensure!(
            timestamp <= u128::from(u64::MAX),
            "ACL event timestamp exhausted"
        );
        let event = Event {
            schema_version: 1,
            event_id: format!(
                "{}:{}",
                self.instance,
                self.ids
                    .try_generate()
                    .context("allocate ACL event sequence")?
            ),
            timestamp_unix_ms: timestamp.to_string(),
            action,
            ip: crate::io::net::canonical_ip(ip).to_string(),
            actor: actor.to_owned(),
            source,
            expire_at_unix_ms: expire_at_unix_ms.map(|value| value.to_string()),
        };
        event.validate()?;
        Ok(event)
    }
}

impl Event {
    /// 业务作用：从共享存储的写入提示读取原封禁事件，不把删除或普通失效提示伪造成业务操作。
    ///
    /// 参数说明：
    /// - `change`：受管DynamicStore或独立Redis消费组取得的类型化变更。
    /// - `collection`：接收业务固定配置的黑名单集合，不能取自消息本身。
    ///
    /// 返回：集合、键和协议均一致时返回原封禁事件；普通提示返回None并由调用方重读事实。
    /// 来源认证仍由接收业务承担，事件不证明该IP此刻仍被封禁。
    pub fn from_change(
        change: &crate::runtime::state::DynamicStoreChange,
        collection: &str,
    ) -> Result<Option<Self>> {
        use crate::runtime::state::DynamicStoreChangeKind;
        ensure!(
            change.collection == collection,
            "ACL notification collection mismatch"
        );
        if change.kind != DynamicStoreChangeKind::Put {
            return Ok(None);
        }
        let Some(value) = &change.notification else {
            return Ok(None);
        };
        let event = Self::decode(&serde_json::to_vec(value).context("encode store notification")?)?;
        ensure!(
            event.action == Action::Ban && change.key == event.ip,
            "ACL store notification does not match written fact"
        );
        Ok(Some(event))
    }

    /// 业务作用：验证事件身份和业务字段，接收方不能用不完整或歧义事件登记去重。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前协议、规范身份、地址、主体与动作组合全部合法时成功，否则拒绝。
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported ACL event schema");
        ensure!(
            self.event_id.len() <= MAX_EVENT_ID_BYTES,
            "ACL event identity oversized"
        );
        let (instance, sequence) = self
            .event_id
            .split_once(':')
            .context("ACL event identity missing instance")?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(instance)
            .context("invalid ACL event instance")?;
        ensure!(
            bytes.len() == 16
                && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) == instance,
            "noncanonical ACL event instance"
        );
        ensure!(
            unsigned(sequence)? <= i64::MAX as u64,
            "ACL event sequence exceeds Snowflake space"
        );
        unsigned(&self.timestamp_unix_ms)?;
        ensure!(
            !self.actor.is_empty()
                && self.actor.len() <= MAX_ACTOR_BYTES
                && !self.actor.chars().any(char::is_control),
            "invalid ACL event actor"
        );
        let ip: IpAddr = self.ip.parse().context("invalid ACL event IP")?;
        ensure!(
            crate::io::net::canonical_ip(ip).to_string() == self.ip,
            "noncanonical ACL event IP"
        );
        if let Some(expire_at) = &self.expire_at_unix_ms {
            ensure!(
                self.action == Action::Ban,
                "ACL unban cannot carry expiration"
            );
            let value = unsigned(expire_at)?;
            ensure!(
                value > 0 && value <= i64::MAX as u64,
                "invalid ACL event expiration"
            );
        }
        Ok(())
    }

    /// 业务作用：将有效事件编码为所有重试共享的有界JSON原文字节。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法且不超过2048字节的完整事件；非法事件或编码超限返回错误。
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).context("encode ACL event")?;
        ensure!(bytes.len() <= MAX_EVENT_BYTES, "ACL event body oversized");
        Ok(bytes)
    }

    /// 业务作用：只从有界完整JSON读取通知，未知或重复字段不进入业务去重流程。
    ///
    /// 参数说明：
    /// - `bytes`：已完成传输或签名验证的完整事件原文。
    ///
    /// 返回：当前协议的合法事件；超限、歧义JSON或非法业务字段返回错误。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_EVENT_BYTES, "ACL event body oversized");
        let event: Self = serde_json::from_slice(bytes).context("decode ACL event")?;
        event.validate()?;
        Ok(event)
    }
}

/// 业务作用：拒绝带符号、前导零或舍入表示的整数，保证事件签名和业务读取使用同一身份。
///
/// 参数说明：
/// - `text`：协议中的规范十进制文本。
///
/// 返回：可精确表示的u64；非规范文本或溢出返回错误。
pub(super) fn unsigned(text: &str) -> Result<u64> {
    ensure!(
        !text.is_empty()
            && text.len() <= 20
            && text.bytes().all(|value| value.is_ascii_digit())
            && (text == "0" || !text.starts_with('0')),
        "noncanonical ACL event integer"
    );
    text.parse().context("ACL event integer overflow")
}
