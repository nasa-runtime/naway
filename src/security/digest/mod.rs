//! 原生 Digest 认证；密码摘要与一次性计数消费共同构成授权，正文保持原流。

mod config;
mod header;
pub(crate) use config::parse;

use crate::runtime::state::ReplayGuard;
use crate::security::auth::{constant_time_eq, escape_header_quote};
use http::{request::Parts, HeaderValue, Uri};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub(crate) struct Policy {
    user: Arc<str>,
    user_hash: [u8; 32],
    consumer: Arc<str>,
    realm: Arc<str>,
    ha1: Arc<str>,
    secret: Arc<str>,
    opaque: Arc<str>,
    session: bool,
    ttl: u64,
}

/// 规范化前的原始目标，只在存在 Digest 策略的入口保留。
#[derive(Clone)]
pub(crate) struct OriginalTarget(pub(crate) Uri);

/// 已完成严格重放登记的凭证；私有字段阻止普通请求头制造本地认证成功。
#[derive(Clone)]
pub(crate) struct Verified {
    opaque: Arc<str>,
    consumer: Arc<str>,
}

pub(crate) enum Failure {
    Challenge(HeaderValue),
    Unavailable,
}

impl Policy {
    /// 业务作用：验证原始目标和 Digest 响应后消费唯一计数，只有完整授权才能建立可信主体。
    /// 参数说明：
    /// - `parts`：规范化后的请求及入口保存的原始目标。
    /// - `scope`：由路由归属与入口构造的受信作用域。
    /// - `guard`：当前本地或共享重放账本。
    ///
    /// 返回：成功凭证；认证失败返回新挑战，熵源或后端权威缺席时返回不可用。
    pub(crate) async fn authenticate(
        &self,
        parts: &Parts,
        scope: &str,
        guard: &dyn ReplayGuard,
    ) -> Result<Verified, Failure> {
        let authority = guard.strict_authority().ok_or(Failure::Unavailable)?;
        let now = unix_seconds().ok_or(Failure::Unavailable)?;
        let checked = self.verify(parts, scope, authority, now);
        if let Some((key, expired, expires_at)) = &checked {
            if !expired {
                // 只在密码响应与 nonce 均有效后占用容量；未知 ACK 不重试，不借另一节点的本地账本放行。
                let result = tokio::time::timeout(
                    Duration::from_secs(1),
                    guard.check_and_set_strict(
                        authority,
                        *expires_at,
                        key,
                        Duration::from_secs(self.ttl + 6),
                        parts.extensions.get(),
                    ),
                )
                .await;
                if matches!(result, Ok(true)) {
                    return Ok(Verified {
                        opaque: self.opaque.clone(),
                        consumer: self.consumer.clone(),
                    });
                }
            }
        }
        self.challenge(
            scope,
            authority,
            now,
            checked.is_some_and(|(_, expired, _)| expired),
        )
        .map(Failure::Challenge)
        .map_or_else(|| Err(Failure::Unavailable), Err)
    }

    /// 业务作用：读取只能由严格认证管线创建的身份，普通验签或重放请求不能绕过登记。
    /// 参数说明：
    /// - `parts`：当前授权请求。
    ///
    /// 返回：同一策略已消费凭证的主体；其它策略或未认证请求返回 None。
    pub(crate) fn consumer(&self, parts: &Parts) -> Option<Arc<str>> {
        parts
            .extensions
            .get::<Verified>()
            .filter(|verified| constant_time_eq(verified.opaque.as_bytes(), self.opaque.as_bytes()))
            .map(|verified| verified.consumer.clone())
    }

    /// 业务作用：验证固定 Digest 协议与签名，生成无原始身份的重放键，避免无效输入污染账本。
    /// 参数说明：
    /// - `parts`：原始凭据及目标。
    /// - `scope`：受信入口和路由归属。
    /// - `authority`：冻结账本权威。
    /// - `now`：当前 Unix 秒。
    ///
    /// 返回：密码响应有效时返回规范化重放摘要和过期标志；其它情况返回 None。
    fn verify(
        &self,
        parts: &Parts,
        scope: &str,
        authority: [u8; 32],
        now: u64,
    ) -> Option<(String, bool, u64)> {
        let input = header::Credentials::parse(&parts.headers)?;
        let target = &parts.extensions.get::<OriginalTarget>()?.0;
        if target.authority().is_some()
            || input.get("uri") != target.path_and_query()?.as_str()
            || input.get("realm") != self.realm.as_ref()
            || input.get("algorithm") != self.algorithm()
            || input.get("qop") != "auth"
            || !constant_time_eq(input.get("opaque").as_bytes(), self.opaque.as_bytes())
        {
            return None;
        }
        let user = match input.get("userhash") {
            "" | "false" => {
                constant_time_eq(input.get("username").as_bytes(), self.user.as_bytes())
            }
            "true" => decode_hex::<32>(input.get("username"))
                .is_some_and(|hash| constant_time_eq(&hash, &self.user_hash)),
            _ => false,
        };
        let cnonce = input.get("cnonce");
        let nc = input.get("nc");
        let count = u32::from_be_bytes(decode_hex::<4>(nc)?);
        if !user || cnonce.is_empty() || cnonce.len() > 128 || count == 0 {
            return None;
        }
        let nonce = input.get("nonce");
        if nonce.len() != 112
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let issued = u64::from_str_radix(&nonce[..16], 16).ok()?;
        let binding = self.nonce_binding(scope, authority, &nonce[..48]);
        if !nasa::crypto::hmac_sha256_verify(&binding, &self.secret, &nonce[48..])
            || issued > now.saturating_add(5)
        {
            return None;
        }
        let ha1 = if self.session {
            hex(&hash(&[
                self.ha1.as_bytes(),
                b":",
                nonce.as_bytes(),
                b":",
                cnonce.as_bytes(),
            ]))
        } else {
            String::new()
        };
        let ha1 = if self.session {
            ha1.as_str()
        } else {
            self.ha1.as_ref()
        };
        let ha2 = hex(&hash(&[
            parts.method.as_str().as_bytes(),
            b":",
            input.get("uri").as_bytes(),
        ]));
        let expected = hash(&[
            ha1.as_bytes(),
            b":",
            nonce.as_bytes(),
            b":",
            nc.as_bytes(),
            b":",
            cnonce.as_bytes(),
            b":auth:",
            ha2.as_bytes(),
        ]);
        if !constant_time_eq(&decode_hex::<32>(input.get("response"))?, &expected) {
            return None;
        }
        let key = hex(&hash(&[
            &authority,
            self.opaque.as_bytes(),
            scope.as_bytes(),
            nonce.as_bytes(),
            cnonce.as_bytes(),
            &count.to_be_bytes(),
        ]));
        Some((
            key,
            now.saturating_sub(issued) >= self.ttl,
            issued.checked_add(self.ttl)?,
        ))
    }

    /// 业务作用：签发不占服务端状态的短期挑战，绑定真实账本，防止跨域借用和降级协商。
    /// 参数说明：
    /// - `scope`：授权路由归属。
    /// - `authority`：当前账本身份。
    /// - `now`：签发 Unix 秒。
    /// - `stale`：只有已验证的过期凭据才可标记。
    ///
    /// 返回：合法且不可预测的挑战；熵源或响应头构造失败返回 None。
    fn challenge(
        &self,
        scope: &str,
        authority: [u8; 32],
        now: u64,
        stale: bool,
    ) -> Option<HeaderValue> {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).ok()?;
        let mut nonce = format!("{now:016x}{}", hex(&random));
        nonce.push_str(&nasa::crypto::hmac_sha256(
            &self.nonce_binding(scope, authority, &nonce),
            &self.secret,
        ));
        HeaderValue::from_str(&format!("Digest realm=\"{}\", nonce=\"{nonce}\", opaque=\"{}\", algorithm={}, qop=\"auth\", userhash=true{}", escape_header_quote(&self.realm), self.opaque, self.algorithm(), if stale {
            ", stale=true"
        } else {
            ""
        })).ok()
    }

    /// 业务作用：编码 nonce 的权威绑定，各字段有明确长度以消除拼接歧义。
    /// 参数说明：
    /// - `scope`：配置归属。
    /// - `authority`：账本身份。
    /// - `prefix`：固定长度签发时间与随机数。
    ///
    /// 返回：用于 NASA HMAC 的固定大小摘要文本。
    fn nonce_binding(&self, scope: &str, authority: [u8; 32], prefix: &str) -> String {
        hex(&hash(&[
            &authority,
            self.opaque.as_bytes(),
            &(scope.len() as u64).to_be_bytes(),
            scope.as_bytes(),
            prefix.as_bytes(),
        ]))
    }

    /// 业务作用：提供唯一允许的算法 token，避免客户端选择未声明的降级算法。
    /// 参数说明: 无。
    /// 返回：当前策略的标准算法名称。
    fn algorithm(&self) -> &'static str {
        if self.session {
            "SHA-256-sess"
        } else {
            "SHA-256"
        }
    }
}

/// 业务作用：分段计算 SHA-256，不拼接凭据或请求目标为额外大缓冲。
/// 参数说明：
/// - `parts`：协议规定的顺序字节片段。
///
/// 返回：固定长度摘要。
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

/// 业务作用：生成协议要求的小写摘要表示，不引入 JSON 或额外序列化层。
/// 参数说明：
/// - `bytes`：有界摘要或随机数。
///
/// 返回：每字节两位的十六进制字符串。
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output
}

/// 业务作用：将固定宽度十六进制协议字段规范化，大小写不能制造第二个重放身份。
/// 参数说明：
/// - `value`：待解析的摘要或计数。
///
/// 返回：宽度及字符均合法时返回栈上字节数组。
fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut result = [0; N];
    for (slot, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = (pair[0] as char).to_digit(16)? as u8 * 16 + (pair[1] as char).to_digit(16)? as u8;
    }
    Some(result)
}

/// 业务作用：以单调经过时间推进 nonce 时钟，避免本进程墙钟回拨使过期凭据重新有效。
/// 参数说明: 无。
/// 返回：Unix 秒；早于纪元返回 None。
fn unix_seconds() -> Option<u64> {
    static CLOCK: OnceLock<Option<(Instant, Duration)>> = OnceLock::new();
    let (started, epoch) = CLOCK
        .get_or_init(|| {
            Some((
                Instant::now(),
                SystemTime::now().duration_since(UNIX_EPOCH).ok()?,
            ))
        })
        .as_ref()?;
    Some(epoch.checked_add(started.elapsed())?.as_secs())
}
