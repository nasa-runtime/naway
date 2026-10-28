//! Digest 控制面编译；运行态只保存 HA1 与预编译 nonce 认证材料。

use super::{hash, Policy};
use anyhow::{ensure, Context, Result};
use std::{collections::BTreeMap, path::Path, sync::Arc};

/// 业务作用：编译原生 Digest 声明，在快照发布前拒绝歧义配置与不受支持的密码协议。
/// 参数说明：
/// - `args`：已移除 filter 名称的配置文本。
/// - `directory`：SecretSource 的解析基准目录。
///
/// 返回：完整冻结的策略，off 返回 None；配置不合法时拒绝候选。
pub(crate) fn parse(args: &str, directory: &Path) -> Result<Option<Policy>> {
    if args.trim().eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let mut options = BTreeMap::new();
    for token in args.split_whitespace() {
        let (key, value) = token
            .split_once('=')
            .context("auth_digest requires named options")?;
        ensure!(
            [
                "user",
                "password",
                "ha1",
                "realm",
                "nonce_secret",
                "algorithm",
                "ttl_secs",
                "consumer"
            ]
            .contains(&key),
            "auth_digest unsupported option"
        );
        let value = if value.starts_with(['\'', '"']) {
            ensure!(
                value.len() >= 2 && value.as_bytes().first() == value.as_bytes().last(),
                "auth_digest unterminated option quote"
            );
            &value[1..value.len() - 1]
        } else {
            ensure!(
                !value.ends_with(['\'', '"']),
                "auth_digest unexpected option quote"
            );
            value
        };
        ensure!(
            options.insert(key, value).is_none(),
            "auth_digest duplicate option"
        );
    }
    let user = *options.get("user").context("auth_digest requires user")?;
    let realm = *options.get("realm").context("auth_digest requires realm")?;
    ensure!(
        identity(user) && !user.contains(':'),
        "auth_digest user must be printable ASCII without colon, at most 128 bytes"
    );
    ensure!(
        identity(realm),
        "auth_digest realm must be printable ASCII, at most 128 bytes"
    );
    let consumer = options.get("consumer").copied().unwrap_or(user);
    ensure!(
        identity(consumer) && !consumer.contains(':'),
        "auth_digest invalid consumer"
    );
    let algorithm = options.get("algorithm").copied().unwrap_or("SHA-256");
    let session = match algorithm {
        "SHA-256" => false,
        "SHA-256-sess" => true,
        _ => anyhow::bail!("auth_digest supports SHA-256 or SHA-256-sess"),
    };
    let ttl: u64 = options
        .get("ttl_secs")
        .copied()
        .unwrap_or("60")
        .parse()
        .context("auth_digest invalid ttl_secs")?;
    ensure!(
        (1..=300).contains(&ttl),
        "auth_digest ttl_secs must be 1..300"
    );
    let secret = crate::security::secret::resolve_text(
        options
            .get("nonce_secret")
            .context("auth_digest requires nonce_secret")?,
        directory,
        "auth_digest nonce_secret",
    )?;
    ensure!(
        (32..=4096).contains(&secret.len()),
        "auth_digest nonce_secret must be 32..4096 bytes"
    );
    let ha1 = match (options.get("password"), options.get("ha1")) {
        (Some(raw), None) => {
            let password =
                crate::security::secret::resolve_text(raw, directory, "auth_digest password")?;
            ensure!(
                !password.is_empty()
                    && password.len() <= 4096
                    && !password.chars().any(char::is_control),
                "auth_digest invalid password"
            );
            hash(&[
                user.as_bytes(),
                b":",
                realm.as_bytes(),
                b":",
                password.as_bytes(),
            ])
        }
        (None, Some(raw)) => {
            let value = crate::security::secret::resolve_text(raw, directory, "auth_digest ha1")?;
            super::decode_hex::<32>(&value)
                .context("auth_digest ha1 must be 64 hexadecimal digits")?
        }
        _ => anyhow::bail!("auth_digest requires exactly one password or ha1"),
    };
    let ha1 = super::hex(&ha1);
    let binding = hash(&[
        user.as_bytes(),
        b"\0",
        realm.as_bytes(),
        b"\0",
        algorithm.as_bytes(),
        b"\0",
        ha1.as_bytes(),
        b"\0",
        consumer.as_bytes(),
        &ttl.to_be_bytes(),
    ]);
    let opaque = nasa::crypto::hmac_sha256(&super::hex(&binding), &secret);
    Ok(Some(Policy {
        user: Arc::from(user),
        user_hash: hash(&[user.as_bytes(), b":", realm.as_bytes()]),
        consumer: Arc::from(consumer),
        realm: Arc::from(realm),
        ha1: Arc::from(ha1),
        secret: Arc::from(secret),
        opaque: Arc::from(opaque),
        session,
        ttl,
    }))
}

/// 业务作用：约束身份和挑战字段，保证有界 HeaderValue 与明确的 ASCII 协议边界。
/// 参数说明：
/// - `value`：配置中的身份文本。
///
/// 返回：非空、最多128字节且全部可打印 ASCII 时为 true。
fn identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}
