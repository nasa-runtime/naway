//! 共用纯声明解析，管理草稿与运行策略对字段、来源和材料保持同一解释。

use super::super::{
    filter_args, starts_filter, unquote_token, validate_basic_auth_user, validate_query_key_name,
};
use anyhow::{bail, ensure, Context, Result};
use http::header::HeaderName;

pub(crate) enum Source<'a> {
    Header(HeaderName),
    Query(&'a str),
}

pub(crate) enum Material<'a> {
    Secret(&'a str),
    Sha256([u8; 32]),
}

pub(crate) struct Declaration<'a> {
    pub source: Source<'a>,
    pub material: Material<'a>,
    pub consumer: Option<&'a str>,
    pub enabled: bool,
}

/// 业务作用：按运行时相同的指令边界识别密钥策略，不把相似名称当成可管理凭据。
///
/// 参数说明：
/// - `spec`：未求值的原始 filter 声明。
///
/// 返回：精确 API-Key 指令为真；其它处理链条目保持原样。
pub(crate) fn accepts(spec: &str) -> bool {
    starts_filter(spec.trim(), "api_key")
}

/// 业务作用：验证密钥来源、主体、启用状态和材料声明，供草稿与完整构建共用且不读取任何依赖。
///
/// 参数说明：
/// - `spec`：一条原始 API-Key 声明，引用仅作为借用字符串保留。
///
/// 返回：无歧义的原生声明；非法或重复字段拒绝，SecretSource 尚未求值。
pub(crate) fn parse(spec: &str) -> Result<Declaration<'_>> {
    ensure!(accepts(spec), "api_key directive required");
    let rest = filter_args(spec.trim(), "api_key").trim();
    ensure!(!rest.is_empty(), "api_key requires source and material");
    let mut source = None;
    let mut value = None;
    let mut digest = None;
    let mut consumer = None;
    let mut enabled = None;
    for token in rest.split_whitespace() {
        let (key, raw_value) = token
            .split_once('=')
            .context("api_key options must be key=value")?;
        let raw_value = unquote_token(raw_value.trim());
        match key {
            "header" => {
                ensure!(source.is_none(), "api_key requires one source declaration");
                source = Some(Source::Header(
                    raw_value.parse().context("api_key invalid header name")?,
                ));
            }
            "query" => {
                ensure!(source.is_none(), "api_key requires one source declaration");
                validate_query_key_name(raw_value)?;
                source = Some(Source::Query(raw_value));
            }
            "value" | "key" | "secret" => {
                ensure!(value.is_none(), "api_key requires one value declaration");
                value = Some(raw_value);
            }
            "sha256" => {
                ensure!(digest.is_none(), "api_key requires one digest declaration");
                digest = Some(raw_value);
            }
            "consumer" => {
                ensure!(
                    consumer.is_none(),
                    "api_key requires one consumer declaration"
                );
                validate_basic_auth_user(raw_value)?;
                consumer = Some(raw_value);
            }
            "enabled" => {
                ensure!(
                    enabled.is_none(),
                    "api_key requires one enabled declaration"
                );
                enabled = Some(match raw_value {
                    "true" => true,
                    "false" => false,
                    _ => bail!("api_key enabled must be true or false"),
                });
            }
            _ => bail!("api_key unsupported option"),
        }
    }
    ensure!(
        value.is_some() ^ digest.is_some(),
        "api_key requires exactly one of value or sha256"
    );
    let material = match value {
        Some(reference) => Material::Secret(reference),
        None => Material::Sha256(sha256(digest.expect("exclusive material checked"))?),
    };
    Ok(Declaration {
        source: source.context("api_key requires header or query source")?,
        material,
        consumer,
        enabled: enabled.unwrap_or(true),
    })
}

/// 业务作用：在字节解码前拒绝非 ASCII 或非法摘要，管理与运行时不能对同一材料有不同解释。
///
/// 参数说明：
/// - `value`：64个十六进制 ASCII 字符。
///
/// 返回：完整32字节摘要；任一非法字符或长度均拒绝。
fn sha256(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "api_key sha256 must contain 64 ASCII hex characters"
    );
    let mut digest = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).expect("checked ASCII digest");
        digest[index] = u8::from_str_radix(pair, 16).expect("checked hexadecimal digest");
    }
    Ok(digest)
}
