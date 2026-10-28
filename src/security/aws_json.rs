//! 固定 AWS JSON 操作的 SigV4 认证；调用方先冻结 endpoint、区域、最小权限与本地凭据。

use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use http::HeaderValue;
use sha2::{Digest, Sha256};

pub(crate) enum Operation {
    SecretValue,
    #[cfg(feature = "config-providers")]
    ListTasks,
    #[cfg(feature = "config-providers")]
    DescribeTasks,
}

pub(crate) struct Credentials<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a [u8],
    pub session_token: Option<&'a HeaderValue>,
}

pub(crate) struct Scope<'a> {
    pub region: &'a str,
    pub operation: Operation,
}

/// 业务作用：为受限 AWS JSON 请求绑定固定操作、区域、精确正文与临时凭据，不能用远端参数替换签名操作。
///
/// 参数说明：
/// - `request`：为同一冻结 POST 目标
/// - `url`：为同一冻结 POST 目标
/// - `scope`：是已授权的操作范围与本地凭据
/// - `credentials`：是已授权的操作范围与本地凭据
/// - `body`：为最终实体
/// - `now`：为签名时刻。
///
/// 返回：包含敏感认证头的请求；不合规凭据、歧义 endpoint 或 HMAC 失败拒绝，不发送网络请求。
pub(crate) fn sign(
    request: reqwest::RequestBuilder,
    url: &reqwest::Url,
    scope: Scope<'_>,
    credentials: Credentials<'_>,
    body: &[u8],
    now: DateTime<Utc>,
) -> Result<reqwest::RequestBuilder> {
    ensure!(
        url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none(),
        "AWS JSON signing endpoint rejected"
    );
    ensure!(
        !scope.region.is_empty()
            && scope.region.len() <= 64
            && scope
                .region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "AWS signing region rejected"
    );
    ensure!(
        !credentials.access_key_id.is_empty()
            && credentials.access_key_id.len() <= 128
            && credentials
                .access_key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
            && !credentials.secret_access_key.is_empty()
            && credentials.secret_access_key.len() <= 4096,
        "AWS signing credential rejected"
    );
    let (service, target) = match scope.operation {
        Operation::SecretValue => ("secretsmanager", "secretsmanager.GetSecretValue"),
        #[cfg(feature = "config-providers")]
        Operation::ListTasks => ("ecs", "AmazonEC2ContainerServiceV20141113.ListTasks"),
        #[cfg(feature = "config-providers")]
        Operation::DescribeTasks => ("ecs", "AmazonEC2ContainerServiceV20141113.DescribeTasks"),
    };
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let authority = url
        .as_str()
        .parse::<http::Uri>()
        .context("AWS signing endpoint invalid")?;
    let host = authority
        .authority()
        .context("AWS signing host missing")?
        .as_str();
    let payload_hash = sha256_hex(body);
    let mut headers = std::collections::BTreeMap::from([
        ("content-type", "application/x-amz-json-1.1".to_owned()),
        ("host", host.to_owned()),
        ("x-amz-content-sha256", payload_hash.clone()),
        ("x-amz-date", amz_date.clone()),
        ("x-amz-target", target.to_owned()),
    ]);
    if let Some(token) = credentials.session_token {
        let token = token.to_str().context("AWS session token invalid")?;
        ensure!(
            !token.is_empty() && token.len() <= 16384 && !token.chars().any(char::is_whitespace),
            "AWS session token rejected"
        );
        headers.insert("x-amz-security-token", token.to_owned());
    }
    let signed_headers = headers.keys().copied().collect::<Vec<_>>().join(";");
    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let canonical_request =
        format!("POST\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let region = scope.region;
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let mut prefixed = b"AWS4".to_vec();
    prefixed.extend_from_slice(credentials.secret_access_key);
    let date_key = hmac_sha256(&prefixed, date.as_bytes())?;
    let region_key = hmac_sha256(&date_key, region.as_bytes())?;
    let service_key = hmac_sha256(&region_key, service.as_bytes())?;
    let signing_key = hmac_sha256(&service_key, b"aws4_request")?;
    let signature = hex(&hmac_sha256(&signing_key, to_sign.as_bytes())?);
    let mut authorization=HeaderValue::from_str(&format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",credentials.access_key_id)).context("AWS signature header invalid")?;
    authorization.set_sensitive(true);
    let mut request = request;
    for (name, value) in headers {
        let mut value = HeaderValue::from_str(&value).context("AWS signed header invalid")?;
        if name == "x-amz-security-token" {
            value.set_sensitive(true);
        }
        request = request.header(name, value);
    }
    Ok(request.header(http::header::AUTHORIZATION, authorization))
}

/// 业务作用：按 SigV4 层次派生二进制密钥，不把中间 MAC 当成 UTF-8 文本再次签名。
///
/// 参数说明：
/// - `key`：为该层密钥与绑定内容。
/// - `data`：为该层密钥与绑定内容。
///
/// 返回：固定三十二字节认证码，初始化失败拒绝签名。
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).context("AWS HMAC initialization failed")?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// 业务作用：将精确请求实体或规范化请求绑定成 AWS 所需 SHA-256 小写摘要。
///
/// 参数说明：
/// - `bytes`：为待签名的完整有限字节。
///
/// 返回：六十四个 ASCII 十六进制字符。
fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// 业务作用：保持 AWS 摘要与签名在线路上的小写十六进制表示。
///
/// 参数说明：
/// - `bytes`：为固定摘要或 MAC。
///
/// 返回：两倍字节长度的 ASCII 文本，不包含原始凭据。
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
