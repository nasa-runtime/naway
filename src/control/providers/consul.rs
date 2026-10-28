//! Consul 单键线性一致读取与有界长轮询；索引仅控制重读位置，声明版本仍由统一目录裁决。

use anyhow::{ensure, Context, Result};
use base64::Engine;
use parking_lot::Mutex;
use serde::Deserialize;

use super::model::Declaration;

pub(super) struct Reader {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    authorization: Option<http::HeaderValue>,
    key: String,
    long_poll_ms: u64,
    cursor: Mutex<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    key: String,
    value: Option<String>,
    modify_index: u64,
    create_index: u64,
}

/// 业务作用：限制精确单键 API 和长轮询预算，避免路径解释与服务端附加等待越过绝对 deadline。
///
/// 参数说明：
/// - `endpoint`：是固定源地址与键
/// - `key`：是固定源地址与键
/// - `wait`：是毫秒预算。
/// - `deadline`：是毫秒预算。
///
/// 返回：地址仅含 origin、键无路径歧义且保留等待余量时成功，否则拒绝候选。
pub(super) fn validate(endpoint: &reqwest::Url, key: &str, wait: u64, deadline: u64) -> Result<()> {
    ensure!(
        endpoint.path().is_empty() || endpoint.path() == "/",
        "Consul provider endpoint requires an origin"
    );
    ensure!(
        !key.is_empty()
            && key.len() <= 512
            && key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
            && key
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "invalid Consul provider key"
    );
    ensure!(
        (100..=20000).contains(&wait) && wait + wait / 16 + 100 <= deadline,
        "Consul long poll must leave deadline headroom"
    );
    Ok(())
}

impl Reader {
    /// 业务作用：为已审核单键创建传输计划，所有 URL 参数由本地生成，令牌只进入敏感请求头。
    ///
    /// 参数说明：
    /// - `client`：为固定 TLS 与认证
    /// - `endpoint`：为固定 TLS 与认证
    /// - `authorization`：为固定 TLS 与认证
    /// - `key`：为已校验读取范围。
    /// - `long_poll_ms`：为已校验读取范围。
    ///
    /// 返回：初始索引为零的惰性计划；地址不能承载路径时拒绝，不进行网络访问。
    pub(super) fn new(
        client: reqwest::Client,
        mut endpoint: reqwest::Url,
        authorization: Option<http::HeaderValue>,
        key: String,
        long_poll_ms: u64,
    ) -> Result<Self> {
        endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("invalid Consul provider endpoint"))?
            .clear()
            .extend(["v1", "kv"])
            .extend(key.split('/'));
        Ok(Self {
            client,
            endpoint,
            authorization,
            key,
            long_poll_ms,
            cursor: Mutex::new(0),
        })
    }

    /// 业务作用：读取完整单键并在服务端等待后续变化；异常索引先复位再全量重读，不能续期旧路由。
    ///
    /// 参数说明：
    /// - `maximum`：为解码后声明的上限，网络 envelope 额外只保留有限元数据和 Base64 开销。
    ///
    /// 返回：通过精确键、索引和大小检查的声明；失联、缺键、回退、ACL 过滤或无效正文拒绝。
    pub(super) async fn read(&self, maximum: usize) -> Result<Declaration> {
        let index = *self.cursor.lock();
        let mut url = self.endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("consistent", "true")
                .append_pair("wait", &format!("{}ms", self.long_poll_ms));
            if index > 0 {
                query.append_pair("index", &index.to_string());
            }
        }
        let mut request = self
            .client
            .get(url)
            .header(http::header::ACCEPT, "application/json")
            .header(http::header::ACCEPT_ENCODING, "identity");
        if let Some(token) = &self.authorization {
            request = request.header("x-consul-token", token.clone());
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Consul provider transport unavailable"))?;
        let next = response
            .headers()
            .get("x-consul-index")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .context("Consul provider index absent")?;
        if next == 0 || next < index {
            // 快照恢复或服务端索引变化使旧游标失效；重读位置可复位，但统一声明水位绝不回退。
            *self.cursor.lock() = if next == 0 {
                1
            } else {
                0
            };
            anyhow::bail!("Consul provider index requires relist");
        }
        ensure!(
            response.status() == http::StatusCode::OK,
            "Consul provider key unavailable"
        );
        ensure!(
            response
                .headers()
                .get("x-consul-results-filtered-by-acls")
                .is_none_or(|value| value == "false"),
            "Consul provider ACL filtered response rejected"
        );
        ensure!(
            response
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .is_none_or(|value| value == "identity"),
            "Consul provider compression unsupported"
        );
        ensure!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .map(str::trim)
                == Some("application/json"),
            "Consul provider content type rejected"
        );
        let envelope_maximum = maximum.saturating_add(2) / 3 * 4 + 4096;
        ensure!(
            response
                .content_length()
                .is_none_or(|size| size <= envelope_maximum as u64),
            "Consul provider envelope budget reached"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("Consul provider read interrupted"))?
        {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= envelope_maximum,
                "Consul provider envelope budget reached"
            );
            bytes.extend_from_slice(&chunk);
        }
        let mut entries: Vec<Entry> = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("Consul provider envelope rejected"))?;
        ensure!(
            entries.len() == 1,
            "Consul provider requires exactly one key"
        );
        let entry = entries.pop().context("Consul provider key missing")?;
        ensure!(
            entry.key == self.key
                && entry.create_index > 0
                && entry.create_index <= entry.modify_index
                && entry.modify_index <= next,
            "Consul provider identity or version rejected"
        );
        let value = entry.value.context("Consul provider document absent")?;
        ensure!(
            value.len() <= maximum.div_ceil(3) * 4,
            "Consul provider encoded document budget reached"
        );
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| anyhow::anyhow!("Consul provider encoding rejected"))?;
        ensure!(
            decoded.len() <= maximum,
            "Consul provider document byte budget reached"
        );
        let document = crate::config::document::decode(&decoded, maximum)
            .map_err(|_| anyhow::anyhow!("Consul provider document rejected"))?;
        // 游标只减少重复等待；尚未完整构建的声明仍不能更新已发布目录或来源新鲜度。
        *self.cursor.lock() = next;
        Ok(document)
    }
}
