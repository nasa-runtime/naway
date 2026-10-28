//! etcd 精确单键的 watch 提示与线性一致重读；提示、取消和 compaction 均不直接形成发布证据。

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use base64::Engine;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};

use super::model::Declaration;

pub(super) struct Reader {
    client: reqwest::Client,
    range_url: reqwest::Url,
    watch_url: reqwest::Url,
    authorization: Option<http::HeaderValue>,
    key: String,
    cluster_id: u64,
    long_poll_ms: u64,
    cursor: Mutex<u64>,
}

#[derive(Deserialize)]
struct Header {
    cluster_id: String,
    revision: String,
}

#[derive(Deserialize)]
struct Entry {
    key: String,
    value: String,
    create_revision: String,
    mod_revision: String,
    version: String,
}

#[derive(Deserialize)]
struct Range {
    header: Header,
    #[serde(default)]
    kvs: Vec<Entry>,
    #[serde(default)]
    more: bool,
    #[serde(default)]
    count: String,
}

/// 业务作用：固定集群身份与精确键，为 watch 后的线性一致重读保留 deadline 余量。
///
/// 参数说明：
/// - `endpoint`：是本地授权的事实源
/// - `key`：是本地授权的事实源
/// - `cluster_id`：是本地授权的事实源
/// - `wait`：为毫秒预算。
/// - `deadline`：为毫秒预算。
///
/// 返回：origin、键和时间预算合法时给出无损解析的非零集群标识，否则拒绝候选。
pub(super) fn validate(
    endpoint: &reqwest::Url,
    key: &str,
    cluster_id: &str,
    wait: u64,
    deadline: u64,
) -> Result<u64> {
    let cluster_id = number(cluster_id)?;
    ensure!(
        endpoint.path().is_empty() || endpoint.path() == "/",
        "etcd provider endpoint requires an origin"
    );
    ensure!(
        !key.is_empty()
            && key.len() <= 512
            && !key.chars().any(char::is_control)
            && cluster_id != 0,
        "invalid etcd provider key or cluster identity"
    );
    ensure!(
        (100..=20000).contains(&wait) && wait + 500 <= deadline,
        "etcd watch must leave read deadline headroom"
    );
    Ok(cluster_id)
}

impl Reader {
    /// 业务作用：建立固定集群的精确单键读取计划，不给来源任务任何写入或任意范围读取入口。
    ///
    /// 参数说明：
    /// - `client`：为本地 TLS 与令牌
    /// - `endpoint`：为本地 TLS 与令牌
    /// - `authorization`：为本地 TLS 与令牌
    /// - `key`：已由本地计划校验。
    /// - `cluster_id`：已由本地计划校验。
    /// - `long_poll_ms`：已由本地计划校验。
    ///
    /// 返回：无网络副作用的惰性计划；URL 不能组合为固定 API 时拒绝。
    pub(super) fn new(
        client: reqwest::Client,
        endpoint: reqwest::Url,
        authorization: Option<http::HeaderValue>,
        key: String,
        cluster_id: u64,
        long_poll_ms: u64,
    ) -> Result<Self> {
        Ok(Self {
            client,
            range_url: endpoint.join("/v3/kv/range")?,
            watch_url: endpoint.join("/v3/watch")?,
            authorization,
            key: base64::engine::general_purpose::STANDARD.encode(key),
            cluster_id,
            long_poll_ms,
            cursor: Mutex::new(0),
        })
    }

    /// 业务作用：将更新通知、watch 断开和 compaction 统一转成完整线性一致读取，只有完整正文可续期。
    ///
    /// 参数说明：
    /// - `maximum`：为声明正文硬上限；调用者另包围来源绝对 deadline。
    ///
    /// 返回：集群、键、revision 与正文都合法的声明；任何读源失败不改变已发布水位。
    pub(super) async fn read(&self, maximum: usize) -> Result<Declaration> {
        let cursor = *self.cursor.lock();
        if cursor > 0 {
            // watch 只提供重读时机，不承诺完整状态；超时、断开、取消或压缩历史后都重新取得线性一致证据。
            let _ = tokio::time::timeout(
                Duration::from_millis(self.long_poll_ms),
                self.watch(cursor, maximum),
            )
            .await;
        }
        let response = self
            .request(
                &self.range_url,
                &json!({
                    "key":self.key,
                    "limit":"1",
                    "serializable":false
                }),
            )
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("etcd provider range unavailable"))?;
        validate_response(&response)?;
        let bytes = bounded_body(response, envelope_limit(maximum)).await?;
        let mut range: Range = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("etcd provider range rejected"))?;
        ensure!(
            number(&range.header.cluster_id)? == self.cluster_id,
            "etcd provider cluster identity changed"
        );
        let revision = revision_value(&range.header.revision)?;
        if revision < cursor {
            // 恢复后的传输 revision 可以变化，但旧声明不能越过统一目录水位；先重置 watch 位置再全量重读。
            *self.cursor.lock() = 0;
            anyhow::bail!("etcd provider revision requires relist");
        }
        ensure!(
            !range.more && range.count == "1" && range.kvs.len() == 1,
            "etcd provider requires exactly one key"
        );
        let entry = range.kvs.pop().context("etcd provider key absent")?;
        let created = revision_value(&entry.create_revision)?;
        let modified = revision_value(&entry.mod_revision)?;
        ensure!(
            entry.key == self.key
                && created <= modified
                && modified <= revision
                && revision_value(&entry.version)? > 0,
            "etcd provider key or version rejected"
        );
        ensure!(
            entry.value.len() <= maximum.saturating_add(2) / 3 * 4,
            "etcd provider encoded document budget reached"
        );
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(entry.value)
            .map_err(|_| anyhow::anyhow!("etcd provider encoding rejected"))?;
        ensure!(
            decoded.len() <= maximum,
            "etcd provider document byte budget reached"
        );
        let document = crate::config::document::decode(&decoded, maximum)
            .map_err(|_| anyhow::anyhow!("etcd provider document rejected"))?;
        *self.cursor.lock() = revision;
        Ok(document)
    }

    /// 业务作用：在有界消息与字节预算内等待单键提示；事件内容不直接进入路由编译或来源新鲜度。
    ///
    /// 参数说明：
    /// - `cursor`：为最近完整读取 revision
    /// - `maximum`：约束单轮全部 watch 字节。
    ///
    /// 返回：出现事件、取消或流结束时完成；超限、畸形或身份不符拒绝提示，由上层重新读取。
    async fn watch(&self, cursor: u64, maximum: usize) -> Result<()> {
        let next = cursor
            .checked_add(1)
            .context("etcd watch revision exhausted")?;
        let mut response = self
            .request(
                &self.watch_url,
                &json!({
                    "create_request":{
                        "key":self.key,
                        "start_revision":next.to_string(),
                        "progress_notify":true
                    }
                }),
            )
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("etcd provider watch unavailable"))?;
        validate_response(&response)?;
        let limit = envelope_limit(maximum);
        let mut buffer = Vec::new();
        let mut total = 0usize;
        let mut frames = 0usize;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("etcd provider watch interrupted"))?
        {
            total = total.saturating_add(chunk.len());
            ensure!(total <= limit, "etcd provider watch byte budget reached");
            buffer.extend_from_slice(&chunk);
            while let Some(end) = buffer.iter().position(|byte| *byte == b'\n') {
                frames += 1;
                ensure!(frames <= 16, "etcd provider watch message budget reached");
                let frame: Value = serde_json::from_slice(&buffer[..end])
                    .map_err(|_| anyhow::anyhow!("etcd provider watch frame rejected"))?;
                let result = frame
                    .get("result")
                    .and_then(Value::as_object)
                    .context("etcd provider watch result absent")?;
                let cluster = result
                    .get("header")
                    .and_then(|header| header.get("cluster_id"))
                    .and_then(Value::as_str)
                    .context("etcd provider watch identity absent")?;
                ensure!(
                    number(cluster)? == self.cluster_id,
                    "etcd provider watch identity changed"
                );
                if result.get("canceled").and_then(Value::as_bool) == Some(true)
                    || result
                        .get("events")
                        .and_then(Value::as_array)
                        .is_some_and(|events| !events.is_empty())
                {
                    return Ok(());
                }
                buffer.drain(..=end);
            }
        }
        Ok(())
    }

    /// 业务作用：为固定只读 API 添加认证与无压缩声明，不能由远端正文决定请求目标。
    ///
    /// 参数说明：
    /// - `url`：为本计划内部固定 API
    /// - `body`：仅由精确键和本地游标生成。
    ///
    /// 返回：未发送的 HTTP 请求，敏感令牌不进入 URL 或正文。
    fn request(&self, url: &reqwest::Url, body: &Value) -> reqwest::RequestBuilder {
        let mut request = self
            .client
            .post(url.clone())
            .header(http::header::ACCEPT, "application/json")
            .header(http::header::ACCEPT_ENCODING, "identity")
            .json(body);
        if let Some(token) = &self.authorization {
            request = request.header(http::header::AUTHORIZATION, token.clone());
        }
        request
    }
}

/// 业务作用：拒绝把错误、压缩或未知媒体类型当作 etcd 状态证据。
///
/// 参数说明：
/// - `response`：为尚未读取正文的响应。
///
/// 返回：仅成功的未压缩 JSON 响应通过，不回显远端错误正文。
fn validate_response(response: &reqwest::Response) -> Result<()> {
    ensure!(
        response.status() == http::StatusCode::OK,
        "etcd provider response rejected"
    );
    ensure!(
        response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .is_none_or(|value| value == "identity"),
        "etcd provider compression unsupported"
    );
    ensure!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            == Some("application/json"),
        "etcd provider content type rejected"
    );
    Ok(())
}

/// 业务作用：为 Base64 正文与有限协议元数据保留网络 envelope 上限。
///
/// 参数说明：
/// - `maximum`：为已验证的声明字节预算。
///
/// 返回：包含 Base64 扩展和 4096 字节元数据的固定上限。
fn envelope_limit(maximum: usize) -> usize {
    maximum.saturating_add(2) / 3 * 4 + 4096
}

/// 业务作用：在聚合单键响应前逐块执行硬字节门，拒绝无 Content-Length 的超大响应。
///
/// 参数说明：
/// - `response`：为已审核的响应
/// - `maximum`：是 envelope 上限。
///
/// 返回：完整有界字节；中断或超限直接失败，不返回部分声明。
async fn bounded_body(mut response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= maximum as u64),
        "etcd provider envelope budget reached"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("etcd provider read interrupted"))?
    {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= maximum,
            "etcd provider envelope budget reached"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// 业务作用：按 protobuf JSON 的十进制字符串解析身份与序号，拒绝浮点或符号歧义。
///
/// 参数说明：
/// - `value`：为协议中的十进制文本。
///
/// 返回：无符号整数；空值、非数字或溢出拒绝。
fn number(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid etcd numeric field"
    );
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("etcd numeric field overflow"))
}

/// 业务作用：限制 etcd revision/version 为正的有符号 64 位协议值。
///
/// 参数说明：
/// - `value`：是十进制 revision 或 version。
///
/// 返回：处于 1..=i64::MAX 的值，否则拒绝。
fn revision_value(value: &str) -> Result<u64> {
    let value = number(value)?;
    ensure!(
        (1..=i64::MAX as u64).contains(&value),
        "invalid etcd revision"
    );
    Ok(value)
}
