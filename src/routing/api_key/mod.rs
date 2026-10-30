//! API-Key 声明编译与请求认证，禁用凭据仍保留路由的认证保护。

pub(crate) mod declaration;

use super::{query_param_raw, validate_basic_auth_secret};
use crate::security::auth::constant_time_eq;
use anyhow::Result;
use http::{header::HeaderName, request::Parts};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};

/// API-Key 已编译策略。
///
/// 数据面只读取一个 header 或 query 参数,并与构建期保存的 key 做常量时间比较。
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKeyPolicy {
    /// 只控制本凭据的匹配资格，关闭后仍保留已配置的 API-Key 认证方式。
    enabled: bool,
    /// SHA-256 前128位的稳定十六进制身份；构建期生成，不保存原始秘密于账本键。
    pub(super) fingerprint: Arc<str>,
    /// API-Key 来源。
    pub(super) source: ApiKeySource,
    /// 构建期保存的明文 SecretSource 结果或管理面生成的不可逆摘要。
    expected: ApiKeyExpected,
    /// 可选稳定 consumer 名；绝不使用原始 API key 作为管理面标识。
    pub(super) consumer: Option<Arc<str>>,
}

/// API-Key 的构建期校验材料；摘要模式使 Console 创建 key 后无需把原值写回配置事实源。
#[derive(Clone, PartialEq, Eq)]
enum ApiKeyExpected {
    /// 兼容既有声明式 SecretSource，运行态以常量时间直接比较。
    Plain(Vec<u8>),
    /// 管理面生成 key 的 SHA-256，原值只在创建响应中出现一次。
    Sha256([u8; 32]),
}

/// API-Key 来源。
#[derive(Clone, PartialEq, Eq)]
pub(super) enum ApiKeySource {
    /// 从请求头读取。
    Header(HeaderName),
    /// 从 query 参数读取。
    Query(String),
}

impl ApiKeyPolicy {
    /// 业务作用：验证请求携带的 API-Key，并统一兼容 SecretSource 明文和 Console 不可逆摘要两种事实。
    ///
    /// 参数说明：
    /// - `parts`：是下游请求 head。
    ///
    /// 返回：已启用且指定 header/query 与期望材料常量时间一致时为真；已撤销、缺失或材料不一致均为假。
    pub(super) fn matches(&self, parts: &Parts) -> bool {
        // 撤销保留策略存在性，让最后一把密钥失效后仍走认证拒绝，而不是把路由变成匿名入口。
        if !self.enabled {
            return false;
        }
        let value = match &self.source {
            ApiKeySource::Header(name) => parts
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok()),
            ApiKeySource::Query(name) => {
                query_param_raw(parts.uri.query().unwrap_or_default(), name)
            }
        };
        value.is_some_and(|value| match &self.expected {
            ApiKeyExpected::Plain(expected) => {
                constant_time_eq(value.as_bytes(), expected.as_slice())
            }
            ApiKeyExpected::Sha256(expected) => {
                let actual: [u8; 32] = Sha256::digest(value.as_bytes()).into();
                constant_time_eq(actual.as_slice(), expected.as_slice())
            }
        })
    }
}

/// 业务作用：把 route 的 `api_key` 声明编译为固定来源和校验材料，拒绝混合明文/摘要或不完整规则。
///
/// 参数说明：
/// - `spec`：是 route filter 原始字符串
/// - `config_dir`：限定 SecretSource 相对路径。
///
/// 返回：合法声明返回不可变策略；禁用仍完整校验，重复、歧义或非法材料拒绝整个候选。
pub(super) fn parse_api_key(spec: &str, config_dir: &Path) -> Result<ApiKeyPolicy> {
    // 纯声明先确认来源与身份，非法声明不能触发文件、环境或远程秘密求值。
    let declaration = declaration::parse(spec)?;
    let source = match declaration.source {
        declaration::Source::Header(name) => ApiKeySource::Header(name),
        declaration::Source::Query(name) => ApiKeySource::Query(name.to_owned()),
    };
    let expected = match declaration.material {
        declaration::Material::Secret(reference) => {
            let value =
                crate::security::secret::resolve_text(reference, config_dir, "api_key value")?;
            validate_basic_auth_secret("api_key value", &value)?;
            ApiKeyExpected::Plain(value.into_bytes())
        }
        declaration::Material::Sha256(digest) => ApiKeyExpected::Sha256(digest),
    };
    let digest: [u8; 32] = match &expected {
        ApiKeyExpected::Plain(value) => Sha256::digest(value).into(),
        ApiKeyExpected::Sha256(digest) => *digest,
    };
    let mut fingerprint = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in &digest[..16] {
        write!(&mut fingerprint, "{byte:02x}").expect("SHA-256 hex formatting");
    }
    Ok(ApiKeyPolicy {
        enabled: declaration.enabled,
        fingerprint: Arc::from(fingerprint),
        source,
        expected,
        consumer: declaration.consumer.map(Arc::from),
    })
}
