//! 不导出私钥的远程密码操作与 TLS 签名桥接。

mod semantic;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

#[cfg(feature = "pkcs11")]
use std::num::NonZeroUsize;
#[cfg(feature = "pkcs11")]
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine as _;
use futures::StreamExt as _;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Serialize;
use sha2::Digest as _;
use tokio_rustls::rustls::pki_types::SubjectPublicKeyInfoDer;
use tokio_rustls::rustls::sign::{Signer, SigningKey};
use tokio_rustls::rustls::{Error as TlsError, SignatureAlgorithm, SignatureScheme};

#[cfg(feature = "pkcs11")]
use crate::config::model::Pkcs11CryptoProviderCfg;
use crate::config::model::{
    ExternalCryptoProviderCfg, ExternalPrivateKeyCfg, RemoteSecretEnvelopeCfg,
};

const MAX_PROVIDER_COUNT: usize = 32;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

struct CircuitState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

/// 已解析的固定 HTTPS 密码 provider；敏感认证材料不实现 Debug 或 Serialize。
pub struct ExternalCryptoProvider {
    backend: ExternalCryptoBackend,
    allowed_algorithms: Vec<SignatureScheme>,
    timeout: Duration,
    max_input_bytes: usize,
    max_response_bytes: usize,
    queue_capacity: usize,
    max_concurrency: usize,
    concurrency: Arc<tokio::sync::Semaphore>,
    circuit_failure_threshold: u32,
    circuit_open: Duration,
    circuit: parking_lot::Mutex<CircuitState>,
    identity: [u8; 32],
}

enum ExternalCryptoBackend {
    Https {
        endpoint: reqwest::Url,
        authorization: Option<HeaderValue>,
        client: reqwest::Client,
    },
    #[cfg(feature = "pkcs11")]
    Pkcs11(Pkcs11Provider),
}

#[cfg(feature = "pkcs11")]
struct Pkcs11Provider {
    returned: crossbeam_channel::Sender<cryptoki::session::Session>,
    available: crossbeam_channel::Receiver<cryptoki::session::Session>,
    timeout: Duration,
}

/// 单次配置快照共享的外部密码 provider 目录。
///
/// 目录按全局唯一名称持有 provider，使多个证书身份和 envelope 操作共同遵守同一并发门与熔断状态。
pub struct ExternalCryptoCatalog {
    providers: HashMap<String, Arc<ExternalCryptoProvider>>,
}

/// 一条远程 Secret envelope 对不可导出 KEK 的已冻结引用。
#[derive(Clone)]
pub struct ExternalEnvelopePlan {
    provider: Arc<ExternalCryptoProvider>,
    key_id: Arc<str>,
    aad_context: Arc<str>,
}

impl std::fmt::Debug for ExternalCryptoProvider {
    /// 业务作用：提供不含 endpoint path、认证值、CA 或客户端私钥的低敏诊断。
    ///
    /// 参数说明：
    /// - `formatter`：是标准格式化目标。
    ///
    /// 返回：只输出算法数量与公开资源预算。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalCryptoProvider")
            .field("algorithm_count", &self.allowed_algorithms.len())
            .field("max_input_bytes", &self.max_input_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_concurrency", &self.max_concurrency)
            .finish()
    }
}

/// 一张 TLS 证书对远程 signer 的已冻结引用。
#[derive(Clone)]
pub struct ExternalPrivateKeyPlan {
    provider: Arc<ExternalCryptoProvider>,
    key_id: Arc<str>,
    schemes: Arc<[SignatureScheme]>,
    algorithm: SignatureAlgorithm,
    identity: [u8; 32],
}

impl PartialEq for ExternalPrivateKeyPlan {
    /// 业务作用：按非敏感内容身份比较外部 signer 计划，使配置热更能识别 provider 或 key 变化。
    ///
    /// 参数说明：
    /// - `other`：是候选 signer 计划。
    ///
    /// 返回：provider、key reference 与算法集合一致时为 true。
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl Eq for ExternalPrivateKeyPlan {}

impl std::fmt::Debug for ExternalPrivateKeyPlan {
    /// 业务作用：避免 key identity 或 provider endpoint 进入 TLS 配置诊断。
    ///
    /// 参数说明：
    /// - `formatter`：是标准格式化目标。
    ///
    /// 返回：仅输出 signature scheme 集合。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalPrivateKeyPlan")
            .field("schemes", &self.schemes)
            .finish()
    }
}

#[derive(Serialize)]
struct OperationRequest<'a> {
    operation: &'a str,
    key_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<&'a str>,
    input_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    aad_base64: Option<String>,
}

struct SignCommand {
    scheme: SignatureScheme,
    message: Vec<u8>,
    completed: mpsc::SyncSender<Result<Vec<u8>>>,
}

struct KeylessDispatcher {
    sender: crossbeam_channel::Sender<SignCommand>,
    timeout: Duration,
    max_input_bytes: usize,
}

impl std::fmt::Debug for KeylessDispatcher {
    /// 业务作用：提供不暴露 provider 与 key identity 的签名桥运行态诊断。
    ///
    /// 参数说明：
    /// - `formatter`：是标准格式化目标。
    ///
    /// 返回：只输出 deadline 与输入字节上限。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeylessDispatcher")
            .field("timeout", &self.timeout)
            .field("max_input_bytes", &self.max_input_bytes)
            .finish()
    }
}

struct ExternalSigningKey {
    dispatcher: Arc<KeylessDispatcher>,
    schemes: Arc<[SignatureScheme]>,
    algorithm: SignatureAlgorithm,
    public_key: SubjectPublicKeyInfoDer<'static>,
}

impl std::fmt::Debug for ExternalSigningKey {
    /// 业务作用：输出 TLS 协商算法而不暴露 provider、key identity 或证书公钥字节。
    ///
    /// 参数说明：
    /// - `formatter`：是标准格式化目标。
    ///
    /// 返回：仅输出允许的 signature scheme。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalSigningKey")
            .field("schemes", &self.schemes)
            .finish()
    }
}

struct ExternalSigner {
    dispatcher: Arc<KeylessDispatcher>,
    scheme: SignatureScheme,
}

impl std::fmt::Debug for ExternalSigner {
    /// 业务作用：只暴露本次 TLS 已选择的公开签名算法。
    ///
    /// 参数说明：
    /// - `formatter`：是标准格式化目标。
    ///
    /// 返回：不包含 message、签名或远程 key 信息。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}

impl SigningKey for ExternalSigningKey {
    /// 业务作用：只从 provider 与证书共同允许的算法中选择客户端已声明支持的方案。
    ///
    /// 参数说明：
    /// - `offered`：是客户端提供的 signature schemes，顺序不改变服务端 allowlist。
    ///
    /// 返回：找到交集时返回同步签名桥；没有安全交集时拒绝该证书身份。
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.schemes
            .iter()
            .find(|scheme| offered.contains(scheme))
            .copied()
            .map(|scheme| {
                Box::new(ExternalSigner {
                    dispatcher: self.dispatcher.clone(),
                    scheme,
                }) as Box<dyn Signer>
            })
    }

    /// 业务作用：向 rustls 提供证书内同一 SPKI，使其可在发布前复验证书与外部 key 身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回从叶证书解析的公开 SPKI，不触及私钥。
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.public_key.clone())
    }

    /// 业务作用：声明外部 key 的公钥算法族，约束 rustls 的签名协商。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回构建期从全部 scheme 一致推导的算法族。
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

impl Signer for ExternalSigner {
    /// 业务作用：把 rustls 待签名 message 投递到有界专用 worker，并在 deadline 内等待远程结果。
    ///
    /// 参数说明：
    /// - `message`：是 rustls 生成的握手签名输入，长度受 provider 配置硬门约束。
    ///
    /// 返回：队列、熔断、deadline、provider 或签名格式失败时拒绝握手；绝不回退本地私钥。
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, TlsError> {
        if message.len() > self.dispatcher.max_input_bytes {
            return Err(TlsError::General(
                "external signer input exceeds configured limit".to_owned(),
            ));
        }
        let (completed, receiver) = mpsc::sync_channel(1);
        self.dispatcher
            .sender
            .try_send(SignCommand {
                scheme: self.scheme,
                message: message.to_vec(),
                completed,
            })
            .map_err(|_| TlsError::General("external signer queue unavailable".to_owned()))?;
        let wait = || {
            receiver
                .recv_timeout(self.dispatcher.timeout)
                .map_err(|_| anyhow::anyhow!("external signer deadline exceeded"))?
        };
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(wait)
            }
            _ => wait(),
        };
        result.map_err(|_| TlsError::General("external signer operation failed".to_owned()))
    }

    /// 业务作用：向 rustls 报告本 signer 固定使用的公开 signature scheme。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回构建期冻结且客户端已提供的 scheme。
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl ExternalPrivateKeyPlan {
    /// 业务作用：为一张叶证书建立固定大小 worker pool 和有界同步桥，远程调用不占用 Tokio worker。
    ///
    /// 参数说明：
    /// - `public_key`：必须来自将与该 signer 绑定的叶证书 SPKI。
    ///
    /// 返回：返回 rustls SigningKey；worker/runtime 创建失败时拒绝 TLS 候选。
    pub fn signing_key(
        &self,
        public_key: SubjectPublicKeyInfoDer<'static>,
    ) -> Result<Arc<dyn SigningKey>> {
        #[cfg(feature = "pkcs11")]
        if let ExternalCryptoBackend::Pkcs11(pkcs11) = &self.provider.backend {
            // rustls 只能核对 SigningKey 声明的 SPKI；HSM 还需在发布前与 token 内
            // 公钥对照，防止同类型错 key 直到首个真实握手才暴露。
            pkcs11.validate_public_key(
                self.key_id.as_ref(),
                public_key.as_ref(),
                self.schemes.as_ref(),
            )?;
        }
        let (sender, receiver) =
            crossbeam_channel::bounded::<SignCommand>(self.provider.queue_capacity);
        for index in 0..self.provider.max_concurrency {
            let receiver = receiver.clone();
            let provider = self.provider.clone();
            let key_id = self.key_id.clone();
            std::thread::Builder::new()
                .name(format!("naway-keyless-{index}"))
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    let Ok(runtime) = runtime else {
                        return;
                    };
                    loop {
                        let command = receiver.recv();
                        let Ok(command) = command else {
                            return;
                        };
                        let result = runtime.block_on(provider.sign(
                            key_id.as_ref(),
                            command.scheme,
                            &command.message,
                        ));
                        let _ = command.completed.send(result);
                    }
                })
                .context("spawn external signer worker")?;
        }
        Ok(Arc::new(ExternalSigningKey {
            dispatcher: Arc::new(KeylessDispatcher {
                sender,
                timeout: self.provider.timeout,
                max_input_bytes: self.provider.max_input_bytes,
            }),
            schemes: self.schemes.clone(),
            algorithm: self.algorithm,
            public_key,
        }))
    }
}

impl ExternalCryptoProvider {
    /// 业务作用：调用不导出私钥的远程 signer，并落实并发、deadline、算法 allowlist 与熔断。
    ///
    /// 参数说明：
    /// - `key_id`：是 provider 固定引用
    /// - `scheme`：是 TLS 算法
    /// - `message`：是原始签名输入。
    ///
    /// 返回：合法有界签名成功；依赖、协议、Base64 或预算失败返回低敏错误。
    pub async fn sign(
        &self,
        key_id: &str,
        scheme: SignatureScheme,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        anyhow::ensure!(
            self.allowed_algorithms.contains(&scheme),
            "external signer algorithm is not allowed"
        );
        self.operation(
            "sign",
            key_id,
            Some(signature_scheme_name(scheme)),
            message,
            None,
            MAX_SIGNATURE_BYTES,
        )
        .await
    }

    /// 业务作用：请求 provider 解开 envelope ciphertext，明文只返回给候选构建者且不进入日志。
    ///
    /// 参数说明：
    /// - `key_id`：固定 KEK
    /// - `ciphertext`：是受限密文
    /// - `aad`：绑定配置上下文。
    ///
    /// 返回：provider 成功时返回有界明文；任何依赖或协议错误失败闭合。
    pub async fn decrypt(&self, key_id: &str, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.operation(
            "decrypt",
            key_id,
            None,
            ciphertext,
            Some(aad),
            self.max_input_bytes,
        )
        .await
    }

    /// 业务作用：请求 provider 使用不可导出的 key 封装明文，供控制面生成 envelope ciphertext。
    ///
    /// 参数说明：
    /// - `key_id`：固定 KEK
    /// - `plaintext`：是有界敏感值
    /// - `aad`：绑定使用上下文。
    ///
    /// 返回：provider 成功时返回有界密文；任何依赖或协议错误失败闭合。
    pub async fn encrypt(&self, key_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.operation(
            "encrypt",
            key_id,
            None,
            plaintext,
            Some(aad),
            self.max_response_bytes,
        )
        .await
    }

    /// 业务作用：执行单次已冻结的密码操作，共享并发门与熔断状态。
    ///
    /// 参数说明：
    /// - `operation`：上层冻结且已经授权的加密或签名动作。
    /// - `key_id`：上层冻结的远端密钥标识。
    /// - `algorithm`：与密钥和动作相容的算法。
    /// - `input`：受输入预算约束的请求字节。
    /// - `aad`：绑定业务来源的附加认证数据。
    /// - `max_output_bytes`：解码后输出字节硬上限。
    ///
    /// 返回：依赖可用且响应成功、格式正确、大小有界时返回结果；失败更新熔断状态。
    async fn operation(
        &self,
        operation: &str,
        key_id: &str,
        algorithm: Option<&str>,
        input: &[u8],
        aad: Option<&[u8]>,
        max_output_bytes: usize,
    ) -> Result<Vec<u8>> {
        anyhow::ensure!(
            !key_id.is_empty() && key_id.len() <= 512,
            "external key id is invalid"
        );
        anyhow::ensure!(
            input.len() <= self.max_input_bytes,
            "external crypto input exceeds limit"
        );
        {
            let state = self.circuit.lock();
            anyhow::ensure!(
                state.open_until.is_none_or(|until| Instant::now() >= until),
                "external crypto circuit is open"
            );
        }
        let permit = tokio::time::timeout(self.timeout, self.concurrency.clone().acquire_owned())
            .await
            .context("external crypto concurrency deadline exceeded")?
            .context("external crypto concurrency gate closed")?;
        let result = match &self.backend {
            ExternalCryptoBackend::Https {
                endpoint,
                authorization,
                client,
            } => {
                self.https_operation(
                    client,
                    endpoint,
                    authorization.as_ref(),
                    operation,
                    key_id,
                    algorithm,
                    input,
                    aad,
                    max_output_bytes,
                )
                .await
            }
            #[cfg(feature = "pkcs11")]
            ExternalCryptoBackend::Pkcs11(provider) => {
                anyhow::ensure!(
                    operation == "sign" && aad.is_none(),
                    "PKCS#11 provider only supports sign"
                );
                let scheme = algorithm
                    .context("PKCS#11 sign operation lacks algorithm")
                    .and_then(parse_signature_scheme)?;
                // PKCS#11 调用可在 vendor 驱动内阻塞；它只在固定 keyless worker 中执行，
                // 不把不可取消的 C 调用扩散到 Tokio worker，熔断也不会触发本地私钥回退。
                provider.sign(key_id, scheme, input)
            }
        };
        drop(permit);
        let mut state = self.circuit.lock();
        match &result {
            Ok(_) => {
                state.consecutive_failures = 0;
                state.open_until = None;
            }
            Err(_) => {
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                if state.consecutive_failures >= self.circuit_failure_threshold {
                    state.open_until = Some(Instant::now() + self.circuit_open);
                    state.consecutive_failures = 0;
                }
            }
        }
        result
    }

    /// 业务作用：按固定 HTTPS endpoint 执行远程密码操作，严格解析
    /// `{result_base64}` 响应契约。
    ///
    /// 参数说明：
    /// - `client`：固定 TLS 与超时策略的 HTTP 客户端。
    /// - `endpoint`：构建期冻结的加密服务 endpoint。
    /// - `authorization`：构建期冻结的服务认证材料。
    /// - `operation`：已经授权的加密或签名动作。
    /// - `key_id`：已经授权的远端密钥标识。
    /// - `algorithm`：与密钥和动作相容的算法。
    /// - `input`：受输入预算约束的请求字节。
    /// - `aad`：绑定业务来源的附加认证数据。
    /// - `max_output_bytes`：解码后输出字节硬上限。
    ///
    /// 返回：deadline 内收到成功 JSON 且 Base64 结果非空、有界时返回字节，
    /// 传输、类型、编码或资源门不满足时失败闭合。
    #[allow(clippy::too_many_arguments)]
    async fn https_operation(
        &self,
        client: &reqwest::Client,
        endpoint: &reqwest::Url,
        authorization: Option<&HeaderValue>,
        operation: &str,
        key_id: &str,
        algorithm: Option<&str>,
        input: &[u8],
        aad: Option<&[u8]>,
        max_output_bytes: usize,
    ) -> Result<Vec<u8>> {
        let request = OperationRequest {
            operation,
            key_id,
            algorithm,
            input_base64: base64::engine::general_purpose::STANDARD.encode(input),
            aad_base64: aad.map(|value| base64::engine::general_purpose::STANDARD.encode(value)),
        };
        let mut builder = client
            .post(endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .json(&request);
        if let Some(authorization) = authorization {
            builder = builder.header(AUTHORIZATION, authorization.clone());
        }
        tokio::time::timeout(self.timeout, async {
            let response = builder
                .send()
                .await
                .context("send external crypto request")?;
            anyhow::ensure!(
                response.status().is_success(),
                "external crypto provider returned failure"
            );
            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_ascii_lowercase();
            anyhow::ensure!(
                content_type
                    .split(';')
                    .next()
                    .is_some_and(|value| value.trim() == "application/json"),
                "external crypto provider returned unexpected content type"
            );
            if let Some(length) = response.content_length() {
                anyhow::ensure!(
                    length <= self.max_response_bytes as u64,
                    "external crypto response exceeds limit"
                );
            }
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("read external crypto response")?;
                anyhow::ensure!(
                    body.len().saturating_add(chunk.len()) <= self.max_response_bytes,
                    "external crypto response exceeds limit"
                );
                body.extend_from_slice(&chunk);
            }
            let value: serde_json::Value =
                serde_json::from_slice(&body).context("parse external crypto JSON")?;
            let encoded = value
                .get("result_base64")
                .and_then(serde_json::Value::as_str)
                .context("external crypto response lacks result_base64")?;
            anyhow::ensure!(
                encoded.len() <= max_output_bytes.saturating_mul(2).saturating_add(16),
                "external crypto encoded result exceeds limit"
            );
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .context("external crypto result is not Base64")?;
            anyhow::ensure!(
                !decoded.is_empty() && decoded.len() <= max_output_bytes,
                "external crypto decoded result exceeds limit"
            );
            Result::<Vec<u8>>::Ok(decoded)
        })
        .await
        .context("external crypto request deadline exceeded")?
    }
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Provider {
    /// 业务作用：从固定 session 池独占一个 HSM session 完成 TLS 签名，
    /// 避免同一 PKCS#11 session 被并发使用。
    ///
    /// 参数说明：
    /// - `key_id`：是精确 private-key label
    /// - `scheme`：是已冻结 TLS 算法
    /// - `message`：是 rustls 待签名原文。
    ///
    /// 返回：在 deadline 内取得 session、唯一命中 key 且 HSM 签名成功时返回
    /// TLS 所需格式；任何歧义、算法错配或 session 异常均失败闭合。
    fn sign(&self, key_id: &str, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>> {
        self.with_session(|session| {
            let key = find_pkcs11_private_key(session, key_id)?;
            ensure_pkcs11_key_type(key.key_type, scheme)?;
            let mechanism = pkcs11_mechanism(scheme)?;
            let signature = session
                .sign(&mechanism, key.handle, message)
                .context("PKCS#11 sign operation failed")?;
            anyhow::ensure!(
                !signature.is_empty() && signature.len() <= MAX_SIGNATURE_BYTES,
                "PKCS#11 signature exceeds limit"
            );
            match scheme {
                SignatureScheme::ECDSA_NISTP256_SHA256 | SignatureScheme::ECDSA_NISTP384_SHA384 => {
                    let component_bytes = match scheme {
                        SignatureScheme::ECDSA_NISTP256_SHA256 => 32,
                        SignatureScheme::ECDSA_NISTP384_SHA384 => 48,
                        _ => unreachable!(),
                    };
                    pkcs11_ecdsa_signature_to_der(&signature, component_bytes)
                }
                SignatureScheme::ED25519 => {
                    anyhow::ensure!(
                        signature.len() == 64,
                        "PKCS#11 Ed25519 signature length is invalid"
                    );
                    Ok(signature)
                }
                _ => Ok(signature),
            }
        })
    }

    /// 业务作用：在发布 TLS 候选前确认 key label 唯一且公钥类型覆盖所有算法。
    ///
    /// 参数说明：
    /// - `key_id`：是精确 private-key label
    /// - `schemes`：是该证书允许的 TLS signature scheme 集合。
    ///
    /// 返回：所有算法均与唯一 key 类型匹配时成功；不读取任何私钥属性或值。
    fn validate_key(&self, key_id: &str, schemes: &[SignatureScheme]) -> Result<()> {
        self.with_session(|session| {
            let key = find_pkcs11_private_key(session, key_id)?;
            for scheme in schemes {
                ensure_pkcs11_key_type(key.key_type, *scheme)?;
            }
            Ok(())
        })
    }

    /// 业务作用：将证书 SPKI 与 HSM 内同一 key pair 的公开属性做密码身份对照。
    ///
    /// 参数说明：
    /// - `key_id`：是 private-key label
    /// - `spki_der`：来自待发布叶证书
    /// - `schemes`：是该身份允许的 TLS signature scheme 集合。
    ///
    /// 返回：唯一 private/public object 共享非空 `CKA_ID`，且 RSA 参数或 EC
    /// curve/point 与证书完全一致时成功；不读取私钥值。
    fn validate_public_key(
        &self,
        key_id: &str,
        spki_der: &[u8],
        schemes: &[SignatureScheme],
    ) -> Result<()> {
        self.with_session(|session| {
            let key = find_pkcs11_private_key(session, key_id)?;
            let public = find_pkcs11_public_key(session, &key.id)?;
            match key.key_type {
                cryptoki::object::KeyType::RSA => {
                    validate_pkcs11_rsa_spki(session, public, spki_der)
                }
                cryptoki::object::KeyType::EC => {
                    validate_pkcs11_ec_spki(session, public, spki_der, schemes, false)
                }
                cryptoki::object::KeyType::EC_EDWARDS => {
                    validate_pkcs11_ec_spki(session, public, spki_der, schemes, true)
                }
                _ => anyhow::bail!("PKCS#11 public key type is unsupported"),
            }
        })
    }

    /// 业务作用：为一次 HSM 操作独占 session，并在成功或失败后归还池中。
    ///
    /// 参数说明：
    /// - `operation`：在独占 session 上执行一次有界业务操作。
    ///
    /// 返回：取得 session 且运算完成时返回结果；排队超时或 session 无法归还时
    /// 视为 provider 不可用。
    fn with_session<T>(
        &self,
        operation: impl FnOnce(&cryptoki::session::Session) -> Result<T>,
    ) -> Result<T> {
        let session = self
            .available
            .recv_timeout(self.timeout)
            .context("PKCS#11 session deadline exceeded")?;
        let result = operation(&session);
        // session 丢失会让后续签名容量永久缩小，因此归还失败必须立即使候选失败。
        self.returned
            .try_send(session)
            .map_err(|_| anyhow::anyhow!("return PKCS#11 session to fixed pool"))?;
        result
    }
}

#[cfg(feature = "pkcs11")]
struct Pkcs11PrivateKey {
    handle: cryptoki::object::ObjectHandle,
    key_type: cryptoki::object::KeyType,
    id: Vec<u8>,
}

/// 业务作用：按精确 label 查找唯一可签名私钥，防止 token 内同名 key 导致身份漂移。
///
/// 参数说明：
/// - `session`：是已登录的独占 session
/// - `key_id`：是配置固定 label。
///
/// 返回：恰好一个 `CKO_PRIVATE_KEY` 且 `CKA_SIGN=true` 时返回 handle、公开 key type 与
/// 非敏感 `CKA_ID`；缺失、重名或身份属性不可读时拒绝。
#[cfg(feature = "pkcs11")]
fn find_pkcs11_private_key(
    session: &cryptoki::session::Session,
    key_id: &str,
) -> Result<Pkcs11PrivateKey> {
    use cryptoki::object::{Attribute, AttributeType, ObjectClass};

    let template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Label(key_id.as_bytes().to_vec()),
        Attribute::Sign(true),
    ];
    let mut objects = session
        .iter_objects_with_cache_size(&template, NonZeroUsize::new(2).expect("non-zero"))
        .context("search PKCS#11 private key")?;
    let key = objects
        .next()
        .transpose()
        .context("read PKCS#11 private key search result")?
        .context("PKCS#11 private key is missing")?;
    anyhow::ensure!(
        objects
            .next()
            .transpose()
            .context("read PKCS#11 duplicate key result")?
            .is_none(),
        "PKCS#11 private key label is ambiguous"
    );
    drop(objects);
    let attributes = session
        .get_attributes(key, &[AttributeType::KeyType, AttributeType::Id])
        .context("read PKCS#11 private key public identity")?;
    let mut key_type = None;
    let mut id = None;
    for attribute in attributes {
        match attribute {
            Attribute::KeyType(value) => key_type = Some(value),
            Attribute::Id(value) => id = Some(value),
            _ => {}
        }
    }
    let key_type = key_type.context("PKCS#11 private key type is unavailable")?;
    let id = id.context("PKCS#11 private key CKA_ID is unavailable")?;
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 512,
        "PKCS#11 private key CKA_ID is invalid"
    );
    Ok(Pkcs11PrivateKey {
        handle: key,
        key_type,
        id,
    })
}

/// 业务作用：按 private key 的非空 `CKA_ID` 查找唯一公钥对象，作为证书身份对照根。
///
/// 参数说明：
/// - `session`：是已登录独占 session
/// - `id`：来自已唯一命中的 private key。
///
/// 返回：恰好一个 `CKO_PUBLIC_KEY` 共享 ID 时返回 handle；缺失或重名时拒绝身份。
#[cfg(feature = "pkcs11")]
fn find_pkcs11_public_key(
    session: &cryptoki::session::Session,
    id: &[u8],
) -> Result<cryptoki::object::ObjectHandle> {
    use cryptoki::object::{Attribute, ObjectClass};

    let template = [
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Id(id.to_vec()),
    ];
    let mut objects = session
        .iter_objects_with_cache_size(&template, NonZeroUsize::new(2).expect("non-zero"))
        .context("search PKCS#11 public key")?;
    let key = objects
        .next()
        .transpose()
        .context("read PKCS#11 public key search result")?
        .context("PKCS#11 public key is missing")?;
    anyhow::ensure!(
        objects
            .next()
            .transpose()
            .context("read PKCS#11 duplicate public key result")?
            .is_none(),
        "PKCS#11 public key identity is ambiguous"
    );
    Ok(key)
}

/// 业务作用：核对 HSM RSA 公钥参数与证书 SPKI，确保不可导出私钥引用属于该证书身份。
///
/// 参数说明：
/// - `session`：是独占 session
/// - `public`：是同 `CKA_ID` 的唯一公钥
/// - `spki_der`：是叶证书的完整 SPKI DER。
///
/// 返回：SPKI 为 `rsaEncryption` 且 modulus/exponent 与 HSM 完全一致时成功；缺失属性、非规范
/// SPKI 或参数错位时拒绝候选。
#[cfg(feature = "pkcs11")]
fn validate_pkcs11_rsa_spki(
    session: &cryptoki::session::Session,
    public: cryptoki::object::ObjectHandle,
    spki_der: &[u8],
) -> Result<()> {
    use cryptoki::object::{Attribute, AttributeType, KeyType};
    use x509_parser::prelude::FromDer as _;
    use x509_parser::public_key::PublicKey;

    let (remainder, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki_der)
        .context("parse TLS certificate SPKI")?;
    anyhow::ensure!(
        remainder.is_empty(),
        "TLS certificate SPKI has trailing data"
    );
    anyhow::ensure!(
        spki.algorithm.algorithm.to_id_string() == "1.2.840.113549.1.1.1",
        "TLS certificate SPKI is not an RSA encryption key"
    );
    let PublicKey::RSA(certificate) = spki.parsed().context("parse RSA certificate public key")?
    else {
        anyhow::bail!("TLS certificate RSA public key is invalid")
    };
    let attributes = session
        .get_attributes(
            public,
            &[
                AttributeType::KeyType,
                AttributeType::Modulus,
                AttributeType::PublicExponent,
            ],
        )
        .context("read PKCS#11 RSA public key")?;
    let mut key_type = None;
    let mut modulus = None;
    let mut exponent = None;
    for attribute in attributes {
        match attribute {
            Attribute::KeyType(value) => key_type = Some(value),
            Attribute::Modulus(value) => modulus = Some(value),
            Attribute::PublicExponent(value) => exponent = Some(value),
            _ => {}
        }
    }
    anyhow::ensure!(
        key_type == Some(KeyType::RSA),
        "PKCS#11 public key is not RSA"
    );
    let modulus = modulus.context("PKCS#11 RSA modulus is unavailable")?;
    let exponent = exponent.context("PKCS#11 RSA exponent is unavailable")?;
    anyhow::ensure!(
        normalized_unsigned_integer(&modulus)? == normalized_unsigned_integer(certificate.modulus)?
            && normalized_unsigned_integer(&exponent)?
                == normalized_unsigned_integer(certificate.exponent)?,
        "PKCS#11 RSA public key does not match TLS certificate"
    );
    Ok(())
}

/// 业务作用：核对 HSM EC/Edwards 曲线与公钥点和证书 SPKI，阻止同类型不同曲线或不同 key 被发布。
///
/// 参数说明：
/// - `session`：是独占 session
/// - `public`：是同 `CKA_ID` 的唯一公钥
/// - `spki_der`：是证书 SPKI
/// - `schemes`：是配置 allowlist
/// - `edwards`：区分 Ed25519 与 NIST ECDSA。
///
/// 返回：算法 OID、命名曲线、scheme、点长度和点值全部一致时成功；压缩点、错曲线或身份错位时拒绝。
#[cfg(feature = "pkcs11")]
fn validate_pkcs11_ec_spki(
    session: &cryptoki::session::Session,
    public: cryptoki::object::ObjectHandle,
    spki_der: &[u8],
    schemes: &[SignatureScheme],
    edwards: bool,
) -> Result<()> {
    use cryptoki::object::{Attribute, AttributeType, KeyType};
    use x509_parser::prelude::FromDer as _;

    const P256_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const P384_PARAMS: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    const ED25519_OID_PARAMS: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    const ED25519_LEGACY_PARAMS: &[u8] = &[
        0x13, 0x0c, b'e', b'd', b'w', b'a', b'r', b'd', b's', b'2', b'5', b'5', b'1', b'9',
    ];
    const P256_PARAM_OPTIONS: &[&[u8]] = &[P256_PARAMS];
    const P384_PARAM_OPTIONS: &[&[u8]] = &[P384_PARAMS];
    const ED25519_PARAM_OPTIONS: &[&[u8]] = &[ED25519_OID_PARAMS, ED25519_LEGACY_PARAMS];

    let (remainder, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki_der)
        .context("parse TLS certificate EC SPKI")?;
    anyhow::ensure!(
        remainder.is_empty(),
        "TLS certificate SPKI has trailing data"
    );
    let (expected_key_type, expected_algorithm_oid, expected_curve_oid, expected_params, point_len) =
        if edwards {
            anyhow::ensure!(
                schemes == [SignatureScheme::ED25519],
                "PKCS#11 Edwards key only supports the Ed25519 TLS scheme"
            );
            (
                KeyType::EC_EDWARDS,
                "1.3.101.112",
                None,
                ED25519_PARAM_OPTIONS,
                32,
            )
        } else {
            let (curve_oid, params, point_len) = match schemes {
                [SignatureScheme::ECDSA_NISTP256_SHA256] => {
                    ("1.2.840.10045.3.1.7", P256_PARAM_OPTIONS, 65)
                }
                [SignatureScheme::ECDSA_NISTP384_SHA384] => {
                    ("1.3.132.0.34", P384_PARAM_OPTIONS, 97)
                }
                _ => anyhow::bail!(
                    "PKCS#11 EC identity must configure exactly one certificate curve"
                ),
            };
            (
                KeyType::EC,
                "1.2.840.10045.2.1",
                Some(curve_oid),
                params,
                point_len,
            )
        };
    anyhow::ensure!(
        spki.algorithm.algorithm.to_id_string() == expected_algorithm_oid,
        "TLS certificate EC algorithm does not match PKCS#11 key"
    );
    if let Some(expected_curve_oid) = expected_curve_oid {
        let actual_curve_oid = spki
            .algorithm
            .parameters
            .as_ref()
            .context("TLS certificate EC SPKI lacks named curve")?
            .as_oid()
            .context("TLS certificate EC SPKI curve is invalid")?
            .to_id_string();
        anyhow::ensure!(
            actual_curve_oid == expected_curve_oid,
            "TLS certificate EC curve does not match configured scheme"
        );
    } else {
        anyhow::ensure!(
            spki.algorithm.parameters.is_none(),
            "TLS certificate Ed25519 SPKI parameters must be absent"
        );
    }
    let certificate_point = spki.subject_public_key.data.as_ref();
    anyhow::ensure!(
        certificate_point.len() == point_len
            && (edwards || certificate_point.first() == Some(&0x04)),
        "TLS certificate EC public point format is invalid"
    );
    let attributes = session
        .get_attributes(
            public,
            &[
                AttributeType::KeyType,
                AttributeType::EcParams,
                AttributeType::EcPoint,
            ],
        )
        .context("read PKCS#11 EC public key")?;
    let mut key_type = None;
    let mut params = None;
    let mut point = None;
    for attribute in attributes {
        match attribute {
            Attribute::KeyType(value) => key_type = Some(value),
            Attribute::EcParams(value) => params = Some(value),
            Attribute::EcPoint(value) => point = Some(value),
            _ => {}
        }
    }
    anyhow::ensure!(
        key_type == Some(expected_key_type),
        "PKCS#11 EC public key type mismatches private key"
    );
    let params = params.context("PKCS#11 EC parameters are unavailable")?;
    anyhow::ensure!(
        expected_params.iter().any(|expected| *expected == params),
        "PKCS#11 EC curve does not match configured scheme"
    );
    let point = point.context("PKCS#11 EC public point is unavailable")?;
    anyhow::ensure!(
        normalized_pkcs11_ec_point(&point, point_len)? == certificate_point,
        "PKCS#11 EC public key does not match TLS certificate"
    );
    Ok(())
}

/// 业务作用：规范比较 ASN.1 INTEGER 与 PKCS#11 无符号整数，忽略只为正数符号添加的前导零。
///
/// 参数说明：
/// - `value`：是 big-endian modulus 或 exponent。
///
/// 返回：非空且非全零时返回去除前导零的切片；无效整数拒绝身份对照。
#[cfg(feature = "pkcs11")]
fn normalized_unsigned_integer(value: &[u8]) -> Result<&[u8]> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .context("PKCS#11 public integer is zero or empty")?;
    Ok(&value[first..])
}

/// 业务作用：兼容 PKCS#11 标准 DER OCTET STRING 与少数 module 的原始 EC point 表示，形成唯一比较值。
///
/// 参数说明：
/// - `value`：是 `CKA_EC_POINT`
/// - `expected_len`：由已冻结曲线确定。
///
/// 返回：长度精确的原始 point；其它编码、长长度形式或大小错位均拒绝。
#[cfg(feature = "pkcs11")]
fn normalized_pkcs11_ec_point(value: &[u8], expected_len: usize) -> Result<&[u8]> {
    if value.len() == expected_len {
        return Ok(value);
    }
    if value.len() == expected_len + 2
        && value.first() == Some(&0x04)
        && value.get(1) == Some(&(expected_len as u8))
    {
        return Ok(&value[2..]);
    }
    anyhow::bail!("PKCS#11 EC public point format is invalid")
}

/// 业务作用：校验 HSM key 类型与 TLS signature scheme 的公钥族一致性。
///
/// 参数说明：
/// - `key_type`：来自 `CKA_KEY_TYPE`
/// - `scheme`：来自已校验配置。
///
/// 返回：RSA、EC 或 EC Edwards 精确匹配时成功，跨族使用时拒绝。
#[cfg(feature = "pkcs11")]
fn ensure_pkcs11_key_type(
    key_type: cryptoki::object::KeyType,
    scheme: SignatureScheme,
) -> Result<()> {
    use cryptoki::object::KeyType;

    let expected = match signature_algorithm(scheme) {
        SignatureAlgorithm::RSA => KeyType::RSA,
        SignatureAlgorithm::ECDSA => KeyType::EC,
        SignatureAlgorithm::ED25519 => KeyType::EC_EDWARDS,
        _ => anyhow::bail!("PKCS#11 signature algorithm is unsupported"),
    };
    anyhow::ensure!(
        key_type == expected,
        "PKCS#11 private key type mismatches TLS algorithm"
    );
    Ok(())
}

/// 业务作用：把 TLS signature scheme 映射为包含消息摘要的 PKCS#11 mechanism。
///
/// 参数说明：
/// - `scheme`：是 provider 与证书共同允许的 TLS 算法。
///
/// 返回：返回与 rustls 原始待签名 message 匹配的标准 mechanism，其它算法失败闭合。
#[cfg(feature = "pkcs11")]
fn pkcs11_mechanism(scheme: SignatureScheme) -> Result<cryptoki::mechanism::Mechanism<'static>> {
    use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
    use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
    use cryptoki::mechanism::{Mechanism, MechanismType};

    let mechanism = match scheme {
        SignatureScheme::RSA_PSS_SHA256 => Mechanism::Sha256RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA256,
            mgf: PkcsMgfType::MGF1_SHA256,
            s_len: 32.into(),
        }),
        SignatureScheme::RSA_PSS_SHA384 => Mechanism::Sha384RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA384,
            mgf: PkcsMgfType::MGF1_SHA384,
            s_len: 48.into(),
        }),
        SignatureScheme::RSA_PSS_SHA512 => Mechanism::Sha512RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA512,
            mgf: PkcsMgfType::MGF1_SHA512,
            s_len: 64.into(),
        }),
        SignatureScheme::ECDSA_NISTP256_SHA256 => Mechanism::EcdsaSha256,
        SignatureScheme::ECDSA_NISTP384_SHA384 => Mechanism::EcdsaSha384,
        SignatureScheme::ED25519 => {
            Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519))
        }
        _ => anyhow::bail!("PKCS#11 signature algorithm is unsupported"),
    };
    Ok(mechanism)
}

/// 业务作用：把 PKCS#11 ECDSA 的 `r || s` 字节串转为 TLS 要求的 DER SEQUENCE。
///
/// 参数说明：
/// - `raw`：必须是等长、非空的 r 与 s 串联值
/// - `component_bytes`：由 TLS 曲线固定。
///
/// 返回：两个正整数都可规范编码时返回短长度 DER；奇数、空值或超界输入拒绝。
#[cfg(feature = "pkcs11")]
fn pkcs11_ecdsa_signature_to_der(raw: &[u8], component_bytes: usize) -> Result<Vec<u8>> {
    anyhow::ensure!(
        matches!(component_bytes, 32 | 48) && raw.len() == component_bytes * 2,
        "PKCS#11 ECDSA signature format is invalid"
    );
    let (r, s) = raw.split_at(component_bytes);
    let r = der_positive_integer(r);
    let s = der_positive_integer(s);
    let content_len = 2 + r.len() + 2 + s.len();
    anyhow::ensure!(
        content_len < 128,
        "PKCS#11 ECDSA signature exceeds DER limit"
    );
    let mut der = Vec::with_capacity(content_len + 2);
    der.extend_from_slice(&[0x30, content_len as u8, 0x02, r.len() as u8]);
    der.extend_from_slice(&r);
    der.extend_from_slice(&[0x02, s.len() as u8]);
    der.extend_from_slice(&s);
    Ok(der)
}

/// 业务作用：把固定宽度无符号整数规范为 DER 正 INTEGER 内容。
///
/// 参数说明：
/// - `value`：是 r 或 s 的 big-endian 固定宽度表示。
///
/// 返回：返回去除多余前导零且必要时增加符号零的非空字节串。
#[cfg(feature = "pkcs11")]
fn der_positive_integer(value: &[u8]) -> Vec<u8> {
    let first_non_zero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len().saturating_sub(1));
    let significant = &value[first_non_zero..];
    let mut encoded = Vec::with_capacity(significant.len() + 1);
    if significant.first().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    encoded.extend_from_slice(significant);
    encoded
}

impl ExternalEnvelopePlan {
    /// 业务作用：用不可导出 KEK 生成可由远程 Secret provider 保存的 envelope ciphertext。
    ///
    /// 参数说明：
    /// - `secret_provider`：用于强制 AAD 的 Secret provider 标识。
    /// - `secret_path`：用于强制 AAD 的远程 Secret 路径。
    /// - `version`：用于强制 AAD 的远程 Secret 版本。
    /// - `plaintext`：待封装的 UTF-8 Secret 明文。
    ///
    /// 返回：远程 encrypt 成功时返回标准 Base64 ciphertext；预算或 provider 失败时返回错误。
    pub async fn encrypt_remote_secret(
        &self,
        secret_provider: &str,
        secret_path: &str,
        version: u64,
        plaintext: &str,
    ) -> Result<String> {
        anyhow::ensure!(
            plaintext.len() <= 64 * 1024,
            "remote secret envelope plaintext exceeds limit"
        );
        let aad = envelope_aad(
            secret_provider,
            secret_path,
            version,
            self.aad_context.as_ref(),
        )?;
        let ciphertext = self
            .provider
            .encrypt(self.key_id.as_ref(), plaintext.as_bytes(), &aad)
            .await?;
        Ok(base64::engine::general_purpose::STANDARD.encode(ciphertext))
    }

    /// 业务作用：解开远程 Secret ciphertext，并用 AAD 强制绑定 provider、路径、版本与业务上下文。
    ///
    /// 参数说明：
    /// - `secret_provider`：标识来源
    /// - `secret_path`：标识来源
    /// - `version`：是单调版本
    /// - `ciphertext_base64`：是远程 JSON value。
    ///
    /// 返回：Base64、远程 decrypt、UTF-8 与大小全部合法时返回明文；否则拒绝候选且不回退密文。
    pub async fn decrypt_remote_secret(
        &self,
        secret_provider: &str,
        secret_path: &str,
        version: u64,
        ciphertext_base64: &str,
    ) -> Result<String> {
        anyhow::ensure!(
            ciphertext_base64.len() <= self.provider.max_input_bytes.saturating_mul(2) + 16,
            "remote secret envelope ciphertext exceeds limit"
        );
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(ciphertext_base64)
            .context("remote secret envelope ciphertext is not Base64")?;
        anyhow::ensure!(
            !ciphertext.is_empty() && ciphertext.len() <= self.provider.max_input_bytes,
            "remote secret envelope ciphertext exceeds limit"
        );
        let aad = envelope_aad(
            secret_provider,
            secret_path,
            version,
            self.aad_context.as_ref(),
        )?;
        let plaintext = self
            .provider
            .decrypt(self.key_id.as_ref(), &ciphertext, &aad)
            .await?;
        anyhow::ensure!(
            plaintext.len() <= 64 * 1024,
            "remote secret envelope plaintext exceeds limit"
        );
        String::from_utf8(plaintext).context("remote secret envelope plaintext is not UTF-8")
    }
}

/// 业务作用：构造不会因字段拼接歧义而碰撞的 envelope AAD，阻止 ciphertext 跨来源重放。
///
/// 参数说明：
/// - `secret_provider`：已经校验的 Secret provider 标识。
/// - `secret_path`：远程 Secret 引用路径。
/// - `version`：远程 Secret 引用版本。
/// - `context`：已经校验的加密上下文，连同来源绑定 AAD。
///
/// 返回：各字段有界且不含 NUL 时返回带协议域分隔的字节串，否则拒绝操作。
fn envelope_aad(
    secret_provider: &str,
    secret_path: &str,
    version: u64,
    context: &str,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        secret_provider.len() <= 128
            && secret_path.len() <= 512
            && context.len() <= 1024
            && !secret_provider.contains('\0')
            && !secret_path.contains('\0')
            && !context.contains('\0'),
        "remote secret envelope AAD is invalid"
    );
    Ok(
        format!("naway.remote-secret.v1\0{secret_provider}\0{secret_path}\0{version}\0{context}")
            .into_bytes(),
    )
}

/// 业务作用：解析外部 TLS private key 引用，验证 provider 唯一性、传输、SecretSource 与算法闭包。
///
/// 参数说明：
/// - `reference`：指定外部 key 与允许算法
/// - `catalog`：是已在候选构建期校验完成的 全局密码 provider 目录。
///
/// 返回：返回不含可导出私钥的签名计划；provider 不存在、算法错配或预算无界时失败。
pub fn build_private_key_plan(
    reference: &ExternalPrivateKeyCfg,
    catalog: &ExternalCryptoCatalog,
) -> Result<ExternalPrivateKeyPlan> {
    let provider = catalog
        .providers
        .get(&reference.provider)
        .cloned()
        .context("external private key provider is missing")?;
    anyhow::ensure!(
        !reference.key_id.is_empty() && reference.key_id.len() <= 512,
        "external private key id must contain 1..=512 bytes"
    );
    anyhow::ensure!(
        !reference.algorithms.is_empty() && reference.algorithms.len() <= 16,
        "external private key algorithms must contain 1..=16 entries"
    );
    let mut schemes = reference
        .algorithms
        .iter()
        .map(|name| parse_signature_scheme(name))
        .collect::<Result<Vec<_>>>()?;
    schemes.sort_by_key(|scheme| u16::from(*scheme));
    schemes.dedup();
    anyhow::ensure!(
        schemes
            .iter()
            .all(|scheme| provider.allowed_algorithms.contains(scheme)),
        "external private key algorithms exceed provider allowlist"
    );
    let algorithm = signature_algorithm(schemes[0]);
    anyhow::ensure!(
        schemes
            .iter()
            .all(|scheme| signature_algorithm(*scheme) == algorithm),
        "external private key algorithms must use one public-key family"
    );
    #[cfg(feature = "pkcs11")]
    if let ExternalCryptoBackend::Pkcs11(pkcs11) = &provider.backend {
        // 候选 TLS 身份只有在 HSM key 唯一且算法族一致后才能发布，
        // 避免首个真实握手才暴露错 key 或跨族配置。
        pkcs11.validate_key(&reference.key_id, &schemes)?;
    }
    let mut digest = sha2::Sha256::new();
    digest.update(provider.identity);
    digest.update(reference.key_id.as_bytes());
    for scheme in &schemes {
        digest.update(u16::from(*scheme).to_be_bytes());
    }
    Ok(ExternalPrivateKeyPlan {
        provider,
        key_id: Arc::from(reference.key_id.as_str()),
        schemes: schemes.into(),
        algorithm,
        identity: digest.finalize().into(),
    })
}

/// 业务作用：在候选快照发布前一次性校验并构建全局外部密码 provider 目录。
///
/// 参数说明：
/// - `config_dir`：是本地 SecretSource 基准
/// - `providers`：是全局声明。
///
/// 返回：名称唯一且每个 provider 的传输、认证与预算均有效时返回共享目录，否则拒绝候选。
pub fn build_catalog(
    config_dir: &Path,
    providers: &[ExternalCryptoProviderCfg],
) -> Result<ExternalCryptoCatalog> {
    anyhow::ensure!(
        providers.len() <= MAX_PROVIDER_COUNT,
        "crypto provider count exceeds 32"
    );
    let mut catalog = HashMap::with_capacity(providers.len());
    for provider in providers {
        anyhow::ensure!(
            !catalog.contains_key(&provider.name),
            "external crypto provider name is duplicated"
        );
        let runtime = Arc::new(build_provider(config_dir, provider)?);
        catalog.insert(provider.name.clone(), runtime);
    }
    Ok(ExternalCryptoCatalog {
        providers: catalog,
    })
}

/// 业务作用：把远程 Secret envelope 引用绑定到本快照共享的外部密码 provider。
///
/// 参数说明：
/// - `reference`：指定 KEK 与附加 AAD
/// - `catalog`：是已校验 provider 目录。
///
/// 返回：provider 存在且 key/AAD 有界时返回解密计划；引用错误时拒绝候选。
pub fn build_envelope_plan(
    reference: &RemoteSecretEnvelopeCfg,
    catalog: &ExternalCryptoCatalog,
) -> Result<ExternalEnvelopePlan> {
    let provider = catalog
        .providers
        .get(&reference.crypto_provider)
        .cloned()
        .context("remote secret envelope crypto provider is missing")?;
    anyhow::ensure!(
        matches!(&provider.backend, ExternalCryptoBackend::Https {
            ..
        }),
        "remote secret envelope requires an HTTPS crypto provider"
    );
    anyhow::ensure!(
        !reference.key_id.is_empty() && reference.key_id.len() <= 512,
        "remote secret envelope key id is invalid"
    );
    anyhow::ensure!(
        reference.aad_context.len() <= 1024 && !reference.aad_context.contains('\0'),
        "remote secret envelope AAD context is invalid"
    );
    Ok(ExternalEnvelopePlan {
        provider,
        key_id: Arc::from(reference.key_id.as_str()),
        aad_context: Arc::from(reference.aad_context.as_str()),
    })
}

/// 业务作用：构建固定 HTTPS 或 PKCS#11 provider，并把身份与资源预算冻结为运行态。
///
/// 参数说明：
/// - `config_dir`：是 SecretSource 基准
/// - `cfg`：是单 provider 声明。
///
/// 返回：恰好一种传输、认证、算法和预算均有效时返回 provider；
/// 敏感材料不进入错误文本。
pub fn build_provider(
    config_dir: &Path,
    cfg: &ExternalCryptoProviderCfg,
) -> Result<ExternalCryptoProvider> {
    anyhow::ensure!(
        !cfg.name.is_empty() && cfg.name.len() <= 128,
        "external crypto provider name is invalid"
    );
    anyhow::ensure!(
        (100..=30_000).contains(&cfg.timeout_ms),
        "external crypto timeout must be within 100..=30000 ms"
    );
    anyhow::ensure!(
        (1..=64).contains(&cfg.max_concurrency),
        "external crypto concurrency must be within 1..=64"
    );
    anyhow::ensure!(
        (1..=4096).contains(&cfg.queue_capacity),
        "external crypto queue capacity must be within 1..=4096"
    );
    anyhow::ensure!(
        (1..=1000).contains(&cfg.circuit_failure_threshold)
            && (100..=300_000).contains(&cfg.circuit_open_ms),
        "external crypto circuit budget is invalid"
    );
    anyhow::ensure!(
        (1024..=1024 * 1024).contains(&cfg.max_input_bytes)
            && (1024..=1024 * 1024).contains(&cfg.max_response_bytes),
        "external crypto byte budget must be within 1024..=1048576"
    );
    anyhow::ensure!(
        cfg.allowed_algorithms.len() <= 32,
        "external crypto provider algorithms must contain at most 32 entries"
    );
    let mut allowed_algorithms = cfg
        .allowed_algorithms
        .iter()
        .map(|name| parse_signature_scheme(name))
        .collect::<Result<Vec<_>>>()?;
    allowed_algorithms.sort_by_key(|algorithm| u16::from(*algorithm));
    allowed_algorithms.dedup();
    let mut digest = sha2::Sha256::new();
    digest.update(cfg.name.as_bytes());
    let backend = if let Some(pkcs11) = &cfg.pkcs11 {
        anyhow::ensure!(
            cfg.endpoint.is_empty()
                && cfg.authorization.is_empty()
                && cfg.authorization_prefix.is_empty()
                && cfg.ca_certificate.is_empty()
                && cfg.client_certificate.is_empty()
                && cfg.client_private_key.is_empty(),
            "PKCS#11 provider cannot configure HTTPS transport or identity"
        );
        anyhow::ensure!(
            !allowed_algorithms.is_empty(),
            "PKCS#11 provider must allow at least one signature algorithm"
        );
        #[cfg(feature = "pkcs11")]
        {
            let (provider, identity) = build_pkcs11_provider(
                config_dir,
                pkcs11,
                cfg.max_concurrency,
                cfg.timeout_ms,
                &allowed_algorithms,
            )?;
            digest.update(b"pkcs11\0");
            digest.update(identity);
            ExternalCryptoBackend::Pkcs11(provider)
        }
        #[cfg(not(feature = "pkcs11"))]
        {
            let _ = pkcs11;
            anyhow::bail!("PKCS#11 provider requires the pkcs11 build feature")
        }
    } else {
        let (backend, identity) = build_https_backend(config_dir, cfg)?;
        digest.update(b"https\0");
        digest.update(identity);
        backend
    };
    for algorithm in &allowed_algorithms {
        digest.update(u16::from(*algorithm).to_be_bytes());
    }
    digest.update(cfg.timeout_ms.to_be_bytes());
    digest.update(cfg.max_concurrency.to_be_bytes());
    digest.update(cfg.queue_capacity.to_be_bytes());
    digest.update(cfg.circuit_failure_threshold.to_be_bytes());
    digest.update(cfg.circuit_open_ms.to_be_bytes());
    digest.update(cfg.max_input_bytes.to_be_bytes());
    digest.update(cfg.max_response_bytes.to_be_bytes());
    Ok(ExternalCryptoProvider {
        backend,
        allowed_algorithms,
        timeout: Duration::from_millis(cfg.timeout_ms),
        max_input_bytes: cfg.max_input_bytes,
        max_response_bytes: cfg.max_response_bytes,
        queue_capacity: cfg.queue_capacity,
        max_concurrency: cfg.max_concurrency,
        concurrency: Arc::new(tokio::sync::Semaphore::new(cfg.max_concurrency)),
        circuit_failure_threshold: cfg.circuit_failure_threshold,
        circuit_open: Duration::from_millis(cfg.circuit_open_ms),
        circuit: parking_lot::Mutex::new(CircuitState {
            consecutive_failures: 0,
            open_until: None,
        }),
        identity: digest.finalize().into(),
    })
}

/// 业务作用：构建固定 HTTPS 密码操作后端，并绑定本地 bootstrap 身份。
///
/// 参数说明：
/// - `config_dir`：是 SecretSource 基准
/// - `cfg`：提供 endpoint、CA、认证与 mTLS。
///
/// 返回：URL 固定且本地身份完整时返回 HTTPS backend 与仅用于热更判定的摘要；
/// 凭据不进入诊断或公开输出。
fn build_https_backend(
    config_dir: &Path,
    cfg: &ExternalCryptoProviderCfg,
) -> Result<(ExternalCryptoBackend, [u8; 32])> {
    anyhow::ensure!(
        !cfg.endpoint.is_empty(),
        "external crypto HTTPS endpoint is required"
    );
    let endpoint = reqwest::Url::parse(&cfg.endpoint).context("parse external crypto endpoint")?;
    anyhow::ensure!(
        endpoint.scheme() == "https"
            && endpoint.host_str().is_some()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none(),
        "external crypto endpoint must be a fixed HTTPS URL without credentials, query or fragment"
    );
    let resolve = |source: &str, label: &str| -> Result<Option<String>> {
        if source.is_empty() {
            return Ok(None);
        }
        anyhow::ensure!(
            !source.starts_with("remote://"),
            "external crypto bootstrap secret cannot use a remote provider"
        );
        crate::security::secret::resolve_text(source, config_dir, label).map(Some)
    };
    let authorization_value = resolve(&cfg.authorization, "external crypto authorization")?;
    let ca = resolve(&cfg.ca_certificate, "external crypto CA")?;
    let certificate = resolve(
        &cfg.client_certificate,
        "external crypto client certificate",
    )?;
    let private_key = resolve(
        &cfg.client_private_key,
        "external crypto client private key",
    )?;
    let authorization = authorization_value
        .as_ref()
        .map(|value| {
            let mut header =
                HeaderValue::from_str(&format!("{}{}", cfg.authorization_prefix, value.trim()))
                    .context("external crypto authorization is not a valid header value")?;
            header.set_sensitive(true);
            Ok::<_, anyhow::Error>(header)
        })
        .transpose()?;
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(cfg.timeout_ms))
        .timeout(Duration::from_millis(cfg.timeout_ms));
    if let Some(ca) = &ca {
        builder = builder.add_root_certificate(
            crate::tls::trust::http_ca(ca.as_bytes())
                .context("external crypto CA is not valid PEM")?,
        );
    }
    anyhow::ensure!(
        certificate.is_some() == private_key.is_some(),
        "external crypto mTLS certificate and private key must be configured together"
    );
    if let (Some(certificate), Some(private_key)) = (&certificate, &private_key) {
        let identity = format!("{certificate}\n{private_key}");
        builder = builder.identity(
            reqwest::Identity::from_pem(identity.as_bytes())
                .context("external crypto mTLS identity is not valid PEM")?,
        );
    }
    let mut digest = sha2::Sha256::new();
    digest.update(endpoint.as_str().as_bytes());
    digest.update(cfg.authorization_prefix.as_bytes());
    for material in [
        authorization_value.as_deref(),
        ca.as_deref(),
        certificate.as_deref(),
        private_key.as_deref(),
    ] {
        if let Some(material) = material {
            digest.update(material.as_bytes());
        }
        digest.update([0]);
    }
    Ok((
        ExternalCryptoBackend::Https {
            endpoint,
            authorization,
            client: builder
                .build()
                .context("build external crypto HTTPS client")?,
        },
        digest.finalize().into(),
    ))
}

/// 业务作用：加载显式指定的 PKCS#11 module，登录唯一 token 并建立固定 session 池。
///
/// 参数说明：
/// - `config_dir`：是 PIN SecretSource 基准
/// - `cfg`：固定 module/token
/// - `session_count`：是并发上限
/// - `timeout_ms`：是 session 排队 deadline
/// - `algorithms`：是允许集。
///
/// 返回：module、token、PIN、mechanism 和全部 session 均可用时返回 provider 与私有身份摘要；
/// 不自动选择其它 slot，不读取私钥值。
#[cfg(feature = "pkcs11")]
fn build_pkcs11_provider(
    config_dir: &Path,
    cfg: &Pkcs11CryptoProviderCfg,
    session_count: usize,
    timeout_ms: u64,
    algorithms: &[SignatureScheme],
) -> Result<(Pkcs11Provider, [u8; 32])> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11};
    use cryptoki::error::{Error as Pkcs11Error, RvError};
    use cryptoki::session::UserType;
    use cryptoki::slot::Slot;
    use cryptoki::types::AuthPin;

    let configured_module_path = PathBuf::from(&cfg.module_path);
    anyhow::ensure!(
        configured_module_path.is_absolute(),
        "PKCS#11 module_path must be absolute"
    );
    let module_path = configured_module_path
        .canonicalize()
        .context("resolve PKCS#11 module_path")?;
    anyhow::ensure!(
        module_path.is_file(),
        "PKCS#11 module_path must be an absolute regular file"
    );
    anyhow::ensure!(
        cfg.slot_id.is_some() ^ !cfg.token_label.is_empty(),
        "PKCS#11 slot_id and token_label must configure exactly one selector"
    );
    anyhow::ensure!(
        cfg.token_label.len() <= 32 && !cfg.token_label.contains('\0'),
        "PKCS#11 token_label is invalid"
    );
    anyhow::ensure!(
        !cfg.user_pin.is_empty() && !cfg.user_pin.starts_with("remote://"),
        "PKCS#11 user_pin must use a local SecretSource"
    );
    let pin_source =
        crate::security::secret::resolve_text(&cfg.user_pin, config_dir, "PKCS#11 user PIN")?;
    let pin = pin_source.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(
        !pin.is_empty() && pin.len() <= 1024 && !pin.contains('\0'),
        "PKCS#11 user PIN is invalid"
    );
    let context = Pkcs11::new(&module_path).context("load PKCS#11 module")?;
    match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(())
        | Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, Function::Initialize)) => {}
        Err(error) => return Err(error).context("initialize PKCS#11 module"),
    }
    let token_slots = context
        .get_slots_with_token()
        .context("enumerate PKCS#11 tokens")?;
    let slot = if let Some(slot_id) = cfg.slot_id {
        let slot = Slot::try_from(slot_id).context("parse PKCS#11 slot id")?;
        anyhow::ensure!(
            token_slots.contains(&slot),
            "configured PKCS#11 slot has no token"
        );
        slot
    } else {
        let mut matches = Vec::new();
        for slot in token_slots {
            let info = context
                .get_token_info(slot)
                .context("read PKCS#11 token identity")?;
            if info.label() == cfg.token_label {
                matches.push(slot);
            }
        }
        let mut matches = matches.into_iter();
        let slot = matches
            .next()
            .context("configured PKCS#11 token label is missing")?;
        anyhow::ensure!(
            matches.next().is_none(),
            "configured PKCS#11 token label is ambiguous"
        );
        slot
    };
    let mechanisms = context
        .get_mechanism_list(slot)
        .context("read PKCS#11 token mechanisms")?;
    for algorithm in algorithms {
        anyhow::ensure!(
            mechanisms.contains(&pkcs11_mechanism_type(*algorithm)?),
            "PKCS#11 token lacks an allowed signature mechanism"
        );
    }
    let (returned, available) = crossbeam_channel::bounded(session_count);
    let auth_pin = AuthPin::new(pin.to_owned().into());
    for _ in 0..session_count {
        let session = context
            .open_ro_session(slot)
            .context("open PKCS#11 read-only session")?;
        match session.login(UserType::User, Some(&auth_pin)) {
            Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, Function::Login)) => {}
            Err(error) => return Err(error).context("login PKCS#11 user session"),
        }
        returned
            .try_send(session)
            .map_err(|_| anyhow::anyhow!("populate fixed PKCS#11 session pool"))?;
    }
    let mut digest = sha2::Sha256::new();
    digest.update(module_path.as_os_str().as_encoded_bytes());
    digest.update(cfg.slot_id.unwrap_or(u64::MAX).to_be_bytes());
    digest.update(cfg.token_label.as_bytes());
    digest.update([0]);
    digest.update(pin.as_bytes());
    Ok((
        Pkcs11Provider {
            returned,
            available,
            timeout: Duration::from_millis(timeout_ms),
        },
        digest.finalize().into(),
    ))
}

/// 业务作用：把 TLS signature scheme 映射为用于 token 能力门的 PKCS#11 mechanism type。
///
/// 参数说明：
/// - `scheme`：是已解析的 TLS 算法。
///
/// 返回：返回 HSM 必须声明的带摘要签名 mechanism；其它算法拒绝。
#[cfg(feature = "pkcs11")]
fn pkcs11_mechanism_type(scheme: SignatureScheme) -> Result<cryptoki::mechanism::MechanismType> {
    use cryptoki::mechanism::MechanismType;

    match scheme {
        SignatureScheme::RSA_PSS_SHA256 => Ok(MechanismType::SHA256_RSA_PKCS_PSS),
        SignatureScheme::RSA_PSS_SHA384 => Ok(MechanismType::SHA384_RSA_PKCS_PSS),
        SignatureScheme::RSA_PSS_SHA512 => Ok(MechanismType::SHA512_RSA_PKCS_PSS),
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(MechanismType::ECDSA_SHA256),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(MechanismType::ECDSA_SHA384),
        SignatureScheme::ED25519 => Ok(MechanismType::EDDSA),
        _ => anyhow::bail!("PKCS#11 signature algorithm is unsupported"),
    }
}

/// 业务作用：把公开配置名映射为 rustls signature scheme，未知或弱算法失败闭合。
///
/// 参数说明：
/// - `name`：是配置算法标识。
///
/// 返回：仅返回当前实现明确支持的现代 TLS 算法。
fn parse_signature_scheme(name: &str) -> Result<SignatureScheme> {
    match name.trim().to_ascii_lowercase().as_str() {
        "rsa_pss_sha256" => Ok(SignatureScheme::RSA_PSS_SHA256),
        "rsa_pss_sha384" => Ok(SignatureScheme::RSA_PSS_SHA384),
        "rsa_pss_sha512" => Ok(SignatureScheme::RSA_PSS_SHA512),
        "ecdsa_nistp256_sha256" => Ok(SignatureScheme::ECDSA_NISTP256_SHA256),
        "ecdsa_nistp384_sha384" => Ok(SignatureScheme::ECDSA_NISTP384_SHA384),
        "ed25519" => Ok(SignatureScheme::ED25519),
        _ => anyhow::bail!("external crypto signature algorithm is unsupported"),
    }
}

/// 业务作用：将 rustls scheme 转为固定 provider 协议字符串，不接受动态算法名。
///
/// 参数说明：
/// - `scheme`：已通过 provider allowlist。
///
/// 返回：返回稳定协议标识。
fn signature_scheme_name(scheme: SignatureScheme) -> &'static str {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256 => "rsa_pss_sha256",
        SignatureScheme::RSA_PSS_SHA384 => "rsa_pss_sha384",
        SignatureScheme::RSA_PSS_SHA512 => "rsa_pss_sha512",
        SignatureScheme::ECDSA_NISTP256_SHA256 => "ecdsa_nistp256_sha256",
        SignatureScheme::ECDSA_NISTP384_SHA384 => "ecdsa_nistp384_sha384",
        SignatureScheme::ED25519 => "ed25519",
        _ => "unsupported",
    }
}

/// 业务作用：把 signature scheme 收敛为 rustls 公钥算法族，禁止一个 key reference 跨族声明。
///
/// 参数说明：
/// - `scheme`：是已支持方案。
///
/// 返回：返回 RSA、ECDSA 或 ED25519 算法族。
fn signature_algorithm(scheme: SignatureScheme) -> SignatureAlgorithm {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => SignatureAlgorithm::RSA,
        SignatureScheme::ECDSA_NISTP256_SHA256 | SignatureScheme::ECDSA_NISTP384_SHA384 => {
            SignatureAlgorithm::ECDSA
        }
        SignatureScheme::ED25519 => SignatureAlgorithm::ED25519,
        _ => SignatureAlgorithm::Unknown(0),
    }
}

/// 业务作用：收集 crypto provider 的本地 SecretSource 文件，纳入统一 watcher 与配置指纹。
///
/// 参数说明：
/// - `providers`：是全局声明
/// - `config_dir`：是相对路径根。
///
/// 返回：返回认证、CA 和 mTLS 身份依赖，不读取或暴露内容。
pub fn dependency_paths(
    providers: &[ExternalCryptoProviderCfg],
    config_dir: &Path,
) -> Vec<std::path::PathBuf> {
    providers
        .iter()
        .flat_map(|provider| {
            [
                provider.authorization.as_str(),
                provider.ca_certificate.as_str(),
                provider.client_certificate.as_str(),
                provider.client_private_key.as_str(),
                provider
                    .pkcs11
                    .as_ref()
                    .map(|pkcs11| pkcs11.user_pin.as_str())
                    .unwrap_or_default(),
            ]
        })
        .filter_map(|source| crate::security::secret::dependency_path(source, config_dir))
        .collect()
}
