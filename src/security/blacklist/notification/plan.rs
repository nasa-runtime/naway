//! 通知候选只冻结目的地、预算与秘密，不启动外部生产者或投递任务。

use crate::config::model::{AclNotificationTlsCfg, AclNotificationTransport, AclNotificationsCfg};
use anyhow::{ensure, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

pub struct Plan {
    pub(super) destination: Destination,
    pub(super) attempts: u8,
    pub(super) timeout: Duration,
    pub(super) retry_delay: Duration,
    pub(super) max_age: Duration,
    pub(super) revoked: AtomicBool,
}

pub(super) enum Destination {
    StoreWatch,
    Webhook {
        url: reqwest::Url,
        key: Zeroizing<String>,
        client: reqwest::Client,
    },
    #[cfg(feature = "acl-kafka")]
    Kafka(Arc<super::kafka::Spec>),
    #[cfg(feature = "acl-rocketmq")]
    Rocketmq(Arc<super::rocketmq::Spec>),
}

impl Plan {
    /// 业务作用：建立没有外部资源的默认通知计划，业务通过原事实源watch取得封禁事件。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未激活且不会进行网络投递的计划。
    pub fn store_watch() -> Arc<Self> {
        Arc::new(Self {
            destination: Destination::StoreWatch,
            attempts: 1,
            timeout: Duration::from_secs(2),
            retry_delay: Duration::from_millis(250),
            max_age: Duration::from_secs(60),
            revoked: AtomicBool::new(true),
        })
    }

    /// 业务作用：校验通知合同并冻结SecretSource与TLS材料，候选构建不会执行事实写入或外发。
    ///
    /// 参数说明：
    /// - `cfg`：平台黑名单固定通知声明，省略时使用store-watch。
    /// - `config_dir`：文件型SecretSource的受管解析基准。
    ///
    /// 返回：全部预算、地址和材料合法的不可变计划；非法或当前制品不支持的出口拒绝整个候选。
    pub fn build(cfg: Option<&AclNotificationsCfg>, config_dir: &Path) -> Result<Arc<Self>> {
        let Some(cfg) = cfg else {
            return Ok(Self::store_watch());
        };
        ensure!(
            (1..=8).contains(&cfg.attempts),
            "ACL notification attempts must be within 1..=8"
        );
        ensure!(
            (50..=10_000).contains(&cfg.timeout_ms),
            "ACL notification timeout_ms must be within 50..=10000"
        );
        ensure!(
            (1..=5000).contains(&cfg.retry_delay_ms),
            "ACL notification retry_delay_ms must be within 1..=5000"
        );
        ensure!(
            (1000..=300_000).contains(&cfg.max_age_ms) && cfg.timeout_ms <= cfg.max_age_ms,
            "ACL notification max_age_ms must be within 1000..=300000 and cover one attempt"
        );
        let destination = match &cfg.transport {
            AclNotificationTransport::StoreWatch => Destination::StoreWatch,
            AclNotificationTransport::Webhook {
                url,
                signing_key,
                allow_plaintext,
                tls,
            } => {
                let url = endpoint(url, *allow_plaintext)?;
                // 明文出口无法履行CA或客户端身份合同，不能接受材料后静默忽略。
                ensure!(
                    url.scheme() != "http"
                        || (tls.ca_pem.is_none()
                            && tls.client_cert_pem.is_none()
                            && tls.client_key_pem.is_none()),
                    "ACL plaintext webhook cannot configure TLS material"
                );
                let key = secret(signing_key, config_dir)?;
                ensure!(
                    key.len() >= 32,
                    "ACL webhook signing key must contain at least 32 bytes"
                );
                let client = http_client(tls, config_dir)?;
                Destination::Webhook {
                    url,
                    key,
                    client,
                }
            }
            AclNotificationTransport::Kafka {
                ..
            } => {
                #[cfg(feature = "acl-kafka")]
                {
                    Destination::Kafka(super::kafka::Spec::build(
                        &cfg.transport,
                        config_dir,
                        Duration::from_millis(cfg.timeout_ms),
                    )?)
                }
                #[cfg(not(feature = "acl-kafka"))]
                anyhow::bail!("ACL Kafka notification transport requires feature `acl-kafka`")
            }
            AclNotificationTransport::Rocketmq {
                ..
            } => {
                #[cfg(feature = "acl-rocketmq")]
                {
                    Destination::Rocketmq(super::rocketmq::Spec::build(
                        &cfg.transport,
                        config_dir,
                        Duration::from_millis(cfg.timeout_ms),
                    )?)
                }
                #[cfg(not(feature = "acl-rocketmq"))]
                anyhow::bail!("ACL RocketMQ notification transport requires feature `acl-rocketmq`")
            }
        };
        Ok(Arc::new(Self {
            destination,
            attempts: cfg.attempts,
            timeout: Duration::from_millis(cfg.timeout_ms),
            retry_delay: Duration::from_millis(cfg.retry_delay_ms),
            max_age: Duration::from_millis(cfg.max_age_ms),
            revoked: AtomicBool::new(true),
        }))
    }

    /// 业务作用：确定计划是否需要唯一外发worker，默认watch不占外部任务或连接。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：显式外部出口为真。
    pub(super) fn external(&self) -> bool {
        !matches!(self.destination, Destination::StoreWatch)
    }

    /// 业务作用：给观测读面提供固定出口类型，不暴露URL、主题或秘密。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前支持的低基数传输名称。
    pub(super) fn kind(&self) -> &'static str {
        match self.destination {
            Destination::StoreWatch => "store_watch",
            Destination::Webhook {
                ..
            } => "webhook",
            #[cfg(feature = "acl-kafka")]
            Destination::Kafka(_) => "kafka",
            #[cfg(feature = "acl-rocketmq")]
            Destination::Rocketmq(_) => "rocketmq",
        }
    }

    /// 业务作用：在同代发布点撤销旧计划，排队与重试不能把旧操作转交新出口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：旧计划不再接受新的外发尝试；已经被远端接收的字节无法追撤。
    pub(super) fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }
}

/// 业务作用：收集所有已声明通知秘密文件，轮换必须进入正常候选指纹与观察链。
///
/// 参数说明：
/// - `cfg`：可选固定通知出口。
/// - `config_dir`：SecretSource相对文件的解析基准。
///
/// 返回：未去重的精确依赖列表；不读取材料、不建立连接。
pub fn dependencies(cfg: Option<&AclNotificationsCfg>, config_dir: &Path) -> Vec<PathBuf> {
    let Some(cfg) = cfg else {
        return Vec::new();
    };
    let mut sources = Vec::new();
    let tls = match &cfg.transport {
        AclNotificationTransport::StoreWatch => None,
        AclNotificationTransport::Webhook {
            signing_key,
            tls,
            ..
        } => {
            sources.push(signing_key.as_str());
            Some(tls)
        }
        AclNotificationTransport::Kafka {
            tls,
            sasl,
            ..
        } => {
            if let Some(sasl) = sasl {
                sources.extend([sasl.username.as_str(), sasl.password.as_str()]);
            }
            Some(tls)
        }
        AclNotificationTransport::Rocketmq {
            tls,
            access_key,
            secret_key,
            ..
        } => {
            sources.extend(access_key.as_deref());
            sources.extend(secret_key.as_deref());
            Some(tls)
        }
    };
    if let Some(tls) = tls {
        sources.extend(tls.ca_pem.as_deref());
        sources.extend(tls.client_cert_pem.as_deref());
        sources.extend(tls.client_key_pem.as_deref());
    }
    sources
        .into_iter()
        .filter_map(|source| crate::security::secret::dependency_path(source, config_dir))
        .collect()
}

/// 业务作用：只接受平台声明的固定HTTP地址，拒绝内嵌凭据和隐式明文降级。
///
/// 参数说明：
/// - `raw`：平台声明的出口地址。
/// - `allow_plaintext`：显式允许HTTP的部署选择，默认关闭。
///
/// 返回：有主机且无userinfo/fragment的固定URL；所有错误只包含固定低敏原因。
pub(super) fn endpoint(raw: &str, allow_plaintext: bool) -> Result<reqwest::Url> {
    ensure!(raw.len() <= 2048, "ACL notification endpoint oversized");
    let url = reqwest::Url::parse(raw)
        .map_err(|_| anyhow::anyhow!("invalid ACL notification endpoint"))?;
    ensure!(
        url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "invalid ACL notification endpoint authority"
    );
    ensure!(
        url.scheme() == "https" || (allow_plaintext && url.scheme() == "http"),
        "ACL notification endpoint requires HTTPS or explicit allow_plaintext"
    );
    Ok(url)
}

/// 业务作用：按受管SecretSource冻结通知秘密，不让依赖错误回显材料或出口。
///
/// 参数说明：
/// - `raw`：配置中的SecretSource。
/// - `config_dir`：相对材料文件基准。
///
/// 返回：最后持有者释放时清零的文本；解析失败返回固定低敏错误。
pub(super) fn secret(raw: &str, config_dir: &Path) -> Result<Zeroizing<String>> {
    crate::security::secret::resolve_text(raw, config_dir, "ACL notification secret")
        .map(Zeroizing::new)
        .map_err(|_| anyhow::anyhow!("ACL notification SecretSource unavailable"))
}

/// 业务作用：编译固定通知HTTP客户端的信任与身份，不跟随重定向或环境代理转移已签名事件。
///
/// 参数说明：
/// - `tls`：显式CA与可选客户端身份SecretSource。
/// - `config_dir`：材料解析基准。
///
/// 返回：尚未发起连接的客户端；坏材料和不完整身份拒绝候选。
fn http_client(tls: &AclNotificationTlsCfg, config_dir: &Path) -> Result<reqwest::Client> {
    Ok(tls_material(tls, config_dir)?.client)
}

pub(super) struct TlsMaterial {
    #[cfg(any(feature = "acl-kafka", feature = "acl-rocketmq"))]
    pub(super) ca: Option<Zeroizing<String>>,
    #[cfg(any(feature = "acl-kafka", feature = "acl-rocketmq"))]
    pub(super) cert: Option<Zeroizing<String>>,
    #[cfg(any(feature = "acl-kafka", feature = "acl-rocketmq"))]
    pub(super) key: Option<Zeroizing<String>>,
    client: reqwest::Client,
}

/// 业务作用：一次读取并校验通知TLS材料，HTTP与MQ使用同一份已冻结的信任和客户端身份。
///
/// 参数说明：
/// - `tls`：固定出口的CA和可选客户端证书/私钥来源。
/// - `config_dir`：文件型材料的解析基准。
///
/// 返回：冻结且已通过客户端构建的完整材料；无外连，坏材料或不完整身份拒绝候选。
pub(super) fn tls_material(tls: &AclNotificationTlsCfg, config_dir: &Path) -> Result<TlsMaterial> {
    let ca = tls
        .ca_pem
        .as_deref()
        .map(|raw| secret(raw, config_dir))
        .transpose()?;
    let cert = tls
        .client_cert_pem
        .as_deref()
        .map(|raw| secret(raw, config_dir))
        .transpose()?;
    let key = tls
        .client_key_pem
        .as_deref()
        .map(|raw| secret(raw, config_dir))
        .transpose()?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(30));
    if let Some(pem) = &ca {
        let certificates = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
            .context("invalid ACL notification CA material")?;
        ensure!(
            !certificates.is_empty(),
            "ACL notification CA material is empty"
        );
        builder = builder.tls_certs_only(certificates);
    }
    ensure!(
        tls.client_cert_pem.is_some() == tls.client_key_pem.is_some(),
        "ACL notification TLS requires both client certificate and key"
    );
    if let (Some(cert), Some(key)) = (&cert, &key) {
        let pem = Zeroizing::new(format!("{}\n{}", cert.as_str(), key.as_str()));
        builder = builder.identity(
            reqwest::Identity::from_pem(pem.as_bytes())
                .context("invalid ACL notification client identity")?,
        );
    }
    let client = builder
        .build()
        .map_err(|_| anyhow::anyhow!("ACL notification HTTP client unavailable"))?;
    Ok(TlsMaterial {
        #[cfg(any(feature = "acl-kafka", feature = "acl-rocketmq"))]
        ca,
        #[cfg(any(feature = "acl-kafka", feature = "acl-rocketmq"))]
        cert,
        #[cfg(any(feature = "acl-kafka", feature = "acl-rocketmq"))]
        key,
        client,
    })
}

/// 业务作用：限制MQ主题为固定有界标识，不让控制字符或保留主题进入通知目的地。
///
/// 参数说明：
/// - `value`：平台显式选择的主题名称。
///
/// 返回：1至128字节ASCII字母、数字、点、下划线或连字符；两个相对路径保留名称拒绝。
#[cfg(any(feature = "acl-kafka", feature = "acl-rocketmq"))]
pub(super) fn topic(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "invalid ACL notification MQ topic"
    );
    Ok(())
}
