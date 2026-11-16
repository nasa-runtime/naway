//! 业务通知复用NASA生产者，仅唯一worker持有一个当前Kafka运行态。

use super::{AclNotifier, Event};
use anyhow::{ensure, Result};
use futures::future::BoxFuture;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroize;

pub(super) struct Spec {
    bootstrap: String,
    topic: String,
    security: nasa::kafka::SecurityConfig,
    properties: BTreeMap<String, String>,
}

impl Drop for Spec {
    /// 业务作用：旧计划最后释放时清除网关保留的MQ口令和客户端私钥副本。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：清零本计划的敏感材料；底层生产者自身持有的副本由其独立停止流程释放。
    fn drop(&mut self) {
        if let Some(password) = self.security.sasl_password.as_mut() {
            password.zeroize();
        }
        for value in self.properties.values_mut() {
            value.zeroize();
        }
    }
}

impl Spec {
    /// 业务作用：冻结固定Kafka目的地、SASL和TLS秘密，不在候选阶段创建生产者线程。
    ///
    /// 参数说明：
    /// - `cfg`：已选择Kafka的固定平台出口。
    /// - `config_dir`：所有SecretSource文件的解析基准。
    /// - `timeout`：当前计划的单次投递预算，静态校验与实际生产者共用。
    ///
    /// 返回：合法主题、端点、凭据和材料的不可变计划；不支持的认证或隐式明文拒绝。
    pub(super) fn build(
        cfg: &crate::config::model::AclNotificationTransport,
        config_dir: &Path,
        timeout: std::time::Duration,
    ) -> Result<Arc<Self>> {
        let crate::config::model::AclNotificationTransport::Kafka {
            bootstrap_servers,
            topic,
            allow_plaintext,
            tls,
            sasl,
        } = cfg
        else {
            anyhow::bail!("ACL Kafka plan unavailable");
        };
        super::plan::topic(topic)?;
        ensure!(
            !bootstrap_servers.is_empty() && bootstrap_servers.len() <= 1024,
            "invalid ACL Kafka bootstrap servers"
        );
        let addresses = bootstrap_servers.split(',').collect::<Vec<_>>();
        ensure!(
            addresses.len() <= 8,
            "ACL Kafka bootstrap servers exceeds eight addresses"
        );
        for address in addresses {
            let authority = address
                .parse::<http::uri::Authority>()
                .map_err(|_| anyhow::anyhow!("invalid ACL Kafka bootstrap authority"))?;
            ensure!(
                !authority.host().is_empty()
                    && authority.port_u16().is_some()
                    && !address.contains('@'),
                "invalid ACL Kafka bootstrap authority"
            );
        }
        let mut security = nasa::kafka::SecurityConfig {
            protocol: Some(
                if *allow_plaintext {
                    "PLAINTEXT"
                } else {
                    "SSL"
                }
                .to_owned(),
            ),
            ..Default::default()
        };
        if let Some(sasl) = sasl {
            ensure!(
                matches!(
                    sasl.mechanism.as_str(),
                    "PLAIN" | "SCRAM-SHA-256" | "SCRAM-SHA-512"
                ),
                "unsupported ACL Kafka SASL mechanism"
            );
            let username = super::plan::secret(&sasl.username, config_dir)?;
            let password = super::plan::secret(&sasl.password, config_dir)?;
            ensure!(
                !username.is_empty()
                    && username.len() <= 256
                    && !username.chars().any(char::is_control)
                    && !password.is_empty(),
                "invalid ACL Kafka SASL credentials"
            );
            security.protocol = Some(
                if *allow_plaintext {
                    "SASL_PLAINTEXT"
                } else {
                    "SASL_SSL"
                }
                .to_owned(),
            );
            security.sasl_mechanism = Some(sasl.mechanism.clone());
            security.sasl_username = Some(username.to_string());
            security.sasl_password = Some(password.to_string());
        }
        ensure!(
            !*allow_plaintext
                || (tls.ca_pem.is_none()
                    && tls.client_cert_pem.is_none()
                    && tls.client_key_pem.is_none()),
            "ACL plaintext Kafka cannot configure TLS material"
        );
        let mut properties = BTreeMap::new();
        if !*allow_plaintext {
            let materials = super::plan::tls_material(tls, config_dir)?;
            if let Some(ca) = materials.ca {
                properties.insert("ssl.ca.pem".to_owned(), ca.to_string());
            }
            if let (Some(cert), Some(key)) = (materials.cert, materials.key) {
                properties.insert("ssl.certificate.pem".to_owned(), cert.to_string());
                properties.insert("ssl.key.pem".to_owned(), key.to_string());
            }
        }
        let spec = Arc::new(Self {
            bootstrap: bootstrap_servers.clone(),
            topic: topic.clone(),
            security,
            properties,
        });
        // 仅验证NASA冻结配置，不创建客户端；框架保留键必须由类型化字段提供。
        configuration(&spec, timeout)
            .validate()
            .map_err(|_| anyhow::anyhow!("invalid ACL Kafka producer configuration"))?;
        Ok(spec)
    }
}

struct Kafka {
    runtime: nasa::kafka::KafkaProxy,
    lane: nasa::kafka::ProducerLane,
    spec: Arc<Spec>,
}

impl AclNotifier for Kafka {
    /// 业务作用：向固定主题提交原通知JSON，以完整事件身份作为分区键，重试仍可能产生重复记录。
    ///
    /// 参数说明：
    /// - `event`：已确认封禁操作的原身份。
    /// - `body`：跨重试不变的有界原文。
    ///
    /// 返回：NASA生产者收到broker投递确认时成功；失败保持原操作事实，不回显连接配置。
    fn send<'a>(&'a mut self, event: &'a Event, body: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.lane
                .publish_raw(&self.spec.topic, body)
                .event("gateway.acl")
                .key(&event.event_id)
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("ACL Kafka delivery unavailable"))?;
            Ok(())
        })
    }

    /// 业务作用：停止旧生产者及其后台资源，确认完成前不能创建下一配置的客户端。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界停止成功或固定错误；外层worker在未知停止结果下关闭后续外发。
    fn shutdown(&mut self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.runtime
                .shutdown()
                .await
                .map_err(|_| anyhow::anyhow!("ACL Kafka shutdown unavailable"))
        })
    }
}

/// 业务作用：由唯一投递worker创建固定容量的NASA Kafka生产者，不随请求或候选构建创建线程。
///
/// 参数说明：
/// - `spec`：原操作绑定的固定主题与材料。
/// - `timeout`：单次投递的已验证期限。
///
/// 返回：最多128条内部消息且单通道的适配器；初始化失败返回低敏错误。
pub(super) fn build(spec: Arc<Spec>, timeout: std::time::Duration) -> Result<Box<dyn AclNotifier>> {
    let runtime = nasa::kafka::KafkaProxy::connect(configuration(&spec, timeout))
        .map_err(|_| anyhow::anyhow!("ACL Kafka producer unavailable"))?;
    let lane = runtime
        .producer_lane("default")
        .map_err(|_| anyhow::anyhow!("ACL Kafka producer lane unavailable"))?;
    Ok(Box::new(Kafka {
        runtime,
        lane,
        spec,
    }))
}

/// 业务作用：让候选静态校验与实际生产者使用同一份容量、顺序及期限配置，避免启动后才发现声明无法执行。
///
/// 参数说明：
/// - `spec`：已冻结的目的地与认证材料。
/// - `timeout`：包含底层重试的单次投递预算。
///
/// 返回：尚未建立连接或启动线程的NASA配置；框架保留键只使用类型化字段。
fn configuration(spec: &Spec, timeout: std::time::Duration) -> nasa::kafka::KafkaConfig {
    let timeout_ms = timeout.as_millis() as u64;
    let producer = nasa::kafka::ProducerConfig {
        request_timeout_ms: timeout_ms,
        delivery_timeout_ms: timeout_ms,
        linger_ms: 0,
        queue_buffering_max_messages: 128,
        queue_buffering_max_kbytes: 512,
        fire_observer_capacity: 128,
        enable_idempotence: true,
        max_in_flight_requests_per_connection: 1,
        ..Default::default()
    };
    nasa::kafka::KafkaConfig {
        client_name: "gateway-acl-notification".to_owned(),
        bootstrap_servers: spec.bootstrap.clone(),
        group_id: None,
        client_id_prefix: Some("gateway-acl".to_owned()),
        producer,
        consumer: Default::default(),
        admin: Default::default(),
        behavior: nasa::kafka::BehaviorConfig {
            publish_timeout_ms: timeout_ms,
            shutdown_timeout_ms: 1000,
            ..Default::default()
        },
        security: spec.security.clone(),
        properties: spec.properties.clone(),
    }
}
