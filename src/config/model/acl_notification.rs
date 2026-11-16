//! 封禁操作通知的固定出口声明；事件不会从请求选择目的地。

use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AclNotificationsCfg {
    pub transport: AclNotificationTransport,
    pub attempts: u8,
    pub timeout_ms: u64,
    pub retry_delay_ms: u64,
    pub max_age_ms: u64,
}

impl Default for AclNotificationsCfg {
    /// 业务作用：默认仅使用事实源watch，不启动外发任务或创建消息生产者。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：三次有界投递预算；外发必须显式选择固定出口。
    fn default() -> Self {
        Self {
            transport: AclNotificationTransport::StoreWatch,
            attempts: 3,
            timeout_ms: 2000,
            retry_delay_ms: 250,
            max_age_ms: 60_000,
        }
    }
}

impl std::fmt::Debug for AclNotificationsCfg {
    /// 业务作用：诊断只展示通知预算，不能打印签名秘密、MQ凭据或含业务身份的出口地址。
    ///
    /// 参数说明：
    /// - `formatter`：接收有限诊断字段的格式器。
    ///
    /// 返回：固定预算及出口是否显式配置，不读取秘密或建立连接。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AclNotificationsCfg")
            .field(
                "external",
                &!matches!(self.transport, AclNotificationTransport::StoreWatch),
            )
            .field("attempts", &self.attempts)
            .field("timeout_ms", &self.timeout_ms)
            .field("retry_delay_ms", &self.retry_delay_ms)
            .field("max_age_ms", &self.max_age_ms)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AclNotificationTransport {
    #[default]
    StoreWatch,
    Webhook {
        url: String,
        signing_key: String,
        #[serde(default)]
        allow_plaintext: bool,
        #[serde(default)]
        tls: AclNotificationTlsCfg,
    },
    Kafka {
        bootstrap_servers: String,
        topic: String,
        #[serde(default)]
        allow_plaintext: bool,
        #[serde(default)]
        tls: AclNotificationTlsCfg,
        #[serde(default)]
        sasl: Option<AclNotificationSaslCfg>,
    },
    Rocketmq {
        endpoint: String,
        topic: String,
        #[serde(default)]
        namespace: String,
        #[serde(default)]
        allow_plaintext: bool,
        #[serde(default)]
        tls: AclNotificationTlsCfg,
        #[serde(default)]
        access_key: Option<String>,
        #[serde(default)]
        secret_key: Option<String>,
    },
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AclNotificationTlsCfg {
    pub ca_pem: Option<String>,
    pub client_cert_pem: Option<String>,
    pub client_key_pem: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclNotificationSaslCfg {
    pub mechanism: String,
    pub username: String,
    pub password: String,
}
