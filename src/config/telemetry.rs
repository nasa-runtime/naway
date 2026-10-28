//! 三信号遥测的独立资源预算与传输配置。

use serde::{Deserialize, Serialize};

/// 所有信号共用的 wire 协议；每个信号仍有独立 endpoint 与运行队列。
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OtlpProtocol {
    #[default]
    HttpProtobuf,
    Grpc,
}

/// 显式启用的三信号出口，不读取 OTEL 环境变量覆盖已审核配置。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OtlpCfg {
    pub protocol: OtlpProtocol,
    pub traces: OtlpSignalCfg,
    pub metrics: OtlpSignalCfg,
    pub logs: OtlpSignalCfg,
    /// 后台读取同一组指标事实的周期，不在请求完成路径构造快照。
    pub metrics_interval_ms: u64,
    /// 作用域采样只读取已验证配置身份，不信任请求携带的 workspace/product 标签。
    pub sampling: SamplingCfg,
    /// 只开放受双主体审批的本机诊断入口，默认不采集任何流量。
    pub traffic_tap: bool,
}

impl Default for OtlpCfg {
    /// 业务作用：为显式选择的三信号出口分配互不借用的有限预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：三个出口默认开启，指标按固定周期采集；顶层 trace 开关仍决定是否记录 span。
    fn default() -> Self {
        Self {
            protocol: OtlpProtocol::HttpProtobuf,
            traces: OtlpSignalCfg::default(),
            metrics: OtlpSignalCfg::default(),
            logs: OtlpSignalCfg::default(),
            metrics_interval_ms: 10_000,
            sampling: SamplingCfg::default(),
            traffic_tap: false,
        }
    }
}

/// 远端父采样策略；两种形态均保留受信父的 trace lineage，不接纳不可信传播头。
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteParent {
    /// 继承 sampled 位；未采样父同时禁止本节点错误/慢请求提升。
    #[default]
    Inherit,
    /// 保留父身份，但由本节点的已冻结策略重新决定本地采样。
    Resample,
}

/// 平台缺省和显式作用域覆盖；完整 trace 的 tail decision 留给 Collector。
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SamplingCfg {
    pub remote_parent: RemoteParent,
    pub error_ratio: f64,
    /// 零表示关闭慢请求提升；正值仅触发有限 server 摘要，不恢复未采集的子 span。
    pub slow_ms: u64,
    pub slow_ratio: f64,
    pub rules: Vec<SamplingRule>,
}

/// 固定层级的采样覆盖，不使用规则声明顺序裁决。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SamplingRule {
    pub scope: SamplingScope,
    pub head_ratio: Option<f64>,
    pub error_ratio: Option<f64>,
    pub slow_ms: Option<u64>,
    pub slow_ratio: Option<f64>,
    pub remote_parent: Option<RemoteParent>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SamplingScope {
    Listener {
        proxy: String,
    },
    Workspace {
        workspace: String,
    },
    Product {
        product: String,
        version: String,
    },
    Route {
        proxy: String,
        route: String,
    },
}

/// 业务作用：拒绝不可执行或资源无界的采样声明，不允许 NaN 参与随机阈值判断。
///
/// 参数说明：
/// - `cfg`：是平台缺省与有限作用域规则。
///
/// 返回：概率、时间和规则身份均满足静态门禁时成功；重复作用域一律拒绝。
pub fn validate_sampling(cfg: &SamplingCfg) -> anyhow::Result<()> {
    let valid_ratio = |ratio: f64| ratio.is_finite() && (0.0..=1.0).contains(&ratio);
    anyhow::ensure!(
        cfg.rules.len() <= 1024
            && cfg.slow_ms <= 600_000
            && valid_ratio(cfg.error_ratio)
            && valid_ratio(cfg.slow_ratio),
        "invalid telemetry sampling defaults or rule budget"
    );
    let mut scopes = std::collections::BTreeSet::new();
    for rule in &cfg.rules {
        anyhow::ensure!(
            scopes.insert(&rule.scope),
            "duplicate telemetry sampling scope"
        );
        anyhow::ensure!(
            [rule.head_ratio, rule.error_ratio, rule.slow_ratio]
                .into_iter()
                .flatten()
                .all(valid_ratio)
                && rule.slow_ms.is_none_or(|value| value <= 600_000),
            "invalid telemetry sampling override"
        );
        let names: Vec<&str> = match &rule.scope {
            SamplingScope::Listener {
                proxy,
            } => vec![proxy],
            SamplingScope::Workspace {
                workspace,
            } => vec![workspace],
            SamplingScope::Product {
                product,
                version,
            } => vec![product, version],
            SamplingScope::Route {
                proxy,
                route,
            } => vec![proxy, route],
        };
        anyhow::ensure!(
            names.iter().all(|name| !name.is_empty()
                && name.len() <= 256
                && !name.chars().any(char::is_control)),
            "invalid telemetry sampling scope identity"
        );
    }
    Ok(())
}

/// 一个信号的记录、批次、总请求期限与失败隔离上限。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OtlpSignalCfg {
    pub enabled: bool,
    /// 未指定时继承 telemetry.endpoint；HTTP 根地址自动附加该信号的标准路径。
    pub endpoint: Option<String>,
    pub queue_size: usize,
    pub batch_size: usize,
    pub max_record_bytes: usize,
    pub max_batch_bytes: usize,
    pub batch_delay_ms: u64,
    /// 从首发到最后一次重试共用同一个绝对期限。
    pub deadline_ms: u64,
    /// 首发之外的最大重试次数；仅重试协议明确允许的瞬时错误。
    pub retry_limit: u32,
    pub retry_base_ms: u64,
    pub circuit_failures: u32,
    pub circuit_open_ms: u64,
}

impl Default for OtlpSignalCfg {
    /// 业务作用：建立不依赖 collector 响应速度的单信号内存与时间边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：队列最多占用 16 MiB 记录载荷，批次最多 1 MiB，后台请求总期限五秒。
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: None,
            queue_size: 1024,
            batch_size: 128,
            max_record_bytes: 16 * 1024,
            max_batch_bytes: 1024 * 1024,
            batch_delay_ms: 1000,
            deadline_ms: 5000,
            retry_limit: 2,
            retry_base_ms: 100,
            circuit_failures: 5,
            circuit_open_ms: 10_000,
        }
    }
}

/// 业务作用：在创建任何 exporter 任务前验证每个信号的最坏资源占用与 collector 地址。
///
/// 参数说明：
/// - `cfg`：是候选出口配置
/// - `fallback`：是顶层 collector 基地址。
///
/// 返回：所有硬门满足时成功；缺少制品能力、非法地址或预算超限时拒绝整个配置候选。
pub fn validate(cfg: &OtlpCfg, fallback: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(feature = "telemetry-otlp"),
        "telemetry.multi_signal requires telemetry-otlp feature"
    );
    anyhow::ensure!(
        (100..=3_600_000).contains(&cfg.metrics_interval_ms),
        "telemetry metrics_interval_ms must be within 100..=3600000"
    );
    validate_sampling(&cfg.sampling)?;
    for (name, signal) in [
        ("traces", &cfg.traces),
        ("metrics", &cfg.metrics),
        ("logs", &cfg.logs),
    ] {
        anyhow::ensure!(
            (1..=16_384).contains(&signal.queue_size)
                && (1..=1024).contains(&signal.batch_size)
                && signal.batch_size <= signal.queue_size
                && (1024..=262_144).contains(&signal.max_record_bytes)
                && (signal.max_record_bytes + 1024..=4 * 1024 * 1024)
                    .contains(&signal.max_batch_bytes)
                && signal.queue_size.saturating_mul(signal.max_record_bytes) <= 64 * 1024 * 1024,
            "telemetry {name} queue or record/batch byte budget is invalid"
        );
        anyhow::ensure!(
            (1..=60_000).contains(&signal.batch_delay_ms)
                && (1..=60_000).contains(&signal.deadline_ms)
                && signal.retry_limit <= 8
                && (1..=10_000).contains(&signal.retry_base_ms)
                && (1..=100).contains(&signal.circuit_failures)
                && (1..=300_000).contains(&signal.circuit_open_ms),
            "telemetry {name} deadline/retry/circuit budget is invalid"
        );
        endpoint(
            cfg.protocol,
            signal.endpoint.as_deref().unwrap_or(fallback),
            name,
        )?;
    }
    Ok(())
}

/// 业务作用：为一个信号生成无凭据、无查询参数的明确 collector 地址。
///
/// 参数说明：
/// - `protocol`：决定路径语义
/// - `configured`：是配置地址
/// - `signal`：是固定协议名称。
///
/// 返回：合法绝对地址；gRPC 非根路径、用户信息、查询参数与 fragment 一律拒绝。
pub fn endpoint(protocol: OtlpProtocol, configured: &str, signal: &str) -> anyhow::Result<String> {
    let uri: http::Uri = configured.parse()?;
    anyhow::ensure!(
        configured.len() <= 2048
            && !configured.contains('#')
            && matches!(uri.scheme_str(), Some("http" | "https"))
            && uri.authority().is_some_and(|value| !value.as_str().contains('@'))
            && uri.query().is_none(),
        "telemetry endpoint must be an absolute http/https address without credentials, query or fragment"
    );
    let root = matches!(uri.path(), "" | "/");
    match protocol {
        OtlpProtocol::Grpc => {
            anyhow::ensure!(
                root,
                "telemetry gRPC endpoint must not contain a signal path"
            );
            Ok(configured.trim_end_matches('/').to_owned())
        }
        OtlpProtocol::HttpProtobuf if root => {
            Ok(format!("{}/v1/{signal}", configured.trim_end_matches('/')))
        }
        OtlpProtocol::HttpProtobuf => Ok(configured.to_owned()),
    }
}
