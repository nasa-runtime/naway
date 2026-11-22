//! 中心输入的启动期总开关；只在候选构建阶段裁剪权限，不在请求路径追加判断。

use super::model::{GatewayConfig, NacosConfigSourceCfg};
use super::providers::TransportCfg;

/// 业务作用：在创建远端客户端、解析中心凭据或合并远端对象前撤销已关闭中心的输入权限。
///
/// 参数说明：
/// - `cfg`：本地文件或完整候选解析得到的配置；仅裁剪构建输入，不改写操作者保存的原始文档。
///
/// 返回：原地关闭对应后端；显式选择已关闭的中心作为共享状态存储，或启用制品未包含的配置传输能力时失败，其它动态引用由完整构建链拒绝。
pub(super) fn apply(cfg: &mut GatewayConfig) -> anyhow::Result<()> {
    if !cfg.config_source.enabled {
        // 共享事实源不能隐式降级为各节点独立文件，否则黑名单和应急规则会失去原有集群一致性。
        anyhow::ensure!(
            !cfg.runtime_state
                .store
                .backend
                .trim()
                .eq_ignore_ascii_case("nacos"),
            "runtime_state.store.backend=nacos requires config_source.enabled=true"
        );
        // 配置中心关闭后不能借 provider 或 xDS 再引入远端权威；本地文件与管理发布不受影响。
        cfg.config_source.nacos.enabled = false;
        cfg.providers.enabled = false;
        cfg.providers.sources.clear();
    }
    if !cfg.discovery.enabled {
        cfg.discovery.nacos.enabled = false;
        cfg.discovery.nacos.self_register.enabled = false;
        cfg.discovery.consul.enabled = false;
        cfg.discovery.eureka.enabled = false;
        cfg.discovery.dns.enabled = false;
        cfg.discovery.kubernetes.enabled = false;
        // 工作负载来源同时发现实例和物化路由，不能绕过注册中心总开关；纯配置来源仍可工作。
        cfg.providers.sources.retain(|source| {
            !matches!(
                source.transport,
                TransportCfg::Ecs { .. } | TransportCfg::Nomad { .. } | TransportCfg::Docker { .. }
            )
        });
        if cfg.providers.sources.is_empty() {
            cfg.providers.enabled = false;
        }
    }
    if !cfg.config_source.enabled || !cfg.discovery.enabled {
        // 这两类输入同时拥有路由和动态端点，必须取得两项授权。关闭后不得读取旧物化文件。
        cfg.kubernetes_routes.enabled = false;
        cfg.control_plane = super::model::ControlPlaneCfg::default();
    }
    if cfg.config_source.nacos.enabled {
        // 订阅必须具备真实传输能力；构建时拒绝才能避免开放业务路由后常驻任务持续失败。
        anyhow::ensure!(
            cfg!(feature = "nacos-sdk"),
            "config_source.nacos.enabled requires building gateway with feature `nacos-sdk`"
        );
    }
    Ok(())
}

/// 业务作用：统一拒绝运行中更换中心输入权威，避免快照与常驻订阅任务持有不同声明。
///
/// 参数说明：
/// - `current`：仍在提供服务的活动快照。
/// - `candidate`：尚未发布的候选快照。
///
/// 返回：总开关或活动配置订阅的启动参数变化时返回需要重启的键；两端均未启用的连接参数可以预填，不修改任何运行态。
pub(crate) fn restart_field(
    current: &super::GatewaySnapshot,
    candidate: &super::GatewaySnapshot,
) -> Option<&'static str> {
    if current.discovery.enabled != candidate.discovery.enabled {
        return Some("discovery.enabled");
    }
    if current.config_source.enabled != candidate.config_source.enabled {
        return Some("config_source.enabled");
    }
    if (current.config_source.nacos.enabled || candidate.config_source.nacos.enabled)
        && !same_nacos_config_bootstrap(
            &current.config_source.nacos,
            &candidate.config_source.nacos,
        )
    {
        // 配置订阅只在启动时创建；先拒绝身份、文档或开关变化，不能发布一个没有对应任务的新权威。
        return Some("config_source.nacos");
    }
    None
}

/// 业务作用：比较配置订阅常驻任务冻结的全部启动参数，使本地和远端候选遵守同一来源合同。
///
/// 参数说明：
/// - `current`：活动快照中绑定的配置订阅声明。
/// - `candidate`：候选快照要求使用的配置订阅声明。
///
/// 返回：开关、连接身份、凭据、文档集合、物化目录和重连策略全部相同时为真；不读取远端、不解析凭据或发布配置。
pub(crate) fn same_nacos_config_bootstrap(
    current: &NacosConfigSourceCfg,
    candidate: &NacosConfigSourceCfg,
) -> bool {
    current.enabled == candidate.enabled
        && current.server_addr == candidate.server_addr
        && current.namespace == candidate.namespace
        && current.group == candidate.group
        && current.app_name == candidate.app_name
        && current.username == candidate.username
        && current.password == candidate.password
        && current.gateway_data_id == candidate.gateway_data_id
        && current.interface_guard_data_id == candidate.interface_guard_data_id
        && current.sentinel_rules_data_id == candidate.sentinel_rules_data_id
        && current.bundle_data_id == candidate.bundle_data_id
        && current.materialized_dir == candidate.materialized_dir
        && current.reconnect_backoff_ms == candidate.reconnect_backoff_ms
}
