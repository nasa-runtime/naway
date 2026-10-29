//! 不可变上游声明的类型化比较，运行中的发现与健康事实不参与配置差异。

use super::{ServiceSnapshot, UpstreamDirectory, UpstreamInstance};
use crate::tls::UpstreamTlsProfile;

impl UpstreamDirectory {
    /// 业务作用：按稳定服务名比较完整配置策略，使同名服务的治理变化也进入候选审查。
    ///
    /// 参数说明：
    /// - `candidate`：完成构建的候选目录，不读取其动态实例或健康状态。
    ///
    /// 返回：借用原目录的新增、删除和变化名称，按字典序排列；不复制实例、策略或凭据。
    pub(crate) fn configuration_changes<'a>(
        &'a self,
        candidate: &'a Self,
    ) -> (Vec<&'a str>, Vec<&'a str>, Vec<&'a str>) {
        let mut added = candidate
            .services
            .keys()
            .filter(|name| !self.services.contains_key(*name))
            .map(String::as_str)
            .collect::<Vec<_>>();
        let mut removed = self
            .services
            .keys()
            .filter(|name| !candidate.services.contains_key(*name))
            .map(String::as_str)
            .collect::<Vec<_>>();
        let mut changed = self
            .services
            .iter()
            .filter_map(|(name, current)| {
                let next = candidate.services.get(name)?;
                let prewarm_changed = self.prewarm_scan_interval_ms
                    != candidate.prewarm_scan_interval_ms
                    && (current.prewarm.is_some() || next.prewarm.is_some());
                (!same_service(current, next) || prewarm_changed).then_some(name.as_str())
            })
            .collect::<Vec<_>>();
        added.sort_unstable();
        removed.sort_unstable();
        changed.sort_unstable();
        (added, removed, changed)
    }
}

/// 业务作用：穷尽比较已编译服务的全部配置字段，避免新增策略默默遗漏在管理差异之外。
///
/// 参数说明：
/// - `current`：活动配置声明，不含后台统计。
/// - `candidate`：同名候选服务的完整声明。
///
/// 返回：所有治理、来源、连接策略与静态实例一致时为真，不比较动态发现目录的瞬时内容。
fn same_service(current: &ServiceSnapshot, candidate: &ServiceSnapshot) -> bool {
    let ServiceSnapshot {
        critical,
        source,
        lb_policy,
        hash,
        session_affinity,
        load_feedback,
        retry_budget,
        adaptive_concurrency,
        next_upstream,
        passive_health,
        outlier,
        active_health,
        prewarm,
        locality,
        instances,
        protocol,
        tls_profile,
        nacos_service,
        registry_service,
        registry_service_import,
        registry_namespace,
        registry_port,
        registry_port_name,
        scheme,
        clusters,
        slow_start_ms,
        discovery_stale_ttl_ms,
    } = current;
    critical == &candidate.critical
        && source == &candidate.source
        && lb_policy == &candidate.lb_policy
        && hash == &candidate.hash
        && session_affinity == &candidate.session_affinity
        && load_feedback == &candidate.load_feedback
        && retry_budget == &candidate.retry_budget
        && adaptive_concurrency == &candidate.adaptive_concurrency
        && next_upstream == &candidate.next_upstream
        && passive_health == &candidate.passive_health
        && outlier == &candidate.outlier
        && active_health == &candidate.active_health
        && prewarm == &candidate.prewarm
        && locality == &candidate.locality
        && protocol == &candidate.protocol
        && same_tls(tls_profile, &candidate.tls_profile)
        && nacos_service == &candidate.nacos_service
        && registry_service == &candidate.registry_service
        && registry_service_import == &candidate.registry_service_import
        && registry_namespace == &candidate.registry_namespace
        && registry_port == &candidate.registry_port
        && registry_port_name == &candidate.registry_port_name
        && scheme == &candidate.scheme
        && clusters == &candidate.clusters
        && slow_start_ms == &candidate.slow_start_ms
        && discovery_stale_ttl_ms == &candidate.discovery_stale_ttl_ms
        && instances.len() == candidate.instances.len()
        && instances
            .iter()
            .zip(candidate.instances.iter())
            .all(|(current, next)| same_instance(current, next))
}

/// 业务作用：比较静态实例的配置事实，重新构建产生的加入时间和反馈代际不能伪装成配置变化。
///
/// 参数说明：
/// - `current`：活动服务中按声明顺序固定的实例。
/// - `candidate`：相同位置的候选实例，实例顺序本身可以影响 first 等调度策略。
///
/// 返回：地址、权重、配置健康、协议、连接与拓扑元数据相同时为真。
fn same_instance(current: &UpstreamInstance, candidate: &UpstreamInstance) -> bool {
    let UpstreamInstance {
        uri,
        health_key,
        healthy,
        weight,
        down,
        backup,
        slow_start_ms,
        // 这些字段只标识当前进程的运行生命周期；稳定服务身份已由外层同名匹配确定。
        created_at: _,
        feedback_generation: _,
        feedback_key: _,
        protocol,
        connect_timeout_ms,
        tls_profile,
        zone,
        region,
        subzone,
        metadata,
    } = current;
    uri == &candidate.uri
        && health_key == &candidate.health_key
        && healthy == &candidate.healthy
        && weight == &candidate.weight
        && down == &candidate.down
        && backup == &candidate.backup
        && slow_start_ms == &candidate.slow_start_ms
        && protocol == &candidate.protocol
        && connect_timeout_ms == &candidate.connect_timeout_ms
        && same_tls(tls_profile, &candidate.tls_profile)
        && zone == &candidate.zone
        && region == &candidate.region
        && subzone == &candidate.subzone
        && metadata == &candidate.metadata
}

/// 业务作用：按已有连接池的 TLS 策略身份比较信任与客户端凭据，避免复制或暴露密钥材料。
///
/// 参数说明：
/// - `current`：活动连接策略，缺省表示无上游 TLS profile。
/// - `candidate`：候选连接策略。
///
/// 返回：池身份、显式主机名与命名凭据授权策略一致时为真；租约时钟由传输门处理，不作为配置修改。
fn same_tls(current: &Option<UpstreamTlsProfile>, candidate: &Option<UpstreamTlsProfile>) -> bool {
    current.as_ref().map(|profile| {
        (
            &profile.key,
            &profile.server_name,
            profile.client_identity_policy_identity,
        )
    }) == candidate.as_ref().map(|profile| {
        (
            &profile.key,
            &profile.server_name,
            profile.client_identity_policy_identity,
        )
    })
}
