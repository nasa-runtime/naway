//! Sentinel 规则文档到原生路由保护计划的编译。

use super::*;

/// 业务作用：保存 Sentinel 文件编译后的 route→filter 索引，并在进入 Router 前校验引用完整性。
pub(super) struct SentinelRouteFilters {
    /// route id 到按声明顺序编译出的限流和熔断 filter。
    pub(super) by_route: HashMap<String, Vec<String>>,
    /// 实际合并并验证的规则与过滤器一起发布，管理比较不得再读另一份 base 或环境。
    pub(super) rules: Arc<SentinelFile>,
}

impl SentinelRouteFilters {
    /// 业务作用：拒绝引用不存在 route 的 Sentinel 规则，避免运维误以为保护策略已经生效。
    ///
    /// 参数说明：
    /// - `matched`：是本轮全部真实 route id。
    ///
    /// 返回：所有规则均命中时成功；任一悬空引用返回错误并阻止候选发布。
    pub(super) fn ensure_all_matched(&self, matched: &HashSet<String>) -> Result<()> {
        for route in self.by_route.keys() {
            if !matched.contains(route) {
                anyhow::bail!("sentinel flow rule references missing route `{route}`");
            }
        }
        Ok(())
    }
}

/// 业务作用：加载 Sentinel 路由规则并编译为确定性 filter，同时保留其 profile 观察候选。
///
/// 参数说明：
/// - `main_cfg`：是相对路径根
/// - `sentinel_file`：是主配置声明的规则文件。
/// - `candidate`：显式文档集的隔离 base，profile 保持真实规则路径语义。
///
/// 返回：schema、标识和规则合法时返回编译结果及 naml 来源；缺失、超限或非法时返回错误。
pub(super) fn load_sentinel_rules(
    main_cfg: &Path,
    sentinel_file: &str,
    candidate: Option<&Path>,
) -> Result<(SentinelRouteFilters, YmlLocalSources)> {
    let path = resolve_relative(main_cfg, sentinel_file);
    if !candidate.unwrap_or(&path).exists() {
        anyhow::bail!(
            "sentinel rules file {} does not exist; create an empty sentinel rules file or fix `sentinel_rules_file`",
            path.display()
        );
    }
    let loaded: LoadedYml<SentinelFile> = candidate::loader(&path, candidate)
        .load_tracked()
        .with_context(|| format!("load sentinel rules {}", path.display()))?;
    let mut rules = loaded.value;
    resolve_schema_version(rules.schema_version, "sentinel-rules.yml")?;
    let mut ids = HashSet::new();
    for rule in &mut rules.flow {
        validate_sentinel_token("sentinel flow id", &rule.id)?;
        // 禁用规则也占有稳定管理身份，否则重新启用时可能覆盖另一条已审批规则。
        anyhow::ensure!(ids.insert(rule.id.as_str()), "duplicate sentinel flow id");
        if rule.behavior == "warmup" {
            rule.cold_factor = Some(rule.cold_factor.unwrap_or(3));
            rule.cold_after_ms = rule.cold_after_ms.or(rule.warmup_ms);
        }
    }
    ids.clear();
    for rule in &rules.degrade {
        validate_sentinel_token("sentinel degrade id", &rule.id)?;
        anyhow::ensure!(
            ids.insert(rule.id.as_str()),
            "duplicate sentinel degrade id"
        );
    }
    let mut by_route: HashMap<String, Vec<String>> = HashMap::new();
    for rule in &rules.flow {
        if !rule.enabled {
            continue;
        }
        validate_sentinel_token("sentinel flow id", &rule.id)?;
        validate_sentinel_token("sentinel flow route", &rule.route)?;
        validate_sentinel_token("sentinel flow key", &rule.key)?;
        let has_warmup =
            rule.warmup_ms.is_some() || rule.cold_factor.is_some() || rule.cold_after_ms.is_some();
        let has_queue = rule.max_queue.is_some() || rule.max_wait_ms.is_some();
        let behavior = match rule.behavior.as_str() {
            "reject" if !has_warmup && !has_queue => String::new(),
            "warmup" if rule.limit.is_none() && !has_queue => {
                let period = rule.warmup_ms.context("sentinel warmup requires warmup_ms")?;
                format!(" warmup_ms={period} cold_factor={} cold_after_ms={}", rule.cold_factor.unwrap_or(3), rule.cold_after_ms.unwrap_or(period))
            }
            "queue" if rule.limit.is_none() && !has_warmup && rule.burst == 0 => {
                let capacity = rule.max_queue.context("sentinel queue requires max_queue")?;
                let wait = rule.max_wait_ms.context("sentinel queue requires max_wait_ms")?;
                format!(" queue_capacity={capacity} queue_wait_ms={wait}")
            }
            _ => anyhow::bail!("sentinel flow `{}` expects reject, warmup or queue with matching fields; queue requires rate and zero burst", rule.id),
        };
        let filter = match (rule.rate.as_ref(), rule.limit) {
            (Some(rate), None) => {
                validate_sentinel_token("sentinel flow rate", rate)?;
                if rule.max_active_keys == 0 {
                    anyhow::bail!(
                        "sentinel flow `{}` max_active_keys must be positive",
                        rule.id
                    );
                }
                let active_keys_fail = match rule.active_keys_fail.as_str() {
                    "open" | "closed" => rule.active_keys_fail.as_str(),
                    other => anyhow::bail!(
                        "sentinel flow `{}` active_keys_fail expects open|closed, got `{other}`",
                        rule.id
                    ),
                };
                format!(
                    "limit_req key={} rate={} burst={} max_active_keys={} active_keys_fail={}{}",
                    rule.key, rate, rule.burst, rule.max_active_keys, active_keys_fail, behavior
                )
            }
            (None, Some(limit)) => {
                if limit == 0 {
                    anyhow::bail!("sentinel flow `{}` limit must be positive", rule.id);
                }
                format!("limit_conn key={} limit={limit}", rule.key)
            }
            (Some(_), Some(_)) => anyhow::bail!(
                "sentinel flow `{}` must configure either `rate` or `limit`, not both",
                rule.id
            ),
            (None, None) => anyhow::bail!(
                "sentinel flow `{}` must configure `rate`(limit_req) or `limit`(limit_conn)",
                rule.id
            ),
        };
        by_route.entry(rule.route.clone()).or_default().push(filter);
    }
    for rule in &rules.degrade {
        if !rule.enabled {
            continue;
        }
        validate_sentinel_token("sentinel degrade id", &rule.id)?;
        validate_sentinel_token("sentinel degrade route", &rule.route)?;
        if rule.window_ms == 0 || rule.min_requests == 0 || rule.break_ms == 0 {
            anyhow::bail!(
                "sentinel degrade `{}` window_ms/min_requests/break_ms must be positive",
                rule.id
            );
        }
        http::StatusCode::from_u16(rule.fallback_status).with_context(|| {
            format!(
                "sentinel degrade `{}` invalid fallback_status `{}`",
                rule.id, rule.fallback_status
            )
        })?;
        if rule.fallback_body.trim().is_empty() {
            anyhow::bail!(
                "sentinel degrade `{}` fallback_body must be non-empty",
                rule.id
            );
        }
        let strategy = match rule.strategy {
            model::SentinelDegradeStrategy::ErrorCount => "error_count",
            model::SentinelDegradeStrategy::ErrorRatio => "error_ratio",
            model::SentinelDegradeStrategy::SlowRatio => "slow_ratio",
        };
        let mut filter = format!(
            "circuit_breaker id={} strategy={} window_ms={} min_requests={} break_ms={} fallback_status={} fallback_body={}",
            rule.id,
            strategy,
            rule.window_ms,
            rule.min_requests,
            rule.break_ms,
            rule.fallback_status,
            rule.fallback_body.split_whitespace().collect::<Vec<_>>().join("_")
        );
        // 原生编译器统一验证参数互斥与数值硬门，不能因来源不同而产生两套保护语义。
        use std::fmt::Write as _;
        if let Some(threshold) = rule.failure_threshold {
            write!(filter, " failure_threshold={threshold}")?;
        }
        if let Some(ratio) = rule.ratio_bps {
            write!(filter, " ratio_bps={ratio}")?;
        }
        if let Some(slow) = rule.slow_ms {
            write!(filter, " slow_ms={slow}")?;
        }
        by_route.entry(rule.route.clone()).or_default().push(filter);
    }
    Ok((
        SentinelRouteFilters {
            by_route,
            rules: Arc::new(rules),
        },
        loaded.sources,
    ))
}

/// 业务作用：校验 Sentinel DSL 的单 token 字段，避免空值或空白字符改变后续指令分词语义。
///
/// 参数说明：
/// - `label`：用于指出非法字段
/// - `value`：是待进入 filter DSL 的原始值。
///
/// 返回：非空且不含空白字符时成功，否则返回错误并阻止候选发布。
fn validate_sentinel_token(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        anyhow::bail!("{label} `{value}` must be non-empty and contain no whitespace");
    }
    Ok(())
}
