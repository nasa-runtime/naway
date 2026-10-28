//! route 级 GeoIP、ASN 与匿名网络策略。
//!
//! 数据库只在候选快照构建阶段有界读取并解析；请求热路径只查询不可变 MMDB reader，
//! 不访问文件、网络或外部服务。

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use maxminddb::{geoip2, Reader};

use crate::config::model::GeoIpCfg;

pub(crate) const MAX_DATABASE_BYTES: usize = 128 * 1024 * 1024;
const MAX_DATABASE_AGE_SECS: u64 = 366 * 24 * 60 * 60;
const MAX_FUTURE_BUILD_SKEW: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_COUNTRY_RULES: usize = 256;
const MAX_ASN_RULES: usize = 4096;

/// GeoIP 数据面固定决策。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GeoIpDecision {
    /// 所有已配置规则均允许该地址。
    Allowed,
    /// 国家 allow/deny 规则拒绝。
    CountryDenied,
    /// ASN allow/deny 规则拒绝。
    AsnDenied,
    /// 匿名网络 trait 规则拒绝。
    AnonymousDenied,
    /// 数据库无记录，按 fail-open 配置允许。
    NotFoundAllowed,
    /// 数据库无记录，按故障关闭配置拒绝。
    NotFoundDenied,
    /// 查询或 record 解码失败，按 fail-open 配置允许。
    LookupErrorAllowed,
    /// 查询或 record 解码失败，按故障关闭配置拒绝。
    LookupErrorDenied,
    /// 数据库过期，按显式 fail-open 配置允许。
    StaleAllowed,
    /// 数据库过期，按显式故障关闭配置拒绝。
    StaleDenied,
}

impl GeoIpDecision {
    /// 业务作用：把 GeoIP 固定决策归并为请求是否可以继续的安全门结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：普通允许或显式 fail-open 结果返回 true，其余拒绝结果返回 false。
    pub(crate) const fn allowed(self) -> bool {
        matches!(
            self,
            Self::Allowed | Self::NotFoundAllowed | Self::LookupErrorAllowed | Self::StaleAllowed
        )
    }

    /// 业务作用：为低敏日志提供不含 IP、国家或 ASN 的固定原因。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回编译期固定原因字符串，可安全进入日志字段。
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::CountryDenied => "country_denied",
            Self::AsnDenied => "asn_denied",
            Self::AnonymousDenied => "anonymous_denied",
            Self::NotFoundAllowed | Self::NotFoundDenied => "not_found",
            Self::LookupErrorAllowed | Self::LookupErrorDenied => "lookup_error",
            Self::StaleAllowed | Self::StaleDenied => "stale",
        }
    }
}

/// 失败或陈旧数据的固定二元动作。
#[derive(Clone, Copy)]
enum BinaryAction {
    /// 允许请求继续。
    Allow,
    /// 拒绝请求。
    Deny,
}

/// 过期数据库的候选发布动作。
#[derive(Clone, Copy)]
enum StaleAction {
    /// 候选构建失败，保留上一份有效快照。
    Reject,
    /// 发布候选，但该 route 对请求故障关闭。
    Deny,
    /// 发布候选，并显式绕过全部 GeoIP 规则。
    Allow,
}

/// 可由 Anonymous-IP MMDB 提供的固定 trait。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AnonymousTrait {
    /// 任意匿名网络。
    Anonymous,
    /// 匿名 VPN。
    AnonymousVpn,
    /// 托管或 VPN provider。
    HostingProvider,
    /// 公共代理。
    PublicProxy,
    /// 住宅代理。
    ResidentialProxy,
    /// Tor exit node。
    TorExitNode,
}

impl AnonymousTrait {
    /// 业务作用：解析配置中的匿名网络 trait，拒绝拼写错误导致策略静默缺失。
    ///
    /// 参数说明：
    /// - `value`：是配置声明的 trait 名。
    ///
    /// 返回：已知名称返回固定 trait；未知名称返回 `None`。
    fn from_name(value: &str) -> Option<Self> {
        match value {
            "anonymous" => Some(Self::Anonymous),
            "anonymous_vpn" => Some(Self::AnonymousVpn),
            "hosting_provider" => Some(Self::HostingProvider),
            "public_proxy" => Some(Self::PublicProxy),
            "residential_proxy" => Some(Self::ResidentialProxy),
            "tor_exit_node" => Some(Self::TorExitNode),
            _ => None,
        }
    }

    /// 业务作用：从已解码 Anonymous-IP record 读取本 trait 的三态值。
    ///
    /// 参数说明：
    /// - `record`：是当前客户端地址对应的只读 MMDB record。
    ///
    /// 返回：数据库明确记录时返回 true/false；字段缺失返回 `None` 并触发未命中策略。
    fn value(self, record: &geoip2::AnonymousIp) -> Option<bool> {
        match self {
            Self::Anonymous => record.is_anonymous,
            Self::AnonymousVpn => record.is_anonymous_vpn,
            Self::HostingProvider => record.is_hosting_provider,
            Self::PublicProxy => record.is_public_proxy,
            Self::ResidentialProxy => record.is_residential_proxy,
            Self::TorExitNode => record.is_tor_exit_node,
        }
    }
}

/// 已解析且可跨 route 共享的 MMDB 快照。
struct DatabaseSnapshot {
    /// 不可变 reader；内部字节随 snapshot 生命周期保持稳定。
    reader: Reader<Vec<u8>>,
    /// MMDB 元数据中的数据库类型。
    database_type: String,
    /// MMDB 元数据中的构建时间。
    build_time: SystemTime,
}

/// 单次 Router 构建共享的 MMDB 目录，相同规范路径只读取和解析一次。
#[derive(Default)]
pub(crate) struct GeoIpCatalog {
    readers: HashMap<PathBuf, Arc<DatabaseSnapshot>>,
}

impl GeoIpCatalog {
    /// 业务作用：有界读取并解析一个 MMDB，同一候选中的相同真实路径复用同一份字节。
    ///
    /// 参数说明：
    /// - `config_dir`：主配置目录，用于解析相对路径。
    /// - `configured_path`：route 声明的数据库文件。
    ///
    /// 返回：文件存在、大小受限且 MMDB 元数据合法时返回共享快照；否则拒绝候选。
    fn load(&mut self, config_dir: &Path, configured_path: &str) -> Result<Arc<DatabaseSnapshot>> {
        let path = resolve_path(config_dir, configured_path);
        let canonical = path
            .canonicalize()
            .with_context(|| format!("canonicalize GeoIP database {}", path.display()))?;
        if let Some(existing) = self.readers.get(&canonical) {
            return Ok(existing.clone());
        }
        let file = File::open(&canonical)
            .with_context(|| format!("open GeoIP database {}", canonical.display()))?;
        let declared = file
            .metadata()
            .with_context(|| format!("stat GeoIP database {}", canonical.display()))?
            .len();
        if declared == 0 || declared > MAX_DATABASE_BYTES as u64 {
            bail!(
                "GeoIP database {} must be in 1..={MAX_DATABASE_BYTES} bytes",
                canonical.display()
            );
        }
        let mut bytes = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));
        file.take((MAX_DATABASE_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(|| format!("read GeoIP database {}", canonical.display()))?;
        if bytes.is_empty() || bytes.len() > MAX_DATABASE_BYTES {
            bail!(
                "GeoIP database {} changed size or exceeded the read limit",
                canonical.display()
            );
        }
        let reader = Reader::from_source(bytes)
            .with_context(|| format!("parse GeoIP database {}", canonical.display()))?;
        let database_type = reader.metadata().database_type.clone();
        let build_time = reader
            .metadata()
            .build_time()
            .with_context(|| format!("read GeoIP build epoch {}", canonical.display()))?;
        let snapshot = Arc::new(DatabaseSnapshot {
            reader,
            database_type,
            build_time,
        });
        self.readers.insert(canonical, snapshot.clone());
        Ok(snapshot)
    }
}

/// 快照内只读的 route GeoIP 策略。
pub(crate) struct GeoIpPolicy {
    /// 可选国家数据库与规范化国家规则。
    country_database: Option<Arc<DatabaseSnapshot>>,
    allowed_countries: HashSet<String>,
    denied_countries: HashSet<String>,
    /// 可选 ASN 数据库与 ASN 规则。
    asn_database: Option<Arc<DatabaseSnapshot>>,
    allowed_asns: HashSet<u32>,
    denied_asns: HashSet<u32>,
    /// 可选 Anonymous-IP 数据库与要拒绝的 trait。
    anonymous_database: Option<Arc<DatabaseSnapshot>>,
    denied_anonymous_traits: HashSet<AnonymousTrait>,
    /// 数据库无对应记录时的明确动作。
    on_not_found: BinaryAction,
    /// 查询或 record 解码失败时的明确动作。
    on_lookup_error: BinaryAction,
    /// 任一必需数据库过期时的 route 级固定结果。
    stale_decision: Option<GeoIpDecision>,
}

impl GeoIpPolicy {
    /// 业务作用：编译 route GeoIP 策略并在快照发布前验证规则、数据库类型与 freshness。
    ///
    /// 参数说明：
    /// - `cfg`：route GeoIP 声明。
    /// - `config_dir`：主配置目录。
    /// - `catalog`：本次 Router 构建共享的 MMDB 目录。
    ///
    /// 返回：全部数据库和策略有效时返回只读计划；无规则、类型错误、过期拒绝或预算越界时返回错误。
    pub(crate) fn build(
        cfg: &GeoIpCfg,
        config_dir: &Path,
        catalog: &mut GeoIpCatalog,
    ) -> Result<Self> {
        if !(1..=MAX_DATABASE_AGE_SECS).contains(&cfg.max_database_age_secs) {
            bail!("max_database_age_secs must be in 1..={MAX_DATABASE_AGE_SECS}");
        }
        let on_not_found = parse_binary_action("on_not_found", cfg.on_not_found.as_str())?;
        let on_lookup_error = parse_binary_action("on_lookup_error", cfg.on_lookup_error.as_str())?;
        let on_stale = match cfg.on_stale.as_str() {
            "reject" => StaleAction::Reject,
            "allow" => StaleAction::Allow,
            "deny" => StaleAction::Deny,
            value => bail!("on_stale must be `reject`, `allow` or `deny`, got `{value}`"),
        };

        let allowed_countries =
            normalize_countries("allowed_countries", cfg.allowed_countries.as_slice())?;
        let denied_countries =
            normalize_countries("denied_countries", cfg.denied_countries.as_slice())?;
        reject_overlap("country", allowed_countries.iter(), &denied_countries)?;
        let allowed_asns = normalize_asns("allowed_asns", cfg.allowed_asns.as_slice())?;
        let denied_asns = normalize_asns("denied_asns", cfg.denied_asns.as_slice())?;
        reject_overlap("ASN", allowed_asns.iter(), &denied_asns)?;
        let denied_anonymous_traits =
            normalize_anonymous_traits(cfg.denied_anonymous_traits.as_slice())?;

        let country_rules = !allowed_countries.is_empty() || !denied_countries.is_empty();
        let asn_rules = !allowed_asns.is_empty() || !denied_asns.is_empty();
        let anonymous_rules = !denied_anonymous_traits.is_empty();
        if !country_rules && !asn_rules && !anonymous_rules {
            bail!("geoip requires at least one country, ASN or anonymous network rule");
        }
        validate_database_presence(
            "country_database_file",
            cfg.country_database_file.as_deref(),
            country_rules,
        )?;
        validate_database_presence(
            "asn_database_file",
            cfg.asn_database_file.as_deref(),
            asn_rules,
        )?;
        validate_database_presence(
            "anonymous_database_file",
            cfg.anonymous_database_file.as_deref(),
            anonymous_rules,
        )?;

        let country_database = load_typed_database(
            catalog,
            config_dir,
            cfg.country_database_file.as_deref(),
            DatabaseKind::Country,
        )?;
        let asn_database = load_typed_database(
            catalog,
            config_dir,
            cfg.asn_database_file.as_deref(),
            DatabaseKind::Asn,
        )?;
        let anonymous_database = load_typed_database(
            catalog,
            config_dir,
            cfg.anonymous_database_file.as_deref(),
            DatabaseKind::Anonymous,
        )?;
        let mut stale = false;
        for database in [
            country_database.as_ref(),
            asn_database.as_ref(),
            anonymous_database.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            stale |= database_is_stale(database, cfg.max_database_age_secs)?;
        }
        let stale_decision = if stale {
            match on_stale {
                StaleAction::Reject => bail!(
                    "GeoIP database build epoch exceeds max_database_age_secs; stale candidate rejected"
                ),
                StaleAction::Allow => Some(GeoIpDecision::StaleAllowed),
                StaleAction::Deny => Some(GeoIpDecision::StaleDenied),
            }
        } else {
            None
        };

        Ok(Self {
            country_database,
            allowed_countries,
            denied_countries,
            asn_database,
            allowed_asns,
            denied_asns,
            anonymous_database,
            denied_anonymous_traits,
            on_not_found,
            on_lookup_error,
            stale_decision,
        })
    }

    /// 业务作用：按客户端权威 IP 执行国家、ASN 与匿名网络策略，不信任客户端自报 header。
    ///
    /// 参数说明：
    /// - `ip`：是已由 listener trusted-proxy 规则确定的真实客户端地址。
    ///
    /// 返回：返回固定允许/拒绝结果；未命中、查询错误和过期均保留各自可观测终态。
    pub(crate) fn evaluate(&self, ip: IpAddr) -> GeoIpDecision {
        if let Some(decision) = self.stale_decision {
            return decision;
        }
        if let Some(database) = &self.country_database {
            let country = match lookup_country(database, ip) {
                Ok(Some(country)) => country,
                Ok(None) => return self.not_found_decision(),
                Err(()) => return self.lookup_error_decision(),
            };
            if (!self.allowed_countries.is_empty()
                && !self.allowed_countries.contains(country.as_str()))
                || self.denied_countries.contains(country.as_str())
            {
                return GeoIpDecision::CountryDenied;
            }
        }
        if let Some(database) = &self.asn_database {
            let asn = match lookup_asn(database, ip) {
                Ok(Some(asn)) => asn,
                Ok(None) => return self.not_found_decision(),
                Err(()) => return self.lookup_error_decision(),
            };
            if (!self.allowed_asns.is_empty() && !self.allowed_asns.contains(&asn))
                || self.denied_asns.contains(&asn)
            {
                return GeoIpDecision::AsnDenied;
            }
        }
        if let Some(database) = &self.anonymous_database {
            let record = match lookup_anonymous(database, ip) {
                Ok(Some(record)) => record,
                Ok(None) => return self.not_found_decision(),
                Err(()) => return self.lookup_error_decision(),
            };
            for denied in &self.denied_anonymous_traits {
                match denied.value(&record) {
                    Some(true) => return GeoIpDecision::AnonymousDenied,
                    Some(false) => {}
                    None => return self.not_found_decision(),
                }
            }
        }
        GeoIpDecision::Allowed
    }

    /// 业务作用：把数据库无记录稳定映射到配置声明的 fail-open/closed 结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回 `NotFoundAllowed` 或 `NotFoundDenied`。
    const fn not_found_decision(&self) -> GeoIpDecision {
        match self.on_not_found {
            BinaryAction::Allow => GeoIpDecision::NotFoundAllowed,
            BinaryAction::Deny => GeoIpDecision::NotFoundDenied,
        }
    }

    /// 业务作用：把 MMDB 查询/解码错误稳定映射到配置声明的 fail-open/closed 结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回 `LookupErrorAllowed` 或 `LookupErrorDenied`。
    const fn lookup_error_decision(&self) -> GeoIpDecision {
        match self.on_lookup_error {
            BinaryAction::Allow => GeoIpDecision::LookupErrorAllowed,
            BinaryAction::Deny => GeoIpDecision::LookupErrorDenied,
        }
    }
}

/// 受支持 MMDB 的固定用途。
#[derive(Clone, Copy)]
enum DatabaseKind {
    /// Country、City 或 Enterprise。
    Country,
    /// ASN。
    Asn,
    /// Anonymous-IP。
    Anonymous,
}

impl DatabaseKind {
    /// 业务作用：核对 MMDB metadata 类型与配置用途，避免用错误 schema 解码后静默放行。
    ///
    /// 参数说明：
    /// - `database_type`：是 MMDB metadata 的原始类型字符串。
    ///
    /// 返回：类型可用于当前规则域时返回 true。
    fn accepts(self, database_type: &str) -> bool {
        match self {
            Self::Country => {
                database_type.ends_with("-Country")
                    || database_type.ends_with("-City")
                    || database_type.ends_with("-Enterprise")
            }
            Self::Asn => database_type.ends_with("-ASN"),
            Self::Anonymous => database_type.ends_with("-Anonymous-IP"),
        }
    }

    /// 业务作用：为数据库类型错误提供稳定配置字段语义。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回当前用途的人类可读固定名称。
    const fn name(self) -> &'static str {
        match self {
            Self::Country => "country",
            Self::Asn => "ASN",
            Self::Anonymous => "Anonymous-IP",
        }
    }
}

/// 业务作用：把 route GeoIP 文件声明转换为 watcher 依赖路径。
///
/// 参数说明：
/// - `config_dir`：是主配置目录
/// - `cfg`：是 route GeoIP 声明。
///
/// 返回：返回已声明数据库的绝对或基于配置目录解析的路径，不读取文件内容。
pub(crate) fn dependency_paths(config_dir: &Path, cfg: &GeoIpCfg) -> Vec<PathBuf> {
    [
        cfg.country_database_file.as_deref(),
        cfg.asn_database_file.as_deref(),
        cfg.anonymous_database_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(|path| resolve_path(config_dir, path))
    .collect()
}

/// 业务作用：解析相对 MMDB 路径而不改变用户声明的 watcher 身份。
///
/// 参数说明：
/// - `config_dir`：是主配置目录
/// - `configured_path`：是配置值。
///
/// 返回：绝对路径原样返回，相对路径拼接到配置目录。
fn resolve_path(config_dir: &Path, configured_path: &str) -> PathBuf {
    let path = Path::new(configured_path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    }
}

/// 业务作用：解析 GeoIP 的二元失败动作。
///
/// 参数说明：
/// - `field`：用于错误定位
/// - `value`：是配置动作。
///
/// 返回：`allow|deny` 返回固定动作，其它值返回构建错误。
fn parse_binary_action(field: &str, value: &str) -> Result<BinaryAction> {
    match value {
        "allow" => Ok(BinaryAction::Allow),
        "deny" => Ok(BinaryAction::Deny),
        _ => bail!("{field} must be `allow` or `deny`, got `{value}`"),
    }
}

/// 业务作用：规范化并验证国家代码集合，阻止大小写或重复配置产生歧义。
///
/// 参数说明：
/// - `field`：用于错误定位
/// - `values`：是配置国家代码。
///
/// 返回：合法 ISO alpha-2 代码返回去重集合；非法、重复或超限返回错误。
fn normalize_countries(field: &str, values: &[String]) -> Result<HashSet<String>> {
    if values.len() > MAX_COUNTRY_RULES {
        bail!("{field} supports at most {MAX_COUNTRY_RULES} entries");
    }
    let mut output = HashSet::with_capacity(values.len());
    for raw in values {
        if raw.len() != 2 || !raw.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            bail!("{field} contains invalid ISO alpha-2 code `{raw}`");
        }
        let value = raw.to_ascii_uppercase();
        if !output.insert(value.clone()) {
            bail!("{field} contains duplicate country `{value}`");
        }
    }
    Ok(output)
}

/// 业务作用：验证 ASN 集合并拒绝保留值、重复值和超量配置。
///
/// 参数说明：
/// - `field`：用于错误定位
/// - `values`：是配置 ASN。
///
/// 返回：合法 ASN 返回去重集合；0、重复或超限返回错误。
fn normalize_asns(field: &str, values: &[u32]) -> Result<HashSet<u32>> {
    if values.len() > MAX_ASN_RULES {
        bail!("{field} supports at most {MAX_ASN_RULES} entries");
    }
    let mut output = HashSet::with_capacity(values.len());
    for value in values {
        if *value == 0 {
            bail!("{field} cannot contain ASN 0");
        }
        if !output.insert(*value) {
            bail!("{field} contains duplicate ASN {value}");
        }
    }
    Ok(output)
}

/// 业务作用：解析匿名网络 trait 并限制固定集合，防止未知字段被静默忽略。
///
/// 参数说明：
/// - `values`：是要拒绝的 trait 名。
///
/// 返回：合法且不重复时返回固定集合；未知或重复名称返回错误。
fn normalize_anonymous_traits(values: &[String]) -> Result<HashSet<AnonymousTrait>> {
    let mut output = HashSet::with_capacity(values.len());
    for value in values {
        let Some(value) = AnonymousTrait::from_name(value.as_str()) else {
            bail!("unknown denied_anonymous_traits value `{value}`");
        };
        if !output.insert(value) {
            bail!("denied_anonymous_traits contains a duplicate value");
        }
    }
    Ok(output)
}

/// 业务作用：拒绝 allowlist 与 denylist 的同值冲突，避免规则优先级依赖实现细节。
///
/// 参数说明：
/// - `kind`：用于错误定位
/// - `allowed`：是已规范化集合。
/// - `denied`：是已规范化集合。
///
/// 返回：无交集返回成功；存在交集返回构建错误。
fn reject_overlap<'a, T>(
    kind: &str,
    allowed: impl Iterator<Item = &'a T>,
    denied: &HashSet<T>,
) -> Result<()>
where
    T: std::fmt::Display + Eq + std::hash::Hash + 'a,
{
    if let Some(value) = allowed.into_iter().find(|value| denied.contains(*value)) {
        bail!("{kind} `{value}` cannot be both allowed and denied");
    }
    Ok(())
}

/// 业务作用：确保数据库声明与实际启用规则一一对应，避免无效文件或缺失数据源被静默接受。
///
/// 参数说明：
/// - `field`：是数据库配置键
/// - `path`：是可选值
/// - `required`：表示对应规则是否存在。
///
/// 返回：规则与文件同时存在或同时缺失时成功；不一致时返回错误。
fn validate_database_presence(field: &str, path: Option<&str>, required: bool) -> Result<()> {
    let present = path.is_some_and(|path| !path.trim().is_empty());
    if present != required {
        bail!("{field} must be configured exactly when its rule set is non-empty");
    }
    Ok(())
}

/// 业务作用：通过共享目录加载可选数据库并核对 metadata 数据类型。
///
/// 参数说明：
/// - `catalog`：是候选共享目录
/// - `config_dir`：是路径基准
/// - `path`：是可选文件
/// - `kind`：是规则要求的数据库用途。
///
/// 返回：未声明返回 `None`；类型与内容有效返回共享数据库；错误返回候选构建失败。
fn load_typed_database(
    catalog: &mut GeoIpCatalog,
    config_dir: &Path,
    path: Option<&str>,
    kind: DatabaseKind,
) -> Result<Option<Arc<DatabaseSnapshot>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let database = catalog.load(config_dir, path)?;
    if !kind.accepts(database.database_type.as_str()) {
        bail!(
            "{} database `{path}` has incompatible MMDB type `{}`",
            kind.name(),
            database.database_type
        );
    }
    Ok(Some(database))
}

/// 业务作用：根据 MMDB build epoch 判断 snapshot 是否超过 route freshness 窗口。
///
/// 参数说明：
/// - `database`：是已解析快照
/// - `max_age_secs`：是 route 最大允许年龄。
///
/// 返回：超过年龄返回 true；未来时间在容差内按新鲜处理，超出容差返回构建错误。
fn database_is_stale(database: &DatabaseSnapshot, max_age_secs: u64) -> Result<bool> {
    match SystemTime::now().duration_since(database.build_time) {
        Ok(age) => Ok(age > Duration::from_secs(max_age_secs)),
        Err(error) if error.duration() <= MAX_FUTURE_BUILD_SKEW => Ok(false),
        Err(_) => bail!("GeoIP database build epoch is implausibly far in the future"),
    }
}

/// 业务作用：从 Country/City/Enterprise MMDB 提取权威国家代码。
///
/// 参数说明：
/// - `database`：是已验证用途的快照
/// - `ip`：是权威客户端地址。
///
/// 返回：有记录返回大写 alpha-2 代码，无数据返回 `None`，查询或解码错误返回 `Err`。
fn lookup_country(
    database: &DatabaseSnapshot,
    ip: IpAddr,
) -> std::result::Result<Option<String>, ()> {
    let lookup = database.reader.lookup(ip).map_err(|_| ())?;
    let record: Option<geoip2::Country<'_>> = lookup.decode().map_err(|_| ())?;
    let country = record.and_then(|record| {
        record
            .country
            .iso_code
            .or(record.registered_country.iso_code)
            .map(str::to_ascii_uppercase)
    });
    match country {
        Some(country)
            if country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_alphabetic()) =>
        {
            Ok(Some(country))
        }
        Some(_) => Err(()),
        None => Ok(None),
    }
}

/// 业务作用：从 ASN MMDB 提取权威 Autonomous System Number。
///
/// 参数说明：
/// - `database`：是已验证用途的快照
/// - `ip`：是权威客户端地址。
///
/// 返回：有记录返回非零 ASN，无数据返回 `None`，查询或解码错误返回 `Err`。
fn lookup_asn(database: &DatabaseSnapshot, ip: IpAddr) -> std::result::Result<Option<u32>, ()> {
    let lookup = database.reader.lookup(ip).map_err(|_| ())?;
    let record: Option<geoip2::Asn<'_>> = lookup.decode().map_err(|_| ())?;
    Ok(record.and_then(|record| record.autonomous_system_number.filter(|asn| *asn > 0)))
}

/// 业务作用：从 Anonymous-IP MMDB 解码匿名网络 trait record。
///
/// 参数说明：
/// - `database`：是已验证用途的快照
/// - `ip`：是权威客户端地址。
///
/// 返回：有记录返回固定字段对象，无数据返回 `None`，查询或解码错误返回 `Err`。
fn lookup_anonymous(
    database: &DatabaseSnapshot,
    ip: IpAddr,
) -> std::result::Result<Option<geoip2::AnonymousIp>, ()> {
    let lookup = database.reader.lookup(ip).map_err(|_| ())?;
    lookup.decode().map_err(|_| ())
}
