//! 内嵌 Casbin RBAC/ABAC 授权。
//!
//! model 与 policy 文件只在 `GatewaySnapshot` 构建期读取，并被编译成只读
//! `Enforcer`。请求期不读文件、不动态解析 matcher；只按构建期已编译的参数计划
//! 组装一个有界 `Vec<String>` 交给 Casbin。Casbin/Rhai 需要拥有的动态值，因此这些小字符串
//! 拷贝是显式授权慢路径的必要成本；业务 body/凭据原文从不进入策略引擎。

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use casbin::{CoreApi, DefaultModel, Enforcer, StringAdapter};
use http::header::HeaderName;
use http::request::Parts;

use crate::config::model::CasbinAuthorizationCfg;

const MAX_CASBIN_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CASBIN_ARGUMENTS: usize = 16;
const MAX_CASBIN_ARGUMENT_BYTES_HARD: usize = 64 * 1024;
const MAX_CASBIN_INPUT_BYTES_HARD: usize = 256 * 1024;

/// 已编译的 route 级 Casbin 决策器。
pub(crate) struct CasbinPolicy {
    enforcer: Enforcer,
    arguments: Arc<[CasbinArgument]>,
    require_identity: bool,
    fail_open: bool,
    max_argument_bytes: usize,
    max_input_bytes: usize,
}

#[derive(Clone)]
enum CasbinArgument {
    Consumer,
    Method,
    Path,
    RouteId,
    ClientIp,
    Scheme,
    UntrustedHeader(HeaderName),
}

/// Casbin 的明确 allow/deny 或内部执行故障。
pub(crate) enum CasbinDecision {
    Allow,
    Deny,
    /// 仅 matcher/enforcer 执行异常；由 policy 的 fail_open 决定是否放行。
    Error(anyhow::Error),
}

/// 本地输入无效不属于策略依赖故障，绝不受 fail-open 影响。
pub(crate) enum CasbinInputError {
    MissingIdentity,
    TooLarge,
    InvalidHeader,
}

impl CasbinPolicy {
    /// 业务作用：从文件构建不可变 Enforcer；并用同样参数数量做一次空输入 enforce，
    /// 在候选快照上线前暴露 request_definition 元数不匹配等错误。
    pub(crate) fn build(
        cfg: &CasbinAuthorizationCfg,
        config_dir: &Path,
        route_id: &str,
    ) -> Result<Self> {
        validate_cfg(cfg)?;
        let model_path = resolve(config_dir, &cfg.model_file);
        let policy_path = resolve(config_dir, &cfg.policy_file);
        let model_text = read_bounded_utf8(&model_path, "Casbin model")?;
        let policy_text = read_bounded_utf8(&policy_path, "Casbin policy")?;
        let arguments = cfg
            .arguments
            .iter()
            .map(|raw| parse_argument(raw))
            .collect::<Result<Vec<_>>>()?;

        // DefaultModel/StringAdapter 的 future 只消费上面已读入的字符串，不包含
        // tokio I/O。用 futures 的小型 executor 保持整个 GatewaySnapshot builder 为同步事务，
        // 避免在初启/reload/admin dry-run 三条路径各自嵌套 Tokio runtime。
        let model = futures::executor::block_on(DefaultModel::from_str(&model_text))
            .map_err(|error| anyhow!(error.to_string()))
            .with_context(|| format!("parse Casbin model {}", model_path.display()))?;
        let enforcer =
            futures::executor::block_on(Enforcer::new(model, StringAdapter::new(policy_text)))
                .map_err(|error| anyhow!(error.to_string()))
                .with_context(|| format!("load Casbin policy {}", policy_path.display()))?;
        enforcer
            .enforce(vec![String::new(); arguments.len()])
            .map_err(|error| anyhow!(error.to_string()))
            .with_context(|| {
                format!(
                    "route `{route_id}` Casbin request_definition must accept {} arguments",
                    arguments.len()
                )
            })?;

        Ok(Self {
            enforcer,
            arguments: arguments.into(),
            require_identity: cfg.require_identity,
            fail_open: cfg.fail_open,
            max_argument_bytes: cfg.max_argument_bytes,
            max_input_bytes: cfg.max_input_bytes,
        })
    }

    /// 业务作用：是否必须有一个已通过网关认证的 consumer。
    pub(crate) fn requires_identity(&self) -> bool {
        self.require_identity
    }

    /// 业务作用：Casbin 内部执行异常是否 fail-open。
    pub(crate) fn fail_open(&self) -> bool {
        self.fail_open
    }

    /// 业务作用：执行一次同步内存决策。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn enforce(
        &self,
        parts: &Parts,
        authenticated: bool,
        consumer: Option<&str>,
        route_id: &str,
        client_ip: IpAddr,
        scheme: &str,
    ) -> std::result::Result<CasbinDecision, CasbinInputError> {
        if self.require_identity && (!authenticated || consumer.is_none()) {
            return Err(CasbinInputError::MissingIdentity);
        }
        let subject = consumer.unwrap_or("anonymous");
        let mut total = 0usize;
        let mut values = Vec::with_capacity(self.arguments.len());
        for argument in self.arguments.iter() {
            let value = match argument {
                CasbinArgument::Consumer => subject.to_owned(),
                CasbinArgument::Method => parts.method.as_str().to_owned(),
                CasbinArgument::Path => parts.uri.path().to_owned(),
                CasbinArgument::RouteId => route_id.to_owned(),
                CasbinArgument::ClientIp => client_ip.to_string(),
                CasbinArgument::Scheme => scheme.to_owned(),
                CasbinArgument::UntrustedHeader(name) => parts
                    .headers
                    .get(name)
                    .map(|value| value.to_str().map(str::to_owned))
                    .transpose()
                    .map_err(|_| CasbinInputError::InvalidHeader)?
                    .unwrap_or_default(),
            };
            if value.len() > self.max_argument_bytes {
                return Err(CasbinInputError::TooLarge);
            }
            total = total
                .checked_add(value.len())
                .ok_or(CasbinInputError::TooLarge)?;
            if total > self.max_input_bytes {
                return Err(CasbinInputError::TooLarge);
            }
            values.push(value);
        }
        Ok(match self.enforcer.enforce(values) {
            Ok(true) => CasbinDecision::Allow,
            Ok(false) => CasbinDecision::Deny,
            Err(error) => CasbinDecision::Error(anyhow!(error.to_string())),
        })
    }
}

/// 业务作用：检查 Casbin 模型、策略和参数声明的资源边界，拒绝无法安全执行的授权配置。
fn validate_cfg(cfg: &CasbinAuthorizationCfg) -> Result<()> {
    if cfg.model_file.trim().is_empty() || cfg.policy_file.trim().is_empty() {
        bail!("model_file and policy_file cannot be empty");
    }
    if cfg.arguments.is_empty() || cfg.arguments.len() > MAX_CASBIN_ARGUMENTS {
        bail!("arguments must contain 1..={MAX_CASBIN_ARGUMENTS} entries");
    }
    if !(1..=MAX_CASBIN_ARGUMENT_BYTES_HARD).contains(&cfg.max_argument_bytes) {
        bail!("max_argument_bytes must be within 1..={MAX_CASBIN_ARGUMENT_BYTES_HARD}");
    }
    if !(cfg.max_argument_bytes..=MAX_CASBIN_INPUT_BYTES_HARD).contains(&cfg.max_input_bytes) {
        bail!("max_input_bytes must be within max_argument_bytes..={MAX_CASBIN_INPUT_BYTES_HARD}");
    }
    Ok(())
}

/// 业务作用：把授权输入声明编译为固定请求来源，防止请求动态选择授权字段。
fn parse_argument(raw: &str) -> Result<CasbinArgument> {
    let raw = raw.trim();
    match raw {
        "consumer" => Ok(CasbinArgument::Consumer),
        "method" => Ok(CasbinArgument::Method),
        "path" => Ok(CasbinArgument::Path),
        "route_id" => Ok(CasbinArgument::RouteId),
        "client_ip" => Ok(CasbinArgument::ClientIp),
        "scheme" => Ok(CasbinArgument::Scheme),
        raw if raw
            .split_once(':')
            .is_some_and(|(kind, name)| kind.eq_ignore_ascii_case("header") && !name.is_empty()) => {
            let (_, name) = raw.split_once(':').expect("guarded by split_once");
            Ok(CasbinArgument::UntrustedHeader(
                HeaderName::from_bytes(name.as_bytes())
                    .context("invalid Casbin header argument")?,
            ))
        }
        _ => bail!(
            "unsupported Casbin argument `{raw}`; expected consumer/method/path/route_id/client_ip/scheme/header:Name"
        ),
    }
}

/// 业务作用：有界读取授权模型与策略文本，拒绝超限或无效 UTF-8 文件。
fn read_bounded_utf8(path: &Path, kind: &str) -> Result<String> {
    let bytes = crate::io::bounded_io::read_file(path, MAX_CASBIN_FILE_BYTES, kind)?;
    String::from_utf8(bytes).with_context(|| format!("{kind} {} must be UTF-8", path.display()))
}

/// 业务作用：以主配置目录为基准定位授权文件，不由业务请求指定本地路径。
fn resolve(base: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// 业务作用：返回 model/policy 文件依赖，供 reload watcher 和配置指纹共用。
pub(crate) fn dependency_paths(config_dir: &Path, cfg: &CasbinAuthorizationCfg) -> [PathBuf; 2] {
    [
        resolve(config_dir, &cfg.model_file),
        resolve(config_dir, &cfg.policy_file),
    ]
}
