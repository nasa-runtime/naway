//! 共享流量账本的配置权威、主体维度与跨入口一致性。

use super::{parse_limit_key, LimitReqKey};
use anyhow::{bail, ensure, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// 只有路由作用域包含入口与路由；其它作用域在同一归属域内有明确共享身份。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    Route,
    Service(Arc<str>),
    Global,
    Shared(Arc<str>),
}

/// 完整候选验证后冻结的状态身份；同一共享域的所有路由共用一份字符串。
#[derive(PartialEq, Eq)]
pub(crate) struct BoundScope {
    pub(crate) quota: Arc<str>,
    pub(crate) request: Arc<str>,
    pub(crate) response: Arc<str>,
}

impl BoundScope {
    /// 业务作用：把策略代际与两个带宽方向固定到同一共享域，避免请求路径重复组合配置身份。
    ///
    /// 参数说明：
    /// - `scope`：已包含配置归属与共享边界的无歧义身份。
    /// - `state_key`：完整流控声明的稳定指纹。
    ///
    /// 返回：只读共享身份；不申请运行态额度或状态名额。
    fn new(scope: &str, state_key: u64) -> Self {
        let quota = format!("{scope}:{state_key:016x}");
        Self {
            request: Arc::from(format!("{quota}:req")),
            response: Arc::from(format!("{quota}:resp")),
            quota: Arc::from(quota),
        }
    }
}

impl Scope {
    /// 业务作用：将共享边界绑定到配置内固定服务或显式命名域，拒绝运行时目标插值。
    ///
    /// 参数说明：
    /// - `raw`：作用域声明。
    /// - `upstream`：路由声明的固定转发目标。
    ///
    /// 返回：合法作用域；未知声明、空名称或不固定的服务目标拒绝构建。
    pub(crate) fn parse(raw: &str, upstream: &str) -> Result<Self> {
        match raw {
            "" | "route" => Ok(Self::Route),
            "global" => Ok(Self::Global),
            "service" => {
                let service = upstream.strip_prefix("lb://").unwrap_or_default();
                ensure!(
                    valid_name(service),
                    "traffic_limit scope=service requires static lb://service"
                );
                Ok(Self::Service(Arc::from(service)))
            }
            other => {
                let name = other.strip_prefix("shared:").unwrap_or_default();
                ensure!(
                    valid_name(name),
                    "traffic_limit scope must be route|service|global|shared:<name>"
                );
                Ok(Self::Shared(Arc::from(name)))
            }
        }
    }

    /// 业务作用：生成无歧义的账本共享身份，配置归属永远位于服务与请求维度之外。
    ///
    /// 参数说明：
    /// - `owner`：冻结工作区命名空间；未启用归属时为平台域。
    /// - `proxy`：冻结入口标识。
    /// - `route`：冻结路由标识。
    ///
    /// 返回：同域共享目标得到相同键，不同工作区或不同路由边界绝不合并。
    pub(crate) fn state_scope(&self, owner: &str, proxy: &str, route: &str) -> String {
        let prefix = format!("traffic:{}:{owner}:", owner.len());
        match self {
            Self::Route => format!(
                "{prefix}route:{}:{proxy}:{}:{route}",
                proxy.len(),
                route.len()
            ),
            Self::Service(service) => format!("{prefix}service:{service}"),
            Self::Global => format!("{prefix}global"),
            Self::Shared(name) => format!("{prefix}shared:{name}"),
        }
    }
}

/// 流量主体可使用普通请求维度，或只能从认证完成后的内部事实取得的主体。
#[derive(PartialEq, Eq)]
pub(crate) enum Key {
    Request(LimitReqKey),
    Consumer,
    ApiCredential,
}

impl Key {
    /// 业务作用：把受信身份与普通请求取值分开建模，防止把 consumer 当成任意 header 别名。
    ///
    /// 参数说明：
    /// - `raw`：配置维度声明。
    ///
    /// 返回：合法维度；不支持的语法拒绝构建。
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        match raw {
            "consumer" => Ok(Self::Consumer),
            "api_key" => Ok(Self::ApiCredential),
            other => Ok(Self::Request(parse_limit_key(other)?)),
        }
    }
}

/// 业务作用：限制显式共享域与服务标识的长度和字符，防止状态键歧义及任意目标插值。
///
/// 参数说明：
/// - `value`：配置内的服务或共享域名。
///
/// 返回：非空、至多256字节且只含标识字符时为 true。
fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// 业务作用：在发布前验证跨入口共享账本的策略一致性，阻止不同路由暗中获得各自额度。
///
/// 参数说明：
/// - `proxies`：完整候选入口与已编译路由。
/// - `ownership`：同候选内已验证的归属目录。
///
/// 返回：共享域内策略完全一致时成功；不一致或缺少已启用的归属证据时拒绝整个候选。
pub(crate) fn validate_scopes(
    proxies: &[crate::config::ProxyRuntime],
    ownership: &crate::control::ownership::OwnershipCatalog,
) -> Result<()> {
    let mut seen: HashMap<String, (u64, Arc<BoundScope>)> = HashMap::new();
    let mut bindings = Vec::new();
    for proxy in proxies {
        for route in proxy.router.routes() {
            let Some(policy) = &route.traffic_limit else {
                continue;
            };
            let owner = if ownership.enabled() {
                ownership
                    .route_owner(&proxy.id, &route.id)
                    .ok_or_else(|| anyhow::anyhow!("traffic_limit owner is unavailable"))?
                    .namespace()
            } else {
                "platform".to_owned()
            };
            let key = policy.scope.state_scope(&owner, &proxy.id, &route.id);
            let binding = if let Some((previous, binding)) = seen.get(&key) {
                // 一个共享域只能有一份限额定义；用策略指纹静默拆桶会把声明的共享配额成倍放大。
                if *previous != policy.state_key {
                    bail!(
                        "traffic_limit shared scope has inconsistent policies at proxy {} route {}",
                        proxy.id,
                        route.id
                    );
                }
                binding.clone()
            } else {
                let binding = Arc::new(BoundScope::new(&key, policy.state_key));
                seen.insert(key, (policy.state_key, binding.clone()));
                binding
            };
            if let Some(previous) = policy.bound_scope.get() {
                // 共享路由对象若已绑定其它归属，必须重新构建，不能修改已被在途请求借用的身份。
                ensure!(
                    previous.quota == binding.quota,
                    "traffic_limit cannot rebind a published scope"
                );
            }
            bindings.push((policy, binding));
        }
    }
    // 所有跨入口冲突检查通过后才发布只读绑定；没有绑定的策略不能进入数据面扣账。
    for (policy, binding) in bindings {
        if let Err(binding) = policy.bound_scope.set(binding) {
            ensure!(
                policy
                    .bound_scope
                    .get()
                    .is_some_and(|current| current.quota == binding.quota),
                "traffic_limit scope changed during compilation"
            );
        }
    }
    Ok(())
}
