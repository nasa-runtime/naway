//! 运行态动作的有界类型化适配，原始查询串仍由既有入口解释。

use crate::config::model::{AdminAction, AdminResource, GuardFile, GuardRuleCfg};
use crate::security::guard::InterfaceGuard;
use anyhow::{ensure, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;

pub(super) const MAX_GRACE_MS: u64 = 365 * 24 * 60 * 60 * 1000;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Action {
    Blacklist {
        ip: IpAddr,
        blocked: bool,
        ttl_ms: Option<String>,
    },
    InterfaceDisable {
        id: String,
        disabled: bool,
        rule: Option<Rule>,
    },
    Connections {
        selector: Selector,
    },
    CacheInvalidate {
        proxy: String,
        route: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rule {
    path: String,
    methods: Vec<String>,
    status: u16,
    body: String,
    ttl_ms: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "by", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Selector {
    Route {
        route: String,
    },
    Ip {
        ip: IpAddr,
    },
    Consumer {
        consumer: String,
    },
    Stale {
        before: String,
        grace_ms: String,
    },
}

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Blacklist(bool),
    InterfaceDisable(bool),
    Connections,
    CacheInvalidate,
}

/// 只由类型化入口建立的进程内参数；HTTP头或查询参数不能创建此适配权威。
#[derive(Clone)]
pub(in crate::admin) struct Inputs {
    pub(super) kind: Kind,
    pub(super) parameters: BTreeMap<String, String>,
    pub(super) digest: String,
    pub(super) value: Option<Value>,
    pub(super) ttl_ms: Option<u64>,
}

impl Kind {
    /// 业务作用：把每种运行态副作用绑定到其既有资源动作，不继承配置或读取权限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原生端点使用的精确RBAC位。
    pub(super) fn permission(self) -> (AdminResource, AdminAction) {
        match self {
            Self::Blacklist(_) => (AdminResource::Acl, AdminAction::EmergencyKill),
            Self::InterfaceDisable(_) => {
                (AdminResource::InterfaceGuard, AdminAction::EmergencyKill)
            }
            Self::Connections => (AdminResource::Connections, AdminAction::EmergencyKill),
            Self::CacheInvalidate => (AdminResource::Cache, AdminAction::Write),
        }
    }

    /// 业务作用：为页面和审计提供固定动作身份，不以用户输入充当动作名。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：四种稳定动作之一。
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Blacklist(_) => "blacklist",
            Self::InterfaceDisable(_) => "interface_disable",
            Self::Connections => "connections",
            Self::CacheInvalidate => "cache_invalidate",
        }
    }
}

impl Action {
    /// 业务作用：在校验具体目标前裁定精确动作权限，不能借另一资源的动作位探测执行入口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前请求对应的固定原生动作。
    pub(super) fn kind(&self) -> Kind {
        match self {
            Self::Blacklist {
                blocked,
                ..
            } => Kind::Blacklist(*blocked),
            Self::InterfaceDisable {
                disabled,
                ..
            } => Kind::InterfaceDisable(*disabled),
            Self::Connections {
                ..
            } => Kind::Connections,
            Self::CacheInvalidate {
                ..
            } => Kind::CacheInvalidate,
        }
    }

    /// 业务作用：在任何审计或外部写入前验证完整输入，构造供同一原生执行体使用的参数。
    ///
    /// 参数说明：
    /// - `digest`：原始有限JSON正文的摘要，只用于低敏审计关联。
    ///
    /// 返回：精确参数和已预编译验证的规则模板；非法字段、预算或范围直接拒绝。
    pub(super) fn prepare(self, digest: String) -> Result<Inputs> {
        let mut input = Inputs {
            kind: Kind::Connections,
            parameters: BTreeMap::new(),
            digest,
            value: None,
            ttl_ms: None,
        };
        match self {
            Self::Blacklist {
                ip,
                blocked,
                ttl_ms,
            } => {
                ensure!(blocked || ttl_ms.is_none(), "unblock cannot carry ttl");
                input.kind = Kind::Blacklist(blocked);
                input.parameters.insert("ip".into(), ip.to_string());
                input.ttl_ms = ttl(ttl_ms)?;
                if let Some(value) = input.ttl_ms {
                    input.parameters.insert("ttl_ms".into(), value.to_string());
                }
                if blocked {
                    input.value = Some(json!({
                        "source": "admin",
                    }));
                }
            }
            Self::InterfaceDisable {
                id,
                disabled,
                rule,
            } => {
                name(&id, 1024)?;
                ensure!(disabled == rule.is_some(), "rule and disable must agree");
                input.kind = Kind::InterfaceDisable(disabled);
                input.parameters.insert("id".into(), id.clone());
                if let Some(rule) = rule {
                    name(&rule.path, 2048)?;
                    ensure!(rule.body.len() <= 4096, "response body too large");
                    ensure!(
                        (200..=599).contains(&rule.status),
                        "invalid final response status"
                    );
                    ensure!(rule.methods.len() <= 16, "too many response methods");
                    for method in &rule.methods {
                        ensure!(
                            method.len() <= 32
                                && method.trim() == method
                                && http::Method::from_bytes(method.as_bytes()).is_ok(),
                            "invalid response method"
                        );
                    }
                    input.ttl_ms = ttl(rule.ttl_ms)?;
                    let value = json!({
                        "id": id,
                        "enabled": true,
                        "match": {
                            "path": rule.path,
                            "methods": rule.methods,
                        },
                        "response": {
                            "status": rule.status,
                            "headers": {
                                "content-type": "text/plain; charset=utf-8",
                            },
                            "body": rule.body,
                        },
                        "expire_at_unix_ms": null,
                    });
                    let rule: GuardRuleCfg = serde_json::from_value(value.clone())?;
                    // 在写入事实源之前通过同一编译器，非法glob不能先成为共享的动态声明。
                    InterfaceGuard::build(GuardFile {
                        schema_version: Some(1),
                        default_response: None,
                        rules: vec![rule],
                    })?;
                    input.value = Some(value);
                }
            }
            Self::Connections {
                selector,
            } => match selector {
                Selector::Route {
                    route,
                } => {
                    name(&route, 256)?;
                    input.parameters.insert("route".into(), route);
                }
                Selector::Ip {
                    ip,
                } => {
                    input.parameters.insert("ip".into(), ip.to_string());
                }
                Selector::Consumer {
                    consumer,
                } => {
                    name(&consumer, 256)?;
                    input.parameters.insert("consumer".into(), consumer);
                }
                Selector::Stale {
                    before,
                    grace_ms,
                } => {
                    decimal(&before)?;
                    ensure!(decimal(&grace_ms)? <= MAX_GRACE_MS, "drain grace too large");
                    input.parameters.insert("stale_before".into(), before);
                    input.parameters.insert("grace_ms".into(), grace_ms);
                }
            },
            Self::CacheInvalidate {
                proxy,
                route,
            } => {
                name(&proxy, 256)?;
                name(&route, 256)?;
                input.kind = Kind::CacheInvalidate;
                input.parameters.insert("proxy".into(), proxy);
                input.parameters.insert("route".into(), route);
            }
        }
        Ok(input)
    }
}

impl Inputs {
    /// 业务作用：在原生执行时刻确定动态事实的TTL，不让正文解析或审批等待提前消耗有效期。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一原生字段合同的JSON正文；撤销类动作没有待写声明。
    pub(in crate::admin) fn native_value(&self) -> Option<String> {
        let mut value = self.value.clone()?;
        if let Some(ttl) = self.ttl_ms {
            let ttl = ttl.min(i64::MAX as u64) as i64;
            value["expire_at_unix_ms"] = json!(super::super::unix_now_ms().saturating_add(ttl));
        }
        Some(value.to_string())
    }
}

/// 业务作用：保持u64配置代和毫秒输入的十进制精确身份，避免浮点舍入或隐式空白转换。
///
/// 参数说明：
/// - `value`：JSON字符串中的规范十进制整数。
///
/// 返回：精确u64；前导零、符号、空白、指数或溢出均拒绝。
fn decimal(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.len() <= 20,
        "invalid decimal size"
    );
    ensure!(
        value.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid decimal"
    );
    let parsed = value.parse::<u64>()?;
    ensure!(parsed.to_string() == value, "noncanonical decimal");
    Ok(parsed)
}

/// 业务作用：把永久声明与显式正TTL分开，零TTL不能被误认为永久。
///
/// 参数说明：
/// - `value`：可选的原样毫秒字符串。
///
/// 返回：无TTL或正u64；非法值不提交动态事实。
fn ttl(value: Option<String>) -> Result<Option<u64>> {
    value
        .map(|value| {
            let parsed = decimal(&value)?;
            ensure!(parsed > 0, "ttl must be positive");
            Ok(parsed)
        })
        .transpose()
}

/// 业务作用：限定精确选择器和规则身份的原生字节预算，不重写中文、空格或保留字符。
///
/// 参数说明：
/// - `value`：尚未交付原生执行体的文本。
/// - `maximum`：对应业务字段的UTF-8上限。
///
/// 返回：合法原值；空、控制字符或越界拒绝。
fn name(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control),
        "invalid action selector"
    );
    Ok(())
}
