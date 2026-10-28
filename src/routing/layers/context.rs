//! 请求内冻结上下文；来源只能是成功认证、已执行 WAF 或受信配置，不从业务 header 反向取身份。

use crate::config::layers::{ContextCfg, MatchCfg, Risk};
use anyhow::{ensure, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, Default)]
pub(crate) struct Context {
    pub authenticated: bool,
    pub consumer: Option<Arc<str>>,
    pub claims: Option<Value>,
    pub risk: Risk,
    variables: BTreeMap<String, String>,
}

impl Context {
    /// 业务作用：仅以父层已经冻结的事实选择子层，不重新解释客户端凭据或身份 header。
    ///
    /// 参数说明：
    /// - `conditions`：是构建期验证过的 AND 条件，数量与值长度均有硬上限。
    ///
    /// 返回：全部条件满足为 true；身份、claim 或变量缺失时不命中。
    pub(crate) fn matches(&self, conditions: &[MatchCfg]) -> bool {
        conditions.iter().all(|condition| match condition {
            MatchCfg::Authenticated {
                value,
            } => self.authenticated == *value,
            MatchCfg::Consumer {
                equals,
            } => self.authenticated && self.consumer.as_deref() == Some(equals.as_str()),
            MatchCfg::Claim {
                name,
                equals,
            } => {
                self.authenticated
                    && self
                        .claims
                        .as_ref()
                        .and_then(|claims| claims.get(name))
                        .and_then(Value::as_str)
                        == Some(equals.as_str())
            }
            MatchCfg::ClaimContains {
                name,
                value,
            } => {
                self.authenticated
                    && self
                        .claims
                        .as_ref()
                        .and_then(|claims| claims.get(name))
                        .and_then(Value::as_array)
                        .is_some_and(|values| {
                            values.len() <= 64
                                && values.iter().any(|entry| entry.as_str() == Some(value))
                        })
            }
            MatchCfg::Risk {
                equals,
            } => self.risk == *equals,
            MatchCfg::Variable {
                name,
                equals,
            } => self.variables.get(name) == Some(equals),
        })
    }

    /// 业务作用：节点策略成功后只追加受信变量，缺少 claim 或已有同名变量时拒绝继续进入后端。
    ///
    /// 参数说明：
    /// - `declarations`：为本地常量或已验证 claim 映射，不能包含请求 header、URL 或表达式求值。
    ///
    /// 返回：所有映射一起追加；任一缺失、超限或覆盖失败时不改变原变量表。
    pub(crate) fn append(&mut self, declarations: &BTreeMap<String, ContextCfg>) -> Result<()> {
        let mut additions = Vec::new();
        for (name, declaration) in declarations {
            ensure!(
                !self.variables.contains_key(name),
                "trusted layer variable already assigned"
            );
            let value = match declaration {
                ContextCfg::Literal {
                    value,
                } => Some(value.as_str()),
                ContextCfg::Claim {
                    name,
                } if self.authenticated => self
                    .claims
                    .as_ref()
                    .and_then(|claims| claims.get(name))
                    .and_then(Value::as_str),
                ContextCfg::Claim {
                    ..
                } => None,
            };
            let value = value
                .filter(|value| text(value))
                .ok_or_else(|| anyhow::anyhow!("trusted layer claim unavailable"))?;
            additions.push((name.clone(), value.to_owned()));
        }
        ensure!(
            self.variables.len() + additions.len() <= 32,
            "trusted layer variable capacity reached"
        );
        self.variables.extend(additions);
        Ok(())
    }

    /// 业务作用：保留整条已执行路径上最严格的 WAF 命中事实，后代不能用一次未命中清除父层风险。
    ///
    /// 参数说明：
    /// - `matched`：表示本节点已配置 WAF 的实际 head 检查结果。
    ///
    /// 返回：首次未命中变为 clear；任何命中永久提升为 matched，不降低已有风险。
    pub(crate) fn observe_waf(&mut self, matched: bool) {
        if matched {
            self.risk = Risk::Matched;
        } else if self.risk == Risk::NotEvaluated {
            self.risk = Risk::Clear;
        }
    }
}

/// 业务作用：限制层级配置标识为稳定精确单项，不允许通配符、分隔路径或控制字符。
///
/// 参数说明：
/// - `value`：是 route、claim 或受信变量的配置名称。
///
/// 返回：一至一百二十八字节的安全 ASCII 标识为 true。
pub(super) fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// 业务作用：限定冻结变量与比较值的内存和可见文本边界，防止 claim 膨胀或注入控制字符。
///
/// 参数说明：
/// - `value`：为实际 claim 或本地声明值。
///
/// 返回：一至二百五十六字节且无控制字符时允许。
pub(super) fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
