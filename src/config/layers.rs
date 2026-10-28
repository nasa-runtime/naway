//! 路由层级的声明合同；受信条件与普通请求断言分离，不能用客户端同名 header 冒充身份。

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LayerCfg {
    /// 单父引用避免同一请求经菱形路径重复执行策略；只能引用同 listener 内的分支节点。
    pub parent_ref: Option<String>,
    /// 分支不具有后端；所有终端行为只能声明在叶子上。
    pub branch: bool,
    /// 子层选择前读取已完成父层策略产生的冻结上下文，条件之间为 AND。
    pub matches: Vec<MatchCfg>,
    /// 节点策略成功后追加只写一次的受信变量，后代不能覆盖已有名称。
    pub context: BTreeMap<String, ContextCfg>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MatchCfg {
    Authenticated {
        value: bool,
    },
    Consumer {
        equals: String,
    },
    Claim {
        name: String,
        equals: String,
    },
    ClaimContains {
        name: String,
        value: String,
    },
    Risk {
        equals: Risk,
    },
    Variable {
        name: String,
        equals: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextCfg {
    Literal {
        value: String,
    },
    Claim {
        name: String,
    },
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    #[default]
    NotEvaluated,
    Clear,
    Matched,
}
