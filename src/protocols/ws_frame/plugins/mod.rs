//! 消息相位只接收冻结身份和完整有界载荷，控制帧不进入业务插件。

mod content;
mod external;

use super::{FrameStats, OpCode};
use crate::config::model::WsMessagePluginCfg;
use anyhow::{ensure, Result};
use bytes::Bytes;
use std::{collections::HashSet, path::Path, sync::Arc, time::Duration};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum Failure {
    Denied,
    Invalid,
    Capacity,
    Deadline,
    Dependency,
    Close,
    Drop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    Acl {
        consumers: HashSet<String>,
        text: bool,
        binary: bool,
    },
    Content(content::Plan),
    Rate {
        messages: u64,
        window: Duration,
    },
    External(external::Plan),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Chain(Arc<[Step]>);

pub(super) struct Context<'a> {
    pub consumer: Option<&'a str>,
    pub from_client: bool,
    pub opcode: OpCode,
    pub policy: &'a super::FramePolicy,
    pub budget: &'a nabudget::RequestBudget,
    pub stats: &'a FrameStats,
}

pub(super) struct Flow {
    chain: Chain,
    windows: Vec<(tokio::time::Instant, u64)>,
}

impl Chain {
    /// 业务作用：把有序消息策略编译为不可变计划，未知规则和不可执行权限不能进入数据面。
    ///
    /// 参数说明：
    /// - `configs`：单个方向的插件声明，顺序决定校验与变换的输入。
    /// - `directory`：外部插件凭据与信任的相对路径根。
    ///
    /// 返回：最多16步的共享链；ACL、配额、Schema 或外呼声明非法时拒绝候选。
    pub(crate) fn build(configs: &[WsMessagePluginCfg], directory: &Path) -> Result<Self> {
        ensure!(configs.len() <= 16, "too many WebSocket message plugins");
        let mut steps = Vec::with_capacity(configs.len());
        for cfg in configs {
            let step = match cfg {
                WsMessagePluginCfg::Acl {
                    consumers,
                    opcodes,
                } => {
                    ensure!(
                        consumers.len() <= 128
                            && consumers
                                .iter()
                                .all(|name| !name.is_empty() && name.len() <= 1024)
                            && opcodes.len() <= 2
                            && opcodes
                                .iter()
                                .all(|opcode| matches!(opcode.as_str(), "text" | "binary")),
                        "invalid WebSocket message ACL"
                    );
                    ensure!(
                        !consumers.is_empty() || !opcodes.is_empty(),
                        "empty WebSocket message ACL"
                    );
                    let unique: HashSet<_> = consumers.iter().cloned().collect();
                    ensure!(
                        unique.len() == consumers.len()
                            && (opcodes.len() != 2 || opcodes[0] != opcodes[1]),
                        "duplicate WebSocket ACL member"
                    );
                    Step::Acl {
                        consumers: unique,
                        text: opcodes.is_empty() || opcodes.iter().any(|opcode| opcode == "text"),
                        binary: opcodes.is_empty()
                            || opcodes.iter().any(|opcode| opcode == "binary"),
                    }
                }
                WsMessagePluginCfg::JsonSchema {
                    schema,
                } => Step::Content(content::Plan::schema(schema)?),
                WsMessagePluginCfg::Redact {
                    pointers,
                } => Step::Content(content::Plan::redact(pointers)?),
                WsMessagePluginCfg::RateLimit {
                    messages,
                    window_ms,
                } => {
                    ensure!(
                        (1..=1_000_000).contains(messages) && (1..=3_600_000).contains(window_ms),
                        "invalid WebSocket message rate budget"
                    );
                    Step::Rate {
                        messages: *messages,
                        window: Duration::from_millis(*window_ms),
                    }
                }
                WsMessagePluginCfg::External {
                    ..
                } => Step::External(external::Plan::build(cfg, directory)?),
            };
            steps.push(step);
        }
        Ok(Self(steps.into()))
    }

    /// 业务作用：判断该方向是否需要完整载荷治理，空链不引入内容缓冲。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有消息插件时为真。
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 业务作用：为一个连接方向分配固定大小的额度时钟，不跨连接共享本地消息计数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与编译链一一对应的有界运行态。
    pub(super) fn flow(&self) -> Flow {
        Flow {
            chain: self.clone(),
            windows: vec![(tokio::time::Instant::now(), 0); self.0.len()],
        }
    }
}

impl Flow {
    /// 业务作用：对完整消息按顺序执行授权、额度和内容策略，同链JSON只在确需修改时重新编码。
    ///
    /// 参数说明：
    /// - `body`：协议门已验证的完整原始或解压后载荷。
    /// - `context`：冻结身份、方向、策略、消息总期限与本连接计数器。
    /// - `resident`：实体内存凭证；阻塞任务存活期间仍持有它。
    ///
    /// 返回：所有步骤通过后返回原始或变换后的Bytes；拒绝和关闭不会产生半完成输出。
    pub(super) async fn apply(
        &mut self,
        body: Bytes,
        context: Context<'_>,
        resident: Arc<crate::runtime::traffic_limit::resources::Retained>,
    ) -> Result<Bytes, Failure> {
        let policy = context.policy;
        let budget = context.budget;
        let stats = context.stats;
        if !self.chain.is_empty() && body.len() > policy.max_plugin_payload_bytes {
            return Err(Failure::Capacity);
        }
        let mut document =
            content::Document::new(body, policy.max_plugin_payload_bytes, resident.clone());
        for (index, step) in self.chain.0.iter().enumerate() {
            budget.check().map_err(|_| Failure::Deadline)?;
            match step {
                Step::Acl {
                    consumers,
                    text,
                    binary,
                } => {
                    if (!consumers.is_empty()
                        && !context
                            .consumer
                            .is_some_and(|name| consumers.contains(name)))
                        || (context.opcode == OpCode::Text && !text)
                        || (context.opcode == OpCode::Binary && !binary)
                    {
                        return Err(Failure::Denied);
                    }
                }
                Step::Rate {
                    messages,
                    window,
                } => {
                    let clock = &mut self.windows[index];
                    let now = tokio::time::Instant::now();
                    if now.duration_since(clock.0) >= *window {
                        *clock = (now, 0);
                    }
                    if clock.1 >= *messages {
                        return Err(Failure::Denied);
                    }
                    clock.1 += 1;
                }
                Step::Content(plan) => {
                    let child = budget.child(policy.plugin_timeout());
                    let result = plan.apply(document, &child).await;
                    if matches!(result, Err(Failure::Deadline)) {
                        stats.record_plugin_timeout();
                    }
                    document = result?;
                }
                Step::External(plan) => {
                    let body = document.finish(budget).await?;
                    let child = budget.child(policy.plugin_timeout());
                    let result = child
                        .run(plan.call(body.clone(), &context, policy.max_plugin_payload_bytes))
                        .await
                        .unwrap_or(Err(Failure::Deadline));
                    if matches!(result, Err(Failure::Deadline)) {
                        stats.record_plugin_timeout();
                    }
                    // 只有明确声明的依赖失败可以开放；非法动作、授权和本地资源门不得转成成功。
                    let output = match result {
                        Ok(output) => output,
                        Err(Failure::Dependency | Failure::Deadline) if plan.fail_open => body,
                        Err(error) => return Err(error),
                    };
                    document = content::Document::new(
                        output,
                        policy.max_plugin_payload_bytes,
                        resident.clone(),
                    );
                }
            }
        }
        budget.check().map_err(|_| Failure::Deadline)?;
        document.finish(budget).await
    }
}
