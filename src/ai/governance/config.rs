use crate::ai::agent::config::{AclCfg, SecurityCfg, TargetCfg};
use crate::config::model::{LlmModerationCfg, LlmModerationFailModeCfg};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceCfg {
    pub security: SecurityCfg,
    /// 数据保留策略必须显式声明；request_only 不存储检索文档、prompt 或治理后响应。
    pub retention: Retention,
    #[serde(default)]
    pub prompt: Option<PromptCfg>,
    #[serde(default)]
    pub rag: Option<RagCfg>,
    #[serde(default)]
    pub output_moderation: Option<OutputModerationCfg>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    RequestOnly,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PromptCfg {
    pub name: String,
    /// 真实业务模板修订标识；客户端不能选择或覆盖模板。
    pub revision: String,
    pub file: String,
    /// 仅允许配置固定变量；{{name}} 不执行表达式或读取客户端输入。
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RagCfg {
    pub sources: Vec<SourceCfg>,
    pub citations: Citations,
    pub max_context_bytes: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Citations {
    Required,
    Optional,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceCfg {
    pub id: String,
    pub target: TargetCfg,
    pub invocation: AclCfg,
    pub timeout_ms: u64,
    pub max_documents: usize,
    pub max_response_bytes: usize,
    pub allowed_sources: Vec<String>,
    pub allowed_citation_origins: Vec<String>,
    pub fail_mode: LlmModerationFailModeCfg,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputModerationCfg {
    pub service: LlmModerationCfg,
    /// 每个文本通道发送前保留的前瞻字节，外部裁决只声明此窗口内的能力。
    pub stream_window_bytes: usize,
    pub max_calls: usize,
}
