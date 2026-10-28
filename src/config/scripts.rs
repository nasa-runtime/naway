//! 脚本只在显式扩展相位执行，输入能力、失败策略和每次调用预算构建期冻结。
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    RequestHeaders,
    RequestBody,
    RequestBodyStream,
    ResponseHeaders,
    ResponseBody,
    ResponseBodyStream,
}
impl Phase {
    /// 业务作用：限定只有显式实体相位可以读取或替换 body。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前阶段属于聚合或逐帧实体处理时为 true。
    pub fn body(self) -> bool {
        !matches!(self, Self::RequestHeaders | Self::ResponseHeaders)
    }
    /// 业务作用：区分完整实体慢路径与逐帧扩展路径，禁止隐式聚合长流。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：逐帧请求或响应阶段时为 true。
    pub fn streaming(self) -> bool {
        matches!(self, Self::RequestBodyStream | Self::ResponseBodyStream)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    Closed,
    Open,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitCfg {
    pub failure_threshold: u32,
    pub open_ms: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptCfg {
    pub id: String,
    pub source_file: String,
    pub phase: Phase,
    /// 只覆盖明确的解释器依赖不可用；输入、输出、资源预算和脚本主动拒绝永不放行。
    pub failure_mode: FailureMode,
    pub circuit: CircuitCfg,
    #[serde(default)]
    pub include_headers: Vec<String>,
    #[serde(default)]
    pub mutation_headers: Vec<String>,
    pub max_memory_bytes: usize,
    pub max_instructions: u64,
    pub max_allocations: u64,
    pub max_cpu_ms: u64,
    pub timeout_ms: u64,
    pub max_header_bytes: usize,
    pub max_mutations: usize,
    /// 实体相位必须显式配置；head 相位必须省略。
    pub max_body_bytes: Option<usize>,
}
impl ScriptCfg {
    /// 业务作用：在候选发布前固定相位、源文件和预算，不允许脚本启用未编译能力或无界实体读取。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：所有显式资源上限和失败策略有效时成功；其它情况拒绝候选。
    pub fn validate(&self) -> Result<()> {
        ensure!(
            cfg!(feature = "lua-scripts"),
            "script_plugins requires lua-scripts feature"
        );
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 128
                && self
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
            "invalid script id"
        );
        ensure!(
            !self.source_file.is_empty() && self.source_file.len() <= 4096,
            "invalid script source_file"
        );
        ensure!(
            (256 << 10..=32 << 20).contains(&self.max_memory_bytes),
            "invalid script memory budget"
        );
        ensure!(
            (1000..=100_000_000).contains(&self.max_instructions),
            "invalid script instruction budget"
        );
        ensure!(
            (100..=1_000_000).contains(&self.max_allocations),
            "invalid script allocation budget"
        );
        ensure!(
            (1..=1000).contains(&self.timeout_ms)
                && (1..=self.timeout_ms).contains(&self.max_cpu_ms),
            "invalid script cpu/deadline budget"
        );
        ensure!(
            (256..=64 << 10).contains(&self.max_header_bytes)
                && (1..=128).contains(&self.max_mutations),
            "invalid script header/mutation budget"
        );
        ensure!(
            self.include_headers.len() <= 32 && self.mutation_headers.len() <= 32,
            "script header allowlist limit"
        );
        if self.phase.body() {
            ensure!(
                self.max_body_bytes
                    .is_some_and(|bytes| (1..=if self.phase.streaming() {
                        1 << 20
                    } else {
                        16 << 20
                    })
                        .contains(&bytes)),
                "body script requires explicit bounded max_body_bytes"
            );
        } else {
            ensure!(
                self.max_body_bytes.is_none(),
                "header script cannot declare body access"
            );
        }
        ensure!(
            (1..=100).contains(&self.circuit.failure_threshold)
                && (10..=60000).contains(&self.circuit.open_ms),
            "invalid script circuit budget"
        );
        Ok(())
    }
    /// 业务作用：为客体、上下文和原子输出副本计算跨语言共享工作集。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定预算内的保守预留，不随脚本自报值扩大。
    pub fn working_set(&self) -> usize {
        self.max_memory_bytes
            .saturating_add(self.max_body_bytes.unwrap_or(0).saturating_mul(4))
            .saturating_add(self.max_header_bytes.saturating_mul(8))
            .saturating_add(1 << 20)
    }
}
