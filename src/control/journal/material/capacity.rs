//! 首次受理同时保留所有后继事实的元数据空间，秘密写入后不能因收据增长失去恢复能力。

use super::{Record, Stage};
use anyhow::{ensure, Context, Result};

// Admission含固定摘要、UUID与有界恢复标识；按每字节六字符转义计入190字节恢复标识。
const ADMISSION: usize = 2048;
// Receipt的字段名、有限结果及原因；实际监听证据单独按完整原协议分母计费。
const RECEIPT: usize = 128;
// Goal只含schema、64位十六进制代及三个32字节数组，包含数组分隔符和最宽十进制字节。
const GOAL: usize = 640;
// Proof和Absence只含固定摘要、UUID、原位置和有限枚举，不含部署路径或正文。
const RELEASE: usize = 512;
const ABSENCE: usize = 1024;
// revision、两处fence、阶段、方向、保护原因及容器分隔符的最大增长。
const SCALARS: usize = 256;

impl Record {
    /// 业务作用：在首次head之前预留原责任所有后继状态的增长空间，完整监听和补偿不能晚于秘密写入才发现超限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：首次记录之外的保守字节上界；只接受已完整校验的首次Reserved或无受理Rejected布局。
    pub(in crate::control::journal) fn successor_reserve(&self) -> Result<usize> {
        if self.schema == 3 {
            ensure!(
                self.stage == Stage::Rejected && self.execution.is_none() && self.absence.is_some(),
                "material absence reservation layout differs"
            );
            return Ok(RELEASE + SCALARS);
        }
        ensure!(
            self.schema == 2 && self.stage == Stage::Reserved && self.absence.is_none(),
            "material execution reservation layout differs"
        );
        let execution = self
            .execution
            .as_ref()
            .context("material reservation sources absent")?;
        // boot为最多128字节的ASCII令牌；两层观察容器、每组和每目标封装按原分母固定计费。
        let mut evidence = 256usize.saturating_add(execution.sources.protocols.len() * 20);
        for group in &execution.sources.protocols {
            for protocols in group {
                // 每条观察只有协议、有限状态、u32计数和64字节材料代，含字段名最多176字节。
                evidence = evidence.saturating_add(20 + protocols.count() * 176);
            }
        }
        // 四个业务效果至多各占一份受理或收据；仅两个apply方向带实际监听证据。
        // 原Reserved中的受理和空字段不抵扣，保证后续所有合法attempt与恢复标识都有空间。
        Ok((SCALARS + RELEASE + ABSENCE + 4 * (ADMISSION + RECEIPT))
            .saturating_add(execution.sources.plans.len().saturating_mul(GOAL))
            .saturating_add(evidence.saturating_mul(2)))
    }
}
