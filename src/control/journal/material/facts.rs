//! 查询保留同一head的原生事实树，只提供不含部署位置或秘密正文的借用视图。

use super::{execution::Direction, Record, Stage};
use crate::control::material::{
    execution::{
        absence::Absence,
        effect::Admission,
        observation::Protocols,
        position::Position,
        receipt::{Reason, Receipt},
        release::Proof,
    },
    node::Intent,
};
use std::sync::Arc;

/// 一次原子查询保留的完整持久事实；内部来源计划不向传输层暴露，也不提供整体序列化入口。
pub(crate) struct Facts {
    revision: u64,
    position: Position,
    record: Arc<Record>,
}

/// 单一原来源可交付的预分配代与协议分母，没有文件位置、私钥或备份摘要。
pub(crate) struct Source<'a> {
    pub source_id: &'a str,
    pub forward_generation: &'a str,
    pub compensation_generation: Option<&'a str>,
    pub protocols: &'a [Protocols],
}

impl Facts {
    /// 业务作用：在共享存储边界投影原子事实，保留原收据Arc并只复制公开来源代，不暴露恢复路径或秘密摘要。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与本机同一head完整一致的原生报告；投影不满足共同阶段或完整证据合同时拒绝交付。
    pub(crate) fn report(
        &self,
    ) -> anyhow::Result<crate::control::material::execution::report::Report> {
        use crate::control::material::execution::report::{Report, Source};
        let (sources, protocols) = self
            .sources()
            .map(|source| {
                (
                    Source {
                        source_id: source.source_id.into(),
                        forward: source.forward_generation.into(),
                        backward: source.compensation_generation.map(str::to_owned),
                    },
                    source.protocols.to_vec(),
                )
            })
            .unzip();
        let report = Report {
            schema: 1,
            revision: self.revision(),
            position: self.position(),
            intent_sha256: self.record.intent_sha256,
            fence: self.fence(),
            stage: self.stage(),
            prepared: self.prepared(),
            direction: self.direction(),
            sources,
            protocols,
            admissions: self.admissions().to_vec(),
            receipts: self.receipts().to_vec(),
            absence: self.absence().cloned(),
            protection: self.protection(),
            release: self.release().cloned(),
        };
        report.validate(self.intent(), self.position())?;
        Ok(report)
    }

    /// 业务作用：在持锁核对head与原命令后保留该次完整事实，后续阶段推进不能混入旧查询结果。
    ///
    /// 参数说明：
    /// - `revision`：当前已确认head的序号。
    /// - `position`：已与原记录完整摘要匹配的物理节点位置。
    /// - `record`：同一head选择的共享记录，不重新解析或深复制来源树。
    ///
    /// 返回：不可变原事实视图；仅允许Journal已验证查询构造。
    pub(super) fn new(revision: u64, position: Position, record: Arc<Record>) -> Self {
        Self {
            revision,
            position,
            record,
        }
    }

    /// 业务作用：让交付方标记完整事实来自哪个已确认提交，不能用后续head拼接本次结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原查询选中的持久序号。
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    /// 业务作用：借用原审批意图和完整目标分母，不从当前在线目录重建结果身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一记录共享的原意图，不含部署路径或秘密正文。
    pub(crate) fn intent(&self) -> &Arc<Intent> {
        &self.record.intent
    }

    /// 业务作用：保持原物理节点步骤位置与节点总数，重投不能借当前集群成员改变工作流。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已与原记录摘要核对的位置。
    pub(crate) fn position(&self) -> Position {
        self.position
    }

    /// 业务作用：区分未决文件方向、稳定监听和保护责任，不用成功字符串代替当前持久阶段。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原查询时刻的阶段，之后的提交不会改变此值。
    pub(crate) fn stage(&self) -> Stage {
        self.record.stage
    }

    /// 业务作用：交付同一head承认的独立材料水位，配置域或当前租约值不能替代原事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原材料域最高持久水位，不授予新的写权。
    pub(crate) fn fence(&self) -> u64 {
        self.record.fence.value
    }

    /// 业务作用：明确原准备是否曾完整持久，重启失效和补偿后也保留该历史事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原记录含完整准备事实时为真；没有执行计划的未受理布局为假。
    pub(crate) fn prepared(&self) -> bool {
        self.record
            .execution
            .as_ref()
            .is_some_and(|execution| execution.prepared)
    }

    /// 业务作用：交付仍保留的文件方向，保护态不能把曾决定的应用或补偿误报为从未执行。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原持久决定的应用或补偿方向；没有文件方向时为空。
    pub(crate) fn direction(&self) -> Option<Direction> {
        self.record
            .execution
            .as_ref()
            .and_then(|execution| execution.direction)
    }

    /// 业务作用：按原来源顺序借用预分配代和所有共享目标协议，当前文件或在线监听不能替换该分母。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不含路径的惰性来源视图；无受理布局为空，迭代不复制完整计划。
    pub(crate) fn sources(&self) -> impl Iterator<Item = Source<'_>> {
        self.record.execution.iter().flat_map(move |execution| {
            execution
                .sources
                .plans
                .iter()
                .enumerate()
                .map(move |(index, plan)| Source {
                    source_id: &self.record.intent.conditions.groups[index].source_id,
                    forward_generation: plan.generation(),
                    compensation_generation: execution
                        .compensation
                        .as_ref()
                        .map(|goals| goals[index].generation()),
                    protocols: &execution.sources.protocols[index],
                })
        })
    }

    /// 业务作用：保留尚无稳定结果的真实受理，后续补偿成功不能抹去原正向未知事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：该head保留的原受理身份切片；不从当前命令制造替代Admission。
    pub(crate) fn admissions(&self) -> &[Admission] {
        self.record
            .execution
            .as_ref()
            .map_or(&[], |execution| execution.admissions.as_slice())
    }

    /// 业务作用：借用所有原稳定收据及真实监听证据，交付当前效果时同时保持原历史事实完整。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原共享收据切片，查询和阶段推进均不深复制证据。
    pub(crate) fn receipts(&self) -> &[Arc<Receipt>] {
        self.record
            .execution
            .as_ref()
            .map_or(&[], |execution| execution.receipts.as_slice())
    }

    /// 业务作用：交付已持久的未受理屏障，与没有查询到记录或没有稳定收据严格区分。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一head中的原否定证明；没有该证明时为空。
    pub(crate) fn absence(&self) -> Option<&Absence> {
        self.record.absence.as_ref().map(|absence| &absence.proof)
    }

    /// 业务作用：说明原责任为何保持保护，有限原因不暴露本机路径或底层错误链。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已持久保护原因；没有明确原因不被补造为成功或确定未执行。
    pub(crate) fn protection(&self) -> Option<Reason> {
        self.record
            .execution
            .as_ref()
            .and_then(|execution| execution.protection)
    }

    /// 业务作用：交付已决定清理的原终态证明，缺失秘密槽不能自行推成共享工作流终态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：该head保留的原释放证明，尚无清理决定时为空。
    pub(crate) fn release(&self) -> Option<&Proof> {
        self.record
            .execution
            .as_ref()
            .and_then(|execution| execution.release.as_ref())
            .or_else(|| {
                self.record
                    .absence
                    .as_ref()
                    .and_then(|absence| absence.release.as_ref())
            })
    }
}
