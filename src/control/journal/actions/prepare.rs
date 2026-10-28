//! 已验真命令在同一文件事务中建立持久准备，不提前改变活动配置。

use super::model::{Record, Stage};
use crate::{
    config::{
        candidate::{dependencies, Documents},
        GatewaySnapshot,
    },
    control::{
        actions::{
            command::{Command, Step},
            definition,
            domain::Domain,
            effect::Admission,
            receipt::{Outcome, Receipt},
        },
        baseline::NodeBaseline,
        journal::{local, Journal},
    },
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;
use sha2::{Digest, Sha256};

/// 原工作区和原文借用跟随真实工作单元；证明已经夹住该候选的实际语义重建。
pub(crate) struct Preparation<'a> {
    pub command: &'a Command,
    pub active: &'a GatewaySnapshot,
    pub documents: Documents<'a>,
    pub files: local::Input<'a>,
    pub dependencies_sha256: [u8; 32],
    pub baseline_dependencies_sha256: [u8; 32],
}

impl Journal {
    /// 业务作用：在已验签、有真实容量并持统一文件写事务的命令处理器中，把完整候选与原受理身份同步为 Prepared。
    ///
    /// 参数说明：
    /// - `input`：本次命令、原活动快照、已完整构建候选及其仍存活的原文工作区。
    /// - `authorize`：每次持久决定前复验当前会话、权限、快照实例及单调期限的门。
    ///
    /// 返回：成功收据随 head 完整同步后才返回；任一失败保留原活动文件与已提交的明确准备状态。
    pub(crate) fn prepare_action(
        &self,
        input: Preparation<'_>,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<Receipt> {
        let command = input.command;
        let definition = definition::cached(command.intent.target_count as usize)?;
        let verified = command.validate(&definition)?;
        ensure!(
            verified.step() == Step::Prepare && verified.identity().phase == StepPhase::Execute,
            "node preparation requires the prepare execute effect"
        );
        let boot = self
            .action_boot
            .get()
            .context("node action boot is not bound")?;
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("node journal action storage is not initialized")?;
        // 新意图只能消费本启动的空槽和更高 fence，不能借准备覆盖其它操作或未决本地文件方向。
        ensure!(
            current.action().is_none()
                && current.local().is_none()
                && command.intent.node_id == self.identity.node_id
                && command.intent.baseline.cluster_id == self.identity.cluster_id
                && command.intent.baseline.store_id == self.identity.store_id
                && command.intent.baseline.node_admission_epoch
                    == current.admission_epoch().to_string()
                && command.delivery.fence > current.highest_fence()
                && command.delivery.receiving_boot_id == *boot
                && command.intent.original_boot_id == *boot,
            "node preparation authority differs"
        );
        authorize()?;
        input.require_baseline()?;
        let candidate = input
            .files
            .candidate
            .context("node preparation candidate is absent")?;
        ensure!(
            input.files.current == input.active.document_paths.ordered()
                && input.files.targets == candidate.document_paths.ordered(),
            "node preparation document paths differ"
        );
        let index = match command.intent.domain {
            Domain::Gateway => 2,
            Domain::Sentinel => 1,
            Domain::InterfaceGuard => 0,
        };
        ensure!(
            input
                .files
                .desired
                .iter()
                .enumerate()
                .all(|(position, body)| position == index || body.is_none()),
            "node preparation contains unsigned document replacements"
        );
        ensure!(
            command.intent.domain == Domain::Gateway || input.files.current == input.files.targets,
            "node rule preparation cannot move document paths"
        );
        let bytes =
            input.files.desired[index].context("node preparation original candidate is absent")?;
        ensure!(
            bytes.len() == command.intent.candidate_bytes as usize
                && Sha256::digest(bytes)[..] == command.intent.candidate_sha256,
            "node preparation candidate integrity differs"
        );
        input.require_dependencies(candidate)?;
        let Preparation {
            command,
            active,
            documents,
            files,
            dependencies_sha256,
            baseline_dependencies_sha256,
        } = input;
        let mut prepared = local::prepare::Prepared::new(files)?
            .context("node preparation file baseline changed")?;
        let next = Record {
            schema: 1,
            intent: command.intent.clone(),
            intent_sha256: *verified.intent_sha256(),
            fence: command.delivery.fence,
            stage: Stage::Preparing,
            dependencies_sha256,
            baseline_dependencies_sha256,
            candidate_fingerprint: None,
            files: Some(prepared.plan.clone()),
            admissions: vec![Admission::new(command, &definition)?],
            receipts: Vec::new(),
            absence: None,
            publication: None,
        };
        authorize()?;
        // 当前 head 已证明没有正文引用，先回收无引用材料，再持久 Preparing，之后才创建本操作正文。
        local::bodies::clear(&self.root)?;
        self.advance_action(&mut storage, next)?;
        local::bodies::write(&self.root, &mut prepared)?;
        ensure!(
            local::prepare::baseline_matches(&prepared.plan)?,
            "node preparation baseline changed before completion"
        );
        require_baseline(command, active)?;
        require_dependencies(
            active,
            candidate,
            documents,
            baseline_dependencies_sha256,
            dependencies_sha256,
        )?;
        authorize()?;
        let mut next = storage
            .as_ref()
            .and_then(|current| current.action())
            .context("node preparation state disappeared")?
            .clone();
        let admission = next
            .admissions
            .pop()
            .context("node preparation admission disappeared")?;
        let receipt = Receipt::settle(
            admission,
            &next.intent,
            &definition,
            Outcome::Succeeded,
            None,
        )?;
        next.receipts.push(receipt.clone());
        next.stage = Stage::Prepared;
        // 同一原文即使没有差异也要确认 prepare 效果，后续全目标屏障依赖此持久事实。
        self.advance_action(&mut storage, next)?;
        Ok(receipt)
    }
}

impl Preparation<'_> {
    /// 业务作用：在建立文件计划前验证活动版本与原文基线，构建成功不能替代最终覆盖权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原 boot 外的版本、指纹与三文档证据全部匹配时成功，否则没有准备副作用。
    fn require_baseline(&self) -> Result<()> {
        require_baseline(self.command, self.active)
    }

    /// 业务作用：保持原活动和候选两套依赖证明，不能把候选文件路径变化混为同一配置来源。
    ///
    /// 参数说明：
    /// - `candidate`：仍由本次原工作区支持的完整候选快照。
    ///
    /// 返回：两套证明均保持实际重建时的事实才成功，读取失败拒绝。
    fn require_dependencies(&self, candidate: &GatewaySnapshot) -> Result<()> {
        require_dependencies(
            self.active,
            candidate,
            self.documents,
            self.baseline_dependencies_sha256,
            self.dependencies_sha256,
        )
    }
}

/// 业务作用：把命令冻结的原文和活动版本与最终文件事实同时比较，外部文件变化不能消耗旧审批基线。
///
/// 参数说明：
/// - `command`：已经核对节点、存储和受理代际的原命令。
/// - `active`：处理器仍通过实例门复验的原活动快照。
///
/// 返回：版本、完整指纹与三文档 SHA 全部一致时成功；缺证据或漂移拒绝。
pub(super) fn require_baseline(command: &Command, active: &GatewaySnapshot) -> Result<()> {
    let identity = active
        .document_identity
        .as_ref()
        .context("node preparation document identity is absent")?;
    let baseline = NodeBaseline::from_parts(
        command.intent.baseline.cluster_id.clone(),
        command.intent.baseline.store_id.clone(),
        command.intent.baseline.node_admission_epoch.parse()?,
        identity.digest(),
    );
    ensure!(
        active.version == command.intent.base_version
            && active.config_fingerprint == Some(command.intent.base_fingerprint)
            && baseline == command.intent.baseline
            && crate::config::config_fingerprint(&active.source_config_path).ok()
                == active.config_fingerprint,
        "node preparation active baseline changed"
    );
    Ok(())
}

/// 业务作用：正文同步前后复验两种配置依赖，固定计划覆盖的 base 不重复参与元数据证明。
///
/// 参数说明：
/// - `active`：原活动快照的真实部署来源。
/// - `candidate`：本次完整候选及实际声明的非 base 依赖。
/// - `documents`：仍存活的隔离工作区读取位置。
/// - `baseline`：建立候选之前冻结的活动依赖证明。
/// - `desired`：夹住候选实际重建的依赖证明。
///
/// 返回：两份有界文件证明一致时成功，不改变文件或快照。
fn require_dependencies(
    active: &GatewaySnapshot,
    candidate: &GatewaySnapshot,
    documents: Documents<'_>,
    baseline: [u8; 32],
    desired: [u8; 32],
) -> Result<()> {
    ensure!(
        dependencies::capture(
            active,
            Documents {
                gateway: &active.source_config_path,
                sidecars: None
            }
        )? == baseline
            && dependencies::capture(candidate, documents)? == desired,
        "node preparation dependencies changed"
    );
    Ok(())
}
