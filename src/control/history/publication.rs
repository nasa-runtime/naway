//! 统一文件写事务内的本地发布、持久决定与条件补偿。

use super::*;

/// 发布等待期间保留的精确文件收据；补偿不重新推导旧规则路径。
pub(crate) struct DocumentPublication {
    pub(crate) fingerprint: u64,
    files: Receipt,
}

enum Receipt {
    Memory(files::Publication),
    #[cfg(feature = "node-journal")]
    Durable(crate::control::journal::LocalReceipt),
}

impl Receipt {
    /// 业务作用：按本次发布实际采用的文件协议执行条件补偿，不在持久失败后降级为内存恢复。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整条件恢复成功为真，失去文件权威为假，不确定提交返回错误并保留保护。
    fn restore(self) -> Result<bool> {
        match self {
            Self::Memory(receipt) => receipt.restore(),
            #[cfg(feature = "node-journal")]
            Self::Durable(receipt) => receipt.restore(),
        }
    }
}

impl ConfigHistory {
    /// 业务作用：将已经通过完整候选校验的归档原文恢复到当前本地配置文件位置。
    ///
    /// 参数说明：
    /// - `documents`: 调用者已完成身份与语义验证的同一份归档原文。
    /// - `baseline`：活动版本归档的完整原文。
    /// - `expected_fingerprint`：活动快照的完整依赖指纹。
    /// - `current_paths`：活动快照冻结的真实目标。
    /// - `targets`: 已验证候选的真实文档目标。
    ///
    /// 返回：文件门成立且替换完成时为真；目标冲突为假，I/O失败报错；已初始化journal存储时保留持久恢复方向。
    pub(crate) fn restore_documents(
        &self,
        documents: &ArchivedDocs,
        baseline: &ArchivedDocs,
        expected_fingerprint: u64,
        current_paths: &crate::config::candidate::Paths,
        targets: &crate::config::candidate::Paths,
    ) -> Result<bool> {
        // 历史回滚同样必须消耗当前基线，不能把构建期间出现的新文件事实冒充待覆盖的旧版本。
        Ok(self
            .compare_and_publish_documents(
                documents,
                baseline,
                expected_fingerprint,
                current_paths,
                targets,
            )?
            .is_some())
    }

    /// 业务作用：把已完成统一候选构建的三份配置文档发布到本地事实源，避免管理接口只改其中一份而
    /// 让 reload 观察到跨版本组合。
    ///
    /// 参数说明：
    /// - `docs`：是完整候选
    /// - `baseline`：是提交时冻结的三文档
    /// - `expected_fingerprint`：绑定所有 已追踪依赖
    /// - `current_paths`：活动快照冻结的基线文档位置。
    /// - `target_paths`：已验证候选冻结的真实目标位置。
    ///
    /// 返回：写锁内基线一致且三文件替换成功返回精确收据；漂移为空，内存协议失败条件补偿，持久协议失败保留已提交方向。
    pub(crate) fn compare_and_publish_documents(
        &self,
        docs: &ArchivedDocs,
        baseline: &ArchivedDocs,
        expected_fingerprint: u64,
        current_paths: &crate::config::candidate::Paths,
        target_paths: &crate::config::candidate::Paths,
    ) -> Result<Option<DocumentPublication>> {
        let _transaction = self.file_transaction.write();
        self.require_journal_ready()?;
        // 基线比较与三文件替换在同一进程内写事务完成，两个并发审批不能先各自通过再相互覆盖。
        if config_fingerprint(&current_paths.gateway).ok() != Some(expected_fingerprint) {
            return Ok(None);
        }
        anyhow::ensure!(
            current_paths.gateway == target_paths.gateway,
            "document publication cannot move the bootstrap path"
        );
        let Some(publication) = self.publish_files(docs, baseline, current_paths, target_paths)?
        else {
            return Ok(None);
        };
        match config_fingerprint(&target_paths.gateway) {
            Ok(fingerprint) => Ok(Some(DocumentPublication {
                fingerprint,
                files: publication,
            })),
            Err(error) => {
                // 无法建立新集合指纹时只恢复收据记录的副作用，不能重算旧路径覆盖无关文件。
                match publication.restore() {
                    Ok(true) => Err(error),
                    Ok(false) => {
                        Err(error).context("document compensation conflicts with another writer")
                    }
                    Err(restore) => Err(error).context(format!(
                        "document compensation was not confirmed: {restore}"
                    )),
                }
            }
        }
    }

    /// 业务作用：按本次文件收据撤销管理发布，恢复新建文件的原缺失状态并保护后来写入。
    ///
    /// 参数说明：
    /// - `publication`：已完成替换的精确目标和原文收据。
    /// - `main`：固定bootstrap路径，用于完整依赖条件复验。
    /// - `before_version`：本次文件发布之前的活动版本。
    /// - `snapshot`：唯一发布者维护的活动快照，与文件事务共同裁决补偿资格。
    ///
    /// 返回：旧快照仍活动且候选文件完整恢复时返回新指纹；快照或文件漂移为空，恢复或同步未确认时返回错误。
    pub(crate) fn restore_publication(
        &self,
        publication: DocumentPublication,
        main: &Path,
        before_version: u64,
        snapshot: &arc_swap::ArcSwap<GatewaySnapshot>,
    ) -> Result<Option<u64>> {
        let _transaction = self.file_transaction.write();
        #[cfg(feature = "node-journal")]
        if let Some(journal) = self.node_journal.get() {
            journal.verify()?;
        }
        // 最终快照发布持有同一事务的读锁；在写锁内复验才能阻止先发布的新快照被旧请求撤回文件。
        // 先完成补偿时，等待中的reload也必须重新核对文件，不能再发布先前构建的候选。
        if snapshot.load().version != before_version
            || config_fingerprint(main).ok() != Some(publication.fingerprint)
            || !publication.files.restore()?
        {
            return Ok(None);
        }
        // 旧快照仍活动且资源已存在，准确恢复其原文后可结束Backward；不能依赖同指纹必然触发watcher。
        self.complete_local_publication(&snapshot.load())?;
        Ok(Some(config_fingerprint(main)?))
    }

    /// 业务作用：在统一文件事务内执行单文档 CAS，避免平台配置与工作区三文档发布互相覆盖。
    ///
    /// 参数说明：
    /// - `content`：是已验证主文档
    /// - `expected_fingerprint`：绑定完整基线
    /// - `current_paths`：同一活动快照的三个原文位置。
    /// - `candidate`：候选完整快照，提供真实目标和编译时的原文身份。
    ///
    /// 返回：基线匹配时返回精确文件收据与新指纹；漂移为空，内存协议失败条件补偿，持久协议失败保留未决记录。
    pub(crate) fn compare_and_publish_main(
        &self,
        content: &[u8],
        expected_fingerprint: u64,
        current_paths: &crate::config::candidate::Paths,
        candidate: &GatewaySnapshot,
    ) -> Result<Option<DocumentPublication>> {
        let _transaction = self.file_transaction.write();
        self.require_journal_ready()?;
        let targets = &candidate.document_paths;
        let target = &targets.gateway;
        anyhow::ensure!(
            current_paths.gateway == targets.gateway,
            "document publication cannot move the bootstrap path"
        );
        // 比较和替换共用所有管理发布的写锁；构建阶段通过不代表此刻仍有覆盖基线的权威。
        if config_fingerprint(target).ok() != Some(expected_fingerprint) {
            return Ok(None);
        }
        files::validate(targets.ordered())?;
        let Some(publication) = self.publish_main_file(content, current_paths, candidate)? else {
            return Ok(None);
        };
        match config_fingerprint(target) {
            Ok(fingerprint) => Ok(Some(DocumentPublication {
                fingerprint,
                files: publication,
            })),
            Err(error) => {
                // 指纹失败只允许撤销仍属于本次候选的单文件副作用，不能覆盖后来写入。
                match publication.restore() {
                    Ok(true) => Err(error),
                    Ok(false) => Err(error)
                        .context("main document compensation conflicts with another writer"),
                    Err(restore) => Err(error).context(format!(
                        "main document compensation was not confirmed: {restore}"
                    )),
                }
            }
        }
    }

    /// 业务作用：在既有写事务内选择显式存储协议，identity-only和未启用部署保持进程内收据。
    ///
    /// 参数说明：
    /// - `docs`：同次验证的三文档原文。
    /// - `baseline`：当前冻结的三文档原文。
    /// - `current_paths`：原文件目标。
    /// - `targets`：候选文件目标。
    ///
    /// 返回：相应协议的精确收据；基线冲突为空，持久错误不会退回非持久写入。
    fn publish_files(
        &self,
        docs: &ArchivedDocs,
        baseline: &ArchivedDocs,
        current_paths: &crate::config::candidate::Paths,
        targets: &crate::config::candidate::Paths,
    ) -> Result<Option<Receipt>> {
        #[cfg(feature = "node-journal")]
        if let Some(journal) = self.node_journal.get() {
            if journal.durable_local_files()? {
                let input = crate::control::journal::LocalInput {
                    current: current_paths.ordered(),
                    targets: targets.ordered(),
                    baseline: Some(
                        document_targets(current_paths, baseline).map(|(_, bytes)| bytes),
                    ),
                    desired: document_targets(targets, docs).map(|(_, bytes)| Some(bytes)),
                    candidate: None,
                };
                return journal
                    .publish_local(input)
                    .map(|receipt| receipt.map(Receipt::Durable));
            }
        }
        files::publish(
            &document_targets(current_paths, baseline),
            &document_targets(targets, docs),
        )
        .map(|receipt| receipt.map(Receipt::Memory))
    }

    /// 业务作用：单主文档持久发布同样冻结两份规则与旧路径，原始Bytes借用不产生额外全文副本。
    ///
    /// 参数说明：
    /// - `content`：候选主文档原文。
    /// - `current_paths`：活动快照冻结的原文来源。
    /// - `candidate`：完整候选的真实目标和原文身份。
    ///
    /// 返回：明确文件协议的收据；目标或候选原文变化拒绝，持久失败保留未决记录。
    fn publish_main_file(
        &self,
        content: &[u8],
        current_paths: &crate::config::candidate::Paths,
        candidate: &GatewaySnapshot,
    ) -> Result<Option<Receipt>> {
        #[cfg(feature = "node-journal")]
        if let Some(journal) = self.node_journal.get() {
            if journal.durable_local_files()? {
                let input = crate::control::journal::LocalInput {
                    current: current_paths.ordered(),
                    targets: candidate.document_paths.ordered(),
                    baseline: None,
                    desired: [None, None, Some(content)],
                    candidate: Some(candidate),
                };
                return journal
                    .publish_local(input)
                    .map(|receipt| receipt.map(Receipt::Durable));
            }
        }
        let _ = current_paths;
        files::replace(&candidate.document_paths.gateway, content)
            .map(|receipt| receipt.map(Receipt::Memory))
    }
}

/// 业务作用：将已冻结路径与原文按同一次序借用给文件提交器，不复制或重编码文档。
///
/// 参数说明：
/// - `paths`：完整快照提供的部署目标。
/// - `documents`：对应的三份原文。
///
/// 返回：依赖先于主文档的三个借用对，不持有新的原文副本。
fn document_targets<'a>(
    paths: &'a crate::config::candidate::Paths,
    documents: &'a ArchivedDocs,
) -> [(&'a Path, &'a [u8]); 3] {
    let bodies = [
        documents.interface_guard.as_bytes(),
        documents.sentinel_rules.as_bytes(),
        documents.gateway.as_bytes(),
    ];
    let paths = paths.ordered();
    [
        (paths[0], bodies[0]),
        (paths[1], bodies[1]),
        (paths[2], bodies[2]),
    ]
}
