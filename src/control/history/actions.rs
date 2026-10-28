//! 正常构建与真实快照发布接入同一个节点动作 owner。

use super::*;

impl ConfigHistory {
    /// 业务作用：在共享文件事务中读取待发布动作，内容相同不能跳过尚未确认的持久方向。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：需要继续正常发布时为真；没有动作 owner 或待发布方向时为假；head 不明时返回错误。
    pub(crate) fn action_publication_pending(&self) -> Result<bool> {
        #[cfg(feature = "node-actions")]
        if let Some(journal) = self.node_journal.get() {
            return self.with_stable_local_files(|| journal.action_publication_pending());
        }
        Ok(false)
    }

    /// 业务作用：让远程动作与全部本地配置写入共用独占文件事务，动作阶段由其自身持久门判定。
    ///
    /// 参数说明：
    /// - `work`：已持真实许可的同步动作，不得重入文件事务或执行异步等待。
    ///
    /// 返回：原动作结果；未安装永久 owner 时拒绝，不借普通空闲门清理未知动作。
    #[cfg(feature = "node-actions")]
    pub(crate) fn with_node_action<T>(
        &self,
        work: impl FnOnce(&crate::control::journal::Journal) -> Result<T>,
    ) -> Result<T> {
        let _transaction = self.file_transaction.write();
        let owner = self
            .node_journal
            .get()
            .context("node actions require an installed journal owner")?;
        work(owner)
    }
    /// 业务作用：将外部策略发布纳入文件事务边界，未决文件方向只能由正常文件 reload 完成。
    ///
    /// 参数说明：
    /// - `snapshot`：完整资源准备后的外部候选。
    ///
    /// 返回：无未决文件决定且原动作覆盖权已处理时成功；无 journal 时保持原发布条件。
    #[cfg(feature = "xds-client")]
    pub(crate) fn prepare_external_publication(&self, snapshot: &GatewaySnapshot) -> Result<()> {
        #[cfg(feature = "node-journal")]
        if let Some(journal) = self.node_journal.get() {
            return journal.prepare_external_publication(snapshot);
        }
        let _ = snapshot;
        Ok(())
    }

    /// 业务作用：用正常构建器完成待恢复方向的依赖复验，没有节点动作时保持一次构建。
    ///
    /// 参数说明：
    /// - `build`：不发布快照的同版本完整构建器。
    ///
    /// 返回：完整候选，动作身份或依赖变化拒绝；调用方仍须持文件事务并执行正常资源准备。
    pub(crate) fn build_action_candidate(
        &self,
        mut build: impl FnMut() -> Result<GatewaySnapshot>,
    ) -> Result<GatewaySnapshot> {
        #[cfg(feature = "node-actions")]
        if let Some(journal) = self.node_journal.get() {
            return journal.build_action_candidate(build);
        }
        build()
    }

    /// 业务作用：把管理监控的实际进程身份交给动作 owner，避免节点报告与效果收据使用两份 boot。
    ///
    /// 参数说明：
    /// - `boot`：同一 AdminState 的固定监控进程标识。
    ///
    /// 返回：首次或同一绑定成功；无 journal 时无副作用，冲突拒绝启动。
    #[cfg(feature = "node-actions")]
    pub(crate) fn bind_action_boot(&self, boot: &str) -> Result<()> {
        if let Some(journal) = self.node_journal.get() {
            journal.bind_action_boot(boot)?;
        }
        Ok(())
    }

    /// 业务作用：实际 ArcSwap 或初始快照装配之后提交效果事实，不能在文件落位时提前确认成功。
    ///
    /// 参数说明：
    /// - `snapshot`：已经实际发布且完成资源准备的完整快照。
    ///
    /// 返回：没有待确认效果或持久提交成功；失败不撤回已可见快照，调用方必须保留未知并停止新动作。
    pub fn confirm_action_publication(&self, snapshot: &GatewaySnapshot) -> Result<()> {
        #[cfg(feature = "node-actions")]
        if let Some(journal) = self.node_journal.get() {
            return journal.confirm_action_publication(snapshot);
        }
        let _ = snapshot;
        Ok(())
    }
}
