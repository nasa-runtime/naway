//! 原审批基线只在初始受理时核对，重投可接续当前boot但不能借旧目录绕过独立材料能力。

use super::*;

impl Manager {
    /// 业务作用：取得原材料目标的当前认证会话，初次执行还须原审批基线完全一致。
    ///
    /// 参数说明：
    /// - `snapshot`：本次发行采用的完整活动快照。
    /// - `intent`：冻结的完整原节点材料意图。
    /// - `initial`：创建任务时为真，已有任务重投时为假。
    ///
    /// 返回：当前boot与随机会话；缺席、撤权、能力关闭或初始基线漂移拒绝。
    pub(in crate::admin) fn remote_material_action_session(
        &self,
        snapshot: &Arc<GatewaySnapshot>,
        intent: &Intent,
        initial: bool,
    ) -> Result<ActionSession, Status> {
        let _gate = self.publication.read();
        let plan = self.action_plan(snapshot, &intent.baseline.cluster_id)?;
        let receiver = plan.receiver.as_ref().expect("validated receiver");
        if intent.node_id == plan.node_id || !receiver.nodes.contains_key(&intent.node_id) {
            return Err(Status::failed_precondition(
                "remote material membership unavailable",
            ));
        }
        self.store
            .lock()
            .material_action_session(&plan, intent, initial)
    }
}

impl Store {
    /// 业务作用：在同一接收锁下读取原材料目标会话与基线，不拼接不同报告的字段。
    ///
    /// 参数说明：
    /// - `plan`：已验证的当前发行计划。
    /// - `intent`：原材料节点与审批基线。
    /// - `initial`：是否额外要求原boot和全部配置基线。
    ///
    /// 返回：独立能力与当前事实有效的地址；不延长心跳、不建立新会话。
    fn material_action_session(
        &mut self,
        plan: &Arc<Plan>,
        intent: &Intent,
        initial: bool,
    ) -> Result<ActionSession, Status> {
        self.reconcile(plan);
        let entry = self
            .entries
            .get(&intent.node_id)
            .ok_or_else(|| Status::failed_precondition("material session absent"))?;
        let address = ActionSession {
            boot: entry.boot.clone(),
            token: entry.session,
        };
        self.material_action_authority(plan, &intent.node_id, &address.boot, &address.token)?;
        let entry = self
            .entries
            .get(&intent.node_id)
            .expect("validated material node");
        // 已受理材料会撤下空闲基线；重投仍由节点永久槽核验原意图，不能据基线缺席重建目标。
        if initial
            && (address.boot != intent.original_boot_id
                || entry.baseline.as_deref() != Some(&intent.baseline)
                || !entry.facts.as_ref().is_some_and(|facts| {
                    facts.config_version == intent.base_version
                        && facts
                            .config_fingerprint
                            .as_deref()
                            .and_then(|value| u64::from_str_radix(value, 16).ok())
                            == Some(intent.base_fingerprint)
                }))
        {
            return Err(Status::failed_precondition(
                "material original baseline differs",
            ));
        }
        Ok(address)
    }

    /// 业务作用：仅让明确启用独立材料动作的真实Data会话继续投递，旧配置动作能力不能代替。
    ///
    /// 参数说明：
    /// - `plan`：当前接收权威计划。
    /// - `node`：实际认证节点。
    /// - `boot`：本次接收启动身份。
    /// - `session`：原随机管理会话。
    ///
    /// 返回：新鲜、就绪、无同名冲突且会话精确一致才成功，不改变任何运行事实。
    pub(in crate::admin::management) fn material_action_authority(
        &mut self,
        plan: &Arc<Plan>,
        node: &str,
        boot: &str,
        session: &[u8],
    ) -> Result<(), Status> {
        self.reconcile(plan);
        let now = Instant::now();
        let valid = self.entries.get(node).is_some_and(|entry| {
            entry.boot == boot
                && crate::security::auth::constant_time_eq(&entry.session, session)
                && entry.material_actions_enabled
                && now.saturating_duration_since(entry.at) <= FRESHNESS
                && entry
                    .conflict
                    .is_none_or(|at| now.saturating_duration_since(at) > FRESHNESS)
                && entry.facts.as_ref().is_some_and(|facts| {
                    facts.ready && matches!(facts.mode.as_str(), "data" | "sidecar" | "all-in-one")
                })
        });
        if !valid {
            // 缺少当前材料能力或真实运行证据时必须等待新报告，不能用共享目标列表替代节点权威。
            return Err(Status::failed_precondition(
                "material execution session unavailable",
            ));
        }
        Ok(())
    }
}
