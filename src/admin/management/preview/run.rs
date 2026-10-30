//! 同一原目标合同分别走本机原生构建或受信主动通道，不替换目标或转发到任意管理地址。

use super::{
    command::{Command, Intent},
    node,
    session::{Session, Work},
    Reason,
};
use crate::{
    admin::{diff::model::Summary, AdminState},
    config::GatewaySnapshot,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

struct LocalSession(Arc<Session>);

pub(in crate::admin) struct Completed {
    pub summary: Summary,
    pub session: Option<[u8; 32]>,
}

/// 业务作用：聚合所有原目标后复验已完成目标的当前基线，等待其它节点不能保留已过时的成功。
///
/// 参数说明：
/// - `state`：实际管理入口及本机状态。
/// - `snapshot`：请求冻结的发行快照。
/// - `intent`：原提案绑定的唯一原目标。
/// - `session`：返回结果的原远端会话；本机原生路径为空。
///
/// 返回：当前观察仍与原基线一致才成功；远端未知或本机换代均撤销已有差异。
pub(in crate::admin) async fn recheck(
    state: &AdminState,
    snapshot: &Arc<GatewaySnapshot>,
    intent: &Intent,
    session: Option<[u8; 32]>,
) -> Result<(), Reason> {
    let plan = state
        .management
        .action_plan(snapshot, &intent.baseline.cluster_id)
        .map_err(|_| Reason::Denied)?;
    if plan.node_id != intent.node {
        let current = state.management.remote_preview_session(snapshot, intent)?;
        if session != Some(current) {
            return Err(Reason::BaselineChanged);
        }
        return Ok(());
    }
    if !state.mode.runs_data()
        || !plan.previews_enabled
        || !state.ready.load(std::sync::atomic::Ordering::Acquire)
        || state.monitor.boot_id() != intent.boot
        || snapshot.version != intent.version
        || snapshot.config_fingerprint != Some(intent.fingerprint)
    {
        return Err(Reason::BaselineChanged);
    }
    let observation = state
        .config_history
        .node_observation(snapshot.clone())
        .await;
    state
        .management
        .action_plan(snapshot, &intent.baseline.cluster_id)
        .map_err(|_| Reason::Denied)?;
    if observation.baseline.as_ref() != Some(&intent.baseline) {
        return Err(Reason::BaselineChanged);
    }
    Ok(())
}

impl Drop for LocalSession {
    /// 业务作用：本机预览请求退出时撤销独立会话，取消等待不留下可继续交付的旧构建授权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：会话立即失效，仍在运行的候选 owner 继续持有实际许可直到清理结束。
    fn drop(&mut self) {
        self.0.revoke();
    }
}

/// 业务作用：让每个冻结原目标独立产生只读比较，缺席或不支持仍保留该目标的明确结果。
///
/// 参数说明：
/// - `state`：本次请求所在管理实例的真实状态。
/// - `snapshot`：原提案读取时冻结的发行权限。
/// - `intent`：唯一原目标及其完整基线，不能改绑当前成员。
/// - `body`：全部原目标共享的一份原始候选。
/// - `issued_at_ms`：本次请求统一签发时刻。
/// - `expires_at_ms`：本次请求统一有限截止。
///
/// 返回：该原目标实际构建后的有限摘要或明确失败类别；不审批、不发布、不登记持久动作。
pub(in crate::admin) async fn inspect(
    state: Arc<AdminState>,
    snapshot: Arc<GatewaySnapshot>,
    intent: Intent,
    body: Bytes,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<Completed, Reason> {
    let plan = state
        .management
        .action_plan(&snapshot, &intent.baseline.cluster_id)
        .map_err(|_| Reason::Unavailable)?;
    if plan.node_id == intent.node {
        if !state.mode.runs_data() {
            return Err(Reason::Unsupported);
        }
        let session = LocalSession(Session::local(plan.clone())?);
        let command = Arc::new(Command {
            intent,
            issuer: plan.node_id.clone(),
            session: session.0.token,
            issued_at_ms,
            expires_at_ms,
        });
        if body.len() != command.intent.candidate_bytes as usize
            || Sha256::digest(&body)[..] != command.intent.candidate_sha256
        {
            return Err(Reason::CandidateInvalid);
        }
        let signature = plan
            .receiver
            .as_ref()
            .and_then(|receiver| receiver.issuer.as_ref())
            .ok_or(Reason::Unavailable)?
            .sign_preview(&plan.node_id, &command)
            .map_err(|_| Reason::Denied)?;
        let verified = session.0.verify(command, &signature)?;
        let work = Work::accept(&state, verified)?;
        let summary =
            tokio::time::timeout(Duration::from_secs(20), node::inspect(state, work, body))
                .await
                .map_err(|_| Reason::Expired)??;
        return Ok(Completed {
            summary,
            session: None,
        });
    }
    let session = state
        .management
        .remote_preview_session(&snapshot, &intent)?;
    let command = Command {
        intent,
        issuer: plan.node_id.clone(),
        session,
        issued_at_ms,
        expires_at_ms,
    };
    let mut ticket = state.management.offer_preview(snapshot, command, body)?;
    let summary = tokio::time::timeout(Duration::from_secs(20), ticket.receive())
        .await
        .map_err(|_| Reason::Expired)??;
    Ok(Completed {
        summary,
        session: Some(session),
    })
}
