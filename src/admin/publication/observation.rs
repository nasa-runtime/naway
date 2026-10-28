//! 以匹配事件与当前快照确认发布，缺少证据时维持待定。

use crate::admin::AdminState;
use std::sync::Arc;
use std::time::Duration;

/// 发布结果:决定 HTTP 状态、审计文案与是否需要回滚文件。
pub(super) enum PublishOutcome {
    /// 已换版并观察到目标指纹的成功事件。
    Applied {
        /// 上线后的配置版本。
        version: u64,
        /// 上线配置集指纹(新 ETag 来源)。
        fingerprint: u64,
    },
    /// reload worker 明确拒绝；文件是否可恢复仍需当前快照和归属门裁决。
    Rejected(String),
    /// 等待窗口内既没成功也没拒绝(worker 卡住/极慢)。诚实回 202,不谎称成功。
    Pending,
}

/// 业务作用：提前拒绝已失去候选文件或旧快照的补偿；实际恢复仍须在文件写锁内复验。
///
/// 参数说明：
/// - `state`：管理状态，提供当前快照和配置事实源。
/// - `before_version`：发布前配置版本。
/// - `expected`：候选实际物化后的完整指纹。
///
/// 返回：两份事实都匹配为 true；缺失、并发变化或读取失败为 false。
pub(super) fn publication_still_owned(
    state: &AdminState,
    before_version: u64,
    expected: Option<u64>,
) -> bool {
    expected.is_some()
        && state.snap.load().version == before_version
        && crate::config::config_fingerprint(&state.cfg_path).ok() == expected
}

/// 业务作用：只接受本次发布之后、同一候选指纹的 reload 结果，历史同代拒绝不代表新候选失败。
///
/// 参数说明：
/// - `state`：管理状态，提供当前快照与发布历史。
/// - `before_version`：发布前配置版本。
/// - `after_event`：开始观察的历史事件游标。
/// - `expected`：候选物化后的完整指纹。
///
/// 返回：观察到匹配提交或拒绝时返回结论，窗口结束仍缺证据则 pending，不推测成功。
pub(super) async fn await_publish_outcome(
    state: &Arc<AdminState>,
    before_version: u64,
    after_event: u64,
    expected: Option<u64>,
) -> PublishOutcome {
    // 观察窗口:reload 是本地文件构建 + ArcSwap 换版,秒级足够;超时只回 pending,不谎称成功。
    const OBSERVE_ATTEMPTS: usize = 120;
    const OBSERVE_INTERVAL: Duration = Duration::from_millis(50);
    for _ in 0..OBSERVE_ATTEMPTS {
        tokio::time::sleep(OBSERVE_INTERVAL).await;
        let snapshot = state.snap.load();
        let version = snapshot.version;
        let live_fingerprint = snapshot.config_fingerprint;
        drop(snapshot);
        let history = state.config_history.snapshot();
        if let Some(outcome) = publication_outcome(
            before_version,
            after_event,
            expected,
            version,
            live_fingerprint,
            &history.events,
        ) {
            return outcome;
        }
    }
    PublishOutcome::Pending
}

/// 业务作用：用事件单调序号、候选指纹和实时快照共同裁决发布，不把旧拒绝或其它候选提交归给本次请求。
///
/// 参数说明：
/// - `before`：发布前配置版本。
/// - `after`：发布前历史事件游标。
/// - `expected`：候选物化后的完整指纹。
/// - `version`：本次观察的活动配置版本。
/// - `live`：本次观察的活动配置指纹。
/// - `events`：游标之后的有界发布历史。
///
/// 返回：有充分匹配证据的结论，否则 None，调用方继续观察而不执行回滚。
fn publication_outcome(
    before: u64,
    after: u64,
    expected: Option<u64>,
    version: u64,
    live: Option<u64>,
    events: &[crate::control::history::ConfigHistoryEvent],
) -> Option<PublishOutcome> {
    let fingerprint = expected?;
    let relevant = |event: &&crate::control::history::ConfigHistoryEvent| {
        event.id > after && event.fingerprint == expected
    };
    if version > before
        && live == expected
        && events
            .iter()
            .filter(relevant)
            .any(|event| event.new_version == Some(version) && event.status.starts_with("applied"))
    {
        return Some(PublishOutcome::Applied {
            version,
            fingerprint,
        });
    }
    if version == before {
        if let Some(rejected) = events
            .iter()
            .filter(relevant)
            .rev()
            .find(|event| event.old_version == before && event.status == "rejected")
        {
            return Some(PublishOutcome::Rejected(
                rejected
                    .error
                    .clone()
                    .unwrap_or_else(|| "config rejected".to_owned()),
            ));
        }
    }
    None
}
