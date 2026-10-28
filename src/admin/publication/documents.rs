//! 完整文档集沿用统一事实源、文件事务与结果观察。

use super::observation::{await_publish_outcome, publication_still_owned, PublishOutcome};
use crate::admin::{
    audit, build_cluster_candidate_snapshot, config_etag, json, plain,
    publish_scoped_cluster_documents, AdminState, BoxBody,
};
use hyper::{Response, StatusCode};
use std::sync::Arc;

/// 业务作用：将高级管理接口生成的完整三文档候选送入与主配置发布相同的集群或本地事实源，统一
/// 执行候选构建、换版观察和失败补偿。
///
/// 参数说明：
/// - `state`：持有配置事务与审计依赖的管理状态。
/// - `target`：完整候选文档集。
/// - `baseline`：用于 CAS 与回退的完整基线文档集。
/// - `initiator`：已认证提交主体。
///
/// 返回：集群源返回 rollout 状态；本地源仅在确认新快照时返回 applied，明确拒绝且仍持有旧快照和候选文件时恢复基线。
pub(in crate::admin) async fn publish_document_set(
    state: &Arc<AdminState>,
    target: crate::control::history::ArchivedDocs,
    baseline: crate::control::history::ArchivedDocs,
    initiator: &str,
) -> Response<BoxBody> {
    publish_scoped_document_set(state, target, baseline, initiator, None).await
}

/// 业务作用：让工作区候选沿用完整本地或集群发布链，归属信息不会在切换事实源时丢失。
///
/// 参数说明：
/// - `state`：持有配置事务与审计依赖的管理状态。
/// - `target`：完整候选文档集。
/// - `baseline`：用于 CAS 与回退的完整基线文档集。
/// - `initiator`：已认证提交主体。
/// - `workspace`：冻结的工作区审批权威。
///
/// 返回：观察结果或有界集群发布登记；CAS 与归属复验失败时拒绝。
pub(in crate::admin) async fn publish_scoped_document_set(
    state: &Arc<AdminState>,
    target: crate::control::history::ArchivedDocs,
    baseline: crate::control::history::ArchivedDocs,
    initiator: &str,
    workspace: Option<audit::WorkspaceAudit>,
) -> Response<BoxBody> {
    let active = state.snap.load_full();
    let current_paths = active.document_paths.clone();
    let expected_fingerprint = match active.config_fingerprint {
        Some(fingerprint) => fingerprint,
        None => {
            return plain(
                StatusCode::CONFLICT,
                "configuration fingerprint unavailable\n",
            )
        }
    };
    if state.snap.load().config_source.nacos.enabled {
        return publish_scoped_cluster_documents(state, target, baseline, initiator, workspace)
            .await;
    }
    let target_paths = match build_cluster_candidate_snapshot(state, &target).await {
        Ok(candidate) => candidate.document_paths,
        Err(error) => return error.response(),
    };
    let observed_before = state.snap.load().version;
    let event_before = state
        .config_history
        .snapshot()
        .events
        .last()
        .map_or(0, |event| event.id);
    let Some(next_version) = observed_before.checked_add(1) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "config version space exhausted"
            }),
        );
    };
    let history = state.config_history.clone();
    let published = tokio::task::spawn_blocking(move || {
        history.compare_and_publish_documents(
            &target,
            &baseline,
            expected_fingerprint,
            &current_paths,
            &target_paths,
        )
    })
    .await;
    let publication = match published {
        Ok(Ok(Some(publication))) => publication,
        Ok(Ok(None)) => {
            return plain(
                StatusCode::PRECONDITION_FAILED,
                "configuration changed before publication\n",
            )
        }
        Ok(Err(error)) => {
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            )
        }
        Err(error) => {
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "error": format!("publish worker failed: {error}")
                }),
            )
        }
    };
    let expected_fingerprint = Some(publication.fingerprint);
    state.config_history.record_control_event(
        "admin-document-publish",
        &state.cfg_path,
        observed_before,
        next_version,
        "publish_scheduled",
    );
    // 三文档已经在事务锁内完成替换；只唤醒唯一 reload worker，由它负责最终 ArcSwap 发布。
    let signal = unsafe {
        libc::kill(std::process::id() as i32, libc::SIGHUP)
    };
    if signal != 0 {
        let history = state.config_history.clone();
        let cfg_path = state.cfg_path.clone();
        let snapshot = state.snap.clone();
        // 文件观察者可能已经发布候选；必须在补偿写锁内同时核对旧快照与文件归属。
        let restored = tokio::task::spawn_blocking(move || {
            history.restore_publication(publication, &cfg_path, observed_before, &snapshot)
        })
        .await;
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "failed to signal reload worker",
                "baseline_restored": matches!(restored, Ok(Ok(Some(_))))
            }),
        );
    }
    match await_publish_outcome(state, observed_before, event_before, expected_fingerprint).await {
        PublishOutcome::Applied {
            version,
            fingerprint,
        } => {
            let etag = config_etag(fingerprint);
            let mut response = json(
                StatusCode::OK,
                serde_json::json!({
                    "ok": true,
                    "status": "applied",
                    "version": version,
                    "fingerprint": fingerprint,
                    "etag": etag,
                }),
            );
            if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
                response.headers_mut().insert(hyper::header::ETAG, value);
            }
            response
        }
        PublishOutcome::Rejected(error) => {
            // 新代或另一候选已占有事实源时禁止用旧审批的 baseline 覆盖它。
            if !publication_still_owned(state, observed_before, expected_fingerprint) {
                return plain(
                    StatusCode::CONFLICT,
                    "publication changed; baseline not restored\n",
                );
            }
            let history = state.config_history.clone();
            let cfg_path = state.cfg_path.clone();
            let snapshot = state.snap.clone();
            let restored = tokio::task::spawn_blocking(move || {
                history.restore_publication(publication, &cfg_path, observed_before, &snapshot)
            })
            .await;
            if !matches!(restored, Ok(Ok(Some(_)))) {
                return json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({
                        "ok": false,
                        "status": "rejected_restore_failed",
                        "error": error,
                    }),
                );
            }
            json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "status": "rejected",
                    "error": error,
                    "note": "complete baseline restored; live snapshot unchanged",
                }),
            )
        }
        PublishOutcome::Pending => json(
            StatusCode::ACCEPTED,
            serde_json::json!({
                "ok": true,
                "status": "pending",
                "note": "reload scheduled but not yet observed; poll /admin/config/history",
            }),
        ),
    }
}
