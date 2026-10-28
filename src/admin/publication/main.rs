//! 单主文档的原文候选与文件发布。

use super::observation::{await_publish_outcome, publication_still_owned, PublishOutcome};
use crate::admin::{candidate, config_etag, json, plain, AdminState, BoxBody};
use bytes::Bytes;
use hyper::{Response, StatusCode};
use std::sync::Arc;

/// 业务作用：把已授权单文档候选构建、落盘并交给唯一 reload owner，按本次身份观察结论。
///
/// 参数说明：
/// - `state`：提供当前配置与历史
/// - `candidate_body`：是有界候选原文
/// - `baseline_fingerprint`：是 If-Match 验证的基线。
///
/// 返回：确认生效、仍待观察或本候选拒绝；只有仍占有候选文件和旧快照时才补偿。
pub(in crate::admin) async fn publish_validated_config(
    state: &Arc<AdminState>,
    candidate_body: Bytes,
    baseline_fingerprint: u64,
) -> Response<BoxBody> {
    let candidate = match candidate::build_main(state, candidate_body.clone()).await {
        Ok(candidate) => candidate,
        Err(error) => return error.response(),
    };
    // 候选构建之后基线可能已改变；统一文件写事务在替换前重新比较完整指纹。
    let current = state.snap.load_full();
    let observed_before = current.version;
    let next_version = candidate.version;
    let event_before = state
        .config_history
        .snapshot()
        .events
        .last()
        .map_or(0, |event| event.id);
    let history = state.config_history.clone();
    let published = tokio::task::spawn_blocking(move || {
        history.compare_and_publish_main(
            &candidate_body,
            baseline_fingerprint,
            &current.document_paths,
            &candidate,
        )
    })
    .await;
    let publication = match published {
        Ok(Ok(Some(result))) => result,
        Ok(Ok(None)) => {
            return plain(
                StatusCode::PRECONDITION_FAILED,
                "configuration baseline changed\n",
            )
        }
        _ => {
            return plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cannot publish config atomically\n",
            )
        }
    };
    let expected_fingerprint = Some(publication.fingerprint);
    state.config_history.record_control_event(
        "admin-publish",
        &state.cfg_path,
        observed_before,
        next_version,
        "publish_scheduled",
    );
    // 只唤醒唯一 reload worker;admin 不自行换版,避免与 file watcher 双重 reload。
    // SAFETY:kill 只向本进程发 SIGHUP,不解引用指针。
    let rc = unsafe {
        libc::kill(std::process::id() as i32, libc::SIGHUP)
    };
    if rc != 0 {
        // 文件观察者可能已接手候选；只有仍处于旧快照且文件归属未变时才撤销本次发布。
        if publication_still_owned(state, observed_before, expected_fingerprint) {
            let history = state.config_history.clone();
            let path = state.cfg_path.clone();
            let snapshot = state.snap.clone();
            let restored = tokio::task::spawn_blocking(move || {
                history.restore_publication(publication, &path, observed_before, &snapshot)
            })
            .await;
            if !matches!(restored, Ok(Ok(Some(_)))) {
                return plain(
                    StatusCode::CONFLICT,
                    "reload signal failed; publication compensation unconfirmed\n",
                );
            }
        }
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "failed to signal reload worker"
            }),
        );
    }

    // 成功事件与活动快照必须共同证明本候选生效，发出信号并不代表发布完成。
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
            // 明确拒绝只取消本次候选；并发发布改变文件或快照后，不再拥有恢复旧基线的权威。
            if !publication_still_owned(state, observed_before, expected_fingerprint) {
                return plain(
                    StatusCode::CONFLICT,
                    "publication changed; baseline not restored\n",
                );
            }
            // 还原发布前文件:线上快照没换版,文件也不能停在被拒内容上。
            {
                let restore_path = state.cfg_path.clone();
                let history = state.config_history.clone();
                let snapshot = state.snap.clone();
                let restored = tokio::task::spawn_blocking(move || {
                    history.restore_publication(
                        publication,
                        &restore_path,
                        observed_before,
                        &snapshot,
                    )
                })
                .await;
                match restored {
                    Ok(Ok(Some(_))) => {}
                    Ok(Ok(None)) => {
                        return plain(
                            StatusCode::CONFLICT,
                            "publication changed; baseline not restored\n",
                        )
                    }
                    Ok(Err(error)) => {
                        tracing::error!(%error, "restore config after rejected publish failed");
                        return plain(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "publication compensation unconfirmed\n",
                        );
                    }
                    Err(error) => {
                        tracing::error!(%error, "restore worker after rejected publish failed");
                        return plain(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "publication compensation unconfirmed\n",
                        );
                    }
                }
            }
            json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "status": "rejected",
                    "error": error,
                    "note": "previous config restored; live snapshot unchanged",
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
