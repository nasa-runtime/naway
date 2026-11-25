//! 单模块事实源提交、精确补偿和活动配置观察。

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use hyper::{header, Response, StatusCode};
use serde_json::json as value;

use super::observation::{await_publish_outcome, PublishOutcome};
use crate::admin::{
    config_etag, current_config_baseline_matches, json, plain, AdminState, BoxBody,
};
use crate::config::GatewaySnapshot;

/// 业务作用：按已启用的配置权威提交一份已校验的具名模块，并返回确切的发布阶段。
/// 参数说明：
/// - `state`：持久事实源与本机唯一配置发布者。
/// - `active`：模块编辑使用的完整活动基线。
/// - `index`：活动目录中已授权的模块。
/// - `body`：完整校验过的原始 YAML。
/// 返回：确认本机生效、仅提交或拒绝的结果。失去基线不能继续写入。
pub(in crate::admin) async fn publish_named(
    state: &Arc<AdminState>,
    active: Arc<GatewaySnapshot>,
    index: usize,
    body: Bytes,
) -> Response<BoxBody> {
    let module = &active.named_documents[index];
    let Some(fingerprint) = active.config_fingerprint else {
        return plain(
            StatusCode::CONFLICT,
            "configuration fingerprint unavailable\n",
        );
    };
    if !current_config_baseline_matches(state, active.version, fingerprint).await {
        return stale();
    }
    if module
        .content
        .as_deref()
        .is_some_and(|original| original.as_bytes() == body)
    {
        let scope = if active.config_bundle_digest.is_some() {
            "nacos"
        } else {
            "file"
        };
        return applied(active.version, fingerprint, scope);
    }
    if active.config_bundle_digest.is_some() {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "named Nacos write authority unavailable\n",
        );
    }
    publish_file(state, active, index, body).await
}

/// 业务作用：提交选定的本机文件，等待唯一重载器裁决，明确拒绝时凭收据恢复原文。
/// 参数说明：
/// - `state`：本机文件事务和快照发布权。
/// - `active`：已验证的活动配置和权限代。
/// - `index`：具有写权限的模块目录索引。
/// - `body`：完整校验过的 YAML。
/// 返回：文件写入只确认本节点，重载拒绝时保留上一代，应用结果未观察到时明确报告等待。
async fn publish_file(
    state: &Arc<AdminState>,
    active: Arc<GatewaySnapshot>,
    index: usize,
    body: Bytes,
) -> Response<BoxBody> {
    let before = active.version;
    let path = active.source_config_path.clone();
    let event = state
        .config_history
        .snapshot()
        .events
        .last()
        .map_or(0, |event| event.id);
    let gate =
        match tokio::time::timeout(Duration::from_secs(3), state.apply_coordinator.lock_owned())
            .await
        {
            Ok(gate) => gate,
            Err(_) => {
                return plain(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "configuration publication busy\n",
                )
            }
        };
    let history = state.config_history.clone();
    let current = state.snap.clone();
    let publication = tokio::task::spawn_blocking(move || {
        let _gate = gate;
        history.compare_and_publish_named(&active, &active.named_documents[index], &body, &current)
    })
    .await;
    let publication = match publication {
        Ok(Ok(Some(publication))) => publication,
        Ok(Ok(None)) => return stale(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "named file publication outcome unconfirmed");
            return unknown();
        }
        Err(_) => return unknown(),
    };
    let expected = Some(publication.fingerprint);
    // 原文已原子安装，由唯一重载器判断监听和其它新资源可否进入活动代。
    let signal = unsafe { libc::kill(std::process::id() as i32, libc::SIGHUP) };
    let outcome = if signal == 0 {
        await_publish_outcome(state, before, event, expected).await
    } else {
        PublishOutcome::Rejected("configuration reload could not be scheduled".into())
    };
    match outcome {
        PublishOutcome::Applied {
            version,
            fingerprint,
        } => applied(version, fingerprint, "file"),
        PublishOutcome::Pending => json(
            StatusCode::ACCEPTED,
            value!({
                "ok": true, "status": "pending", "source": "file", "scope": "node", "local_applied": false,
            }),
        ),
        PublishOutcome::Rejected(error) => {
            let history = state.config_history.clone();
            let current = state.snap.clone();
            // 补偿只撤回本次已安装原文。活动版本或文件已经变化时保留后来者的决定。
            let restored = tokio::task::spawn_blocking(move || {
                history.restore_publication(publication, &path, before, &current)
            })
            .await;
            match restored {
                Ok(Ok(Some(_))) => json(
                    StatusCode::BAD_REQUEST,
                    value!({
                        "ok": false, "status": "rejected", "error": error, "baseline_restored": true,
                    }),
                ),
                Ok(Ok(None)) => plain(
                    StatusCode::CONFLICT,
                    "configuration changed before compensation\n",
                ),
                _ => unknown(),
            }
        }
    }
}

/// 业务作用：返回已观察到的活动代，同时更新用于下次编辑的 ETag。
/// 参数说明：
/// - `version`：本节点活动版本。
/// - `fingerprint`：本节点实际观察到的完整指纹。
/// - `source`：已确认的事实源名称。
/// 返回：由活动版本支持的本机生效响应。
fn applied(version: u64, fingerprint: u64, source: &str) -> Response<BoxBody> {
    let etag = config_etag(fingerprint);
    let mut response = json(
        StatusCode::OK,
        value!({
            "ok": true, "status": "applied", "source": source, "scope": "node",
            "version": version, "etag": etag, "local_applied": true,
        }),
    );
    if let Ok(value) = header::HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

/// 业务作用：告知调用方重新读取模块及完整配置条件。
/// 参数说明: 无。
/// 返回：基线已经失效的 HTTP 412 响应。
fn stale() -> Response<BoxBody> {
    plain(
        StatusCode::PRECONDITION_FAILED,
        "configuration baseline changed\n",
    )
}

/// 业务作用：在副作用之后失去明确确认时，禁止客户端把错误解释为没有写入。
/// 参数说明: 无。
/// 返回：带准确歧义标记的失败响应。
fn unknown() -> Response<BoxBody> {
    json(
        StatusCode::SERVICE_UNAVAILABLE,
        value!({
            "ok": false, "status": "outcome_unknown", "operation_may_have_completed": true,
        }),
    )
}
