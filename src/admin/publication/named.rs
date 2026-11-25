//! 单模块事实源提交、精确补偿和活动配置观察。

use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};

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
        return publish_remote(state, &active, &module.name, body).await;
    }
    publish_files(state, active, vec![(index, body)]).await
}

/// 业务作用：提交已验证的本机文件集合，等待唯一重载器裁决，明确拒绝时凭收据恢复原文。
/// 参数说明：
/// - `state`：本机文件事务和快照发布权。
/// - `active`：已验证的活动配置和权限代。
/// - `writes`：已授权的模块目录索引及完整校验过的 YAML。
/// 返回：文件写入只确认本节点，重载拒绝时保留上一代，应用结果未观察到时明确报告等待。
async fn publish_files(
    state: &Arc<AdminState>,
    active: Arc<GatewaySnapshot>,
    writes: Vec<(usize, Bytes)>,
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
        let changes = writes
            .iter()
            .map(|(index, body)| (&active.named_documents[*index], body.as_ref()))
            .collect::<Vec<_>>();
        history.compare_and_publish_named(&active, &changes, &current)
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

/// 业务作用：以部署时绑定的 Nacos 权威和实际 Data ID 提交 YAML，并确认本机是否经订阅采用该代。
/// 参数说明：
/// - `state`：活动快照、本机配置权威及发布许可。
/// - `active`：已校验的配置与认证代。
/// - `name`：已授权的模块名。
/// - `body`：完整校验过的原文。
/// 返回：Nacos 写入确认及本机观察。远端确认不足时保留结果未知，不能声称集群已生效。
async fn publish_remote(
    state: &Arc<AdminState>,
    active: &GatewaySnapshot,
    name: &str,
    body: Bytes,
) -> Response<BoxBody> {
    let Some(source) = state.named_nacos.get() else {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "configuration authority unavailable\n",
        );
    };
    let Ok(content) = std::str::from_utf8(&body) else {
        return plain(StatusCode::BAD_REQUEST, "YAML document must be UTF-8\n");
    };
    let edit = match source.prepare_edit(active, name, content).await {
        Ok(Some(edit)) => edit,
        Ok(None) => return stale(),
        Err(error) => {
            tracing::warn!(%error, "Nacos module write preparation failed");
            return plain(
                StatusCode::CONFLICT,
                "cannot prepare Nacos module publication at this revision\n",
            );
        }
    };
    commit_remote(state, active, edit.commit(content)).await
}

/// 业务作用：把已授权的历史具名配置交给当前事实源，以完整内容代观察本机恢复。
/// 参数说明：
/// - `state`：当前配置来源、发布许可和观察入口。
/// - `active`：授权和恢复候选使用的活动配置代。
/// - `target`：已整代验证的历史模块原文。
/// 返回：已应用、已提交、待观察或明确拒绝。集群数据源确认不能当作每节点生效证据。
pub(in crate::admin) async fn restore_named(
    state: &Arc<AdminState>,
    active: Arc<GatewaySnapshot>,
    mut target: BTreeMap<String, String>,
) -> Response<BoxBody> {
    use sha2::{Digest, Sha256};

    if target.iter().all(|(name, body)| {
        active.named_documents.iter().any(|module| {
            &module.name == name && module.digest == Sha256::digest(body.as_bytes()).as_slice()
        })
    }) {
        let Some(fingerprint) = active.config_fingerprint else {
            return stale();
        };
        if !current_config_baseline_matches(state, active.version, fingerprint).await {
            return stale();
        }
        let source = if active.config_bundle_digest.is_some() {
            "nacos"
        } else {
            "file"
        };
        return applied(active.version, fingerprint, source);
    }
    if active.config_bundle_digest.is_some() {
        let Some(source) = state.named_nacos.get() else {
            return plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "configuration authority unavailable\n",
            );
        };
        let edit = match source.prepare_rollback(&active, target).await {
            Ok(Some(edit)) => edit,
            Ok(None) => return stale(),
            Err(error) => {
                tracing::warn!(%error, "Nacos named rollback preparation failed");
                return plain(
                    StatusCode::CONFLICT,
                    "named Nacos rollback requires a stable committed revision\n",
                );
            }
        };
        return commit_remote(state, &active, edit.commit()).await;
    }
    let writes = active
        .named_documents
        .iter()
        .enumerate()
        .filter_map(|(index, module)| {
            target
                .remove(&module.name)
                .map(|body| (index, Bytes::from(body)))
        })
        .collect();
    publish_files(state, active, writes).await
}

/// 业务作用：紧邻远端写入复验活动授权，从提交回执中分别报告远端写入与本机观察。
/// 参数说明：
/// - `state`：当前活动快照、配置发布许可。
/// - `active`：产生写入意图的冻结权限代。
/// - `commit`：由实际配置中心提供的条件写入任务，获得权威前不执行。
/// 返回：提交确认、条件冲突或结果未知，成功时附本机已观察的目标代。
async fn commit_remote(
    state: &Arc<AdminState>,
    active: &GatewaySnapshot,
    commit: impl Future<Output = anyhow::Result<Option<String>>>,
) -> Response<BoxBody> {
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
    // 远端读取期间授权配置可能换代，必须在发出写副作用前持有原快照的决策权。
    let Some(fingerprint) = active.config_fingerprint else {
        return stale();
    };
    if !current_config_baseline_matches(state, active.version, fingerprint).await {
        return stale();
    }
    let committed = commit.await;
    drop(gate);
    let generation = match committed {
        Ok(Some(generation)) => generation,
        Ok(None) => return stale(),
        Err(error) => {
            tracing::warn!(%error, "Nacos module publication outcome unknown");
            return unknown();
        }
    };
    let observed = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let live = state.snap.load_full();
            if live.config_bundle_digest.as_deref() == Some(&generation) {
                break live;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .ok();
    let etag = observed
        .as_ref()
        .and_then(|live| live.config_fingerprint)
        .map(config_etag);
    json(
        StatusCode::ACCEPTED,
        value!({
            "ok": true, "status": "committed", "source": "nacos", "scope": "configuration-center",
            "generation": generation, "local_applied": observed.is_some(),
            "version": observed.as_ref().map(|live| live.version), "etag": etag,
        }),
    )
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
