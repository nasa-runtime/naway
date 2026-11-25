//! 管理端具名历史回滚的权限与活动代门禁。

use std::sync::Arc;

use hyper::{header, Response, StatusCode};
use sha2::{Digest, Sha256};

use super::module_resource;
use crate::admin::{
    approval_required, candidate, config_etag, plain, publication, AdminAction, AdminIdentity,
    AdminRequestParts, AdminResource, AdminState, BoxBody,
};
use crate::config::GatewaySnapshot;

/// 业务作用：在与普通管理写入相同的当前授权、审计和候选预算下恢复历史模块集合。
/// 参数说明：
/// - `request`：附带当前完整配置 If-Match 的受信管理请求。
/// - `state`：候选预算、原文归档和写入权威。
/// - `identity`：通过管理端认证和 Config/Rollback 门的主体。
/// - `active`：请求发起时的活动配置及模块权限基线。
/// - `version`：需要恢复的历史活动版本。
/// 返回：事实源确认或明确拒绝；未知状态交由配置历史观察，连接取消不会撤销已经调度的回滚。
pub(in crate::admin) async fn restore(
    request: &AdminRequestParts,
    state: &Arc<AdminState>,
    identity: &AdminIdentity,
    active: Arc<GatewaySnapshot>,
    version: u64,
) -> Response<BoxBody> {
    let Some(fingerprint) = active.config_fingerprint else {
        return plain(
            StatusCode::CONFLICT,
            "configuration fingerprint unavailable\n",
        );
    };
    let Some(etag) = request.headers.get(header::IF_MATCH) else {
        return plain(StatusCode::PRECONDITION_REQUIRED, "If-Match is required\n");
    };
    if etag.as_bytes() != config_etag(fingerprint).as_bytes() {
        return plain(
            StatusCode::PRECONDITION_FAILED,
            "configuration baseline changed\n",
        );
    }
    if approval_required(state, AdminResource::Config) {
        return plain(
            StatusCode::CONFLICT,
            "named rollback requires the configured approval workflow\n",
        );
    }
    let target = match candidate::build_named_rollback(state, active.clone(), version).await {
        Ok(candidate) => candidate,
        Err(error) => return error.response(),
    };
    for document in active.named_documents.iter() {
        if document.digest == Sha256::digest(target[&document.name].as_bytes()).as_slice() {
            continue;
        }
        let resource = module_resource(document.domain);
        // 全组回滚可能改变独立守卫或流控授权域，配置历史权限不能取代这些文档的写权和复核。
        if resource != AdminResource::Config && !identity.allows(resource, AdminAction::Write) {
            return plain(
                StatusCode::FORBIDDEN,
                "rollback includes an unauthorized module\n",
            );
        }
        if approval_required(state, resource) {
            return plain(
                StatusCode::CONFLICT,
                "named rollback requires the configured approval workflow\n",
            );
        }
    }
    let state = state.clone();
    tokio::spawn(async move {
        let response = publication::restore_named(&state, active.clone(), target).await;
        state.config_history.record_control_event(
            "named-rollback",
            &state.cfg_path,
            active.version,
            version,
            response.status().as_str(),
        );
        response
    })
    .await
    .unwrap_or_else(|_| plain(StatusCode::SERVICE_UNAVAILABLE, "rollback result unknown\n"))
}
