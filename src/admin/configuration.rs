//! 独立配置文档与完整配置集共享发布、校验和原文格式化合同。

pub(super) mod named;
pub(super) mod named_rollback;

use super::{
    approval_required, build_cluster_candidate_snapshot, collect_bounded_admin_body, config_etag,
    finish_config_write, json, plain, prepare_config_action, prepare_config_write,
    publish_document_set, record_admin_audit, request_content_type, submit_approval_change,
    AdminAction, AdminIdentity, AdminRequest, AdminRequestParts, AdminResource, AdminState,
    ApprovalPayload, BoxBody,
};
use crate::config::DocumentDomain;
use crate::control::history::ArchivedDocs;
use hyper::{Response, StatusCode};
use std::sync::Arc;

/// 业务作用：读取已生效的模块目录或单文档原文，保持接口守卫和 Sentinel 各自的访问权限。
///
/// 参数说明：
/// - `state`：含有当前活动快照与审计权威的管理状态。
/// - `request`：通过一般认证的读取请求，URI 只能选择已登记名称。
/// - `identity`：当前请求主体，限制可见业务域。
///
/// 返回：可读目录或活动原文。来源未知、不属于主体、超出预算时不返回正文。
pub(super) async fn read_modules(
    state: &Arc<AdminState>,
    request: &AdminRequestParts,
    identity: &AdminIdentity,
) -> Response<BoxBody> {
    if request.uri.query().is_some() {
        return plain(
            StatusCode::BAD_REQUEST,
            "only active module documents are available\n",
        );
    }
    let snapshot = state.snap.load_full();
    if !snapshot.named_configuration {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let Some(fingerprint) = snapshot.config_fingerprint else {
        return plain(
            StatusCode::CONFLICT,
            "configuration fingerprint unavailable\n",
        );
    };
    let source = if snapshot.config_bundle_digest.is_some() {
        "nacos"
    } else {
        "file"
    };
    let etag = config_etag(fingerprint);
    let Some(name) = request.uri.path().strip_prefix("/api/config/modules/") else {
        let documents = snapshot
            .named_documents
            .iter()
            .filter(|document| identity.allows(module_resource(document.domain), AdminAction::Read))
            .map(|document| {
                let resource = module_resource(document.domain);
                let write_available = identity.allows(resource, AdminAction::Write)
                    && (snapshot.config_bundle_digest.is_none()
                        || state.named_nacos.get().is_some())
                    && !(snapshot.admin_approval.enabled
                        && snapshot.admin_approval.resources.contains(&resource));
                serde_json::json!({
                    "name": document.name,
                    "resource": super::admin_resource_name(resource),
                    "readable": document.content.is_some(),
                    "write_available": write_available && document.content.is_some(),
                })
            })
            .collect::<Vec<_>>();
        if documents.is_empty() {
            return plain(StatusCode::FORBIDDEN, "forbidden\n");
        }
        let rollback_versions = if identity.allows(AdminResource::Config, AdminAction::Rollback)
            && !approval_required(state, AdminResource::Config)
            && (snapshot.config_bundle_digest.is_none()
                || state
                    .named_nacos
                    .get()
                    .is_some_and(|source| source.has_revision()))
        {
            state.config_history.named_versions()
        } else {
            Vec::new()
        };
        #[cfg(feature = "admin-grpc")]
        let synchronization = if identity.allows(AdminResource::Cluster, AdminAction::Read) {
            state.management.file_sync_status(&snapshot)
        } else {
            None
        };
        #[cfg(not(feature = "admin-grpc"))]
        let synchronization: Option<serde_json::Value> = None;
        return json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "source": source,
                "version": snapshot.version,
                "etag": etag,
                "documents": documents,
                "synchronization": synchronization,
                "rollback_versions": rollback_versions,
            }),
        );
    };
    let Some(document) = snapshot
        .named_documents
        .iter()
        .find(|document| document.name == name)
    else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let resource = module_resource(document.domain);
    if !identity.allows(resource, AdminAction::Read) {
        let _ = record_admin_audit(
            state,
            identity,
            request,
            resource,
            AdminAction::Read,
            "completed",
            Some(StatusCode::FORBIDDEN.as_u16()),
        )
        .await;
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    }
    let Some(content) = document.content.as_ref() else {
        return plain(StatusCode::CONFLICT, "active document exceeds read limit\n");
    };
    let digest = sha2::digest::Output::<sha2::Sha256>::from(document.digest);
    let mut response = json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "document": document.name,
            "source": source,
            "version": snapshot.version,
            "etag": etag,
            "document_etag": format!("\"sha256-{digest:x}\""),
            "max_config_body_bytes": snapshot.admin_max_config_body_bytes,
            "content": content,
        }),
    );
    if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
        response.headers_mut().insert(hyper::header::ETAG, value);
    }
    response
}

/// 业务作用：把具名模块绑定到部署声明确定的权限域，文件名本身不能变更权限。
///
/// 参数说明：
/// - `domain`：该文档在活动配置集合中承担的业务角色。
///
/// 返回：与既有原文端点一致的 Admin 资源。
fn module_resource(domain: DocumentDomain) -> AdminResource {
    match domain {
        DocumentDomain::Configuration => AdminResource::Config,
        DocumentDomain::InterfaceGuard => AdminResource::InterfaceGuard,
        DocumentDomain::Sentinel => AdminResource::Sentinel,
    }
}

/// 原子配置集中的固定文档，不能由请求指定磁盘路径或远端dataId。
#[derive(Clone, Copy)]
pub(super) enum Document {
    Gateway,
    Sentinel,
    InterfaceGuard,
}

impl Document {
    /// 业务作用：把独立文档绑定到原有权限域，避免编辑入口扩大主体授权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：主配置、Sentinel或接口守卫的固定资源域。
    fn resource(self) -> AdminResource {
        match self {
            Self::Gateway => AdminResource::Config,
            Self::Sentinel => AdminResource::Sentinel,
            Self::InterfaceGuard => AdminResource::InterfaceGuard,
        }
    }

    /// 业务作用：向页面声明当前编辑的文档，防止不同领域的回执相互替代。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不含用户输入的固定文档标识。
    fn name(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Sentinel => "sentinel",
            Self::InterfaceGuard => "interface-guard",
        }
    }

    /// 业务作用：只从同代完整归档读取指定原文，不回退到尚未生效的文件。
    ///
    /// 参数说明：
    /// - `documents`：活动配置代对应的完整三文档归档。
    ///
    /// 返回：指定文档的原始UTF-8内容。
    fn content(self, documents: &ArchivedDocs) -> &str {
        match self {
            Self::Gateway => &documents.gateway,
            Self::Sentinel => &documents.sentinel_rules,
            Self::InterfaceGuard => &documents.interface_guard,
        }
    }

    /// 业务作用：在完整候选中替换指定文档，使另外两份原文继续受同一CAS保护。
    ///
    /// 参数说明：
    /// - `documents`：从同代基线复制的完整候选。
    /// - `content`：操作者显式提交的新原文。
    ///
    /// 返回：仅改变内存候选，尚未构建、发布或写入磁盘。
    fn replace(self, documents: &mut ArchivedDocs, content: String) {
        match self {
            Self::Gateway => documents.gateway = content,
            Self::Sentinel => documents.sentinel_rules = content,
            Self::InterfaceGuard => documents.interface_guard = content,
        }
    }
}

/// 业务作用：读取独立文档的在线原文、来源和整体ETag，为集群编辑建立一致基线。
///
/// 参数说明：
/// - `state`：当前快照、归档与管理读取预算。
/// - `document`：固定配置文档。
///
/// 返回：原文和基线一致时返回200；非控制角色、归档缺失、超限或换代竞争时拒绝。
pub(super) async fn read(state: &Arc<AdminState>, document: Document) -> Response<BoxBody> {
    // Data不提供完整配置读取，不能通过新增领域入口绕过角色边界。
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let snapshot = state.snap.load_full();
    let version = snapshot.version;
    let Some(fingerprint) = snapshot.config_fingerprint else {
        return plain(
            StatusCode::CONFLICT,
            "configuration fingerprint unavailable\n",
        );
    };
    let history = state.config_history.clone();
    let archived = tokio::task::spawn_blocking(move || history.read_archived(version)).await;
    let documents = match archived {
        Ok(Ok(documents)) => documents,
        _ => {
            return plain(
                StatusCode::CONFLICT,
                "active configuration archive unavailable\n",
            );
        }
    };
    let limit = snapshot.admin_max_config_body_bytes;
    let content = document.content(&documents);
    if content.len() > limit {
        return plain(StatusCode::CONFLICT, "active document exceeds read limit\n");
    }
    // 异步读取后复验活动代，不能将旧原文和新版本的ETag拼接交付。
    let current = state.snap.load();
    if current.version != version || current.config_fingerprint != Some(fingerprint) {
        return plain(StatusCode::CONFLICT, "configuration changed during read\n");
    }
    let etag = config_etag(fingerprint);
    let source = if snapshot.config_source.nacos.enabled
        || (snapshot.named_configuration && snapshot.config_bundle_digest.is_some())
    {
        "nacos"
    } else {
        "file"
    };
    let mut response = json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "document": document.name(),
            "version": version,
            "etag": etag,
            "document_etag": format!("\"sha256-{}\"", nasa::crypto::sha256(content)),
            "source": source,
            "max_config_body_bytes": limit,
            "content": content,
        }),
    );
    if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
        response.headers_mut().insert(hyper::header::ETAG, value);
    }
    response
}

/// 业务作用：按原权限和配置集CAS发布接口守卫等独立原文，仍通过完整三文档候选和唯一热加载链。
///
/// 参数说明：
/// - `request`：携带原整体ETag及YAML正文的写请求。
/// - `state`：活动事实源、审计与审批状态。
/// - `document`：不能由用户扩展的固定文档域。
///
/// 返回：校验、审批或发布的真实结果；Nacos来源始终写远端bundle，不旁路改本地文件。
pub(super) async fn publish(
    request: AdminRequest,
    state: Arc<AdminState>,
    document: Document,
) -> Response<BoxBody> {
    let (parts, body) = request.into_parts();
    let resource = document.resource();
    let prepared = match prepare_config_write(&parts, &state, resource).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let response = async {
        if !request_content_type(&parts, "application/yaml") {
            return plain(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/yaml\n",
            );
        }
        let bytes = match collect_bounded_admin_body(
            &parts,
            body,
            state.snap.load().admin_max_config_body_bytes,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(response) => return *response,
        };
        let content = match String::from_utf8(bytes.to_vec()) {
            Ok(content) => content,
            Err(_) => return plain(StatusCode::BAD_REQUEST, "document must be UTF-8\n"),
        };
        let mut target = prepared.baseline.clone();
        document.replace(&mut target, content);
        if approval_required(&state, resource) {
            return submit_approval_change(
                &state,
                &prepared,
                resource,
                ApprovalPayload::Documents {
                    target,
                    baseline: prepared.baseline.clone(),
                },
            );
        }
        // 所有文档沿用完整候选构建和发布权威；远端事实源存在时不允许退回单文件写入。
        publish_document_set(
            &state,
            target,
            prepared.baseline.clone(),
            prepared.identity.principal_id.as_ref(),
        )
        .await
    }
    .await;
    finish_config_write(&state, &prepared.identity, &parts, resource, response).await
}

/// 业务作用：在同代基线上校验完整候选或生成两空格YAML预览，不执行环境展开后的反向固化或发布。
///
/// 参数说明：
/// - `request`：携带整体ETag与有界YAML正文的请求。
/// - `state`：活动配置和审计依赖。
/// - `document`：待编辑的固定文档域。
/// - `format`：为true时只做naml文档解析与编码，为false时构建完整候选。
///
/// 返回：成功明确返回applied=false；语法、预算、权限或基线不满足时拒绝，事实源保持不变。
pub(super) async fn inspect(
    request: AdminRequest,
    state: Arc<AdminState>,
    document: Document,
    format: bool,
) -> Response<BoxBody> {
    let (parts, body) = request.into_parts();
    let resource = document.resource();
    let prepared = match prepare_config_action(&parts, &state, resource, AdminAction::DryRun).await
    {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let response = async {
        if !request_content_type(&parts, "application/yaml") {
            return plain(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/yaml\n",
            );
        }
        let limit = state.snap.load().admin_max_config_body_bytes;
        let bytes = match collect_bounded_admin_body(&parts, body, limit).await {
            Ok(bytes) => bytes,
            Err(response) => return *response,
        };
        let content = match String::from_utf8(bytes.to_vec()) {
            Ok(content) => content,
            Err(_) => return plain(StatusCode::BAD_REQUEST, "document must be UTF-8\n"),
        };
        if format {
            // 原文格式化不执行imports、占位符或环境求值，防止把本机秘密写进编辑结果。
            let normalized = tokio::task::spawn_blocking(move || {
                let value = crate::config::document::parse(content.as_bytes(), limit)?;
                anyhow::ensure!(
                    value.is_object(),
                    "configuration document must be a mapping"
                );
                let formatted = crate::config::document::encode(&value, limit)?;
                Ok::<_, anyhow::Error>((formatted != content, formatted))
            })
            .await;
            return match normalized {
                Ok(Ok((changed, content))) => json(
                    StatusCode::OK,
                    serde_json::json!({
                        "ok": true,
                        "applied": false,
                        "document": document.name(),
                        "source_etag": config_etag(prepared.base_fingerprint),
                        "indentation": 2,
                        "comments_preserved": false,
                        "changed": changed,
                        "content": content,
                    }),
                ),
                Ok(Err(error)) => json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "ok": false,
                        "applied": false,
                        "error": format!("{error:#}"),
                    }),
                ),
                Err(_) => plain(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "document formatter unavailable\n",
                ),
            };
        }
        let mut target = prepared.baseline.clone();
        document.replace(&mut target, content);
        match build_cluster_candidate_snapshot(&state, &target).await {
            Ok(_) => json(
                StatusCode::OK,
                serde_json::json!({
                    "ok": true,
                    "applied": false,
                    "document": document.name(),
                    "source_etag": config_etag(prepared.base_fingerprint),
                }),
            ),
            Err(error) => error.response(),
        }
    }
    .await;
    // 校验结果也必须有对应审计；这里只报告失败，不伪造任何配置发布或未知写入状态。
    if record_admin_audit(
        &state,
        &prepared.identity,
        &parts,
        resource,
        AdminAction::DryRun,
        "completed",
        Some(response.status().as_u16()),
    )
    .await
    .is_err()
    {
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "applied": false,
                "error": "validation result audit failed",
            }),
        );
    }
    response
}
