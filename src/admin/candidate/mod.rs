//! 管理候选的原文工作区、完整构建与启动边界。

mod admission;
mod error;
mod inspection;
#[cfg(feature = "node-actions")]
pub(in crate::admin) mod node;
#[cfg(feature = "node-actions")]
mod node_policy;
mod workspace;

use std::path::Path;

use anyhow::Result;
use bytes::Bytes;

use super::AdminState;
use crate::config::candidate::Documents;
use crate::config::GatewaySnapshot;
use crate::control::history::ArchivedDocs;
pub(super) use admission::Admission;
pub(super) use error::BuildError;
#[cfg(feature = "node-actions")]
pub(in crate::admin) use inspection::inspect_guarded;
pub(super) use inspection::{inspect_archived, DocumentKind};
use workspace::Workspace;

enum Input {
    Main(Bytes),
    Documents(ArchivedDocs),
}

/// 业务作用：以同一候选预算复验当前实际来源，远端模式不能误读bootstrap且磁盘读取不阻塞异步执行线程。
///
/// 参数说明：
/// - `state`：提供已发布来源、provider视图与统一文件读事务。
///
/// 返回：当前来源的完整构建结果；忙碌、版本耗尽或读取/语义失败时不改变快照。
pub(super) async fn build_current(state: &AdminState) -> Result<GatewaySnapshot, BuildError> {
    let permit = state.candidate_builds.acquire()?;
    let current = state.snap.load_full();
    let version = current
        .version
        .checked_add(1)
        .ok_or(BuildError::Exhausted)?;
    let history = state.config_history.clone();
    permit
        .spawn(move |_| {
            history.with_stable_local_files(|| {
                #[cfg(feature = "config-providers")]
                {
                    crate::config::load_snapshot_with_providers(
                        &current.source_config_path,
                        version,
                        crate::upstream::DynamicUpstreamStore::new(),
                        crate::control::providers::Input {
                            previous: current.providers.clone(),
                            observation: None,
                        },
                    )
                }
                #[cfg(not(feature = "config-providers"))]
                {
                    crate::config::load_snapshot(&current.source_config_path, version)
                }
            })
        })
        .await
        .map_err(|_| BuildError::Worker)?
        .map_err(|error| BuildError::Invalid(error.to_string()))
}

/// 业务作用：在独立 owner 中构建完整原文候选，使请求取消不会遗失临时文件清理职责。
///
/// 参数说明：
/// - `state`：提供真实部署根与活动版本、来源和启动边界。
/// - `docs`：待验证的三份原文，不重写声明路径或展开秘密。
///
/// 返回：完整候选快照；读取、语义、启动边界或清理失败均拒绝，不修改活动配置。
pub(super) async fn build(
    state: &AdminState,
    docs: &ArchivedDocs,
) -> Result<GatewaySnapshot, BuildError> {
    Workspace::validate(docs).map_err(|error| BuildError::Invalid(error.to_string()))?;
    // 任务容量必须先于大原文复制取得，取消旧等待者不能让新的副本继续堆积。
    let permit = state.candidate_builds.acquire()?;
    build_owned(state, permit, Input::Documents(docs.clone())).await
}

/// 业务作用：使主文档发布与dry-run沿用同一私有工作区和真实任务预算，取消不遗失清理owner。
///
/// 参数说明：
/// - `state`：提供真实部署根、活动快照和共享候选容量。
/// - `bytes`：已接收的主文档Bytes，不复制正文或改写YAML。
///
/// 返回：完整候选；超限、忙碌、非法或内部失败均不写活动配置。
pub(super) async fn build_main(
    state: &AdminState,
    bytes: Bytes,
) -> Result<GatewaySnapshot, BuildError> {
    if bytes.len() > crate::config::document::MAX_DOCUMENT_BYTES {
        return Err(BuildError::Invalid(
            "candidate document exceeds size limit".into(),
        ));
    }
    let permit = state.candidate_builds.acquire()?;
    build_owned(state, permit, Input::Main(bytes)).await
}

/// 业务作用：让唯一工作单元持有输入、许可和临时文件，只有真实清理完成才能释放构建容量。
///
/// 参数说明：
/// - `state`：冻结真实配置根、当前启动边界及文件事务。
/// - `permit`：在输入复制之前取得的独占工作许可。
/// - `input`：已转交当前工作单元的单文档或三文档原文。
///
/// 返回：构建且清理均完成的候选；任务异常、清理未确认或当前启动边界变化时拒绝。
async fn build_owned(
    state: &AdminState,
    permit: admission::Permit,
    input: Input,
) -> Result<GatewaySnapshot, BuildError> {
    let active = state.snap.load_full();
    let version = active.version.checked_add(1).ok_or(BuildError::Exhausted)?;
    let real = state.cfg_path.clone();
    let history = state.config_history.clone();
    // 阻塞任务必须拥有原文和工作区；外层请求取消后仍能走到清理，不能把文件所有权留在 await 外。
    let built = permit
        .spawn(move |permit| {
            let mut workspace =
                Workspace::create(&real, permit).map_err(|_| BuildError::Workspace)?;
            let documents = match &input {
                Input::Main(bytes) => {
                    workspace
                        .write_main(bytes)
                        .map_err(|_| BuildError::Workspace)?;
                    workspace.main_document()
                }
                Input::Documents(docs) => {
                    workspace.write(docs).map_err(|_| BuildError::Workspace)?;
                    workspace.documents()
                }
            };
            let built = load_documents(&real, documents, version, &active, &history);
            workspace.cleanup().map_err(|_| BuildError::Workspace)?;
            built.map_err(|error| BuildError::Invalid(error.to_string()))
        })
        .await
        .map_err(|_| BuildError::Worker)??;
    let current = state.snap.load();
    // 常驻计量 owner 不能由审批候选替换；构建期间发生的热更也必须在返回前复验。
    if built.usage_meter.signature != current.usage_meter.signature
        || built.traffic_meter.signature != current.traffic_meter.signature
    {
        return Err(BuildError::Invalid(
            "meter transport changes require restart".to_owned(),
        ));
    }
    Ok(built)
}

/// 业务作用：让单文档和完整文档集共用构建与启动权威门，避免先写入再由 reload 拒绝。
///
/// 参数说明：
/// - `real`：相对依赖与 profile 的真实配置根。
/// - `documents`：本次原文输入位置。
/// - `version`：候选版本。
/// - `active`：当前来源、中心开关和进程日志 owner。
/// - `history`：发布前复验永久节点绑定的文件事务。
///
/// 返回：语义合法且不改变启动权威的完整快照；失败保留活动状态。
fn load_documents(
    real: &Path,
    documents: Documents<'_>,
    version: u64,
    active: &GatewaySnapshot,
    history: &crate::control::history::ConfigHistory,
) -> Result<GatewaySnapshot> {
    let built = crate::config::candidate::load_documents(
        real,
        documents,
        version,
        #[cfg(feature = "config-providers")]
        active.providers.clone(),
    )?;
    // 管理候选不能先修改事实源再由reload拒绝跨节点或跨集群的身份变化。
    history.validate_candidate(&built)?;
    // 中心切换和日志 writer 都属于进程启动权威，审批与落盘之前必须拒绝热替换。
    if let Some(field) = crate::config::centers::restart_field(active, &built) {
        anyhow::bail!("{field} change requires restart");
    }
    anyhow::ensure!(
        active.process_log.same_bootstrap(&built.process_log),
        "log configuration changes require restart"
    );
    anyhow::ensure!(
        active.usage_meter.signature == built.usage_meter.signature
            && active.traffic_meter.signature == built.traffic_meter.signature,
        "meter transport changes require restart"
    );
    Ok(built)
}
