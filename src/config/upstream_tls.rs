//! 服务与直接流上游共用的 TLS 声明编译边界。

use std::path::Path;

use anyhow::{Context, Result};

use super::{model::UpstreamTlsCfg, resolve_relative};
use crate::tls::UpstreamTlsProfile;

/// 业务作用：把上游 TLS 声明编译为统一的信任、客户端身份和动态授权策略。
///
/// 参数说明：
/// - `cfg_path`：主配置路径，用于解析相对证书与密钥文件。
/// - `tls`：服务或直接流上游的完整 TLS 声明。
///
/// 返回：材料与策略有效时返回可复用 profile；互斥来源、非法身份或材料加载失败时拒绝配置。
pub(crate) fn build_profile(cfg_path: &Path, tls: &UpstreamTlsCfg) -> Result<UpstreamTlsProfile> {
    if tls.insecure_skip_verify {
        // 关闭证书认证只保留传输加密，不能接受看似仍会生效的信任约束或客户端身份。
        anyhow::ensure!(
            tls.ca_file.is_none()
                && tls.ca_pem.is_none()
                && tls.subject_alt_names.is_empty()
                && tls.client_cert_file.is_none()
                && tls.client_key_file.is_none()
                && tls.client_cert_pem.is_none()
                && tls.client_key_pem.is_none()
                && tls.spire.is_none(),
            "insecure_skip_verify cannot be combined with trust or client identity material"
        );
        return crate::tls::build_encryption_only_upstream_tls_profile(tls.server_name.as_deref())
            .context("build encryption-only upstream TLS profile");
    }
    let ca_file = tls
        .ca_file
        .as_deref()
        .map(|path| resolve_relative(cfg_path, path));
    let client_cert_file = tls
        .client_cert_file
        .as_deref()
        .map(|path| resolve_relative(cfg_path, path));
    let client_key_file = tls
        .client_key_file
        .as_deref()
        .map(|path| resolve_relative(cfg_path, path));
    let mut profile = match &tls.spire {
        Some(spire) => {
            // 来源冲突应在联系身份 Agent 前拒绝，避免为不会接纳的声明取得客户端凭据。
            anyhow::ensure!(
                client_cert_file.is_none()
                    && client_key_file.is_none()
                    && tls.client_cert_pem.is_none()
                    && tls.client_key_pem.is_none(),
                "upstream SPIRE identity cannot be combined with file or inline client identity"
            );
            let source =
                crate::tls::spire::build_source(spire).context("build upstream SPIRE identity")?;
            crate::tls::build_upstream_tls_profile_with_spire(
                tls.server_name.as_deref(),
                ca_file.as_deref(),
                tls.ca_pem.as_deref(),
                &tls.subject_alt_names,
                client_cert_file.as_deref(),
                client_key_file.as_deref(),
                tls.client_cert_pem.as_deref(),
                tls.client_key_pem.as_deref(),
                source,
            )
        }
        None => crate::tls::build_upstream_tls_profile_with_material(
            tls.server_name.as_deref(),
            ca_file.as_deref(),
            tls.ca_pem.as_deref(),
            &tls.subject_alt_names,
            client_cert_file.as_deref(),
            client_key_file.as_deref(),
            tls.client_cert_pem.as_deref(),
            tls.client_key_pem.as_deref(),
        ),
    }?;
    // 材料编译不能延长控制面授权；数据面仍须在新请求或连接边界复验原截止点。
    profile.client_identity_not_after = tls.client_identity_not_after;
    profile.client_identity_policy_identity = tls.client_identity_policy_identity;
    Ok(profile)
}
