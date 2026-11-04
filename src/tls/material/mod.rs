//! 与握手配置同源的公开证书事实；构建产物尚不表示监听器已安装。

mod build;
mod certificate;

pub use build::build_server_material;
pub(super) use build::build_with_resolver;
pub use certificate::{
    CertificateBinding, CertificateLeaf, CertificateObservation, CertificateSnapshot,
    CertificateSource, ObservationState,
};

use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;

/// 同一次材料读取构建的握手配置与低敏事实；调用方必须在配置安装后才发布事实。
#[derive(Clone)]
pub struct ServerMaterial {
    pub config: Arc<ServerConfig>,
    pub observation: CertificateObservation,
}

#[cfg(any(test, feature = "xds-server"))]
pub(crate) use build::build_in_memory_material;
#[cfg(any(test, feature = "spire-workload"))]
pub(crate) use certificate::single_certificate;

/// 业务作用：把完整 TLS 构建产物交给监听器控制面发布门，证书错误时保留在线材料与事实。
///
/// 参数说明：
/// - `tls`：本代完整的材料来源计划。
/// - `publish`：安装配置与同源事实的发布动作。
/// - `shutdown`：撤销本代后台监控任务。
///
/// 返回：无同步结果；停止时释放 watcher，候选或发布失败只记录错误并保留 LKG。
pub fn spawn_material_watcher_until<F>(
    tls: crate::config::TlsRuntimeCfg,
    publish: F,
    shutdown: tokio::sync::watch::Receiver<bool>,
) where
    F: Fn(ServerMaterial) -> anyhow::Result<()> + Send + 'static,
{
    super::spawn_cert_material_watcher_inner(tls, publish, Some(shutdown));
}
