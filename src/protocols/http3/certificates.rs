//! HTTP/3 证书与会话材料的受控更新；只有 endpoint actor 能发布安装事实。

use super::build_quic_server_config;
use crate::config::{Http3RuntimeCfg, TlsRuntimeCfg};
use crate::tls::material::{build_server_material, CertificateObservation, ServerMaterial};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// 已完成 QUIC 转换但尚未安装的同源材料。
#[derive(Clone)]
pub struct QuicServerMaterial {
    pub config: quinn::ServerConfig,
    pub observation: CertificateObservation,
}

/// 业务作用：为现有调用方提供只携带 QUIC 配置的热换通道。
///
/// 参数说明：
/// - `tls`：已验证的材料计划。
/// - `http3`：本代 transport 与密钥轮换预算。
/// - `shutdown`：撤销本代监控任务。
///
/// 返回：待安装配置通道；构建或转换失败保留旧配置。
pub fn spawn_cert_watcher(
    tls: TlsRuntimeCfg,
    http3: Http3RuntimeCfg,
    shutdown: watch::Receiver<bool>,
) -> watch::Receiver<Option<quinn::ServerConfig>> {
    let (updates, receiver) = watch::channel(None);
    let initial = build_server_material(&tls).ok();
    spawn_updates(tls, http3, initial, shutdown, move |material| {
        updates.send_replace(Some(material.config));
    });
    receiver
}

/// 业务作用：从已经安装的材料开始监控，将后续配置与证书事实作为一个候选发送给 endpoint actor。
///
/// 参数说明：
/// - `tls`：本代材料来源。
/// - `http3`：本代 transport 与密钥轮换预算。
/// - `initial`：prepare 阶段构建且 commit 已安装的实际材料。
/// - `shutdown`：撤销本代后台任务。
///
/// 返回：完整候选通道；发送候选不等于安装成功，接收者仍须复验 owner 并串行发布。
pub fn spawn_observed_cert_watcher(
    tls: TlsRuntimeCfg,
    http3: Http3RuntimeCfg,
    initial: ServerMaterial,
    shutdown: watch::Receiver<bool>,
) -> watch::Receiver<Option<QuicServerMaterial>> {
    let (updates, receiver) = watch::channel(None);
    spawn_updates(tls, http3, Some(initial), shutdown, move |material| {
        updates.send_replace(Some(material));
    });
    receiver
}

/// 业务作用：串行协调文件换材、Retry 密钥与 early-data 会话代，防止旧候选覆盖新身份。
///
/// 参数说明：
/// - `tls`：文件或动态身份来源。
/// - `http3`：固定协议预算。
/// - `initial`：当前已安装材料，兼容调用方可能尚未取得。
/// - `shutdown`：后台所有权停止广播。
/// - `publish`：仅发送完整候选，不持有 endpoint。
///
/// 返回：无同步结果；失败保留 LKG，停止后释放发送端。
fn spawn_updates<F>(
    tls: TlsRuntimeCfg,
    http3: Http3RuntimeCfg,
    initial: Option<ServerMaterial>,
    shutdown: watch::Receiver<bool>,
    publish: F,
) where
    F: Fn(QuicServerMaterial) + Send + Sync + 'static,
{
    let material = Arc::new(Mutex::new(initial));
    let publish = Arc::new(publish);
    let cert_material = material.clone();
    let cert_publish = publish.clone();
    let cert_http3 = http3.clone();
    crate::tls::material::spawn_material_watcher_until(
        tls,
        move |tls_config| {
            let mut current = cert_material.lock();
            let server_config = build_quic_server_config(tls_config.config.clone(), &cert_http3)?;
            let observation = tls_config.observation.clone();
            *current = Some(tls_config);
            // callback 不持有 Endpoint；accept loop 串行应用更新，停机后 sender 释放，不可能把
            // 已经 set_server_config(None) 的旧 generation 重新打开。
            cert_publish(QuicServerMaterial {
                config: server_config,
                observation,
            });
            Ok(())
        },
        shutdown.clone(),
    );
    tokio::spawn(async move {
        let period = Duration::from_secs(http3.retry_token_rotation_seconds);
        let mut rotation = tokio::time::interval(period);
        rotation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let session_period = Duration::from_secs(http3.early_data_session_rotation_seconds);
        let mut session_rotation = tokio::time::interval(session_period);
        session_rotation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // `interval` 首次 tick 立即就绪；初始 endpoint 已有随机密钥，不需要 commit 后立刻再换一次。
        rotation.tick().await;
        session_rotation.tick().await;
        let mut shutdown = shutdown;
        loop {
            tokio::select! {
                _ = rotation.tick() => {
                    let current = material.lock();
                    let Some(tls_config) = current.as_ref() else {
                        continue;
                    };
                    match build_quic_server_config(tls_config.config.clone(), &http3) {
                        Ok(server_config) => {
                            // 新 key 只服务后续 Initial；轮换瞬间携带旧 token 的客户端会被当作
                            // 未验证来源重新 Retry，不会降级成无认证放行。
                            publish(QuicServerMaterial {
                                config: server_config,
                                observation: tls_config.observation.clone(),
                            });
                            tracing::info!("HTTP/3 Retry token key rotated");
                        }
                        Err(error) => tracing::warn!(
                            error = %format!("{error:#}"),
                            "HTTP/3 Retry token key rotation failed; keeping previous config"
                        ),
                    }
                }
                _ = session_rotation.tick(), if http3.zero_rtt => {
                    // 只撤销会话 storage，不重新读取证书；轮换必须继续使用当前已验证身份，
                    // 防止与文件 watcher 竞争时把材料倒退到先前的一次读取。
                    let mut current = material.lock();
                    let Some(previous) = current.as_ref() else {
                        continue;
                    };
                    let next = rotate_session_material(previous);
                    match build_quic_server_config(next.config.clone(), &http3) {
                        Ok(server_config) => {
                            let observation = next.observation.clone();
                            *current = Some(next);
                            publish(QuicServerMaterial {
                                config: server_config,
                                observation,
                            });
                            tracing::info!("HTTP/3 early-data session generation rotated");
                        }
                        Err(error) => tracing::warn!(
                            error = %format!("{error:#}"),
                            "HTTP/3 early-data session rotation failed; keeping previous config"
                        ),
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    });
}

/// 业务作用：撤销尚未消费的 early-data 会话，同时保留当前证书、动态授权来源和低敏观察值。
///
/// 参数说明：
/// - `current`：已通过材料与 QUIC 转换校验的当前配置。
///
/// 返回：独立空会话存储的配置；证书 resolver 与观察值共享，不读取文件或重新解析证书。
fn rotate_session_material(current: &ServerMaterial) -> ServerMaterial {
    let mut config = (*current.config).clone();
    // 与 rustls 构建器一致的有界会话容量；替换 storage 立即撤销本代未使用的恢复凭据。
    config.session_storage = tokio_rustls::rustls::server::ServerSessionMemoryCache::new(256);
    ServerMaterial {
        config: Arc::new(config),
        observation: current.observation.clone(),
    }
}
