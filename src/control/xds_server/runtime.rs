//! 管理端监听器的 prepare、发布后接管与撤权；业务快照仍由唯一 reload worker 拥有。

use super::{admission::Admission, plan::NodePlan, security, stream};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// 独立管理端运行 owner；不保存第二份资源事实，只持有当前快照句柄与传输名额。
pub struct Manager {
    pub(crate) snapshots: Arc<ArcSwap<crate::config::GatewaySnapshot>>,
    pub(crate) audit: crate::admin::audit::AdminAuditLog,
    pub(crate) admission: Arc<Admission>,
    pub(crate) publication: Arc<parking_lot::RwLock<()>>,
    pub(crate) stopping: CancellationToken,
    active: parking_lot::Mutex<Option<Active>>,
    handshakes: Arc<tokio::sync::Semaphore>,
}

struct Active {
    address: SocketAddr,
    cancel: CancellationToken,
}

/// 候选监听仅绑定，不接受任何客户端；丢弃事务会释放候选 socket。
pub struct Prepared {
    manager: Arc<Manager>,
    address: Option<SocketAddr>,
    listener: Option<TcpListener>,
}

#[derive(Clone)]
pub(crate) struct Peer {
    pub manager: Arc<Manager>,
    pub address: SocketAddr,
    pub tls_digest: [u8; 32],
    pub certificate_digest: String,
    pub node_id: String,
    pub grant_digest: String,
    pub ttl_ms: u64,
}

impl Manager {
    /// 业务作用：创建跨热更稳定的管理端 owner，资源查询始终从唯一已发布快照读取。
    ///
    /// 参数说明：
    /// - `snapshots`：与数据面共享的 ArcSwap。
    /// - `audit`：与管理写操作共享的持久审计器。
    ///
    /// 返回：尚未监听的 owner；不会因构造句柄就接受配置或下发密钥。
    pub fn new(
        snapshots: Arc<ArcSwap<crate::config::GatewaySnapshot>>,
        audit: crate::admin::audit::AdminAuditLog,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshots,
            audit,
            admission: Arc::new(Admission::default()),
            publication: Arc::new(parking_lot::RwLock::new(())),
            stopping: CancellationToken::new(),
            active: parking_lot::Mutex::new(None),
            handshakes: Arc::new(tokio::sync::Semaphore::new(8)),
        })
    }

    /// 业务作用：在快照发布之前绑定新的管理端地址，端口冲突不得留下半完成的新权限图。
    ///
    /// 参数说明：
    /// - `candidate`：完成资源和 TLS 构建的完整候选快照。
    ///
    /// 返回：已准备但仍不 accept 的事务；绑定失败保留旧 listener 和旧快照。
    pub async fn prepare(
        self: &Arc<Self>,
        candidate: &crate::config::GatewaySnapshot,
    ) -> Result<Prepared> {
        let address = candidate.xds_server.as_ref().map(|p| p.listen);
        let old = self.active.lock().as_ref().map(|a| a.address);
        let listener = if address != old {
            if let Some(address) = address {
                Some(
                    TcpListener::bind(address)
                        .await
                        .context("bind candidate xDS management listener")?,
                )
            } else {
                None
            }
        } else {
            None
        };
        Ok(Prepared {
            manager: self.clone(),
            address,
            listener,
        })
    }

    /// 业务作用：让授权撤回与最后的响应出队复验互斥，防止检查旧权限后在新代下发秘密。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只应在同步 ArcSwap 发布临界区内持有的写 guard；不得跨 await。
    pub fn publication_guard(&self) -> parking_lot::RwLockWriteGuard<'_, ()> {
        self.publication.write()
    }

    /// 业务作用：停机时先撤销管理端传输权威，再结束 accept 与全部 ADS 连接。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；以后所有响应出队都会失败关闭。
    pub fn shutdown(&self) {
        let _gate = self.publication.write();
        self.stopping.cancel();
        if let Some(active) = self.active.lock().take() {
            active.cancel.cancel();
        }
    }
}

impl Prepared {
    /// 业务作用：仅在完整快照已经发布后接管监听权威，旧地址停止接收，新地址才开始握手。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：提交无外部失败步骤；同地址的证书和授权由后续握手从当前快照读取。
    pub fn commit(self) {
        let mut active = self.manager.active.lock();
        if active.as_ref().map(|a| a.address) == self.address {
            return;
        }
        // 旧地址失去权威之后立即停止接收；其已建立连接会按当前快照复验并关闭。
        if let Some(old) = active.take() {
            old.cancel.cancel();
        }
        if let (Some(address), Some(listener)) = (self.address, self.listener) {
            let cancel = self.manager.stopping.child_token();
            tokio::spawn(accept(
                self.manager.clone(),
                listener,
                address,
                cancel.clone(),
            ));
            *active = Some(Active {
                address,
                cancel,
            });
        }
    }
}

impl Peer {
    /// 业务作用：复验本流的传输身份、节点绑定与授权图，迟到请求不能继承新身份的资源权限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前单调版本与本节点资源；失权、TLS 轮换、监听变化或 TTL 合同变化均关闭旧流。
    pub(crate) fn current(&self) -> Result<(u64, Arc<NodePlan>), tonic::Status> {
        if self.manager.stopping.is_cancelled() {
            return Err(tonic::Status::unavailable("xDS server is draining"));
        }
        let snapshot = self.manager.snapshots.load();
        let plan = snapshot
            .xds_server
            .as_ref()
            .ok_or_else(|| tonic::Status::permission_denied("xDS authority withdrawn"))?;
        let node = plan
            .nodes
            .get(&self.node_id)
            .ok_or_else(|| tonic::Status::permission_denied("xDS node authorization withdrawn"))?;
        if plan.listen != self.address
            || plan.tls.digest != self.tls_digest
            || plan.ttl_ms != self.ttl_ms
            || node.certificate_sha256 != self.certificate_digest
            || node.grant_digest != self.grant_digest
        {
            return Err(tonic::Status::permission_denied(
                "xDS generation authority changed",
            ));
        }
        Ok((snapshot.version, node.clone()))
    }
}

/// 业务作用：只为有握手席位的连接创建任务，未认证客户端不能耗尽无界 TLS worker。
///
/// 参数说明：
/// - `manager`：稳定运行 owner。
/// - `listener`：已提交的监听 socket。
/// - `address`：本代监听权威。
/// - `cancel`：停止接收通知，不允许旧地址继续提供配置。
///
/// 返回：撤权或 listener 错误时退出；每个握手受三秒期限和八席上限限制。
async fn accept(
    manager: Arc<Manager>,
    listener: TcpListener,
    address: SocketAddr,
    cancel: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            _ = cancel.cancelled() => break,
            result = listener.accept() => result,
        };
        let Ok((socket, _)) = accepted else {
            break;
        };
        let Ok(handshake) = manager.handshakes.clone().try_acquire_owned() else {
            continue;
        };
        let plan = manager.snapshots.load().xds_server.clone();
        let Some(plan) = plan.filter(|p| p.listen == address) else {
            continue;
        };
        let manager = manager.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let _ = socket.set_nodelay(true);
            let acceptor = tokio_rustls::TlsAcceptor::from(plan.tls.config.clone());
            let connection =
                tokio::time::timeout(Duration::from_secs(3), acceptor.accept(socket)).await;
            drop(handshake);
            let Ok(Ok(connection)) = connection else {
                super::metrics::DENIED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            };
            let Some(certificate) = connection
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
            else {
                return;
            };
            let digest = security::certificate_digest(certificate.as_ref());
            let Some((node_id, node)) = plan
                .nodes
                .iter()
                .find(|(_, n)| n.certificate_sha256 == digest)
            else {
                super::metrics::DENIED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            };
            let Ok(lease) = manager.admission.acquire(node_id, false) else {
                return;
            };
            let peer = Peer {
                manager: manager.clone(),
                address,
                tls_digest: plan.tls.digest,
                certificate_digest: digest,
                node_id: node_id.clone(),
                grant_digest: node.grant_digest.clone(),
                ttl_ms: plan.ttl_ms,
            };
            // 握手可能跨越配置发布；业务协议开放前必须重新核对当前权威，不能只使用握手开始时的快照。
            if peer.current().is_err() {
                return;
            }
            drop(plan);
            let service_peer = peer.clone();
            let service = hyper::service::service_fn(move |request| {
                stream::dispatch(service_peer.clone(), request)
            });
            let mut builder =
                hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
            builder
                .timer(hyper_util::rt::TokioTimer::new())
                .max_concurrent_streams(2)
                .max_header_list_size(16 * 1024)
                .initial_stream_window_size(64 * 1024)
                .initial_connection_window_size(128 * 1024)
                .max_send_buf_size(64 * 1024)
                .keep_alive_interval(Some(Duration::from_secs(10)))
                .keep_alive_timeout(Duration::from_secs(5));
            let serving =
                builder.serve_connection(hyper_util::rt::TokioIo::new(connection), service);
            tokio::pin!(serving);
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = &mut serving => break,
                    _ = interval.tick() => {
                        if peer.current().is_err() {
                            break;
                        }
                    }
                }
            }
            drop(lease);
        });
    }
}
