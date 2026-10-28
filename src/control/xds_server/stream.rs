//! ADS gRPC 适配、有界发送与秘密出站前的持久审计及最终权限复验。

use super::{admission::Lease, proto as p, runtime::Peer, state};
use futures::{Stream, StreamExt};
use prost::Message;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status, Streaming};

type Input = Pin<Box<dyn Stream<Item = Result<state::Request, Status>> + Send>>;
type Output<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;
type Call<T> =
    Pin<Box<dyn std::future::Future<Output = Result<Response<Output<T>>, Status>> + Send>>;

struct Sotw(Peer);
struct Delta(Peer);

/// 实际响应体持有名额；worker 退场、慢客户端和取消都不能提前归还仍驻留的输出资源。
struct AuthorizedOutput {
    receiver: mpsc::Receiver<Result<state::Packet, Status>>,
    peer: Peer,
    cancel: CancellationToken,
    discarded: mpsc::Sender<state::Unsent>,
    _lease: Lease,
}

impl Stream for AuthorizedOutput {
    type Item = Result<state::Packet, Status>;

    /// 业务作用：在最后出队点复验当前快照和授权，撤权后不能把旧队列中的资源交给 gRPC 编码器。
    ///
    /// 参数说明：
    /// - `cx`：传输层唤醒上下文。
    ///
    /// 返回：仍由当前发布版本授权的包或终止错误；Pending 不持有发布锁。
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let gate = self.peer.manager.publication.clone();
        let _guard = gate.read();
        loop {
            match self.receiver.poll_recv(cx) {
                Poll::Ready(Some(Ok(packet))) => {
                    match self.peer.current() {
                        Err(error) => {
                            self.cancel.cancel();
                            return Poll::Ready(Some(Err(error)));
                        }
                        Ok((version, _)) if version != packet.snapshot_version => {
                            // 授权仍有效时只撤销过期队列项；每类型至多一个 flight，回传队列不超过五项。
                            if self.discarded.try_send(packet.unsent()).is_err() {
                                self.cancel.cancel();
                                return Poll::Ready(Some(Err(Status::unavailable(
                                    "ADS coalescing channel unavailable",
                                ))));
                            }
                            continue;
                        }
                        _ => {}
                    }
                    return Poll::Ready(Some(Ok(packet)));
                }
                other => return other,
            }
        }
    }
}

impl Drop for AuthorizedOutput {
    /// 业务作用：真实响应体销毁时终止读取和状态机，避免取消后仍处理授权请求或审计下发。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；取消通知与 RAII 名额释放共同结束本流。
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl tonic::server::StreamingService<p::DiscoveryRequest> for Sotw {
    type Response = p::DiscoveryResponse;
    type ResponseStream = Output<p::DiscoveryResponse>;
    type Future = Call<p::DiscoveryResponse>;

    /// 业务作用：把标准 SotW 双向 RPC 适配到统一授权流，协议模式不能由消息内容更改。
    ///
    /// 参数说明：
    /// - `request`：已经过字节预算的 SotW 请求流。
    ///
    /// 返回：认证和首请求成功时返回有界响应流；身份、预算或能力不符时拒绝 RPC。
    fn call(&mut self, request: Request<Streaming<p::DiscoveryRequest>>) -> Self::Future {
        let peer = self.0.clone();
        Box::pin(async move {
            let input = Box::pin(request.into_inner().map(|r| r.map(state::Request::Sotw)));
            let output = open(peer, input, false).await?;
            let output: Output<p::DiscoveryResponse> = Box::pin(output.map(|packet| {
                packet.and_then(|p| match p.response {
                    state::Response::Sotw(response) => Ok(response),
                    _ => Err(Status::internal("ADS response mode mismatch")),
                })
            }));
            Ok(Response::new(output))
        })
    }
}

impl tonic::server::StreamingService<p::DeltaRequest> for Delta {
    type Response = p::DeltaResponse;
    type ResponseStream = Output<p::DeltaResponse>;
    type Future = Call<p::DeltaResponse>;

    /// 业务作用：把标准 Delta 双向 RPC 接入相同身份、审计和容量边界。
    ///
    /// 参数说明：
    /// - `request`：已经过字节预算的 Delta 请求流。
    ///
    /// 返回：首请求验证成功时返回增量响应流；不兼容协议和越权请求失败关闭。
    fn call(&mut self, request: Request<Streaming<p::DeltaRequest>>) -> Self::Future {
        let peer = self.0.clone();
        Box::pin(async move {
            let input = Box::pin(request.into_inner().map(|r| r.map(state::Request::Delta)));
            let output = open(peer, input, true).await?;
            let output: Output<p::DeltaResponse> = Box::pin(output.map(|packet| {
                packet.and_then(|p| match p.response {
                    state::Response::Delta(response) => Ok(response),
                    _ => Err(Status::internal("ADS response mode mismatch")),
                })
            }));
            Ok(Response::new(output))
        })
    }
}

/// 业务作用：只暴露两个标准 ADS 方法，并在解码前设置严格消息字节上限。
///
/// 参数说明：
/// - `peer`：TLS 会话冻结并在每次使用时复验的节点身份。
/// - `request`：h2 HTTP 请求。
///
/// 返回：标准 gRPC 响应；其它路径、非 POST、错误媒体类型或失去授权都不能进入状态机。
pub(crate) async fn dispatch(
    peer: Peer,
    request: http::Request<hyper::body::Incoming>,
) -> Result<http::Response<tonic::body::Body>, Infallible> {
    if peer.current().is_err() {
        return Ok(Status::permission_denied("xDS peer authority changed").into_http());
    }
    if request.method() != http::Method::POST
        || !request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "application/grpc" || v == "application/grpc+proto")
    {
        return Ok(Status::invalid_argument("ADS requires protobuf gRPC POST").into_http());
    }
    let response = match request.uri().path() {
        "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources" => {
            tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                p::DiscoveryResponse,
                p::DiscoveryRequest,
            >::default())
            .max_decoding_message_size(64 * 1024)
            .max_encoding_message_size(5 * 1024 * 1024)
            .streaming(Sotw(peer), request)
            .await
        }
        "/envoy.service.discovery.v3.AggregatedDiscoveryService/DeltaAggregatedResources" => {
            tonic::server::Grpc::new(
                tonic_prost::ProstCodec::<p::DeltaResponse, p::DeltaRequest>::default(),
            )
            .max_decoding_message_size(64 * 1024)
            .max_encoding_message_size(5 * 1024 * 1024)
            .streaming(Delta(peer), request)
            .await
        }
        _ => Status::unimplemented("only ADS SotW and Delta are available").into_http(),
    };
    Ok(response)
}

/// 业务作用：在读取首请求前占用真实流名额，并把自报 node.id 与已验证证书绑定进行精确比较。
///
/// 参数说明：
/// - `peer`：传输身份和当前授权。
/// - `input`：已确定 RPC 模式的请求流。
/// - `delta`：协议选择。
///
/// 返回：验证完成后启动单个有界 worker；超时、缺失 node 或身份不符立即释放名额并拒绝。
async fn open(peer: Peer, mut input: Input, delta: bool) -> Result<AuthorizedOutput, Status> {
    let lease = peer.manager.admission.acquire(&peer.node_id, true)?;
    let first = tokio::time::timeout(Duration::from_secs(5), input.next())
        .await
        .map_err(|_| Status::deadline_exceeded("ADS first request deadline exceeded"))?
        .ok_or_else(|| Status::invalid_argument("ADS stream needs an initial request"))??;
    let node = first
        .node()
        .ok_or_else(|| Status::unauthenticated("first ADS request needs node identity"))?;
    if node.id != peer.node_id {
        super::metrics::DENIED.fetch_add(1, Ordering::Relaxed);
        return Err(Status::permission_denied(
            "node id does not match authenticated certificate",
        ));
    }
    let mut session = state::Session::new(delta, peer.ttl_ms, node)?;
    let (_, node) = peer.current()?;
    session.apply(first, &node)?;
    let (sender, receiver) = mpsc::channel(1);
    let (discarded, unsent) = mpsc::channel(p::TYPES.len());
    let cancel = peer.manager.stopping.child_token();
    tokio::spawn(run(
        peer.clone(),
        input,
        session,
        sender,
        unsent,
        cancel.clone(),
    ));
    Ok(AuthorizedOutput {
        receiver,
        peer,
        cancel,
        discarded,
        _lease: lease,
    })
}

/// 业务作用：串行推进一个节点流，发送背压与 ACK 等待均不占用其它节点的任务或配置发布锁。
///
/// 参数说明：
/// - `peer`：必须持续有效的权限证据。
/// - `input`：有界请求流。
/// - `session`：当前流私有协议状态。
/// - `sender`：只有一个槽位的输出通道。
/// - `unsent`：出队前已过期的响应身份，固定为每类型至多一项。
/// - `cancel`：响应体销毁或停机通知。
///
/// 返回：失权、慢流、输入错误或取消时结束；最终错误只能尝试占用已有槽位，不建立旁路队列。
async fn run(
    peer: Peer,
    mut input: Input,
    mut session: state::Session,
    sender: mpsc::Sender<Result<state::Packet, Status>>,
    mut unsent: mpsc::Receiver<state::Unsent>,
    cancel: CancellationToken,
) {
    let outcome = async {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            while let Ok(discarded) = unsent.try_recv() {
                session.discard(discarded);
            }
            let (version, node) = peer.current()?;
            while let Some(packet) = session.next(version, &node)? {
                if packet.secrets {
                    // 持久审计失败时从不把私钥送入输出队列；审计完成后仍须再次复验当前版本和权限。
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        audit_release(&peer, &packet, &node),
                    )
                    .await
                    .map_err(|_| {
                        Status::deadline_exceeded("SDS durable audit deadline exceeded")
                    })??;
                }
                let bytes = match &packet.response {
                    state::Response::Sotw(r) => r.encoded_len(),
                    state::Response::Delta(r) => r.encoded_len(),
                };
                if bytes > 5 * 1024 * 1024 {
                    return Err(Status::resource_exhausted(
                        "ADS response byte capacity exceeded",
                    ));
                }
                let permit = tokio::time::timeout(Duration::from_secs(2), sender.reserve())
                    .await
                    .map_err(|_| {
                        super::metrics::SLOW.fetch_add(1, Ordering::Relaxed);
                        Status::deadline_exceeded("ADS output backpressure deadline exceeded")
                    })?
                    .map_err(|_| Status::cancelled("ADS receiver closed"))?;
                let _gate = peer.manager.publication.read();
                let (current, _) = peer.current()?;
                if current != packet.snapshot_version {
                    // 仍有权限但候选已过期时直接合并到下一代，不向慢流排队保存历史版本。
                    session.discard(packet.unsent());
                    break;
                }
                if packet.secrets {
                    super::metrics::SECRET_SENDS.fetch_add(1, Ordering::Relaxed);
                }
                permit.send(Ok(packet));
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = sender.closed() => return Ok(()),
                _ = interval.tick() => {},
                Some(discarded) = unsent.recv() => session.discard(discarded),
                request = input.next() => {
                    let Some(request) = request else {
                        return Ok(());
                    };
                    let request = request?;
                    if request.node().is_some_and(|n| n.id != peer.node_id) {
                        return Err(Status::permission_denied("ADS node identity changed within stream"));
                    }
                    let (_, node) = peer.current()?;
                    session.apply(request, &node)?;
                }
            }
        }
    };
    let result = tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        result = outcome => result,
    };
    if let Err(error) = result {
        super::metrics::DENIED.fetch_add(1, Ordering::Relaxed);
        let _ = sender.try_send(Err(error));
    }
}

/// 业务作用：记录已授权节点的秘密下发尝试，不把私钥、证书正文或客户端错误内容写入审计。
///
/// 参数说明：
/// - `peer`：已通过传输认证的节点。
/// - `packet`：尚未进入传输的当前版本响应。
/// - `node`：同代工作区归属与独立 SDS 授权。
///
/// 返回：持久收据成立且版本仍一致时成功；任何审计失败均禁止下发，成功也不代表客户端已接收。
async fn audit_release(
    peer: &Peer,
    packet: &state::Packet,
    node: &super::plan::NodePlan,
) -> Result<(), Status> {
    let binding = {
        let snapshot = peer.manager.snapshots.load();
        if snapshot.version != packet.snapshot_version {
            return Err(Status::unavailable("SDS snapshot changed before audit"));
        }
        snapshot
            .ownership
            .binding(&node.workspace)
            .ok_or_else(|| Status::permission_denied("SDS workspace withdrawn"))?
    };
    peer.manager
        .audit
        .record_required(crate::admin::audit::AdminAuditPayload {
            workspace: Some(crate::admin::audit::WorkspaceAudit {
                binding,
                candidate_sha256: node.grant_digest.clone(),
                approved_by: None,
            }),
            ts_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            principal: peer.node_id.clone(),
            method: "ADS".into(),
            path: "/xds/sds".into(),
            resource: "secrets".into(),
            action: "read".into(),
            phase: "attempt".into(),
            status: None,
            query_sha256: None,
            config_version: packet.snapshot_version,
        })
        .await
        .map_err(|_| Status::unavailable("SDS durable audit unavailable"))
}
