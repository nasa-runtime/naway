//! 管理成员的固定只读传输；目标、路径和容量来自服务端领域合同。

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio_util::task::AbortOnDropHandle;

#[derive(Clone, Copy)]
pub(in crate::admin) enum Endpoint {
    Monitor,
    Facts,
}

pub(in crate::admin) struct Reply {
    pub bytes: Bytes,
    pub age: u64,
    pub started: Instant,
}

/// 业务作用：约束完整远端只读交换期限，连接、响应头和实体读取共用一秒预算。
///
/// 参数说明：
/// - `target`：已通过成员目录验证的管理地址。
/// - `authorization`：本机配置派生的只读凭据。
/// - `endpoint`：领域固定的路径与实体容量，不接受请求提供的URL。
///
/// 返回：有界当前实体与年龄；失败时随future销毁连接，不自动重试或跟随重定向。
pub(in crate::admin) async fn get(
    target: SocketAddr,
    authorization: &str,
    endpoint: Endpoint,
) -> Result<Reply, &'static str> {
    tokio::time::timeout(
        Duration::from_secs(1),
        exchange(target, authorization, endpoint),
    )
    .await
    .map_err(|_| "timeout")?
}

/// 业务作用：完成固定HTTP交换并在接收每帧前检查实体硬门，单帧实体直接转移Bytes所有权。
///
/// 参数说明：
/// - `target`：配置或已验证发现结果中的IP与端口。
/// - `authorization`：不写入日志或错误文本的节点读取凭据。
/// - `endpoint`：固定读面合同。
///
/// 返回：校验响应状态和年龄后的原始实体；多帧仅在需要拼接时复制。
async fn exchange(
    target: SocketAddr,
    authorization: &str,
    endpoint: Endpoint,
) -> Result<Reply, &'static str> {
    let (path, limit) = match endpoint {
        Endpoint::Monitor => ("/admin/monitor/sample", 1024 * 1024),
        Endpoint::Facts => ("/admin/cluster/facts", 32 * 1024),
    };
    let started = Instant::now();
    let stream = tokio::net::TcpStream::connect(target)
        .await
        .map_err(|_| "unreachable")?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| "protocol")?;
    let _connection = AbortOnDropHandle::new(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request = http::Request::builder()
        .uri(path)
        .header(http::header::HOST, target.to_string())
        .header(http::header::AUTHORIZATION, authorization)
        .header(http::header::CONNECTION, "close")
        .body(http_body_util::Full::<Bytes>::default())
        .map_err(|_| "credential")?;
    let response = sender.send_request(request).await.map_err(|_| "protocol")?;
    if response.status() != http::StatusCode::OK {
        return Err(if response.status() == http::StatusCode::ACCEPTED {
            "sampling"
        } else {
            "rejected"
        });
    }
    let age = response
        .headers()
        .get("x-naway-sample-age-ms")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or("invalid_sample")?;
    let mut body = response.into_body();
    let mut first = Bytes::new();
    let mut joined = BytesMut::new();
    let mut length = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| "protocol")?;
        if let Ok(data) = frame.into_data() {
            // 未知或伪造Content-Length不能绕过实际实体预算，拒绝前不为超额帧分配拼接空间。
            if data.len() > limit - length {
                return Err("capacity");
            }
            if length == 0 {
                first = data;
                length = first.len();
            } else {
                if joined.is_empty() {
                    joined.extend_from_slice(&first);
                    first = Bytes::new();
                }
                joined.extend_from_slice(&data);
                length += data.len();
            }
        }
    }
    Ok(Reply {
        bytes: if joined.is_empty() {
            first
        } else {
            joined.freeze()
        },
        age,
        started,
    })
}
