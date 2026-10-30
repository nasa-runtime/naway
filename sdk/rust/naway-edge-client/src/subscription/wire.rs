//! 区分完整 gRPC 结束状态与传输中断，认证拒绝不能被普通 EOF 吞掉。

use crate::{header_str, EdgeError, Result};
use bytes::Bytes;
use http::HeaderMap;
use http_body_util::BodyExt;

/// 业务作用：解析唯一规范 gRPC 状态，保留明确拒绝而不把缺失或畸形状态解释成成功。
///
/// 参数说明：
/// - `headers`：响应头或最终 trailers。
///
/// 返回：无状态为 None，成功为 Some；非零状态保留原码，重复或非法数字返回协议错误。
pub(super) fn status(headers: &HeaderMap) -> Result<Option<()>> {
    let mut values = headers.get_all("grpc-status").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| EdgeError::Protocol("invalid grpc-status".into()))?;
    if values.next().is_some()
        || !matches!(
            value,
            "0" | "1"
                | "2"
                | "3"
                | "4"
                | "5"
                | "6"
                | "7"
                | "8"
                | "9"
                | "10"
                | "11"
                | "12"
                | "13"
                | "14"
                | "15"
                | "16"
        )
    {
        return Err(EdgeError::Protocol(
            "invalid or repeated grpc-status".into(),
        ));
    }
    if value != "0" {
        return Err(EdgeError::Status {
            status: value.to_owned(),
            message: header_str(headers, "grpc-message")
                .unwrap_or_default()
                .chars()
                .take(1024)
                .collect(),
        });
    }
    Ok(Some(()))
}

/// 业务作用：读取一个非空 DATA 或合法结束，服务端拒绝在流尾也必须传播给订阅状态机。
///
/// 参数说明：
/// - `stream`：当前订阅唯一响应体。
///
/// 返回：DATA 借用共享字节，成功 trailers 返回 None；中断和缺失状态可退避，畸形状态拒绝。
pub(super) async fn next_chunk(stream: &mut hyper::body::Incoming) -> Result<Option<Bytes>> {
    while let Some(frame) = stream.frame().await {
        let frame = frame.map_err(|error| EdgeError::Transport(error.to_string()))?;
        match frame.into_data() {
            Ok(chunk) => {
                if !chunk.is_empty() {
                    return Ok(Some(chunk));
                }
            }
            Err(frame) => {
                let trailers = frame
                    .into_trailers()
                    .map_err(|_| EdgeError::Protocol("unexpected subscription frame".into()))?;
                if status(&trailers)?.is_none() {
                    return Err(EdgeError::Transport(
                        "subscription trailers missing grpc-status".into(),
                    ));
                }
                return Ok(None);
            }
        }
    }
    Err(EdgeError::Transport(
        "subscription ended without grpc-status".into(),
    ))
}
