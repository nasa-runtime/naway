//! 按句柄保有订阅流、终止原因与重连截止，没有后台订阅任务或离线消息队列。

mod backoff;
mod wire;

use crate::{
    decode_frame_push, frame, full_request_body, header_str, is_terminal, take_message, EdgeClient,
    EdgeError, Result,
};
use backoff::Backoff;
use bytes::{Bytes, BytesMut};
use hyper::body::{Body, Incoming};

/// 一个按需读取的订阅；关闭或终止后不会重新连接，Drop 释放当前流及重组缓冲。
pub struct Subscription {
    client: EdgeClient,
    group: String,
    stream: Option<Incoming>,
    buffer: BytesMut,
    backoff: Option<Backoff>,
    terminal: Option<EdgeError>,
}

impl Subscription {
    /// 业务作用：冻结订阅身份与有限重连策略，非法配置在任何网络请求之前终止。
    ///
    /// 参数说明：
    /// - `client`：共享连接池与不可变端点契约。
    /// - `group`：本次订阅的明确组名。
    ///
    /// 返回：尚未连接的句柄，配置非法时首次及后续 next 返回同一错误。
    pub(super) fn new(client: EdgeClient, group: String) -> Self {
        let (backoff, terminal) =
            match Backoff::new(client.cfg.reconnect_base, client.cfg.reconnect_max) {
                Ok(backoff) if client.cfg.max_message_bytes > 0 => (Some(backoff), None),
                Ok(_) => (
                    None,
                    Some(EdgeError::Protocol(
                        "max_message_bytes must be positive".into(),
                    )),
                ),
                Err(error) => (None, Some(error)),
            };
        Self {
            client,
            group,
            stream: None,
            buffer: BytesMut::new(),
            backoff,
            terminal,
        }
    }

    /// 业务作用：立即关闭本订阅并释放在途响应与缓冲，后续读取不再拨号。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：幂等终止；未终止句柄后续返回 CANCELLED，已有终止原因保持不变。
    pub fn close(&mut self) {
        if self.terminal.is_none() {
            self.finish(EdgeError::Status {
                status: "1".into(),
                message: "subscription closed".into(),
            });
        }
    }

    /// 业务作用：让调用方区分可继续读取的暂时断流与已经关闭的订阅。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：显式关闭、配置错误、不可重试拒绝或协议错误后为真。
    pub fn is_closed(&self) -> bool {
        self.terminal.is_some()
    }

    /// 业务作用：读取一条完整业务消息，并在可恢复断流后遵守同一句柄的退避截止。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：成功共享 payload 字节；3/7/16或协议错误终止并清理。取消等待可继续使用原句柄，
    /// 传输中断及其它状态退避重连，期间不保留离线消息；终止后的读取只返回原错误。
    pub async fn next(&mut self) -> Result<Bytes> {
        loop {
            if let Some(error) = &self.terminal {
                return Err(error.clone());
            }
            if self.stream.is_none() {
                self.backoff
                    .as_mut()
                    .expect("valid subscription")
                    .wait()
                    .await;
                match self.open().await {
                    Ok(Some(stream)) => self.stream = Some(stream),
                    Ok(None) => {
                        self.disconnected();
                        continue;
                    }
                    Err(error) => {
                        self.failed(error)?;
                        continue;
                    }
                }
            }
            let message = match take_message(&mut self.buffer, self.client.cfg.max_message_bytes) {
                Ok(message) => message,
                Err(error) => return Err(self.finish(error)),
            };
            if let Some(message) = message {
                let payload = match decode_frame_push(&message) {
                    Ok(payload) => payload,
                    Err(error) => return Err(self.finish(error)),
                };
                self.backoff
                    .as_mut()
                    .expect("valid subscription")
                    .delivered();
                return Ok(payload);
            }
            match wire::next_chunk(self.stream.as_mut().expect("opened stream")).await {
                Ok(Some(chunk)) => {
                    if self.buffer.is_empty() {
                        // 独占 DATA 可直接转入重组缓冲；共享底层存储时只在此处做一次必要复制。
                        self.buffer = chunk
                            .try_into_mut()
                            .unwrap_or_else(|bytes| BytesMut::from(bytes.as_ref()));
                    } else {
                        self.buffer.extend_from_slice(&chunk);
                    }
                }
                Ok(None) => {
                    if !self.buffer.is_empty() {
                        return Err(self.finish(EdgeError::Protocol(
                            "successful subscription ended with a partial message".into(),
                        )));
                    }
                    self.disconnected();
                }
                Err(error) => self.failed(error)?,
            }
        }
    }

    /// 业务作用：记录不可恢复原因前先撤下响应流与半帧，旧消息不能在下一次读取中继续交付。
    ///
    /// 参数说明：
    /// - `error`：已裁定的唯一终止原因。
    ///
    /// 返回：保留可重读原因并返回同类错误，释放网络及缓冲容量。
    fn finish(&mut self, error: EdgeError) -> EdgeError {
        self.stream = None;
        self.buffer = BytesMut::new();
        self.backoff = None;
        self.terminal = Some(error.clone());
        error
    }

    /// 业务作用：丢弃断流的全部半帧并登记等待，不能把旧连接的残片拼入新消息。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前响应已释放，下一次拨号受保留的退避截止控制。
    fn disconnected(&mut self) {
        self.stream = None;
        self.buffer = BytesMut::new();
        self.backoff.as_mut().expect("valid subscription").arm();
    }

    /// 业务作用：统一区分明确终止与可重连故障，流头和流尾拒绝使用相同裁决。
    ///
    /// 参数说明：
    /// - `error`：当前拨号、读取或状态解析错误。
    ///
    /// 返回：明确拒绝或协议错误持久终止，其它故障登记退避后继续等待。
    fn failed(&mut self, error: EdgeError) -> Result<()> {
        // 身份拒绝和畸形协议不能靠自动重试重新获取资格，必须由调用者明确创建新订阅。
        if is_terminal(&error) || matches!(error, EdgeError::Protocol(_)) {
            return Err(self.finish(error));
        }
        self.disconnected();
        Ok(())
    }

    /// 业务作用：发送唯一空订阅消息并核对响应合同，立即结束与流式响应各自保留准确状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：正常响应体或合法 trailers-only 成功；拒绝、非法协议及传输失败分别传播。
    async fn open(&self) -> Result<Option<Incoming>> {
        let request = self
            .client
            .base_request(
                &self.client.cfg.subscribe_path,
                "subscribe",
                &self.client.cfg.group_header,
                &self.group,
            )?
            .body(full_request_body(frame(&[])))
            .map_err(|error| EdgeError::Protocol(format!("build subscribe: {error}")))?;
        let response = self
            .client
            .http
            .request(request)
            .await
            .map_err(|error| EdgeError::Transport(error.to_string()))?;
        let ended = wire::status(response.headers())?.is_some();
        let content_type = header_str(response.headers(), "content-type").unwrap_or_default();
        if response.status() != http::StatusCode::OK
            || !(content_type == "application/grpc"
                || content_type.starts_with("application/grpc+")
                || content_type.starts_with("application/grpc;"))
        {
            return Err(EdgeError::Protocol(
                "subscription response must be HTTP 200 application/grpc".into(),
            ));
        }
        if ended {
            if !response.body().is_end_stream() {
                return Err(EdgeError::Protocol(
                    "grpc-status in headers requires a trailers-only response".into(),
                ));
            }
            return Ok(None);
        }
        Ok(Some(response.into_body()))
    }
}
