//! 精确只读 ZooKeeper Jute 子集；分配前检查帧长，取消读取时保留已接收字节与帧边界。

use anyhow::{ensure, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(super) struct Wire {
    pub io: Box<dyn Io>,
    pending: Vec<u8>,
    received: usize,
    frames: usize,
    budget: usize,
}

impl Wire {
    /// 业务作用：为单次短会话设置全部响应的硬预算，取消后不留下后台读取任务。
    ///
    /// 参数说明：
    /// - `io`：为已验证连接
    /// - `maximum`：为允许的声明正文上限。
    ///
    /// 返回：未发送协议消息的有界会话。
    pub fn new(io: Box<dyn Io>, maximum: usize) -> Self {
        Self {
            io,
            pending: Vec::new(),
            received: 0,
            frames: 0,
            budget: maximum * 2 + 16384,
        }
    }

    /// 业务作用：发送由本地固定操作构造的有限帧，不暴露任意 ZooKeeper 操作给声明。
    ///
    /// 参数说明：
    /// - `payload`：为握手或精确请求。
    ///
    /// 返回：整帧写入成功；网络错误由外层关闭本次会话。
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        ensure!(payload.len() <= 8192, "ZooKeeper request budget reached");
        self.io
            .write_all(&(payload.len() as i32).to_be_bytes())
            .await?;
        self.io.write_all(payload).await?;
        Ok(())
    }

    /// 业务作用：完整接收前先验证帧长，watch 等待超时也不会丢失半帧而误读下一响应。
    ///
    /// 参数说明：
    /// - `maximum`：为本类响应允许的字节数。
    ///
    /// 返回：一帧正文；EOF、负长度、过大长度、消息数或总字节超限均拒绝。
    pub async fn frame(&mut self, maximum: usize) -> Result<Vec<u8>> {
        loop {
            let target = if self.pending.len() < 4 {
                4
            } else {
                let length = i32::from_be_bytes(self.pending[..4].try_into()?);
                // 不按不可信长度 reserve；确认单帧与整轮预算后才逐块接收。
                ensure!(
                    length >= 0 && length as usize <= maximum,
                    "ZooKeeper frame budget reached"
                );
                4 + length as usize
            };
            if self.pending.len() == target {
                self.frames += 1;
                ensure!(self.frames <= 32, "ZooKeeper message budget reached");
                let mut frame = std::mem::take(&mut self.pending);
                frame.drain(..4);
                return Ok(frame);
            }
            let mut chunk = [0u8; 8192];
            let capacity = (target - self.pending.len()).min(chunk.len());
            let length = self.io.read(&mut chunk[..capacity]).await?;
            ensure!(length > 0, "ZooKeeper connection closed");
            self.received += length;
            ensure!(
                self.received <= self.budget,
                "ZooKeeper session byte budget reached"
            );
            self.pending.extend_from_slice(&chunk[..length]);
        }
    }

    /// 业务作用：按 xid 关联唯一在途请求；交错的单键 watch 只能被消费，不能被当作读取响应。
    ///
    /// 参数说明：
    /// - `xid`：为固定协议编号
    /// - `op`：为固定协议编号
    /// - `payload`：为本地精确路径
    /// - `maximum`：约束响应与通知。
    /// - `path`：约束响应与通知。
    ///
    /// 返回：成功响应正文；错误、未知 xid 或非法通知拒绝本轮。
    pub async fn request(
        &mut self,
        xid: i32,
        op: i32,
        payload: &[u8],
        maximum: usize,
        path: &str,
    ) -> Result<Vec<u8>> {
        let mut message = Vec::with_capacity(payload.len() + 8);
        message.extend_from_slice(&xid.to_be_bytes());
        message.extend_from_slice(&op.to_be_bytes());
        message.extend_from_slice(payload);
        self.send(&message).await?;
        loop {
            let frame = self.frame(maximum.max(544)).await?;
            let mut body = frame.as_slice();
            let received_xid = integer(&mut body)?;
            let _zxid = long(&mut body)?;
            ensure!(integer(&mut body)? == 0, "ZooKeeper request rejected");
            if received_xid == -1 {
                event(body, path)?;
                continue;
            }
            ensure!(received_xid == xid, "ZooKeeper response identity mismatch");
            return Ok(body.to_vec());
        }
    }

    /// 业务作用：等待唯一单次 watch 提示；只有下一次完整重读才产生发布证据。
    ///
    /// 参数说明：
    /// - `path`：为唯一允许出现的 znode。
    ///
    /// 返回：合法通知后完成；超时由调用者控制并保留半帧。
    pub async fn watch(&mut self, path: &str) -> Result<()> {
        let frame = self.frame(544).await?;
        let mut body = frame.as_slice();
        ensure!(
            integer(&mut body)? == -1,
            "ZooKeeper watch identity mismatch"
        );
        let _zxid = long(&mut body)?;
        ensure!(integer(&mut body)? == 0, "ZooKeeper watch rejected");
        event(body, path)
    }
}

/// 业务作用：只接收已连接会话的目标键变化，过期会话或未知通知不能获得重读权威。
///
/// 参数说明：
/// - `body`：为通知正文
/// - `path`：是本地固定目标。
///
/// 返回：合法单键删除或变更通知通过，其它通知拒绝。
fn event(mut body: &[u8], path: &str) -> Result<()> {
    let kind = integer(&mut body)?;
    let state = integer(&mut body)?;
    ensure!(
        matches!(kind, 2 | 3)
            && state == 3
            && buffer(&mut body, 512)? == path.as_bytes()
            && body.is_empty(),
        "ZooKeeper watch state rejected"
    );
    Ok(())
}

/// 业务作用：检查剩余长度后消费定长协议字段，截断不能触发越界。
///
/// 参数说明：
/// - `body`：当前帧尚未消费的切片，成功后推进固定长度 N 个字节。
///
/// 返回：指定字段并推进游标，截断拒绝。
fn take<const N: usize>(body: &mut &[u8]) -> Result<[u8; N]> {
    let value = body
        .get(..N)
        .context("ZooKeeper truncated field")?
        .try_into()?;
    *body = &body[N..];
    Ok(value)
}

/// 业务作用：读取有符号 Jute 整数字段，保留错误码及长度的负值语义。
///
/// 参数说明：
/// - `body`：为剩余帧。
///
/// 返回：整数并推进游标，截断拒绝。
pub(super) fn integer(body: &mut &[u8]) -> Result<i32> {
    Ok(i32::from_be_bytes(take(body)?))
}

/// 业务作用：无损读取事务或会话标识，不经过 JSON 浮点转换。
///
/// 参数说明：
/// - `body`：为剩余帧。
///
/// 返回：64 位字段并推进游标，截断拒绝。
pub(super) fn long(body: &mut &[u8]) -> Result<i64> {
    Ok(i64::from_be_bytes(take(body)?))
}

/// 业务作用：限制变长字符串和数据字段，禁止把负长度或越界数据当作空值。
///
/// 参数说明：
/// - `body`：为剩余帧
/// - `maximum`：为该字段的硬上限。
///
/// 返回：借用的字段并推进游标，不额外分配。
pub(super) fn buffer<'a>(body: &mut &'a [u8], maximum: usize) -> Result<&'a [u8]> {
    let length = integer(body)?;
    ensure!(
        length >= 0 && length as usize <= maximum,
        "ZooKeeper field budget reached"
    );
    let value = body
        .get(..length as usize)
        .context("ZooKeeper truncated field")?;
    *body = &body[length as usize..];
    Ok(value)
}

/// 业务作用：编码已受本地预算约束的路径或认证字段。
///
/// 参数说明：
/// - `value`：为本地已验证内容
/// - `output`：为有限请求缓冲区。
///
/// 返回：追加长度和内容，不发生网络副作用。
pub(super) fn put_buffer(value: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(value.len() as i32).to_be_bytes());
    output.extend_from_slice(value);
}
