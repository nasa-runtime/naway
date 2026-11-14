//! 应用流的写入观测；原始缓冲、Pending、错误与关闭结果保持透传。

use super::{Direction, Handle};
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 不缓存或预读正文的应用流包装，字节只按底层成功写入累计。
pub struct ObservedIo<T> {
    inner: T,
    handle: Handle,
    direction: Direction,
}

impl<T> ObservedIo<T> {
    /// 业务作用：将既有应用流与冻结所有者绑定，不增加后台任务或逐帧缓冲。
    ///
    /// 参数说明：
    /// - `inner`：经过协议建立阶段后的原应用流。
    /// - `handle`：接入时捕获的监听器所有者。
    /// - `direction`：写入该流的固定转发方向。
    ///
    /// 返回：仅持有原流与固定计数引用的包装，构造本身不分配正文。
    pub(super) fn new(inner: T, handle: Handle, direction: Direction) -> Self {
        Self {
            inner,
            handle,
            direction,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    /// 业务作用：原样读取应用流，不将读取长度重复计为成功转发字节。
    ///
    /// 参数说明：
    /// - `cx`：原异步 I/O 的唤醒上下文。
    /// - `buf`：调用者提供的唯一接收缓冲。
    ///
    /// 返回：原读取结果与缓冲变化，既不预读也不复制正文。
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    /// 业务作用：只按本次底层成功写入的部分累计，写错误或 Pending 不推算字节。
    ///
    /// 参数说明：
    /// - `cx`：原写入任务的唤醒上下文。
    /// - `buf`：调用者拥有的待发送正文切片。
    ///
    /// 返回：与原流一致的写入长度、错误或 Pending，不改变背压与重试语义。
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(length)) = &result {
            self.handle.written(self.direction, *length);
        }
        result
    }

    /// 业务作用：保留原流的分散写入能力，避免为观测把多段正文合并到新缓冲。
    ///
    /// 参数说明：
    /// - `cx`：原写入任务的唤醒上下文。
    /// - `bufs`：调用者拥有的原始正文切片序列。
    ///
    /// 返回：原写入结果；只累计此次确认的总字节数，不按输入长度估计。
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(length)) = &result {
            self.handle.written(self.direction, *length);
        }
        result
    }

    /// 业务作用：向转发器保留底层分散写能力，观测不改变其缓冲选择。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原流的分散写支持声明。
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    /// 业务作用：原样推进应用流刷新，不把重复刷新记为新写入。
    ///
    /// 参数说明：
    /// - `cx`：原刷新任务的唤醒上下文。
    ///
    /// 返回：原流的刷新结果，保持原有背压。
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// 业务作用：原样推进写半边关闭，不将关闭成功推断为远端已确认所有字节。
    ///
    /// 参数说明：
    /// - `cx`：原关闭任务的唤醒上下文。
    ///
    /// 返回：原流的关闭结果；会话终态由唯一生命周期观察器决定。
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
