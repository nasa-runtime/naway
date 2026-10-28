//! 统一HTTP入口的正文观察边界，认证、解码、重试与镜像共享同一次下游消费事实。

use super::*;
use crate::observability::http_stream::{Observed, Tracker};

/// 统一入口已验证的连接元数据与唯一观察权；整组移动到业务管线，不创建额外请求分配。
pub(super) struct Ingress<'a> {
    pub(super) conn: ConnInfo,
    pub(super) downstream_proto: &'static str,
    pub(super) proxy_id: Arc<str>,
    pub(super) connection_client_ip_header: Option<ConnectionClientIpHeader>,
    pub(super) listener_snapshot: Option<Arc<GatewaySnapshot>>,
    pub(super) observation: &'a mut Tracker,
}

impl GatewayProxy {
    /// 业务作用：把请求原始正文和最终响应包在同一生命周期内，所有短路与取消分支都保留真实终态。
    ///
    /// 参数说明：
    /// - `req`：下游原始HTTP请求，正文尚未被认证或内容处理消费。
    /// - `conn`：已验证的连接元数据。
    /// - `downstream_proto`：受信任监听器给出的协议。
    /// - `proxy_id`：逻辑入口身份。
    /// - `connection_client_ip_header`：同一连接的预编码客户端地址。
    /// - `listener_snapshot`：接受连接时的监听配置，可用于既有排空合同。
    ///
    /// 返回：最终响应保留原有头和正文帧；等待取消、正文错误或丢弃均释放观察占用。
    pub(super) async fn handle_observed<B>(
        self: Arc<Self>,
        req: Request<B>,
        conn: ConnInfo,
        downstream_proto: &'static str,
        proxy_id: Arc<str>,
        connection_client_ip_header: Option<ConnectionClientIpHeader>,
        listener_snapshot: Option<Arc<GatewaySnapshot>>,
    ) -> Result<Response<BoxBody>, Infallible>
    where
        B: Body<Data = Bytes> + Unpin + Send + Sync + 'static,
        B::Error: Into<crate::BoxError>,
    {
        let mut tracker = Tracker::response(self.metrics.clone());
        let method = req.method().clone();
        // 先观察原始编码实体，再进入认证和解码；重试或镜像重放不能再次计为下游输入。
        let req = req.map(|body| {
            Observed::request(body, self.metrics.clone())
                .map_err(Into::into)
                .boxed()
        });
        let response = self
            .handle_inner(
                req,
                Ingress {
                    conn,
                    downstream_proto,
                    proxy_id,
                    connection_client_ip_header,
                    listener_snapshot,
                    observation: &mut tracker,
                },
            )
            .await?;
        Ok(tracker.attach(response, &method))
    }
}
