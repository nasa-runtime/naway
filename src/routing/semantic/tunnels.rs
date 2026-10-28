//! 隧道与消息治理比较只借用冻结策略，不访问当前会话、重放账本或消息计数。

use super::Route;

impl Route {
    /// 业务作用：识别 CONNECT、WebTransport、0-RTT 与双向 WebSocket 消息链的完整策略变化。
    ///
    /// 参数说明：
    /// - `candidate`：已完成协议互斥、安全边界和消息插件编译的候选路由。
    ///
    /// 返回：所有隧道及消息策略一致时为真；活动连接和插件运行状态不参与比较。
    pub(crate) fn same_tunnel_configuration(&self, candidate: &Self) -> bool {
        self.forward_proxy == candidate.forward_proxy
            && self.webtransport == candidate.webtransport
            && self.early_data == candidate.early_data
            && self.ws_frame == candidate.ws_frame
    }
}
