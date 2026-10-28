//! 文件与记录协议比较直接借用已编译计划，不访问业务文件或后端连接。

use super::Route;

impl Route {
    /// 业务作用：识别静态文件、媒体、CGI 与 WebDAV 的完整策略及固定资源归属变化。
    ///
    /// 参数说明：
    /// - `candidate`：已经完成制品能力和资源边界校验的候选路由。
    ///
    /// 返回：所有已编译资源声明一致时为真；当前内容、mtime、锁和活动请求不参与比较。
    pub(crate) fn same_resource_configuration(&self, candidate: &Self) -> bool {
        let same = self.static_serve == candidate.static_serve;
        #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
        let same = same && self.cgi == candidate.cgi;
        #[cfg(feature = "webdav")]
        let same = same && self.webdav == candidate.webdav;
        same
    }
}
