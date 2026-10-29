//! 管理台静态资源白名单；页面壳公开可加载，所有状态由认证API提供。

use super::{AdminState, BoxBody};
use bytes::Bytes;
use http::Response;

/// 业务作用：从编译进制品的固定资源提供管理壳，不按请求路径访问文件系统。
///
/// 参数说明：
/// - `path`：已由HTTP解析器分离的请求路径。
/// - `state`：决定该进程是否允许完整管理界面。
///
/// 返回：控制节点已知资源或None；数据/sidecar节点始终不开放页面。
pub(super) fn asset(path: &str, state: &AdminState) -> Option<Response<BoxBody>> {
    if !state.mode.full_control_plane() {
        return None;
    }
    let (mime, content): (&str, &[u8]) = match path {
        "/monitor" | "/cluster" | "/catalog" | "/operations" | "/traffic" => (
            "text/html; charset=utf-8",
            include_bytes!("assets/index.html"),
        ),
        "/ui/shell.css" => (
            "text/css; charset=utf-8",
            include_bytes!("assets/shell.css"),
        ),
        "/ui/core/http.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/core/http.js"),
        ),
        "/ui/core/dom.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/core/dom.js"),
        ),
        "/ui/core/app.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/core/app.js"),
        ),
        "/ui/views/monitor.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/monitor.js"),
        ),
        "/ui/views/routes.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/routes.js"),
        ),
        "/ui/views/nodes.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/nodes.js"),
        ),
        "/ui/views/nodes/publication.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/nodes/publication.js"),
        ),
        "/ui/views/catalog.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/catalog.js"),
        ),
        "/ui/views/operations.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/operations.js"),
        ),
        "/ui/views/operations/form.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/operations/form.js"),
        ),
        "/ui/views/operations/draft/editor.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("assets/views/operations/draft/editor.js"),
        ),
        "/ui/views/operations/draft/fields.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("assets/views/operations/draft/fields.js"),
        ),
        "/ui/views/operations/draft/schema.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("assets/views/operations/draft/schema.js"),
        ),
        "/ui/views/operations/draft/controls.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("assets/views/operations/draft/controls.js"),
        ),
        "/ui/views/operations/draft/nested.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("assets/views/operations/draft/nested.js"),
        ),
        "/ui/views/operations/detail.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/operations/detail.js"),
        ),
        "/ui/views/operations/execution.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/operations/execution.js"),
        ),
        "/ui/views/operations/targets.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/views/operations/targets.js"),
        ),
        "/ui/workspaces/catalog.js" => (
            "application/javascript; charset=utf-8",
            include_bytes!("assets/workspaces/catalog.js"),
        ),
        _ => return None,
    };
    Some(super::admin_ui_asset(mime, Bytes::from_static(content)))
}
