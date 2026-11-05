//! 材料控制域共享原生身份和授权，持久存储与网络适配由各自入口负责。

pub(crate) mod authorization;
#[cfg(feature = "node-actions")]
pub(crate) mod conditions;
#[cfg(feature = "node-actions")]
pub(crate) mod installation;
mod frame;
#[cfg(all(feature = "admin-operations-pgsql", feature = "node-actions"))]
pub(crate) mod impact;
#[cfg(feature = "admin-operations-pgsql")]
mod target;
pub(crate) use frame::Material;
#[cfg(feature = "admin-operations-pgsql")]
pub(crate) use frame::Summary;
#[cfg(feature = "admin-operations-pgsql")]
pub(crate) use target::Target;

/// 业务作用：编码公开证书或不可逆业务摘要，保持既有持久字段的小写十六进制合同。
///
/// 参数说明：
/// - `bytes`：需要编码的固定摘要。
///
/// 返回：不包含原始材料的规范文本。
#[cfg(feature = "admin-operations-pgsql")]
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("write hexadecimal digest");
    }
    text
}
