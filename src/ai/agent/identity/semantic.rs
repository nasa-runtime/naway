//! ACL 比较固定消费者、组与 NASA scope 编译输入，不触碰请求主体或授权计数。

use super::{Acl, Digest, Sha256};

/// 业务作用：冻结 scope 集合身份，避免管理比较复制策略或把声明顺序误判为权限变化。
///
/// 参数说明：
/// - `scopes`：已验证无重复、名称合法且最多 64 项的 scope 声明。
///
/// 返回：排序借用名称后按数量和字节长度分隔的摘要；原文只存于实际 NASA 执行策略。
pub(super) fn scope_identity(scopes: &[String]) -> [u8; 32] {
    let mut ordered: Vec<_> = scopes.iter().map(String::as_str).collect();
    ordered.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(b"naway-agent-acl-scopes\0");
    digest.update((ordered.len() as u64).to_be_bytes());
    for scope in ordered {
        digest.update((scope.len() as u64).to_be_bytes());
        digest.update(scope.as_bytes());
    }
    digest.finalize().into()
}

impl PartialEq for Acl {
    /// 业务作用：比较实际授权维度，防止同名工具改变 scope 要求时遗漏管理差异。
    ///
    /// 参数说明：
    /// - `other`：已通过同一 ACL 构建器的候选权限。
    ///
    /// 返回：消费者、组和 scope 编译输入相同时为真；不构造 Principal 或执行授权请求。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            consumers,
            groups,
            scopes: _,
            scope_identity,
        } = self;
        *consumers == other.consumers
            && *groups == other.groups
            && *scope_identity == other.scope_identity
    }
}

impl Eq for Acl {}
