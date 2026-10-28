//! 工作区读取证明只绑定授权范围，与对象目录在同一个配置代发布。

use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::admin) struct ScopeAuthority {
    pub workspace: String,
    pub digest: [u8; 32],
}

impl ScopeAuthority {
    /// 业务作用：核算权限证明实际保留的内存，使其与对象共用目录预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：结构体与工作区身份字符串的分配字节。
    pub(in crate::admin) fn bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.workspace.capacity()
    }

    /// 业务作用：限制远端工作区身份为本地授权配置可表达的固定标识。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：非空、最多128字节且只含安全身份字符时有效。
    #[cfg(feature = "admin-grpc")]
    pub(in crate::admin) fn valid(&self) -> bool {
        !self.workspace.is_empty()
            && self.workspace.len() <= 128
            && self
                .workspace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    }
}

/// 业务作用：使分片中的权限证明集合具有独立完整性，保持原对象摘要的协议兼容性。
///
/// 参数说明：
/// - `scopes`：按工作区身份唯一排序的完整权限证明。
///
/// 返回：按长度与固定摘要分隔的SHA-256，不构造中间JSON。
pub(in crate::admin) fn scope_digest(scopes: &[ScopeAuthority]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naway-catalog-scopes\0");
    hash.update((scopes.len() as u64).to_be_bytes());
    for scope in scopes {
        hash.update((scope.workspace.len() as u64).to_be_bytes());
        hash.update(scope.workspace.as_bytes());
        hash.update(scope.digest);
    }
    hash.finalize().into()
}
