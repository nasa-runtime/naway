//! 会话策略按冻结声明比较，实际系统或文件信任均在构建时取得身份。

use super::WebTransportPolicy;
use sha2::{Digest, Sha256};

impl PartialEq for WebTransportPolicy {
    /// 业务作用：识别固定上游、来源、安全预算与实际信任变化，不触碰正在运行的会话。
    ///
    /// 参数说明：
    /// - `other`：已完成来源规范化及信任解析的候选策略。
    ///
    /// 返回：全部冻结声明一致时为真；根证书容器由同次构建的身份代表。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            upstream,
            allowed_origins,
            roots: _,
            trust_identity,
            connect_timeout_ms,
            budget,
            max_lifetime_ms,
        } = self;
        upstream == &other.upstream
            && allowed_origins == &other.allowed_origins
            && trust_identity == &other.trust_identity
            && connect_timeout_ms == &other.connect_timeout_ms
            && budget == &other.budget
            && max_lifetime_ms == &other.max_lifetime_ms
    }
}

impl Eq for WebTransportPolicy {}

/// 业务作用：对实际接受的信任锚生成固定身份，使系统证书轮换与文件证书轮换都能进入配置差异。
///
/// 参数说明：
/// - `roots`：已完成解析并实际交给 QUIC 客户端的根证书集合。
///
/// 返回：按字段分帧且与枚举顺序无关的摘要；只排序借用引用，不复制证书或重新读取信任来源。
pub(super) fn trust_identity(roots: &tokio_rustls::rustls::RootCertStore) -> [u8; 32] {
    let mut anchors: Vec<_> = roots.roots.iter().collect();
    anchors.sort_unstable_by_key(|anchor| {
        (
            anchor.subject.as_ref(),
            anchor.subject_public_key_info.as_ref(),
            anchor.name_constraints.as_ref().map(|value| value.as_ref()),
        )
    });
    anchors.dedup();
    let mut hash = Sha256::new();
    hash.update((anchors.len() as u64).to_be_bytes());
    for anchor in anchors {
        for field in [
            Some(anchor.subject.as_ref()),
            Some(anchor.subject_public_key_info.as_ref()),
            anchor.name_constraints.as_ref().map(|value| value.as_ref()),
        ] {
            if let Some(bytes) = field {
                hash.update([1]);
                hash.update((bytes.len() as u64).to_be_bytes());
                hash.update(bytes);
            } else {
                hash.update([0]);
            }
        }
    }
    hash.finalize().into()
}
