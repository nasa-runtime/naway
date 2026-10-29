//! 凭据差异借用最终注入值，授权声明只在构建期冻结固定身份。

use super::{UpstreamCredentialCfg, UpstreamCredentialPlan};
use sha2::{Digest, Sha256};

impl UpstreamCredentialPlan {
    /// 业务作用：识别实际注入内容与凭据授权变化，不把后台续租产生的截止点当作配置修改。
    ///
    /// 参数说明：
    /// - `candidate`：已经完成来源解析、归属和冲突校验的候选计划。
    ///
    /// 返回：有序 header/query 及完整绑定身份一致时为真，不读取文件、缓存或当前时间。
    pub(crate) fn configuration_eq(&self, candidate: &Self) -> bool {
        let Self {
            headers,
            query,
            not_after: _,
            binding_identity,
        } = self;
        headers == &candidate.headers
            && query == &candidate.query
            && binding_identity == &candidate.binding_identity
    }
}

/// 业务作用：冻结命名凭据的固定授权，使同值不同归属或远程信任策略进入管理审查。
///
/// 参数说明：
/// - `credentials`：按实际应用次序排列的已验证声明；backend 集已在定义阶段规范排序。
///
/// 返回：长度分隔的固定身份；实际值与目标由消费计划比较，不重复读取或复制材料。
pub(super) fn binding_identity(credentials: &[UpstreamCredentialCfg]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"naway-upstream-credential-binding\0");
    digest.update((credentials.len() as u64).to_be_bytes());
    for credential in credentials {
        let UpstreamCredentialCfg {
            name,
            kind,
            overwrite,
            allowed_backends,
            resolved_policy_identity,
            // 这些来源已经被解析，实际值、目标和 Basic 用户名由注入计划或 TLS 材料身份承载。
            value: _,
            username: _,
            target: _,
            client_certificate: _,
            client_private_key: _,
            resolved_value: _,
            resolved_client_certificate: _,
            resolved_client_private_key: _,
            resolved_not_after: _,
        } = credential;
        for text in [name, kind] {
            part(&mut digest, text.as_bytes());
        }
        digest.update([match overwrite {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        }]);
        digest.update((allowed_backends.len() as u64).to_be_bytes());
        for backend in allowed_backends {
            part(&mut digest, backend.as_bytes());
        }
        digest.update([u8::from(resolved_policy_identity.is_some())]);
        if let Some(identity) = resolved_policy_identity {
            digest.update(identity);
        }
    }
    digest.finalize().into()
}

/// 业务作用：为可变长度授权字段编码长度，避免相邻字段的不同分界产生同一摘要输入。
///
/// 参数说明：
/// - `digest`：当前固定授权摘要。
/// - `bytes`：一个已经验证的字段。
///
/// 返回：只推进摘要，不产生中间序列化结果。
fn part(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}
