//! 动作意图引用的节点存储与原文基线，不代表授权或执行成功。

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeBaseline {
    pub schema: u32,
    pub cluster_id: String,
    pub store_id: String,
    pub node_admission_epoch: String,
    pub documents_sha256: String,
}

impl NodeBaseline {
    /// 业务作用：限定冻结基线的完整编码，避免截断代际、歧义存储身份或弱摘要进入动作意图。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：格式完整且代际为规范正u64时为true；不证明这些声明已由目标节点确认。
    #[cfg(any(feature = "admin-grpc", feature = "admin-operations-pgsql"))]
    pub(crate) fn valid(&self) -> bool {
        use base64::Engine as _;
        self.schema == 1
            && crate::config::operations::token(&self.cluster_id, 128)
            && self.store_id.len() == 43
            && base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&self.store_id)
                .is_ok_and(|bytes| bytes.len() == 32)
            && self
                .node_admission_epoch
                .parse::<u64>()
                .is_ok_and(|epoch| epoch > 0 && epoch.to_string() == self.node_admission_epoch)
            && self.documents_sha256.len() == 64
            && self
                .documents_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    /// 业务作用：将已验证存储事实和固定原文摘要转换为可精确往返的低敏声明。
    ///
    /// 参数说明：
    /// - `cluster`：永久发行集群身份。
    /// - `store`：永久随机存储身份。
    /// - `epoch`：节点已提交且未关闭的受理代际。
    /// - `digest`：三个base原文的域分隔SHA-256。
    ///
    /// 返回：固定schema声明，代际用字符串避免JSON消费方丢失整数精度。
    #[cfg(feature = "admin-grpc")]
    pub(crate) fn from_parts(
        cluster: String,
        store: String,
        epoch: u64,
        digest: &[u8; 32],
    ) -> Self {
        use std::fmt::Write as _;
        let mut documents_sha256 = String::with_capacity(64);
        for byte in digest {
            write!(&mut documents_sha256, "{byte:02x}").expect("writing digest to String");
        }
        Self {
            schema: 1,
            cluster_id: cluster,
            store_id: store,
            node_admission_epoch: epoch.to_string(),
            documents_sha256,
        }
    }
}
