//! 实际加载身份的材料归属随 resolver 保留，后续磁盘换代不能改写已安装事实。

use std::sync::Arc;

/// 只绑定受管来源与不可重用材料代，不保存路径、私钥或私钥摘要。
#[derive(Debug, PartialEq, Eq)]
pub struct ManagedMaterial {
    pub source_id: [u8; 32],
    pub generation: String,
}

/// 完整 pair 加载时的归属证据；合法 TLS 身份不必具有本机受管材料所有权。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaterialProvenance {
    /// SDS、SPIRE 或外部 signer 不具有本机文件交付权威。
    External,
    /// 本次文件加载没有已登记的受管代，读取不收养外部材料。
    Unmanaged,
    /// 元数据损坏、不匹配或来源无法证明；不能由有效叶证书推断所有权。
    Unproven,
    /// 仅供策略预检的候选没有已安装材料代。
    Candidate,
    /// 同一材料锁内读取的完整 pair 与原持久代一致。
    Managed(Arc<ManagedMaterial>),
}
