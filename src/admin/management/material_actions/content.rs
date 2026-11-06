//! 材料候选始终使用唯一清零帧，工作与请求容量晚于最后一份明文释放。

use crate::control::material::Material;
#[cfg(feature = "admin-operations-workflow-pgsql")]
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;

pub(in crate::admin) struct Content {
    pub material: Material,
    pub digest: [u8; 32],
    _admission: Option<OwnedSemaphorePermit>,
    _worker: Option<Arc<super::Work>>,
}

impl Content {
    /// 业务作用：将原批准解密的唯一材料帧与共享任务容量绑定，节点间只共享Arc而不复制秘密。
    ///
    /// 参数说明：
    /// - `material`：原记录已认证且完整解密的唯一候选帧。
    /// - `permit`：读取原记录之前取得的实际容量。
    ///
    /// 返回：最后持有者先清零材料再释放容量，不取得任何节点文件写权。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(in crate::admin) fn admitted(material: Material, permit: OwnedSemaphorePermit) -> Self {
        Self {
            digest: Sha256::digest(&material.0).into(),
            material,
            _admission: Some(permit),
            _worker: None,
        }
    }

    /// 业务作用：接管已核验摘要的节点下载帧，候选清零前不能释放覆盖下载和执行的真实名额。
    ///
    /// 参数说明：
    /// - `material`：分片接收器唯一且有界的完整帧。
    /// - `digest`：接收器逐字节核对的原签名摘要。
    /// - `work`：同次验签和实际受理的原材料工作。
    ///
    /// 返回：不复制秘密的候选容器；最终销毁顺序为材料、请求名额、节点工作。
    pub(super) fn downloaded(material: Material, digest: [u8; 32], work: Arc<super::Work>) -> Self {
        Self {
            material,
            digest,
            _admission: None,
            _worker: Some(work),
        }
    }
}
