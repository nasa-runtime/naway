//! 候选明文和实际受理名额共用生命周期，普通管理响应不能取得该类型。

use crate::control::material::Material;
#[cfg(feature = "admin-operations-pgsql")]
use sha2::{Digest, Sha256};
use tokio::sync::OwnedSemaphorePermit;

/// 材料字段先销毁清零再释放名额；本机后台持有者不会因 HTTP 退出获得额外秘密容量。
pub(in crate::admin) struct Content {
    pub material: Material,
    pub digest: [u8; 32],
    _admission: Option<OwnedSemaphorePermit>,
    _worker: Option<std::sync::Arc<super::session::Work>>,
}

impl Content {
    /// 业务作用：将一次原提案认证产物与整请求名额绑定，同一明文通过 Arc 共享给原目标。
    ///
    /// 参数说明：
    /// - `material`：已经认证并验证完整意图的唯一材料帧。
    /// - `permit`：装载原记录之前取得的真实整请求名额。
    ///
    /// 返回：最后一个持有者退出后先清零材料再释放名额，不产生第二份明文。
    #[cfg(feature = "admin-operations-pgsql")]
    pub(in crate::admin) fn admitted(material: Material, permit: OwnedSemaphorePermit) -> Self {
        Self {
            digest: Sha256::digest(&material.0).into(),
            material,
            _admission: Some(permit),
            _worker: None,
        }
    }

    /// 业务作用：接管原节点在受信短期通道下载的唯一帧，下载和构建名额由节点工作持有。
    ///
    /// 参数说明：
    /// - `material`：已经核对完整长度和命令摘要的有界候选。
    /// - `digest`：分片接收器已逐字节核对的签名摘要，避免重新遍历材料。
    /// - `work`：持有下载与构建真实节点名额的工作，材料清零前不能释放。
    ///
    /// 返回：不复制明文的节点产物，最后持有者退出时自动清零。
    pub(super) fn downloaded(
        material: Material,
        digest: [u8; 32],
        work: std::sync::Arc<super::session::Work>,
    ) -> Self {
        Self {
            material,
            digest,
            _admission: None,
            _worker: Some(work),
        }
    }
}
