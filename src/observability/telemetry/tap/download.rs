//! 下载名额与最终交付字节共同存活，传输层仍持有数据时不能提前释放容量。

use super::Registry;
use bytes::Bytes;
use std::sync::{atomic::Ordering, Arc};

pub(crate) struct Permit(Arc<Registry>);
struct Payload {
    bytes: Vec<u8>,
    _permit: Permit,
}

impl Permit {
    /// 业务作用：在复制诊断样本前非阻塞取得进程级下载名额。
    ///
    /// 参数说明：
    /// - `registry`：是不随会话或配置代重建的目录。
    ///
    /// 返回：最多八份并行交付；容量不足直接拒绝，不排队保存待交付副本。
    pub(super) fn acquire(registry: &Arc<Registry>) -> anyhow::Result<Self> {
        registry
            .downloads
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 8).then_some(count + 1)
            })
            .map_err(|_| anyhow::anyhow!("diagnostics download capacity reached"))?;
        Ok(Self(registry.clone()))
    }

    /// 业务作用：把名额绑定到不可变 JSON 字节，所有传输切片释放后才归还并发容量。
    ///
    /// 参数说明：
    /// - `value`：是已扣次数、通过终态审计与代际复验的有限诊断文档。
    ///
    /// 返回：持有唯一名额的共享字节；复制或切片不会产生额外名额或提前归还。
    pub(crate) fn bytes(self, value: &serde_json::Value) -> Bytes {
        Bytes::from_owner(Payload {
            bytes: value.to_string().into_bytes(),
            _permit: self,
        })
    }
}

impl Drop for Permit {
    /// 业务作用：审计中止或最后一份交付字节释放后归还进程下载名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：减少全局在途计数，已扣除的会话下载次数不补回。
    fn drop(&mut self) {
        self.0.downloads.fetch_sub(1, Ordering::AcqRel);
    }
}

impl AsRef<[u8]> for Payload {
    /// 业务作用：只向传输层借出已序列化的脱敏数据，不暴露目录和下载权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与持有者同生命周期的固定字节视图。
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
