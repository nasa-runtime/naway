//! 跨配置换代保留的节点连接和流名额；真实传输释放后才退还容量。

use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct Admission {
    entries: parking_lot::Mutex<BTreeMap<String, [usize; 2]>>,
}

pub(crate) struct Lease {
    admission: Arc<Admission>,
    node: String,
    kind: usize,
}

impl Admission {
    /// 业务作用：在创建认证连接或 ADS 流之前保留节点和全局名额，拒绝通过重连/热更重置占用。
    ///
    /// 参数说明：
    /// - `node`：证书绑定后的服务端节点标识。
    /// - `stream`：为 true 时申请 ADS 流，否则申请已认证物理连接。
    ///
    /// 返回：每节点最多四连接、两流且各自全局不超过 64 时返回 RAII lease；否则立即拒绝。
    pub(crate) fn acquire(
        self: &Arc<Self>,
        node: &str,
        stream: bool,
    ) -> Result<Lease, tonic::Status> {
        let kind = usize::from(stream);
        let mut entries = self.entries.lock();
        if entries.values().map(|v| v[kind]).sum::<usize>() >= 64 {
            return Err(tonic::Status::resource_exhausted(
                "xDS global admission capacity reached",
            ));
        }
        let counts = entries.entry(node.to_owned()).or_default();
        if counts[kind]
            >= if stream {
                2
            } else {
                4
            }
        {
            return Err(tonic::Status::resource_exhausted(
                "xDS node admission capacity reached",
            ));
        }
        counts[kind] += 1;
        if stream {
            super::metrics::STREAMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(Lease {
            admission: self.clone(),
            node: node.to_owned(),
            kind,
        })
    }
}

impl Drop for Lease {
    /// 业务作用：只在连接或响应流真正销毁时释放保留名额，移除无活动引用的节点槽。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；同步减少全局事实与节点占用，不因后台 worker 提前退出而退额。
    fn drop(&mut self) {
        let mut entries = self.admission.entries.lock();
        if let Some(counts) = entries.get_mut(&self.node) {
            counts[self.kind] -= 1;
            if *counts == [0, 0] {
                entries.remove(&self.node);
            }
        }
        if self.kind == 1 {
            super::metrics::STREAMS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
