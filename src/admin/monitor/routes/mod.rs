//! 集群路由当前读面只复用采样事实，工作区需要同代目录授权，不保存历史。

mod aggregate;
mod read;
mod scope;
pub(in crate::admin) use read::read;

use super::model;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub(super) struct Publication {
    pub nodes: Arc<[Node]>,
    pub total: usize,
    pub sequence: u64,
    pub at: Instant,
    pub complete_directory: bool,
}

pub(super) struct Node {
    pub id: String,
    pub availability: &'static str,
    pub sample: Option<Arc<model::Sample>>,
    pub previous: Option<Arc<model::Sample>>,
    pub interval_ms: Option<u64>,
    pub at: Instant,
}

impl Node {
    /// 业务作用：让失败节点保留在覆盖分母中，同时撤下它的所有旧路由事实。
    ///
    /// 参数说明：
    /// - `id`：明确声明的成员身份。
    /// - `availability`：本轮观察失败的有限原因。
    ///
    /// 返回：无旧样本与基线的缺席节点，不将不可观测写为零流量。
    pub(super) fn missing(id: &str, availability: &'static str) -> Self {
        Self {
            id: id.into(),
            availability,
            sample: None,
            previous: None,
            interval_ms: None,
            at: Instant::now(),
        }
    }
}
