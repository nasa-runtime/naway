//! 节点当前动作基线的只读投影；可观察不等于可执行。

use crate::control::publication_status::PublicationStatus;
use crate::{admin::AdminState, config::GatewaySnapshot, control::baseline::NodeBaseline};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub(in crate::admin) struct Observation {
    pub availability: &'static str,
    pub node_baseline: Option<Arc<NodeBaseline>>,
    pub local_publication: Arc<PublicationStatus>,
}

impl Observation {
    /// 业务作用：为没有类型化持久基线协议的节点保留明确能力缺口，不能从HTTP或注册目录猜测。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：unsupported且无基线，不影响既有节点健康读面。
    pub(in crate::admin) fn unsupported() -> Self {
        Self {
            availability: "unsupported",
            node_baseline: None,
            local_publication: Arc::new(PublicationStatus::empty("unsupported")),
        }
    }

    /// 业务作用：在节点失去同次事实权威时一起撤下基线和文件决定，禁止只清除其中一份证据。
    ///
    /// 参数说明：
    /// - `reason`：身份冲突、接收端不可用或配置换代等当前缺失原因。
    ///
    /// 返回：原观察不再持有存储或操作身份，节点成员仍保留在集群覆盖范围内。
    pub(in crate::admin) fn withdraw(&mut self, reason: &'static str) {
        self.availability = reason;
        self.node_baseline = None;
        self.local_publication = Arc::new(PublicationStatus::empty("unavailable"));
    }
}

/// 业务作用：读取本机当前受保护基线，并在异步文件观察后确认原配置仍有发布权。
///
/// 参数说明：
/// - `state`：固定部署角色和唯一配置历史owner。
/// - `snapshot`：本轮事实所使用的活动配置。
///
/// 返回：类型化当前基线或明确能力缺口；不返回路径、正文或目录错误细节。
pub(in crate::admin) async fn collect(
    state: &AdminState,
    snapshot: &Arc<GatewaySnapshot>,
) -> Observation {
    #[cfg(not(feature = "node-journal"))]
    {
        let _ = (state, snapshot);
        Observation::unsupported()
    }
    #[cfg(feature = "node-journal")]
    {
        if !state.mode.runs_data() {
            return Observation::unsupported();
        }
        let observation = state
            .config_history
            .node_observation(snapshot.clone())
            .await;
        // 异步读取不能把旧配置的存储证明附到热更后的当前节点事实。
        if !Arc::ptr_eq(&state.snap.load_full(), snapshot) {
            let mut observation = Observation::unsupported();
            observation.withdraw("unavailable");
            return observation;
        }
        Observation {
            availability: if observation.baseline.is_some() {
                "available"
            } else {
                "unavailable"
            },
            node_baseline: observation.baseline.map(Arc::new),
            local_publication: Arc::new(observation.publication),
        }
    }
}
