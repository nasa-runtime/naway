//! 固定目标的有界内部累计采样，不接受页面地址或转发观察者凭据。

use super::super::model;
use crate::admin::cluster::transport::{self, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 业务作用：在完整一秒预算内读取已授权成员的当前样本，任何失败都中止该节点连接。
///
/// 参数说明：
/// - `target`：配置或成员目录已验证的IP与管理端口。
/// - `authorization`：从本机配置派生的Cluster/Read凭据。
///
/// 返回：有限、校验后的当前事实；超时、拒绝、过期或协议不符返回固定原因。
pub(super) async fn fetch(
    target: SocketAddr,
    authorization: &str,
) -> Result<(Arc<model::Sample>, Instant), &'static str> {
    let reply = transport::get(target, authorization, Endpoint::Monitor).await?;
    let mut sample: model::Sample =
        serde_json::from_slice(&reply.bytes).map_err(|_| "invalid_sample")?;
    if !model::validate(&mut sample) {
        return Err("invalid_sample");
    }
    // 只有明确声明且仍新鲜的当前样本才能建立基线；缺失年龄不能被解释为刚采样。
    if reply.age > sample.sampling_period_ms.saturating_mul(3) {
        return Err("stale");
    }
    let sampled = reply
        .started
        .checked_sub(Duration::from_millis(reply.age))
        .ok_or("stale")?;
    Ok((Arc::new(sample), sampled))
}
