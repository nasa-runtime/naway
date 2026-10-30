//! 凭据事实独立分片与限额，不因不支持新领域而撤销其它目录或心跳。

mod receive;
mod send;

pub(super) use receive::State;
pub(super) use send::Upload;

use super::protocol;
use crate::admin::consumers::Entry;

pub(super) const STORE_BYTES: usize = 64 * 1024 * 1024;
const CHUNK: usize = 16;

/// 业务作用：把已解码固定字段移交目录所有者，不保留协议壳或复制文本。
///
/// 参数说明：
/// - `value`：仍需检查长度、身份和排序的绑定。
///
/// 返回：没有校验材料的业务条目。
fn decode(value: protocol::ConsumerEntry) -> Entry {
    Entry {
        consumer: value.consumer,
        proxy: value.proxy,
        route: value.route,
        ordinal: value.ordinal,
        source: value.source,
        name: value.name,
        enabled: value.enabled,
        plan: value.plan,
        workspace: value.workspace,
        tenant: value.tenant,
        environment: value.environment,
    }
}

/// 业务作用：只为当前有界分片构造类型化字段，未变化目录不重新编码或复制全量绑定。
///
/// 参数说明：
/// - `value`：当前不可变执行目录的一个条目。
///
/// 返回：仅低敏字段的gRPC消息。
fn encode(value: &Entry) -> protocol::ConsumerEntry {
    protocol::ConsumerEntry {
        consumer: value.consumer.clone(),
        proxy: value.proxy.clone(),
        route: value.route.clone(),
        ordinal: value.ordinal,
        source: value.source.clone(),
        name: value.name.clone(),
        enabled: value.enabled,
        plan: value.plan.clone(),
        workspace: value.workspace.clone(),
        tenant: value.tenant.clone(),
        environment: value.environment.clone(),
    }
}
