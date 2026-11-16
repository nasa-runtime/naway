//! 已确认操作的外发适配器；worker统一承担队列、期限、重试和撤销。

use super::{Event, Plan};
use anyhow::Result;
use futures::future::BoxFuture;
use std::sync::Arc;

/// 通知适配器只交付原事件，不写黑名单，也不以网络失败触发整个封禁动作重放。
pub trait AclNotifier: Send {
    /// 业务作用：执行一次原事件投递，成功只代表该出口的接收确认。
    ///
    /// 参数说明：
    /// - `event`：已经确认写入事实的固定事件。
    /// - `body`：所有重试共用的完整原始JSON字节。
    ///
    /// 返回：接收确认成功或固定低敏错误；超时仍可能已经被远端接收。
    fn send<'a>(&'a mut self, event: &'a Event, body: &'a [u8]) -> BoxFuture<'a, Result<()>>;

    /// 业务作用：停止旧出口生产资源，配置换代不能留下继续发送的旧owner。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完成资源停止；失败或超时必须关闭该进程的通知worker，不继续累积新客户端。
    fn shutdown(&mut self) -> BoxFuture<'_, Result<()>> {
        Box::pin(std::future::ready(Ok(())))
    }
}

struct Webhook {
    plan: Arc<Plan>,
}

impl AclNotifier for Webhook {
    /// 业务作用：向固定出口POST原事件并携带精确字节HMAC，不读取响应正文或跟随重定向。
    ///
    /// 参数说明：
    /// - `event`：已确认操作的原身份。
    /// - `body`：重试保持不变的完整事件字节。
    ///
    /// 返回：仅HTTP 2xx确认成功；其它状态、网络或时钟失败不回显远端内容。
    fn send<'a>(&'a mut self, event: &'a Event, body: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let super::plan::Destination::Webhook {
                url,
                key,
                client,
            } = &self.plan.destination
            else {
                anyhow::bail!("ACL webhook plan unavailable");
            };
            let timestamp = super::receiver::now_ms()?.to_string();
            let signature = super::sign_webhook(body, &timestamp, key)?;
            let response = client
                .post(url.clone())
                .header("content-type", "application/json")
                .header("x-naway-acl-event-id", &event.event_id)
                .header("x-naway-acl-timestamp", timestamp)
                .header("x-naway-acl-signature", signature)
                .body(body.to_vec())
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("ACL webhook delivery unavailable"))?;
            anyhow::ensure!(
                response.status().is_success(),
                "ACL webhook delivery was not acknowledged"
            );
            Ok(())
        })
    }
}

/// 业务作用：只在唯一worker实际持有当前操作时创建适配器，不在候选阶段启动外部生产者。
///
/// 参数说明：
/// - `plan`：已经激活且仍有投递资格的原计划。
///
/// 返回：独占发送适配器；默认watch无需外发，不构造适配器。
pub(super) fn build(plan: Arc<Plan>) -> Result<Box<dyn AclNotifier>> {
    match plan.destination {
        super::plan::Destination::Webhook {
            ..
        } => Ok(Box::new(Webhook {
            plan,
        })),
        super::plan::Destination::StoreWatch => {
            anyhow::bail!("ACL store-watch does not use an external notifier")
        }
        #[cfg(feature = "acl-kafka")]
        super::plan::Destination::Kafka(ref spec) => {
            super::kafka::build(spec.clone(), plan.timeout)
        }
        #[cfg(feature = "acl-rocketmq")]
        super::plan::Destination::Rocketmq(ref spec) => Ok(super::rocketmq::build(spec.clone())),
    }
}
