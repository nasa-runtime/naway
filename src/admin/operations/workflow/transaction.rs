//! 推进锁只覆盖数据库事实，任何远程交付都在提交和释放锁之后进行。

use super::super::{model::Error, store::DATASOURCE, Store};
use std::future::Future;

impl Store {
    /// 业务作用：让同一 schema 的创建、结果和定时器在复验方向后推进，防止旧 Resolve 跨方向解释。
    ///
    /// 参数说明：
    /// - `body`：只执行本数据库的有限工作流事实变更，不得包含节点网络或文件动作。
    ///
    /// 返回：同源事务明确提交的值；其它 Admin 正在推进时立即返回容量不足，未知提交保留原分类。
    pub(in crate::admin::operations) async fn workflow_transaction<T>(
        &self,
        body: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        if self.stopping.is_cancelled() || !self.delivery_installed || self.workflow.get().is_none()
        {
            return Err(Error::Unavailable);
        }
        self.transaction(Box::pin(async {
            {
                let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                    .await
                    .map_err(|_| Error::Unavailable)?;
                // 独立 Naway 锁域只串行有限状态推进；竞争不占住池等待，更不能把此锁延伸到节点交付。
                let acquired: bool = sqlx::query_scalar(
                    "SELECT pg_try_advisory_xact_lock(1851881313, hashtext(current_schema()))",
                )
                .fetch_one(connection.as_mut())
                .await
                .map_err(|_| Error::Unavailable)?;
                if !acquired {
                    return Err(Error::Capacity);
                }
            }
            if self.stopping.is_cancelled() {
                return Err(Error::Unavailable);
            }
            body.await
        }))
        .await
    }
}
