//! 只读数据库连接的有限生命周期；取消后的未同步协议状态不能阻塞连接池归还。

use sqlx::{pool::PoolConnection, PgConnection, PgPool, Postgres};
use std::time::Duration;

pub(super) struct Reading {
    connection: Option<PoolConnection<Postgres>>,
}

impl Reading {
    /// 业务作用：为一次有绝对期限的读取获取专用池连接，未完成查询时保持独占所有权。
    ///
    /// 参数说明：
    /// - `pool`：最多四连接且获取期限已固定的管理池。
    ///
    /// 返回：负责取消清理的连接 owner；池不可用时不开始读取。
    pub(super) async fn acquire(pool: &PgPool) -> Result<Self, sqlx::Error> {
        Ok(Self {
            connection: Some(pool.acquire().await?),
        })
    }

    /// 业务作用：只借用当前读取持有的物理会话，禁止同一次查询跨池重取连接。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚未归还的会话；归还消费 owner，因此不会再次借用已转移连接。
    pub(super) fn as_mut(&mut self) -> &mut PgConnection {
        self.connection
            .as_mut()
            .expect("reading owns its connection")
            .as_mut()
    }

    /// 业务作用：完整取得查询事实后有界完成协议清理，失去回包时释放连接而非永久占住池容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：连接已归还或丢弃；该清理不改变已取得的数据库事实。
    pub(super) async fn release(mut self) {
        let mut connection = self.connection.take().expect("reading owns its connection");
        // return_to_pool 将物理连接移入返回的 Future；该 Future 被取消时连同容量 owner 一起释放。
        let _ = tokio::time::timeout(Duration::from_secs(2), connection.return_to_pool()).await;
    }
}

impl Drop for Reading {
    /// 业务作用：在查询失败、超时或取消时关闭仍有未读协议帧的连接，防止污染后续读取。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：物理连接与池容量同步放弃，不创建后台等待服务器响应的任务。
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            // detach 同时释放池容量；丢弃底层连接直接关闭 socket，不尝试无期限协议往返。
            drop(connection.detach());
        }
    }
}
