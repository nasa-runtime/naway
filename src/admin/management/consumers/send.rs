//! 每目标仅保留目录身份和确认偏移，绑定内容由所有目标共享同一个不可变目录。

use super::{encode, protocol, CHUNK};
use crate::admin::consumers::Directory;
use nasa::grpc::{Channel, Code, Status};
use protocol::node_management_client::NodeManagementClient;

#[derive(Default)]
pub(in crate::admin::management) struct Upload {
    generation: Option<(u64, Option<u64>, [u8; 32])>,
    offset: usize,
    complete: bool,
}

impl Upload {
    /// 业务作用：在心跳剩余时间内发送有限分片，旧接收端的能力缺席不会触发此调用。
    ///
    /// 参数说明：
    /// - `client`：原mTLS会话复用通道。
    /// - `facts`：接收端已确认的本轮节点事实。
    /// - `session`：接收端签发的当前启动会话。
    /// - `directory`：各目标共享的同代消费者目录。
    /// - `deadline`：与本轮心跳和其它目录共用的绝对截止。
    ///
    /// 返回：有界进展；错误不隐式重发业务动作或修改心跳新鲜度。
    pub(in crate::admin::management) async fn send(
        &mut self,
        client: &mut NodeManagementClient<Channel>,
        facts: &protocol::NodeFacts,
        session: &[u8],
        directory: &Directory,
        deadline: tokio::time::Instant,
    ) -> Result<(), Status> {
        let generation = (directory.version, directory.fingerprint, directory.digest);
        if self.generation != Some(generation) {
            self.generation = Some(generation);
            self.offset = 0;
            self.complete = false;
        }
        for _ in 0..8 {
            if self.complete {
                break;
            }
            let end = (self.offset + CHUNK).min(directory.entries.len());
            let request = protocol::ConsumersRequest {
                node_id: facts.node_id.clone(),
                boot_id: facts.boot_id.clone(),
                session: session.to_vec(),
                config_version: directory.version,
                config_fingerprint: directory.fingerprint,
                digest: directory.digest.to_vec(),
                total: directory.entries.len() as u32,
                offset: self.offset as u32,
                capacity: directory.capacity,
                entries: directory.entries[self.offset..end]
                    .iter()
                    .map(encode)
                    .collect(),
            };
            let response = match client
                .consumers(super::super::reporter::timed_request(request, deadline)?)
                .await
            {
                Ok(response) => response.into_inner(),
                Err(error) => {
                    if matches!(
                        error.code(),
                        Code::FailedPrecondition | Code::OutOfRange | Code::DataLoss
                    ) {
                        // 接收槽可能随配置或重连退休，从同一完整目录起点恢复，不继承失效偏移。
                        self.offset = 0;
                    }
                    return Err(error);
                }
            };
            let next = response.next_offset as usize;
            if next < end
                || next > directory.entries.len()
                || response.complete != (next == directory.entries.len())
            {
                return Err(Status::data_loss("consumer acknowledgement mismatch"));
            }
            self.offset = next;
            self.complete = response.complete;
        }
        Ok(())
    }
}
