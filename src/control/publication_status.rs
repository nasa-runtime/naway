//! 本地文件决定的低敏当前观察；存储事实不代表快照已生效。

use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct PublicationStatus {
    pub schema: u32,
    pub state: &'static str,
    pub storage: Option<Storage>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Storage {
    pub cluster_id: String,
    pub store_id: String,
    pub node_admission_epoch: String,
    pub revision: String,
    pub operation_id: Option<String>,
}

impl PublicationStatus {
    /// 业务作用：撤下未确认的提交信息，仅保留当前无法提供文件决定的低敏原因。
    ///
    /// 参数说明：
    /// - `state`：能力关闭、读取不可用或保护等不携带提交证据的固定状态。
    ///
    /// 返回：无存储身份、代际或操作的观察，不沿用先前报告。
    pub(crate) fn empty(state: &'static str) -> Self {
        Self {
            schema: 1,
            state,
            storage: None,
        }
    }

    /// 业务作用：在跨节点接收之前约束状态组合、永久身份和整数，避免把未知状态解释为空闲。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定状态及其必需证据完整合法时为真；任何多余、缺失或非规范字段均拒绝。
    #[cfg(feature = "admin-grpc")]
    pub(crate) fn valid(&self) -> bool {
        use base64::Engine as _;
        if self.schema != 1 {
            return false;
        }
        match self.state {
            "unsupported" | "disabled" | "uninitialized" | "unavailable" | "protected" => {
                self.storage.is_none()
            }
            "idle" | "preparing" | "forward" | "backward" => {
                let Some(storage) = &self.storage else {
                    return false;
                };
                crate::config::operations::token(&storage.cluster_id, 128)
                    && storage.store_id.len() == 43
                    && base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(&storage.store_id)
                        .is_ok_and(|bytes| bytes.len() == 32)
                    && [&storage.node_admission_epoch, &storage.revision]
                        .into_iter()
                        .all(|value| {
                            value
                                .parse::<u64>()
                                .is_ok_and(|number| number > 0 && number.to_string() == *value)
                        })
                    && match &storage.operation_id {
                        None => self.state == "idle",
                        Some(value) => {
                            self.state != "idle"
                                && value.len() == 32
                                && value.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                        }
                    }
            }
            _ => false,
        }
    }
}
