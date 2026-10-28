//! 永久节点身份的有界、完整性校验记录。

use anyhow::{ensure, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const MAX_RECORD: usize = 4096;
const MAGIC: &[u8; 8] = b"NWYJNL1\0";
const HEADER: usize = 44;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub(super) schema: u32,
    pub(super) node_id: String,
    pub(super) cluster_id: String,
    pub(super) store_id: String,
}

impl Identity {
    /// 业务作用：为显式初始化创建永久节点绑定与不可复用的存储实例身份。
    ///
    /// 参数说明：
    /// - `node`：该目录唯一服务的管理节点。
    /// - `cluster`：该节点接受发行命令的永久集群。
    ///
    /// 返回：合法身份与新随机store ID；非法名称或随机源失败时不产生记录。
    pub(super) fn new(node: &str, cluster: &str) -> Result<Self> {
        validate_names(node, cluster)?;
        let mut random = [0; 32];
        getrandom::getrandom(&mut random)
            .map_err(|_| anyhow::anyhow!("node journal randomness unavailable"))?;
        Ok(Self {
            schema: 1,
            node_id: node.to_owned(),
            cluster_id: cluster.to_owned(),
            store_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random),
        })
    }

    /// 业务作用：把初始化身份编码为完整记录，使截断与字段损坏不能被当成空目录重新受理。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定头、正文长度和SHA-256覆盖的有限原文；超限拒绝，不生成部分证据。
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        let body = serde_json::to_vec(self).context("cannot encode node journal identity")?;
        ensure!(
            body.len() <= MAX_RECORD - HEADER,
            "node journal identity exceeds limit"
        );
        let mut record = Vec::with_capacity(HEADER + body.len());
        record.extend_from_slice(MAGIC);
        record.extend_from_slice(&(body.len() as u32).to_be_bytes());
        record.extend_from_slice(&Sha256::digest(&body));
        record.extend_from_slice(&body);
        Ok(record)
    }

    /// 业务作用：在取得任何节点写权之前复验完整持久身份，未知格式和损坏不得静默迁移。
    ///
    /// 参数说明：
    /// - `record`：已经按记录上限读取至EOF的完整字节。
    ///
    /// 返回：全部结构、校验和及业务身份均合法的记录；失败不修改文件。
    pub(super) fn decode(record: &[u8]) -> Result<Self> {
        ensure!(
            (HEADER..=MAX_RECORD).contains(&record.len()) && &record[..8] == MAGIC,
            "node journal identity format differs"
        );
        let length = u32::from_be_bytes(record[8..12].try_into().expect("fixed identity length"));
        ensure!(
            length as usize == record.len() - HEADER,
            "node journal identity length differs"
        );
        let body = &record[HEADER..];
        ensure!(
            Sha256::digest(body)[..] == record[12..HEADER],
            "node journal identity integrity differs"
        );
        let identity: Self = serde_json::from_slice(body)
            .map_err(|_| anyhow::anyhow!("node journal identity fields differ"))?;
        ensure!(
            identity.schema == 1,
            "node journal identity schema is unsupported"
        );
        validate_names(&identity.node_id, &identity.cluster_id)?;
        let store = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&identity.store_id)
            .map_err(|_| anyhow::anyhow!("node journal store identity is invalid"))?;
        ensure!(
            store.len() == 32 && identity.store_id.len() == 43,
            "node journal store identity is invalid"
        );
        Ok(identity)
    }

    /// 业务作用：重复初始化只确认原永久绑定，不能利用重试更换节点、集群或存储代际。
    ///
    /// 参数说明：
    /// - `node`：本次请求确认的节点身份。
    /// - `cluster`：本次请求确认的集群身份。
    ///
    /// 返回：精确匹配成功，异身份拒绝且不写入。
    pub(super) fn require_binding(&self, node: &str, cluster: &str) -> Result<()> {
        validate_names(node, cluster)?;
        ensure!(
            self.node_id == node && self.cluster_id == cluster,
            "node journal permanent binding differs"
        );
        Ok(())
    }
}

/// 业务作用：复用管理节点与持久集群的名称合同，避免同一身份在磁盘和协议中有不同解释。
///
/// 参数说明：
/// - `node`：管理节点标识。
/// - `cluster`：永久集群标识。
///
/// 返回：两个标识均合法时成功；不合法时不输出输入原文。
fn validate_names(node: &str, cluster: &str) -> Result<()> {
    ensure!(
        crate::admin::management::valid_node_id(node),
        "invalid node journal node identity"
    );
    ensure!(
        crate::config::operations::token(cluster, 128),
        "invalid node journal cluster identity"
    );
    Ok(())
}
