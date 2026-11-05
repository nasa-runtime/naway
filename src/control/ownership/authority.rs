//! 归属权威使用固定字段顺序，独立 Data 与 Admin 构建必须得到同一授权摘要。

use super::{Object, config::OwnershipCfg};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io};

#[derive(Serialize)]
struct Declaration<'a> {
    objects: &'a BTreeMap<String, Object>,
    authority: &'a OwnershipCfg,
}

struct HashWriter(Sha256);

/// 业务作用：从完整对象图及归属声明生成跨构建一致的权限绑定，防止序列化选项改变集群授权。
///
/// 参数说明：
/// - `objects`：已完成归属与引用验证、按稳定身份排序的完整对象图。
/// - `authority`：包含成员、配额与显式跨域授权的当前声明。
///
/// 返回：完整声明的 SHA-256 摘要；序列化失败拒绝候选，不发布部分权限图。
pub(super) fn digest(
    objects: &BTreeMap<String, Object>,
    authority: &OwnershipCfg,
) -> anyhow::Result<String> {
    let mut writer = HashWriter(Sha256::new());
    // 直接借用强类型字段并流式散列；经过 Value 会使对象键顺序受依赖 feature 影响，不能用于权威绑定。
    serde_json::to_writer(
        &mut writer,
        &Declaration {
            objects,
            authority,
        },
    )?;
    Ok(format!("{:x}", writer.0.finalize()))
}

impl io::Write for HashWriter {
    /// 业务作用：按协议序列化顺序累计摘要，避免保留第二份完整对象图或序列化正文。
    ///
    /// 参数说明：
    /// - `bytes`：序列化器交付的当前连续片段。
    ///
    /// 返回：整个片段已参与摘要，不产生文件或网络副作用。
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    /// 业务作用：满足序列化器的写入完成约定，摘要接收器没有待刷新的外部状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：立即成功，不改变摘要或发布权限。
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
