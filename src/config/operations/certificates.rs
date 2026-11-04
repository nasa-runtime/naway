//! 独立材料受理开关与有界钥环；关闭时不读取任何加密秘密。

use anyhow::{ensure, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path, sync::Arc};
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub accept_proposals: bool,
    pub write_key_id: String,
    pub keys: BTreeMap<String, String>,
    pub max_material_bytes: u32,
    pub max_total_bytes: u64,
    pub max_records: u32,
    pub max_records_per_scope: u32,
}

impl Default for Config {
    /// 业务作用：材料持久受理默认关闭，并为显式启用提供独立容量上界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无秘密引用的关闭声明；默认单材料一 MiB、全部密文及元数据六十四 MiB。
    fn default() -> Self {
        Self {
            enabled: false,
            accept_proposals: true,
            write_key_id: String::new(),
            keys: BTreeMap::new(),
            max_material_bytes: 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_records: 4096,
            max_records_per_scope: 256,
        }
    }
}

impl Config {
    /// 业务作用：从资源比较或长期资源副本中移除可以热更的受理和秘密声明。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：保留独立功能开关与四项预算；不触碰已经发布的配置。
    pub(super) fn clear_dynamic(&mut self) {
        self.accept_proposals = false;
        self.write_key_id.clear();
        self.keys.clear();
    }
}

/// 解析秘密只由配置快照和正在运行的材料任务共享，不提供诊断或序列化实现。
#[derive(PartialEq, Eq)]
pub(crate) struct Keyring {
    pub(crate) write_key_id: String,
    keys: BTreeMap<String, Arc<Zeroizing<String>>>,
}

impl Keyring {
    /// 业务作用：验证显式材料预算和秘密来源，构建可轮换且会清零的有限钥环。
    ///
    /// 参数说明：
    /// - `config`：材料受理声明；关闭时忽略秘密及其来源。
    /// - `retention`：共享单调受理代与有限保留是否开启。
    /// - `root`：文件型 SecretSource 的配置目录。
    ///
    /// 返回：关闭时为空；非法边界、缺钥或解析失败拒绝候选，不回显来源或秘密。
    pub(super) fn build(
        config: &Config,
        retention: bool,
        root: &Path,
    ) -> Result<Option<Arc<Self>>> {
        if !config.enabled {
            return Ok(None);
        }
        ensure!(
            retention,
            "certificate proposals require operations retention"
        );
        ensure!(
            (1024..=1024 * 1024).contains(&config.max_material_bytes)
                && (1..=4096).contains(&config.max_records)
                && (1..=config.max_records).contains(&config.max_records_per_scope)
                && (u64::from(config.max_material_bytes) * 2 + 65536..=64 * 1024 * 1024)
                    .contains(&config.max_total_bytes),
            "invalid certificate proposal capacity"
        );
        ensure!(
            (1..=8).contains(&config.keys.len())
                && super::token(&config.write_key_id, 64)
                && config.keys.contains_key(&config.write_key_id),
            "invalid certificate proposal keyring"
        );
        let mut keys = BTreeMap::new();
        for (id, source) in &config.keys {
            ensure!(
                super::token(id, 64)
                    && ["env://", "file://", "k8s-file://", "vault-agent://"]
                        .iter()
                        .any(|prefix| source
                            .strip_prefix(prefix)
                            .is_some_and(|tail| !tail.is_empty())),
                "invalid certificate proposal secret source"
            );
            let value = Zeroizing::new(
                crate::security::secret::resolve_text(source, root, "certificate proposal key")
                    .map_err(|_| anyhow::anyhow!("certificate proposal key unavailable"))?,
            );
            ensure!(
                (32..=1024).contains(&value.len()),
                "invalid certificate proposal key length"
            );
            keys.insert(id.clone(), Arc::new(value));
        }
        Ok(Some(Arc::new(Self {
            write_key_id: config.write_key_id.clone(),
            keys,
        })))
    }

    /// 业务作用：按密文冻结的公开 key id 借用对应秘密，不允许缺钥时退回当前写钥。
    ///
    /// 参数说明：
    /// - `id`：新写入或已保存密文声明的精确钥标识。
    ///
    /// 返回：该钥仍在当前配置中时共享其清零容器；已退休或未知标识为空。
    #[cfg(feature = "admin-operations-pgsql")]
    pub(crate) fn get(&self, id: &str) -> Option<Arc<Zeroizing<String>>> {
        self.keys.get(id).cloned()
    }
}
