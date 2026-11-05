//! 一次来源解析固定 pair 与归属所在位置，活动指针后续变化不能替换已选的材料证据。

use super::generation;
use crate::config::TlsRuntimeCfg;
use anyhow::Result;
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

pub(super) struct Files<'a> {
    tls: &'a TlsRuntimeCfg,
    directory: Option<PathBuf>,
}

impl<'a> Files<'a> {
    /// 业务作用：在调用方持有材料锁时只解析一次活动指针，后续读取沿用同一来源而不追随新目录。
    ///
    /// 参数说明：
    /// - `tls`：已经完成旧双文件事务恢复的本机来源声明。
    ///
    /// 返回：固定的活动目录或明确 seed/legacy 来源；指针损坏拒绝，不读取秘密正文。
    pub(super) fn capture(tls: &'a TlsRuntimeCfg) -> Result<Self> {
        let directory = tls
            .keypair_manifest_file
            .as_deref()
            .map(super::current_material_directory)
            .transpose()?
            .flatten();
        Ok(Self {
            tls,
            directory,
        })
    }

    /// 业务作用：将完整 pair 的两个角色派生自同一个已选目录，默认来源直接借用配置路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：证书及私钥位置；不重新读取 manifest，也不生成材料或写入权限。
    pub(super) fn paths(&self) -> (Cow<'_, Path>, Cow<'_, Path>) {
        match &self.directory {
            Some(directory) => (
                Cow::Owned(directory.join("cert.pem")),
                Cow::Owned(directory.join("key.pem")),
            ),
            None => (
                Cow::Borrowed(&self.tls.cert_file),
                Cow::Borrowed(&self.tls.key_file),
            ),
        }
    }

    /// 业务作用：只读取与已选 pair 同一来源的归属，旧 seed 和退休目录不能借当前指针的新代补证据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同源合法记录或明确未受管；损坏与跨来源记录拒绝，不回查另一活动目录。
    pub(super) fn owner(&self) -> Result<Option<generation::Record>> {
        let path = if self.tls.keypair_manifest_file.is_some() {
            // seed只属于原文件读取；稍后激活的manifest不能向这次读取补发受管归属。
            let Some(directory) = &self.directory else {
                return Ok(None);
            };
            directory.join(generation::MANIFEST_RECORD)
        } else {
            generation::legacy_path(self.tls)?
        };
        Ok(generation::read(&path, &generation::target(self.tls)?)?.map(|(_, record)| record))
    }

    /// 业务作用：把原条件比较绑定到本次读取来源，manifest切换不能为已读原文提供另一目录的代。
    ///
    /// 参数说明：
    /// - `certificate`：本次从已选来源读取的完整证书。
    /// - `private_key`：条件写入或预检提供的完整私钥；公开目录只比较证书时为空。
    ///
    /// 返回：提供的全部材料与同源归属一致时返回原代，否则为空；损坏记录拒绝，不收养外部材料。
    pub(super) fn current(
        &self,
        certificate: &[u8],
        private_key: Option<&[u8]>,
    ) -> Result<Option<String>> {
        Ok(self
            .owner()?
            .filter(|record| record.matches(certificate, private_key))
            .map(|record| record.generation))
    }
}
