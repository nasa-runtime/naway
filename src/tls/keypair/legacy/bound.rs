//! 双文件事务的固定目录能力与持久位置，读取和副作用沿用同一组本机槽位。

use super::super::{generation, io};
use crate::{
    config::TlsRuntimeCfg,
    io::file_target::{Location, Target},
};
use anyhow::{ensure, Context, Result};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use std::{ffi::OsStr, path::Path, sync::Arc};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Locations {
    certificate: Location,
    private_key: Location,
    owner: Location,
    transaction: Location,
}

pub(super) struct Targets<'a> {
    declared: &'a TlsRuntimeCfg,
    pub(super) certificate: Target,
    pub(super) private_key: Target,
    pub(super) owner: Target,
    pub(super) transaction: Target,
}

pub(super) struct Journal {
    target: Target,
    directory: Arc<Dir>,
}

impl<'a> Targets<'a> {
    /// 业务作用：从已持有的原位置计算配对身份，不再次解析可能已经切换的父目录别名。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与同一规范双文件计划一致的域分隔摘要，不读取正文。
    pub(super) fn source(&self) -> [u8; 32] {
        generation::digest_paths(b"legacy", &[&self.certificate.path, &self.private_key.path])
    }
    /// 业务作用：从本机配置取得完整材料的固定父目录，归属与journal共享证书原目录能力。
    ///
    /// 参数说明：
    /// - `tls`：无manifest的本机双文件声明，父目录已经存在。
    /// - `transaction`：当前唯一journal位置，旧兼容声明仍由上层定位。
    ///
    /// 返回：四个角色的目录能力；路径不属于同一受管来源时拒绝，不读取正文。
    pub(super) fn capture(tls: &'a TlsRuntimeCfg, transaction: &Path) -> Result<Self> {
        let certificate = Target::open(&tls.cert_file)?;
        let private_key = Target::open(&tls.key_file)?;
        let owner_path = generation::legacy_path(tls)?;
        let owner =
            certificate.sibling(owner_path.file_name().context("TLS owner name absent")?)?;
        let transaction_target = Target::open(transaction)?;
        // journal及归属必须与该证书共享真实父目录，另一位置的记录不能取得配对写权。
        ensure!(
            Location::capture(&transaction_target)?
                == Location::capture(&certificate.sibling(&transaction_target.name)?)?
                && owner.path == generation::identity_path(&owner_path)?,
            "TLS transaction parent differs from its source"
        );
        Ok(Self {
            declared: tls,
            certificate,
            private_key,
            owner,
            transaction: transaction_target,
        })
    }

    /// 业务作用：在活动文件变化之前冻结完整角色位置，重启后同名新目录不能继承本事务的资格。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：四个角色的原路径及父目录设备/inode；不复制秘密正文。
    pub(super) fn locations(&self) -> Result<Locations> {
        Ok(Locations {
            certificate: Location::capture(&self.certificate)?,
            private_key: Location::capture(&self.private_key)?,
            owner: Location::capture(&self.owner)?,
            transaction: Location::capture(&self.transaction)?,
        })
    }

    /// 业务作用：在批内第一个副作用前复验所有父目录，不能在写完私钥后才发现证书位置已变化。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：所有位置仍指向原目录时成功；后续操作仍使用原句柄，不重新取得路径写权。
    pub(super) fn require_current(&self) -> Result<()> {
        // 固定真实目录不能代替声明复验；父目录别名转向另一来源后，原事务不再代表当前配置。
        ensure!(
            generation::identity_path(&self.declared.cert_file)? == self.certificate.path
                && generation::identity_path(&self.declared.key_file)? == self.private_key.path,
            "TLS declared source location changed"
        );
        for target in [
            &self.certificate,
            &self.private_key,
            &self.owner,
            &self.transaction,
        ] {
            target.require_current()?;
        }
        Ok(())
    }
}

impl Journal {
    /// 业务作用：打开唯一活动恢复目录并固定句柄，后续state与备份不能来自重开路径的另一目录。
    ///
    /// 参数说明：
    /// - `target`：已定位的唯一事务目录项。
    ///
    /// 返回：原普通目录能力；链接、替换或打开失败拒绝。
    pub(super) fn open(target: Target) -> Result<Self> {
        ensure!(
            target.directory.symlink_metadata(&target.name)?.is_dir(),
            "TLS journal must be a directory"
        );
        let directory = Arc::new(target.directory.open_dir(&target.name)?);
        let journal = Self {
            target,
            directory,
        };
        journal.require_current()?;
        Ok(journal)
    }

    /// 业务作用：在原父目录排他创建尚未激活的准备目录，失败不能清理另一个事务的活动证据。
    ///
    /// 参数说明：
    /// - `target`：最终journal的固定位置。
    ///
    /// 返回：随机准备目录的独占句柄；尚未赋予活动文件写入资格。
    pub(super) fn create(target: &Target) -> Result<Self> {
        target.require_current()?;
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).context("TLS preparation entropy unavailable")?;
        let name = format!(
            ".naway-keypair-prepare-{:032x}",
            u128::from_le_bytes(random)
        );
        let temporary = target.sibling(OsStr::new(&name))?;
        temporary.directory.create_dir(&temporary.name)?;
        Self::open(temporary)
    }

    /// 业务作用：将协议固定的正文槽放在已持有journal目录内，备份读取不重新跟随外部目录替换。
    ///
    /// 参数说明：
    /// - `name`：本实现确定的单一材料或state槽名。
    ///
    /// 返回：共享journal能力的文件目标；非法多组件名字拒绝。
    pub(super) fn file(&self, name: &str) -> Result<Target> {
        let target = Target {
            directory: self.directory.clone(),
            path: self.target.path.join("state.json"),
            name: "state.json".into(),
        };
        target.sibling(OsStr::new(name))
    }

    /// 业务作用：复验活动目录项仍由已打开journal持有，旧备份不能覆盖另一事务的证据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：父目录及journal自身的设备/inode都匹配时成功；其它情况保留现场。
    pub(super) fn require_current(&self) -> Result<()> {
        self.target.require_current()?;
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt as _;
            let current = self.target.directory.symlink_metadata(&self.target.name)?;
            let original = self.directory.dir_metadata()?;
            ensure!(
                current.is_dir()
                    && current.dev() == original.dev()
                    && current.ino() == original.ino(),
                "TLS journal directory identity changed"
            );
        }
        #[cfg(not(unix))]
        anyhow::bail!("TLS journal requires Unix filesystem semantics");
        Ok(())
    }

    /// 业务作用：先同步完整准备目录，再在原父目录激活唯一恢复入口，之后才能修改活动材料。
    ///
    /// 参数说明：
    /// - `destination`：已固定的最终journal槽。
    ///
    /// 返回：恢复入口已同步时成功；rename后的同步错误保留活动目录，不能当准备失败删除。
    pub(super) fn publish(&mut self, destination: &Target) -> Result<()> {
        self.require_current()?;
        destination.require_current()?;
        // 已有恢复入口不属于本次暂存；同一进程的材料事务由外层安装锁串行化。
        match destination.directory.symlink_metadata(&destination.name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => anyhow::bail!("TLS active journal already exists or is unavailable"),
        }
        self.directory.try_clone()?.into_std_file().sync_all()?;
        self.target.directory.rename(
            &self.target.name,
            &destination.directory,
            &destination.name,
        )?;
        self.target = destination.clone();
        destination.sync()?;
        self.require_current()
    }

    /// 业务作用：完成完整材料与归属后先退休恢复入口，再清理本次已退休备份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：退休与清理均已同步时成功；未知同步保留退休目录，不删除活动恢复入口的部分文件。
    pub(super) fn finish(&self) -> Result<()> {
        self.require_current()?;
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).context("TLS retirement entropy unavailable")?;
        let name = format!(
            ".naway-keypair-retired-{:032x}",
            u128::from_le_bytes(random)
        );
        // 先撤下完整恢复入口，删除阶段崩溃不能留下会被自动恢复的半份journal。
        self.target
            .directory
            .rename(&self.target.name, &self.target.directory, &name)?;
        self.target.sync()?;
        self.target.directory.remove_dir_all(&name)?;
        self.target.sync()
    }

    /// 业务作用：仅撤销尚未发布的精确准备目录，出错时不清理同名后来事务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原目录身份成立才删除；失败由调用者保留原准备错误，不扩展为其它路径清理权。
    pub(super) fn discard(&self) -> Result<()> {
        self.require_current()?;
        self.target.directory.remove_dir_all(&self.target.name)?;
        self.target.sync()
    }
}

/// 业务作用：在固定材料槽上读取完整有界归属，不沿用路径重开取得另一父目录的owner。
///
/// 参数说明：
/// - `target`：本事务持有的owner槽。
/// - `source`：当前完整材料来源摘要。
///
/// 返回：缺失为空，合法时保留原文字节与记录；格式或来源错误拒绝。
pub(super) fn owner(
    target: &Target,
    source: &[u8; 32],
) -> Result<Option<(zeroize::Zeroizing<Vec<u8>>, generation::Record)>> {
    let Some(bytes) = io::read(target, 4096)? else {
        return Ok(None);
    };
    let record: generation::Record =
        serde_json::from_slice(&bytes).context("parse TLS generation")?;
    record.validate(source)?;
    Ok(Some((bytes, record)))
}
