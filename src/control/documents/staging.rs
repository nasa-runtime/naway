//! 进程内候选暂存的排他创建、提交与精确清理。

use super::{target::same_file, Fingerprint, Target, LIMIT};
use anyhow::{ensure, Context, Result};
use base64::Engine as _;
use cap_std::fs::{File, OpenOptions, Permissions};
use std::ffi::OsString;
use std::io::{ErrorKind, Write};

pub(in crate::control) struct Staged {
    target: Target,
    pub(in crate::control) name: Option<OsString>,
    file: File,
    pub(in crate::control) sealed: Option<(Fingerprint, Permissions)>,
}

impl Staged {
    /// 业务作用：排他建立私有随机临时文件并完整同步，所有目标准备完成之前不触碰活动文件。
    ///
    /// 参数说明：
    /// - `target`：已经固定目录的最终位置。
    /// - `bytes`：直接写入的有限原文。
    /// - `permissions`：原文件权限；为空时保留排他创建的新文件私有权限。
    ///
    /// 返回：独占临时文件owner；任何失败由该owner精确清理自己的临时项。
    pub(in crate::control) fn create(
        target: &Target,
        bytes: &[u8],
        permissions: Option<Permissions>,
    ) -> Result<Self> {
        ensure!(bytes.len() <= LIMIT, "configuration document exceeds limit");
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| anyhow::anyhow!("configuration staging randomness unavailable"))?;
        let suffix = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        let name = OsString::from(format!(".naway-document-{suffix}"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = target.directory.open_with(&name, &options)?;
        let mut staged = Self {
            target: target.clone(),
            name: Some(name),
            file,
            sealed: None,
        };
        staged.file.write_all(bytes)?;
        if let Some(permissions) = permissions {
            staged.file.set_permissions(permissions)?;
        }
        staged.file.sync_all()?;
        staged.sealed = Some((
            Fingerprint::of(bytes),
            staged.file.metadata()?.permissions(),
        ));
        Ok(staged)
    }

    /// 业务作用：以原子目录项替换提交单个已完整同步的文档，并把真实副作用交给补偿收据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：rename及目录同步完成；同步失败时name已为空，调用方必须记入已发生的替换。
    pub(in crate::control) fn install(&mut self) -> Result<()> {
        let name = self
            .name
            .as_ref()
            .context("configuration staging file already installed")?;
        // 暂存成功不能证明目录项或内容此刻仍属于本候选，外部替换不得被发布到活动配置。
        ensure!(
            same_file(
                &self.target.directory.symlink_metadata(name)?,
                &self.file.metadata()?
            ),
            "configuration staging owner changed"
        );
        let (fingerprint, permissions) = self
            .sealed
            .as_ref()
            .context("configuration staging is incomplete")?;
        let mut temporary = self.target.clone();
        temporary.name = name.clone();
        ensure!(
            temporary.matches(Some((*fingerprint, permissions)))?,
            "configuration staging content changed"
        );
        self.target
            .directory
            .rename(name, &self.target.directory, &self.target.name)?;
        self.name = None;
        self.target.sync()
    }
}

impl Drop for Staged {
    /// 业务作用：清理仍未发布的精确临时项，取消请求或错误不能留下失去owner的随机文件。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有未提交文件时无副作用；清理失败记录固定原因，不递归删除其它内容。
    fn drop(&mut self) {
        if let Some(name) = &self.name {
            // 路径曾由本owner排他创建不代表现在仍属于它；外部替换过的目录项必须保留。
            match (
                self.target.directory.symlink_metadata(name),
                self.file.metadata(),
            ) {
                (Err(error), _) if error.kind() == ErrorKind::NotFound => return,
                (Ok(current), Ok(original)) if same_file(&current, &original) => {}
                _ => {
                    tracing::warn!(
                        "configuration staging ownership changed; preserving directory entry"
                    );
                    return;
                }
            }
            if let Err(error) = self.target.directory.remove_file(name) {
                if error.kind() != ErrorKind::NotFound {
                    tracing::warn!(%error, "configuration staging cleanup failed");
                }
            }
        }
    }
}
