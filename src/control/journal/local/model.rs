//! 本地文件决定的有限元数据；所有路径与正文引用在副作用之前固定。

use crate::control::documents::{Fingerprint, Target};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

pub(super) const LIMIT: usize = crate::config::document::MAX_DOCUMENT_BYTES;
pub(super) const BODY_NAMES: [&str; 6] = [
    "local-old-guard",
    "local-old-sentinel",
    "local-old-main",
    "local-new-guard",
    "local-new-sentinel",
    "local-new-main",
];

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::control::journal) enum Direction {
    Preparing,
    Forward,
    Backward,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Body {
    pub(super) slot: u8,
    pub(super) fingerprint: Fingerprint,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Location {
    pub(super) path: PathBuf,
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileState {
    pub(super) body: Body,
    pub(super) mode: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Document {
    pub(super) location: Location,
    pub(super) state: FileState,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Destination {
    pub(super) location: Location,
    pub(super) original: Option<FileState>,
    pub(super) candidate: FileState,
    pub(super) forward_stage: String,
    pub(super) backward_stage: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::control::journal) struct Plan {
    pub(in crate::control::journal) operation: String,
    pub(in crate::control::journal) direction: Direction,
    pub(super) baseline: [Document; 3],
    pub(super) targets: [Destination; 3],
}

impl Location {
    /// 业务作用：绑定真实父目录与文件名，进程重启后不能把旧决定应用到替换过的目录。
    ///
    /// 参数说明：
    /// - `target`：已经取得父目录能力的配置位置。
    ///
    /// 返回：有界绝对路径与父目录设备/inode；平台或路径不能稳定表达时拒绝。
    pub(super) fn capture(target: &Target) -> Result<Self> {
        validate_path(&target.path)?;
        let (device, inode) = directory_identity(target)?;
        Ok(Self {
            path: target.path.clone(),
            device,
            inode,
        })
    }

    /// 业务作用：恢复前重新取得相同父目录能力，路径相同而目录已换代时保留保护状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：父目录和真实路径均匹配的目标；缺失、别名漂移或目录替换拒绝。
    pub(super) fn open(&self) -> Result<Target> {
        let target = Target::open(&self.path)?;
        ensure!(
            Self::capture(&target)? == *self,
            "local publication parent identity differs"
        );
        Ok(target)
    }
}

impl Body {
    /// 业务作用：把已校验正文引用映射到六个固定槽，不允许元数据提供任意文件名。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：唯一固定正文槽名；非法引用在状态校验时拒绝。
    pub(super) fn name(self) -> &'static str {
        BODY_NAMES[usize::from(self.slot)]
    }
}

impl Plan {
    /// 业务作用：识别完整基线已包含候选的情况，避免为没有文件变化的请求写入持久决定和正文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：三个明确位置、存在状态、原文和权限全部相同时为真；调用方仍须先复验实际基线。
    pub(super) fn unchanged(&self) -> bool {
        self.baseline
            .iter()
            .zip(&self.targets)
            .all(|(old, target)| {
                old.location == target.location && target.original == Some(target.candidate)
            })
    }

    /// 业务作用：拒绝不完整或相互矛盾的文件决定，恢复不能从损坏元数据推导覆盖权限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：操作身份、路径角色、正文预算与暂存名字全部符合合同；不读取或修改配置。
    pub(in crate::control::journal) fn validate(&self) -> Result<()> {
        ensure!(
            self.operation.len() == 32
                && self
                    .operation
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "local publication operation identity differs"
        );
        let mut old_paths = BTreeSet::new();
        let mut new_paths = BTreeSet::new();
        let mut bodies = [None; 6];
        for (index, (old, target)) in self.baseline.iter().zip(&self.targets).enumerate() {
            validate_path(&old.location.path)?;
            validate_path(&target.location.path)?;
            ensure!(
                old_paths.insert(&old.location.path) && new_paths.insert(&target.location.path),
                "local publication document paths overlap"
            );
            ensure!(
                target.forward_stage == stage_name(&self.operation, index, Direction::Forward)
                    && target.backward_stage
                        == stage_name(&self.operation, index, Direction::Backward),
                "local publication reserved staging name differs"
            );
            if old.location.path == target.location.path {
                ensure!(
                    old.location == target.location && target.original == Some(old.state),
                    "local publication original target differs"
                );
            } else if let Some(original) = target.original {
                // 新引用位置只有已经等于候选才可接纳，不能借路径迁移覆盖未授权的第三份正文。
                ensure!(
                    original == target.candidate,
                    "local publication new target was not a candidate"
                );
            }
            if let Some(original) = target.original {
                ensure!(
                    original.mode == target.candidate.mode,
                    "local publication cannot change target permissions"
                );
            } else {
                ensure!(
                    target.candidate.mode == 0o600,
                    "local publication new target must be private"
                );
            }
            for state in [Some(old.state), target.original, Some(target.candidate)]
                .into_iter()
                .flatten()
            {
                ensure!(
                    usize::from(state.body.slot) < BODY_NAMES.len()
                        && state.body.fingerprint.length <= LIMIT as u64
                        && state.mode & !0o7777 == 0,
                    "local publication body or permissions exceed bounds"
                );
                let reference = &mut bodies[usize::from(state.body.slot)];
                ensure!(
                    reference.is_none_or(|fingerprint| fingerprint == state.body.fingerprint),
                    "local publication body references differ"
                );
                *reference = Some(state.body.fingerprint);
            }
        }
        ensure!(
            self.baseline[2].location == self.targets[2].location,
            "local publication cannot move the bootstrap path"
        );
        for (index, target) in self.targets.iter().enumerate() {
            for (old_index, old) in self.baseline.iter().enumerate() {
                ensure!(
                    index == old_index || target.location.path != old.location.path,
                    "local publication target overlaps another role"
                );
            }
        }
        // 保留名字必须与所有实际目标分离，不能把配置自身误认成可回收的暂存项。
        for target in &self.targets {
            for name in [&target.forward_stage, &target.backward_stage] {
                let path = target
                    .location
                    .path
                    .parent()
                    .context("local publication parent absent")?
                    .join(name);
                ensure!(
                    !old_paths.contains(&path) && !new_paths.contains(&path),
                    "local publication staging overlaps a document"
                );
            }
        }
        Ok(())
    }

    /// 业务作用：枚举当前记录实际引用的有限正文，重复内容仅校验和保存一次。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：按固定槽顺序排列的至多六个原文身份，不读取正文。
    pub(super) fn bodies(&self) -> [Option<Body>; 6] {
        let mut bodies = [None; 6];
        for old in &self.baseline {
            bodies[usize::from(old.state.body.slot)] = Some(old.state.body);
        }
        for target in &self.targets {
            for state in [target.original, Some(target.candidate)]
                .into_iter()
                .flatten()
            {
                bodies[usize::from(state.body.slot)] = Some(state.body);
            }
        }
        bodies
    }
}

/// 业务作用：由已验证随机身份和固定角色产生协议保留名，外部业务标识不能成为路径。
///
/// 参数说明：
/// - `operation`：本次计划的随机十六进制身份。
/// - `index`：guard、Sentinel、main的固定位置。
/// - `direction`：已决定的安装方向。
///
/// 返回：单目录项名字，完整计划必须在创建它之前持久化。
pub(super) fn stage_name(operation: &str, index: usize, direction: Direction) -> String {
    let direction = match direction {
        Direction::Forward => "forward",
        Direction::Backward => "backward",
        Direction::Preparing => "preparing",
    };
    format!(".naway-local-{operation}-{index}-{direction}")
}

/// 业务作用：限定持久路径的长度和组件，恢复不能解释父目录跳转或非规范绝对路径。
///
/// 参数说明：
/// - `path`：待编码或解码的真实配置位置。
///
/// 返回：有界UTF-8绝对文件路径时成功，否则拒绝。
fn validate_path(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .context("local publication path must be UTF-8")?;
    ensure!(
        text.len() <= 4096
            && !text.as_bytes().contains(&0)
            && path.is_absolute()
            && path.file_name().is_some()
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "local publication path differs"
    );
    Ok(())
}

/// 业务作用：提取固定父目录身份，不能仅凭文本位置承认恢复副作用。
///
/// 参数说明：
/// - `target`：持有父目录能力的目标。
///
/// 返回：Unix设备与inode；未支持平台拒绝持久文件恢复。
fn directory_identity(target: &Target) -> Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        let metadata = target.directory.dir_metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        anyhow::bail!("local publication requires Unix filesystem semantics")
    }
}

/// 业务作用：把访问权限纳入精确文件身份，后续恢复不能撤销另一写者设置的新权限。
///
/// 参数说明：
/// - `permissions`：实际打开文件的权限。
///
/// 返回：Unix权限位；未支持平台拒绝。
pub(super) fn mode(permissions: &cap_std::fs::Permissions) -> Result<u32> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        Ok(permissions.mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = permissions;
        anyhow::bail!("local publication permissions are unsupported")
    }
}

/// 业务作用：恢复已记录访问权限，不采用进程umask推测原文件权限。
///
/// 参数说明：
/// - `mode`：已经验证的Unix权限位。
///
/// 返回：可用于文件句柄的权限；未支持平台拒绝。
pub(super) fn permissions(mode: u32) -> Result<cap_std::fs::Permissions> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        Ok(cap_std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        anyhow::bail!("local publication permissions are unsupported")
    }
}
