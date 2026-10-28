//! 明确目标集合的原文发布与条件补偿；进程内收据不提供掉电恢复。

use crate::control::documents::{Fingerprint, Original, Staged, Target};
use anyhow::{ensure, Context, Result};
use cap_std::fs::Permissions;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const LIMIT: usize = super::MAX_ARCHIVED_DOCUMENT_BYTES;

/// 业务作用：单主文档切换也必须保持三个真实目标分离，不能借路径声明把配置与规则覆盖成同一文件。
///
/// 参数说明：
/// - `paths`：候选完整合并后的guard、Sentinel和主配置位置。
///
/// 返回：父目录存在、目标各异且已有文件类型合法时成功；不读取正文或创建文件。
pub(crate) fn validate(paths: [&Path; 3]) -> Result<()> {
    let mut targets = BTreeSet::new();
    for path in paths {
        let target = Target::open(path)?;
        ensure!(
            targets.insert(target.path.clone()),
            "configuration document targets must differ"
        );
        target.file()?;
    }
    Ok(())
}

struct Mutation {
    target: Target,
    original: Option<Original>,
    installed: Fingerprint,
    permissions: Permissions,
}

/// 一次已发布集合的精确逆操作证据；不输出配置正文，不跨进程持久化。
pub(crate) struct Publication {
    changes: Vec<Mutation>,
}

/// 业务作用：在触碰任一目标前冻结基线并完成全部原文暂存，阻止规则路径迁移覆盖无关文件。
///
/// 参数说明：
/// - `baseline`：按guard、Sentinel、主文档排列的现有目标与已冻结原文。
/// - `desired`：同次语义构建给出的目标与原文，顺序与基线一致。
///
/// 返回：基线或新目标内容冲突为空且不写目标；成功给出精确补偿收据，I/O失败尝试条件恢复。
pub(crate) fn publish(
    baseline: &[(&Path, &[u8])],
    desired: &[(&Path, &[u8])],
) -> Result<Option<Publication>> {
    ensure!(
        cfg!(unix),
        "document publication requires Unix filesystem semantics"
    );
    ensure!(
        !baseline.is_empty() && baseline.len() <= 3 && baseline.len() == desired.len(),
        "invalid document target count"
    );
    let mut originals = BTreeMap::new();
    let mut roles = BTreeMap::new();
    let mut evidence = Vec::with_capacity(baseline.len());
    for (index, (path, expected)) in baseline.iter().enumerate() {
        let target = Target::open(path)?;
        ensure!(
            roles.insert(target.path.clone(), index).is_none(),
            "configuration document targets must differ"
        );
        let Some(original) = target.read()? else {
            return Ok(None);
        };
        if original.bytes != *expected {
            return Ok(None);
        }
        evidence.push((
            target.clone(),
            original.fingerprint,
            original.permissions.clone(),
        ));
        originals.insert(target.path, original);
    }
    let mut planned = Vec::with_capacity(desired.len());
    let mut paths = BTreeSet::new();
    for (index, (path, bytes)) in desired.iter().enumerate() {
        ensure!(bytes.len() <= LIMIT, "configuration document exceeds limit");
        let target = Target::open(path)?;
        ensure!(
            paths.insert(target.path.clone())
                && roles.get(&target.path).is_none_or(|role| *role == index),
            "configuration document targets overlap another role"
        );
        let original = if roles.contains_key(&target.path) {
            originals.remove(&target.path)
        } else {
            let existing = target.read()?;
            // 未引用过的文件没有被当前配置授予覆盖权；只接纳与候选相同的已有正文。
            if existing.as_ref().is_some_and(|old| old.bytes != *bytes) {
                return Ok(None);
            }
            existing
        };
        if original.as_ref().is_some_and(|old| old.bytes == *bytes) {
            continue;
        }
        let stage = Staged::create(
            &target,
            bytes,
            original.as_ref().map(|old| old.permissions.clone()),
        )?;
        let (installed, permissions) = stage
            .sealed
            .as_ref()
            .expect("completed staging has sealed content")
            .clone();
        planned.push((
            Mutation {
                target,
                original,
                installed,
                permissions,
            },
            stage,
        ));
    }
    // 路径迁移后退出引用的旧文件也属于基线；暂存期间它们变化时同样不能消耗旧发布权。
    for (target, fingerprint, permissions) in evidence {
        if !target.matches(Some((fingerprint, &permissions)))? {
            return Ok(None);
        }
    }
    Ok(Some(commit(planned)?))
}

/// 业务作用：为单主文档入口复用相同的排他暂存、原文比较与精确补偿，不另建可预测临时路径。
///
/// 参数说明：
/// - `path`：固定bootstrap主文档位置。
/// - `bytes`：已完成语义验证的候选原文。
///
/// 返回：当前文件存在时返回精确收据；文件缺失为空，读取、替换或补偿未确认时报错。
pub(crate) fn replace(path: &Path, bytes: &[u8]) -> Result<Option<Publication>> {
    ensure!(
        cfg!(unix),
        "document publication requires Unix filesystem semantics"
    );
    let target = Target::open(path)?;
    let Some(original) = target.read()? else {
        return Ok(None);
    };
    if original.bytes == bytes {
        return Ok(Some(Publication {
            changes: Vec::new(),
        }));
    }
    let stage = Staged::create(&target, bytes, Some(original.permissions.clone()))?;
    let (installed, permissions) = stage
        .sealed
        .as_ref()
        .expect("completed staging has sealed content")
        .clone();
    Ok(Some(commit(vec![(
        Mutation {
            target,
            original: Some(original),
            installed,
            permissions,
        },
        stage,
    )])?))
}

/// 业务作用：把已全部暂存的有限计划按依赖顺序发布，并在任一失败后仅撤销确实发生的替换。
///
/// 参数说明：
/// - `planned`：持有每个原目标和已完整同步临时文件的有限集合。
///
/// 返回：全部已发生替换的收据；错误时条件恢复，补偿不确定不能声明已还原。
fn commit(planned: Vec<(Mutation, Staged)>) -> Result<Publication> {
    let mut publication = Publication {
        changes: Vec::with_capacity(planned.len()),
    };
    for (change, mut staged) in planned {
        let installed = (|| -> Result<()> {
            // 暂存其它文档期间原目标也可能被改动，必须紧邻替换复验，不能延续旧读取的覆盖权。
            ensure!(
                change.target.matches_original(change.original.as_ref())?,
                "configuration document changed before replacement"
            );
            staged.install()?;
            Ok(())
        })();
        // rename已经发生但目录同步失败时仍属于本次副作用，不能遗漏补偿对象。
        if staged.name.is_none() {
            publication.changes.push(change);
        }
        if let Err(error) = installed {
            return match publication.restore() {
                Ok(true) => Err(error),
                Ok(false) => {
                    Err(error).context("document compensation conflicts with another writer")
                }
                Err(restore) => Err(error).context(format!(
                    "document compensation was not confirmed: {restore}"
                )),
            };
        }
    }
    Ok(publication)
}

impl Publication {
    /// 业务作用：只撤销仍属于本次候选的文件副作用，保留原缺失状态且不覆盖后来的第三方内容。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：全部原文或原缺失已恢复并同步时为真；内容漂移为假且不开始恢复，I/O失败显式报错。
    pub(crate) fn restore(self) -> Result<bool> {
        for change in &self.changes {
            if !change
                .target
                .matches(Some((change.installed, &change.permissions)))?
            {
                return Ok(false);
            }
        }
        let mut staged = Vec::with_capacity(self.changes.len());
        for change in &self.changes {
            staged.push(
                change
                    .original
                    .as_ref()
                    .map(|original| {
                        Staged::create(
                            &change.target,
                            &original.bytes,
                            Some(original.permissions.clone()),
                        )
                    })
                    .transpose()?,
            );
        }
        for (change, temporary) in self.changes.iter().zip(&mut staged) {
            // 全集合检查不能替代每个副作用前的检查；后来出现的内容必须留下，不得强制恢复旧配置。
            ensure!(
                change
                    .target
                    .matches(Some((change.installed, &change.permissions)))?,
                "configuration document changed during compensation"
            );
            if let Some(temporary) = temporary {
                temporary.install()?;
            } else {
                change.target.directory.remove_file(&change.target.name)?;
                change.target.sync()?;
            }
        }
        Ok(true)
    }
}
