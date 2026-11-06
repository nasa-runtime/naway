//! 整批方向已经持久后才允许重放原来源，完整目标代存在时跳过，不重复生成材料归属。

use super::super::{generation, legacy, manifest, source::held};
use super::source::{Binding, Goal, Plan};
use crate::control::material::{
    backup::{Backup, PART_LIMIT},
    Material,
};
use anyhow::{Context, Result};

impl Plan {
    /// 业务作用：在新整批方向提交前验证该来源仍是准备时的完整原边界，不能接纳相同代下改写的归属。
    ///
    /// 参数说明：
    /// - `backup`：原固定秘密槽中经过完整校验的唯一备份帧。
    ///
    /// 返回：原声明、目录、owner和完整pair均未变化时成功，不执行底层恢复或文件写入。
    pub(crate) fn require_prepared(&self, backup: &Backup) -> Result<()> {
        let tls = self.declared.files();
        let current = held::Source::capture(&tls, PART_LIMIT)?;
        self.require_original(&current, backup)
    }

    /// 业务作用：在监听收据或恢复后开放路由之前证明全部文件已经属于原持久方向。
    ///
    /// 参数说明：
    /// - `compensation`：原整批补偿代；空表示原正向目标代。
    ///
    /// 返回：完整目标归属成立时成功，不把文件观察解释为监听已加载。
    pub(crate) fn require_goal(&self, compensation: Option<&Goal>) -> Result<()> {
        self.require_locations()?;
        let next = match compensation {
            Some(goal) => {
                goal.validate(self)?;
                &goal.owner
            }
            None => &self.next,
        };
        let tls = self.declared.files();
        let current = held::Source::capture(&tls, PART_LIMIT)?;
        current.require_owner(next)?;
        self.require_locations()
    }

    /// 业务作用：沿用原整批文件方向补齐一个来源，已经完成的精确目标pair保持不写，第三方来源保持保护。
    ///
    /// 参数说明：
    /// - `candidate`：原审批唯一候选帧，已由秘密槽完整校验。
    /// - `backup`：该来源原完整备份帧，不能替换为当前磁盘内容。
    /// - `compensation`：整批Backward预分配的新代；为空执行原Forward目标代。
    ///
    /// 返回：该来源完整目标代已确认时成功；失败保留已提交方向和底层恢复责任，不宣称全部监听成功。
    pub(crate) fn replay(
        &self,
        candidate: &Material,
        backup: &Backup,
        compensation: Option<&Goal>,
    ) -> Result<()> {
        self.require_locations()?;
        self.require_backup(backup)?;
        let (certificate, private_key, previous, next) = match compensation {
            Some(goal) => {
                goal.validate(self)?;
                let (certificate, private_key) = backup.parts()?;
                (certificate, private_key, &self.next, &goal.owner)
            }
            None => {
                let (certificate, private_key) = candidate
                    .parts()
                    .map_err(|_| anyhow::anyhow!("material decided candidate frame differs"))?;
                (certificate, private_key, &self.original, &self.next)
            }
        };
        next.require_material(&self.binding.validate()?, certificate, private_key)?;
        let tls = self.declared.files();
        if tls.keypair_manifest_file.is_none() {
            // 原全批方向已经提交，启动补齐只可结算同一预分配代的底层事务，不能接管后来journal。
            legacy::recover_decided(&tls, &boundary(self, previous)?, next)?;
        }
        let current = held::Source::capture(&tls, PART_LIMIT)?;
        if current.generation() == next.generation {
            current.require_owner(next)?;
            self.require_locations()?;
            return Ok(());
        }
        // 同字节第三方代仍属于另一写者；补偿和正向都必须证明完整旧pair，不能只比较公开叶证书。
        current.require_owner(previous)?;
        if compensation.is_none() {
            self.require_original(&current, backup)?;
        }
        self.require_locations()?;
        match &self.binding {
            Binding::Legacy {
                ..
            } => {
                legacy::install_decided(
                    &tls,
                    certificate,
                    private_key,
                    next.clone(),
                    &boundary(self, previous)?,
                )?;
            }
            Binding::Manifest {
                root,
                ..
            } => {
                let pointer = tls
                    .keypair_manifest_file
                    .as_deref()
                    .context("material decided manifest absent")?;
                let prepared = manifest::prepare_decided(
                    pointer,
                    certificate,
                    private_key,
                    next.clone(),
                    root,
                    || {
                        self.require_locations()?;
                        current.require_owner(previous)
                    },
                )?;
                // 原pair和原指针能力在激活前再次复验；候选目录完整不代表已经获得指针覆盖权。
                current.require_owner(previous)?;
                self.require_locations()?;
                prepared.publish()?;
            }
        }
        let installed = held::Source::capture(&tls, PART_LIMIT)?;
        installed.require_owner(next)?;
        self.require_locations()
    }

    /// 业务作用：在全批补偿决定之前要求该来源仍属于原正向目标，第三方接管后不能借原备份覆盖。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原目录、声明、完整owner及pair均为原next时成功；不恢复底层事务、不写文件。
    pub(crate) fn require_applied(&self) -> Result<()> {
        self.require_goal(None)
    }
}

/// 业务作用：把整批原legacy角色投影为底层事务约束，路径和旧owner均借用原计划。
///
/// 参数说明：
/// - `plan`：原固定来源计划。
/// - `previous`：所选执行或补偿方向唯一允许的旧完整归属。
///
/// 返回：四角色原目录和旧owner借用；manifest不能进入双文件恢复器。
fn boundary<'a>(plan: &'a Plan, previous: &'a generation::Record) -> Result<legacy::Boundary<'a>> {
    if let Binding::Legacy {
        certificate,
        private_key,
        owner,
        transaction,
    } = &plan.binding
    {
        Ok(legacy::Boundary {
            certificate,
            private_key,
            owner,
            transaction,
            previous,
        })
    } else {
        anyhow::bail!("material source is not a legacy transaction")
    }
}

/// 业务作用：整批文件重放与普通安装共用唯一材料锁，来源之间的已提交方向不能被本进程其它写者穿插。
///
/// 参数说明：
/// - `execute`：外层已取得发布权、目录owner并确认原整批方向的同步操作，不得重入安装锁。
///
/// 返回：完整操作结果；互斥锁失效时不执行任何文件动作。
pub(crate) fn locked<T>(execute: impl FnOnce() -> Result<T>) -> Result<T> {
    let _guard = super::super::keypair_install_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("material installation lock is poisoned"))?;
    execute()
}
