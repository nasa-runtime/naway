//! 完整工作区候选必须能由既有受限对象动作重放，完整文档不能扩大委派权威。

use super::{
    mutation::{find_object_mut, route_array_mut, Mutation},
    OwnershipCatalog,
};
use anyhow::{ensure, Result};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

impl OwnershipCatalog {
    /// 业务作用：在完整构建前证明原文差异全部属于当前工作区可委派动作，防止完整文档夹带平台或其它租户修改。
    ///
    /// 参数说明：
    /// - `baseline`：已经与原活动主文档 SHA 核对的有限解析树，校验中仅作为重放副本。
    /// - `candidate`：签名候选原字节的有限解析树，不展开环境或改写发布正文。
    /// - `principal`：本机仍具有写入资格的原创建者。
    /// - `workspace`：命令冻结的工作区身份。
    ///
    /// 返回：所有差异能经现有 mutate 合同重放且最终结构完全相等时成功；未知字段、跨域、授权表或顺序变化拒绝。
    pub(crate) fn validate_replacement(
        &self,
        mut baseline: Value,
        mut candidate: Value,
        principal: &str,
        workspace: &str,
    ) -> Result<()> {
        ensure!(
            self.allows(principal, workspace, super::config::Action::Write),
            "workspace replacement denied"
        );
        for (key, owner) in &self.objects {
            if owner.owner.workspace != workspace {
                continue;
            }
            let Some(old) = find_object_mut(&mut baseline, key) else {
                continue;
            };
            let mutation = match find_object_mut(&mut candidate, key) {
                Some(new) if old == new => continue,
                Some(new) => {
                    let old = old
                        .as_object()
                        .ok_or_else(|| anyhow::anyhow!("workspace baseline object is invalid"))?;
                    let new = new
                        .as_object()
                        .ok_or_else(|| anyhow::anyhow!("workspace candidate object is invalid"))?;
                    let keys: BTreeSet<_> = old.keys().chain(new.keys()).collect();
                    let fields: Map<_, _> = keys
                        .into_iter()
                        .filter(|key| old.get(*key) != new.get(*key))
                        .map(|key| (key.clone(), new.get(key).cloned().unwrap_or(Value::Null)))
                        .collect();
                    Mutation::Patch {
                        object: key.clone(),
                        fields,
                    }
                }
                None => Mutation::Delete {
                    object: key.clone(),
                },
            };
            // 所有字段和对象仍由原 mutate 判定，不另建一套较宽松的完整文档权限白名单。
            self.mutate(&mut baseline, principal, workspace, mutation)?;
        }
        for owner in self
            .objects
            .values()
            .filter(|owner| owner.kind == "proxy" && owner.owner.workspace == workspace)
        {
            let proxy = owner
                .key
                .strip_prefix("proxy:")
                .expect("validated proxy identity");
            if let Some(routes) = route_array_mut(&mut candidate, proxy) {
                for route in routes {
                    let Some(id) = route.get("id").and_then(Value::as_str) else {
                        anyhow::bail!("workspace route identity is absent");
                    };
                    if self.objects.contains_key(&format!("route:{proxy}/{id}")) {
                        continue;
                    }
                    self.mutate(
                        &mut baseline,
                        principal,
                        workspace,
                        Mutation::CreateRoute {
                            proxy: proxy.into(),
                            route: route.clone(),
                        },
                    )?;
                }
            }
        }
        // 只验证已识别对象不足以保护平台字段；全部重放后的剩余结构必须逐值等于原候选。
        ensure!(
            baseline == candidate,
            "workspace replacement contains undelegated changes"
        );
        Ok(())
    }
}
