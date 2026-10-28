//! 与快照同代的对象归属和依赖图；只有配置权威可建立工作区及跨域引用。

pub mod admission;
mod cluster;
pub mod config;
mod inventory;
pub mod mutation;
#[cfg(feature = "node-actions")]
mod replacement;
mod reservation;
pub mod state;

pub use reservation::ReservationDenied;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::model::GatewayConfig;
use config::{Action, OwnershipCfg, Role, WorkspaceCfg};

pub const PLATFORM: &str = "platform";

/// 归属只来自冻结配置；运行期请求提供的 tenant/workspace 字符串不参与选择。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Owner {
    pub workspace: String,
    pub tenant: String,
    pub environment: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Object {
    pub key: String,
    pub kind: String,
    pub name: String,
    pub parent: Option<String>,
    pub owner: Owner,
    pub labels: BTreeMap<String, String>,
    /// 所有引用指向稳定身份，不把 display name 当作授权边界。
    pub dependencies: BTreeSet<String>,
}

/// 对象及角色是不可变事实；公平运行态由进程级 owner 独立持有，不随快照重建。
pub struct OwnershipCatalog {
    enabled: bool,
    workspaces: BTreeMap<String, WorkspaceCfg>,
    read_authorities: BTreeMap<String, [u8; 32]>,
    objects: BTreeMap<String, Object>,
    route_owners: BTreeMap<String, BTreeMap<String, Owner>>,
    consumers: BTreeMap<String, BTreeMap<String, Arc<str>>>,
    grants: BTreeSet<(String, String)>,
    digest: String,
}

/// 审批、审计与回滚共用的配置权威绑定；摘要改变后旧动作不能继续执行。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Binding {
    pub owner: Owner,
    pub authority_digest: String,
}

/// 已通过认证且按路由归属解析的主体，不允许外部 header 改写。
#[derive(Clone)]
pub(crate) struct Consumer(pub Option<Arc<str>>);

/// 请求期状态域包含入口和归属；同名路由或 owner 转移不能沿用原域账本。
#[derive(Clone)]
pub(crate) struct RequestScope(pub String);

struct Builder<'a> {
    cfg: &'a OwnershipCfg,
    objects: BTreeMap<String, Object>,
    names: BTreeSet<(String, String, String)>,
    referenced_assignments: BTreeSet<String>,
    edges: Vec<(String, String)>,
}

impl OwnershipCatalog {
    /// 业务作用：冻结工作区身份和当前权限图摘要，供低频管理操作绑定候选权威。
    ///
    /// 参数说明：
    /// - `workspace`：是已经过端点授权的固定工作区。
    ///
    /// 返回：存在时返回不可伪造的配置绑定；未知工作区返回 None。
    pub fn binding(&self, workspace: &str) -> Option<Binding> {
        let cfg = self.workspaces.get(workspace)?;
        Some(Binding {
            owner: Owner {
                workspace: workspace.into(),
                tenant: cfg.tenant.clone(),
                environment: cfg.environment.clone(),
            },
            authority_digest: self.digest.clone(),
        })
    }

    /// 业务作用：提供每个审批域可占用的固定容量，防止一个工作区耗尽进程审批队列。
    ///
    /// 参数说明：
    /// - `workspace`：为目标归属；None 表示平台域
    /// - `global`：为进程总审批容量。
    ///
    /// 返回：工作区显式预算，或扣除全部工作区预留后的平台余额。
    pub fn approval_capacity(&self, workspace: Option<&str>, global: usize) -> usize {
        match workspace {
            Some(id) => self
                .workspaces
                .get(id)
                .map_or(0, |cfg| cfg.quota.max_pending_changes),
            None => global.saturating_sub(
                self.workspaces
                    .values()
                    .map(|cfg| cfg.quota.max_pending_changes)
                    .sum::<usize>(),
            ),
        }
    }
    /// 业务作用：在任何候选外呼或资源构建前检查对象归属、配额和跨域引用。
    ///
    /// 参数说明：
    /// - `gateway`：是同次配置加载的强类型候选。
    ///
    /// 返回：不可变权限图；悬空归属、越权依赖、重复名字或容量冲突拒绝整个候选。
    pub fn build(gateway: &GatewayConfig) -> Result<Arc<Self>> {
        let cfg = &gateway.ownership;
        if !cfg.enabled {
            ensure!(
                !gateway
                    .admin
                    .rbac
                    .principals
                    .iter()
                    .any(|principal| principal
                        .roles
                        .contains(&crate::config::model::AdminRole::Workspace)),
                "workspace role requires enabled ownership"
            );
            ensure!(
                cfg.workspaces.is_empty() && cfg.objects.is_empty() && cfg.grants.is_empty(),
                "disabled ownership must not contain declarations"
            );
            return Ok(Arc::new(Self {
                enabled: false,
                workspaces: BTreeMap::new(),
                read_authorities: BTreeMap::new(),
                objects: BTreeMap::new(),
                route_owners: BTreeMap::new(),
                consumers: BTreeMap::new(),
                grants: BTreeSet::new(),
                digest: String::new(),
            }));
        }
        // 归属隔离依赖可认证主体与持久审计；未认证的兼容管理员不能成为委派通道。
        ensure!(
            gateway.admin.auth.enabled && gateway.admin.rbac.enabled && gateway.admin.audit.enabled,
            "ownership requires authenticated RBAC and durable audit"
        );
        ensure!(
            (1..=128).contains(&cfg.workspaces.len())
                && cfg.objects.len() <= 65_536
                && cfg.grants.len() <= 8192,
            "ownership declaration capacity exceeded"
        );
        let principals: BTreeSet<_> = gateway
            .admin
            .rbac
            .principals
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        for principal in &gateway.admin.rbac.principals {
            if principal
                .roles
                .contains(&crate::config::model::AdminRole::Workspace)
            {
                ensure!(
                    principal.roles.len() == 1 && principal.grants.is_empty(),
                    "workspace-only principal cannot hold platform permissions"
                );
            }
        }
        let mut max_objects = 0_usize;
        let mut max_inflight = 0_usize;
        let mut max_states = 0_usize;
        for (id, workspace) in &cfg.workspaces {
            token(id)?;
            ensure!(id != PLATFORM, "platform workspace is reserved");
            token(&workspace.tenant)?;
            token(&workspace.environment)?;
            labels(&workspace.labels)?;
            ensure!(
                !workspace.members.is_empty() && workspace.members.len() <= 256,
                "workspace membership capacity exceeded"
            );
            ensure!(
                workspace
                    .members
                    .values()
                    .any(|role| *role == Role::Administrator),
                "workspace requires an administrator"
            );
            if gateway.admin.approval.enabled {
                ensure!(
                    workspace
                        .members
                        .values()
                        .filter(|role| **role == Role::Administrator)
                        .count()
                        >= 2,
                    "workspace maker-checker requires two administrators"
                );
            }
            for principal in workspace.members.keys() {
                ensure!(
                    principals.contains(principal.as_str()),
                    "workspace references unknown authenticated principal"
                );
            }
            let quota = &workspace.quota;
            ensure!(
                (1..=16_384).contains(&quota.max_objects)
                    && (1..=65_536).contains(&quota.max_inflight)
                    && (1..=128).contains(&quota.max_pending_changes)
                    && (1..=1_000_000).contains(&quota.max_state_entries),
                "invalid workspace quota"
            );
            max_objects = max_objects.saturating_add(quota.max_objects);
            max_inflight = max_inflight.saturating_add(quota.max_inflight);
            max_states = max_states.saturating_add(quota.max_state_entries);
        }
        ensure!(
            max_objects <= 65_536 && max_inflight <= 262_144 && max_states <= 4_000_000,
            "workspace reservation exceeds process capacity"
        );
        ensure!(
            cfg.workspaces
                .values()
                .map(|cfg| cfg.quota.max_pending_changes)
                .sum::<usize>()
                < gateway.admin.approval.max_pending,
            "workspace approval reservations must leave platform capacity"
        );
        let mut builder = Builder {
            cfg,
            objects: BTreeMap::new(),
            names: BTreeSet::new(),
            referenced_assignments: BTreeSet::new(),
            edges: Vec::new(),
        };
        inventory::collect(gateway, &mut builder)?;
        for assignment in cfg.objects.keys() {
            // 拼错或已删除的目标不得静默变成平台对象，删除时必须同步撤掉归属与依赖。
            ensure!(
                builder.referenced_assignments.contains(assignment),
                "ownership assignment references an unknown object"
            );
        }
        let mut grants = BTreeSet::new();
        for grant in &cfg.grants {
            ensure!(
                cfg.workspaces.contains_key(&grant.source_workspace)
                    || grant.source_workspace == PLATFORM,
                "grant references an unknown source workspace"
            );
            let target = builder
                .objects
                .get(&grant.target)
                .context("grant target does not exist")?;
            ensure!(
                target.owner.workspace != grant.source_workspace,
                "same workspace grant is redundant"
            );
            ensure!(
                grants.insert((grant.source_workspace.clone(), grant.target.clone())),
                "duplicate cross-workspace grant"
            );
        }
        for (source, target) in &builder.edges {
            let from = builder
                .objects
                .get(source)
                .context("dependency source is absent")?;
            let to = builder
                .objects
                .get(target)
                .context("dependency target is absent")?;
            // 平台声明也必须显式获得引用目标的授权，避免平台汇聚入口无意扩大租户可见面。
            ensure!(
                from.owner.workspace == to.owner.workspace
                    || grants.contains(&(from.owner.workspace.clone(), target.clone())),
                "cross-workspace reference requires an explicit target grant"
            );
            builder
                .objects
                .get_mut(source)
                .expect("validated source")
                .dependencies
                .insert(target.clone());
        }
        let mut counts = BTreeMap::<&str, usize>::new();
        let mut route_owners = BTreeMap::<String, BTreeMap<String, Owner>>::new();
        let mut consumers = BTreeMap::<String, BTreeMap<String, Arc<str>>>::new();
        for object in builder.objects.values() {
            *counts.entry(&object.owner.workspace).or_default() += 1;
            if let Some(id) = object.key.strip_prefix("consumer:") {
                let names = consumers.entry(object.owner.workspace.clone()).or_default();
                for name in [id, object.name.as_str()] {
                    if let Some(previous) = names.insert(name.to_owned(), Arc::from(id)) {
                        ensure!(
                            previous.as_ref() == id,
                            "consumer alias conflicts with another stable identity"
                        );
                    }
                }
            }
            if object.kind == "route" {
                if let Some((proxy, route)) = object
                    .key
                    .strip_prefix("route:")
                    .and_then(|id| id.split_once('/'))
                {
                    route_owners
                        .entry(proxy.to_owned())
                        .or_default()
                        .insert(route.to_owned(), object.owner.clone());
                }
            }
        }
        for (id, workspace) in &cfg.workspaces {
            ensure!(
                counts.get(id.as_str()).copied().unwrap_or_default() <= workspace.quota.max_objects,
                "workspace object quota exceeded"
            );
        }
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&json!({
                "objects":builder.objects,"authority":cfg
            }))?)
        );
        Ok(Arc::new(Self {
            enabled: true,
            read_authorities: cluster::compile(&cfg.workspaces)?,
            workspaces: cfg.workspaces.clone(),
            objects: builder.objects,
            route_owners,
            consumers,
            grants,
            digest,
        }))
    }

    /// 业务作用：判断当前快照是否启用了工作区边界，供关闭形态跳过额外运行态工作。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅完整归属图验证成功且显式启用时为 true。
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// 业务作用：提供同代工作区读取范围及证明，不复制主体目录或节点列表。
    ///
    /// 参数说明：
    /// - `workspace`：已认证请求选定的工作区身份。
    ///
    /// 返回：该域配置与独立读取摘要；不存在时返回None，不退回平台范围。
    pub(crate) fn cluster_scope(&self, workspace: &str) -> Option<(&WorkspaceCfg, &[u8; 32])> {
        Some((
            self.workspaces.get(workspace)?,
            self.read_authorities.get(workspace)?,
        ))
    }

    /// 业务作用：为受认证的节点上报借用全部固定工作区证明，不输出成员凭据或配置正文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：按工作区身份排序的有界证明迭代器。
    pub(crate) fn cluster_authorities(&self) -> impl Iterator<Item = (&str, &[u8; 32])> {
        self.read_authorities
            .iter()
            .map(|(id, digest)| (id.as_str(), digest))
    }

    /// 业务作用：读取绑定到具体路由的配置权威，不从请求 tenant header 推断归属。
    ///
    /// 参数说明：
    /// - `proxy`：来自已经命中的冻结路由。
    /// - `route`：来自已经命中的冻结路由。
    ///
    /// 返回：启用时返回对应归属；未登记路由不获得任何委派权限。
    pub fn route_owner(&self, proxy: &str, route: &str) -> Option<&Owner> {
        self.route_owners.get(proxy)?.get(route)
    }

    /// 业务作用：让门户等受限入口绑定已登记对象的同一归属，而不是从请求声明推断 owner。
    ///
    /// 参数说明：
    /// - `key`：为固定对象种类与稳定身份。
    ///
    /// 返回：当前已验证的归属；不存在返回 None。
    pub(crate) fn object_owner(&self, key: &str) -> Option<&Owner> {
        self.objects.get(key).map(|object| &object.owner)
    }

    /// 业务作用：在路由工作区内解析已认证 consumer，同名主体不会取得另一域的套餐或策略。
    ///
    /// 参数说明：
    /// - `proxy`：固定入口归属
    /// - `route`：固定入口归属
    /// - `subject`：只能来自已验证认证结果。
    ///
    /// 返回：本域稳定身份或显式共享身份；指向其它域已登记主体却没有 grant 时拒绝。
    pub fn resolve_consumer(
        &self,
        proxy: &str,
        route: &str,
        subject: Arc<str>,
    ) -> Result<Arc<str>> {
        if !self.enabled {
            return Ok(subject);
        }
        let owner = self
            .route_owner(proxy, route)
            .context("consumer route owner unavailable")?;
        if let Some(id) = self
            .consumers
            .get(&owner.workspace)
            .and_then(|names| names.get(subject.as_ref()))
        {
            return Ok(id.clone());
        }
        let key = format!("consumer:{subject}");
        // 未登记的外部主体可使用本路由默认策略；已登记的跨域主体不能以同一个字符串偷用绑定。
        ensure!(
            !self.objects.contains_key(&key)
                || self.grants.contains(&(owner.workspace.clone(), key)),
            "consumer belongs to another workspace"
        );
        Ok(subject)
    }

    /// 业务作用：把身份级策略限制在配置 owner 内，避免同名 consumer 触发其它租户的策略。
    ///
    /// 参数说明：
    /// - `policy`：是稳定策略 id
    /// - `proxy`：是静态目标
    /// - `route`：是静态目标
    /// - `shared`：仅由全局或已匹配服务范围指定。
    ///
    /// 返回：关闭归属、同 owner 或显式共享的上层策略允许物化，未知对象拒绝。
    pub(crate) fn policy_applies(
        &self,
        policy: &str,
        proxy: &str,
        route: &str,
        shared: bool,
    ) -> bool {
        if !self.enabled {
            return true;
        }
        let Some(target) = self.route_owner(proxy, route) else {
            return false;
        };
        self.objects
            .get(&format!("policy:{policy}"))
            .is_some_and(|object| object.owner == *target || shared)
    }

    /// 业务作用：复验已认证主体在当前工作区的动作权限，撤销成员关系下一代立即生效。
    ///
    /// 参数说明：
    /// - `principal`：是认证产生的稳定主体
    /// - `workspace`：是服务端端点范围。
    /// - `action`：是服务端端点范围。
    ///
    /// 返回：只有当前显式角色允许时返回 true，不继承其它工作区角色。
    pub fn allows(&self, principal: &str, workspace: &str, action: Action) -> bool {
        self.workspaces
            .get(workspace)
            .and_then(|w| w.members.get(principal))
            .is_some_and(|role| role.allows(action))
    }

    /// 业务作用：按当前成员关系输出低敏工作区目录，不泄露其它租户的对象数、标签或环境。
    ///
    /// 参数说明：
    /// - `principal`：是认证产生的主体。
    ///
    /// 返回：仅授权工作区的有界摘要数组。
    pub fn list(&self, principal: &str) -> Value {
        Value::Array(
            self.workspaces
                .iter()
                .filter_map(|(id, w)| {
                    w.members.get(principal).map(|role| {
                        json!({
                            "id":id,
                            "tenant":w.tenant,
                            "environment":w.environment,
                            "labels":w.labels,
                            "role":role,
                            "quota":w.quota
                        })
                    })
                })
                .collect(),
        )
    }

    /// 业务作用：输出单工作区归属视图；不读取配置正文、SecretSource 或证书文件。
    ///
    /// 参数说明：
    /// - `principal`：为认证主体
    /// - `workspace`：为固定目标。
    ///
    /// 返回：获授权时返回本域对象和归属摘要，否则不提供存在性信息。
    pub fn objects(&self, principal: &str, workspace: &str) -> Option<Value> {
        self.objects_page(principal, workspace, 0, 128)
    }

    /// 业务作用：有界分页读取本域对象，不因租户对象规模增加单次响应和序列化开销。
    ///
    /// 参数说明：
    /// - `principal`：固定权限
    /// - `workspace`：固定权限
    /// - `offset`：是同代页偏移
    /// - `limit`：最大 128。
    ///
    /// 返回：授权页与下一页偏移；权限或预算非法时不返回对象。
    pub fn objects_page(
        &self,
        principal: &str,
        workspace: &str,
        offset: usize,
        limit: usize,
    ) -> Option<Value> {
        if !self.allows(principal, workspace, Action::Read)
            || !(1..=128).contains(&limit)
            || offset > 65_536
        {
            return None;
        }
        let mut page = self
            .objects
            .values()
            .filter(|o| o.owner.workspace == workspace)
            .skip(offset);
        let values: Vec<_> = page.by_ref().take(limit).collect();
        let next = page.next().map(|_| offset + limit);
        Some(json!({
            "objects":values,
            "next_offset":next,
            "ownership_digest":self.digest
        }))
    }
}

impl Builder<'_> {
    /// 业务作用：登记唯一稳定对象身份并从父对象继承归属，显式覆盖仍由平台配置授权。
    ///
    /// 参数说明：
    /// - `kind`：为固定种类
    /// - `id`：为稳定身份
    /// - `parent`：是可选组合对象。
    ///
    /// 返回：规范对象键；未知 owner、重复身份或同域同名冲突拒绝候选。
    fn add(&mut self, kind: &str, id: &str, parent: Option<&str>) -> Result<String> {
        ensure!(
            !id.is_empty() && id.len() <= 1024 && !id.chars().any(char::is_control),
            "invalid object identity"
        );
        let key = format!("{kind}:{id}");
        let inherited = parent
            .and_then(|key| self.objects.get(key))
            .map(|o| o.owner.workspace.as_str())
            .unwrap_or(if kind == "workspace" {
                id
            } else {
                PLATFORM
            });
        let assignment = self.cfg.objects.get(&key);
        let workspace = assignment.map_or(inherited, |a| a.workspace.as_str());
        let (owner, mut object_labels) = if workspace == PLATFORM {
            (
                Owner {
                    workspace: PLATFORM.into(),
                    tenant: PLATFORM.into(),
                    environment: PLATFORM.into(),
                },
                BTreeMap::new(),
            )
        } else {
            let declaration = self
                .cfg
                .workspaces
                .get(workspace)
                .context("unknown object workspace")?;
            (
                Owner {
                    workspace: workspace.into(),
                    tenant: declaration.tenant.clone(),
                    environment: declaration.environment.clone(),
                },
                declaration.labels.clone(),
            )
        };
        let name = assignment
            .and_then(|a| a.name.as_deref())
            .unwrap_or(id)
            .to_owned();
        if let Some(assignment) = assignment {
            labels(&assignment.labels)?;
            object_labels.extend(assignment.labels.clone());
            self.referenced_assignments.insert(key.clone());
        }
        ensure!(
            !name.is_empty() && name.len() <= 1024 && !name.chars().any(char::is_control),
            "invalid object name"
        );
        ensure!(
            self.names
                .insert((workspace.to_owned(), kind.to_owned(), name.clone())),
            "duplicate object name within workspace"
        );
        ensure!(
            self.objects
                .insert(
                    key.clone(),
                    Object {
                        key: key.clone(),
                        kind: kind.into(),
                        name,
                        parent: parent.map(str::to_owned),
                        owner,
                        labels: object_labels,
                        dependencies: BTreeSet::new()
                    }
                )
                .is_none(),
            "duplicate stable object identity"
        );
        ensure!(
            self.objects.len() <= 65_536,
            "ownership object capacity exceeded"
        );
        Ok(key)
    }

    /// 业务作用：登记待统一复验的引用，避免声明顺序改变授权结果。
    ///
    /// 参数说明：
    /// - `source`：为已登记对象
    /// - `kind`：精确定位目标。
    /// - `id`：精确定位目标。
    ///
    /// 返回：记录有界边；过量引用拒绝候选。
    fn edge(&mut self, source: &str, kind: &str, id: &str) -> Result<()> {
        ensure!(
            self.edges.len() < 262_144,
            "ownership reference capacity exceeded"
        );
        self.edges.push((source.to_owned(), format!("{kind}:{id}")));
        Ok(())
    }
}

/// 业务作用：限制归属和角色标识的可解释命名空间，不允许通配、路径或控制字符。
///
/// 参数说明：
/// - `value`：是候选标识。
///
/// 返回：1..=128 字节字母数字与点、下划线、横线有效，否则拒绝。
fn token(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid ownership token"
    );
    Ok(())
}

/// 业务作用：限制配置标签的大小与字符，避免管理列表把任意文本变成无限元数据。
///
/// 参数说明：
/// - `values`：为工作区或对象标签。
///
/// 返回：最多 16 个短标签有效，否则拒绝候选。
fn labels(values: &BTreeMap<String, String>) -> Result<()> {
    ensure!(values.len() <= 16, "ownership label capacity exceeded");
    for (key, value) in values {
        token(key)?;
        ensure!(
            value.len() <= 256 && !value.chars().any(char::is_control),
            "invalid ownership label value"
        );
    }
    Ok(())
}
