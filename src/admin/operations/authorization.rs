//! 提案授权来自当前管理主体与工作区目录，不能由请求正文扩大范围。

use super::model::{Domain, Error};
use crate::config::GatewaySnapshot;
use crate::control::actions::authorization::Scope as AuthorityScope;
use crate::control::ownership::config::Action;

/// 请求选定的唯一域；每次存储查询都携带同一过滤条件。
pub(super) struct Scope {
    pub key: String,
    pub workspace: Option<String>,
}

#[derive(serde::Serialize)]
pub(super) struct Access {
    pub read: bool,
    pub write: bool,
    pub review: bool,
}

impl Scope {
    /// 业务作用：把当前精确范围的动作权限交给页面，不让客户端按角色名推测写入资格。
    ///
    /// 参数说明：
    /// - `snapshot`：本次请求冻结的认证和工作区目录。
    /// - `principal`：已经认证的当前主体。
    /// - `domain`：选定的唯一提案领域。
    ///
    /// 返回：当前读、写和审阅动作位；按钮显示不替代每次请求的服务端复验。
    pub(super) fn access(
        &self,
        snapshot: &GatewaySnapshot,
        principal: &str,
        domain: Domain,
    ) -> Access {
        Access {
            read: self
                .check(snapshot, principal, domain, Action::Read)
                .is_ok(),
            write: self
                .check(snapshot, principal, domain, Action::Write)
                .is_ok(),
            review: self
                .check(snapshot, principal, domain, Action::Review)
                .is_ok(),
        }
    }

    /// 业务作用：把已校验的工作区参数映射为与平台不相交的持久键。
    ///
    /// 参数说明：
    /// - `workspace`：可选工作区身份，后续仍需按当前配置授权。
    ///
    /// 返回：固定范围或非法身份错误；不从候选正文提取租户。
    pub(super) fn new(workspace: Option<String>) -> Result<Self, Error> {
        match workspace {
            Some(id) if crate::config::operations::token(&id, 118) => Ok(Self {
                key: format!("workspace.{id}"),
                workspace: Some(id),
            }),
            Some(_) => Err(Error::Invalid),
            None => Ok(Self {
                key: "platform".into(),
                workspace: None,
            }),
        }
    }

    /// 业务作用：对读取、提交或审阅分别按当前主体和精确领域裁决权限。
    ///
    /// 参数说明：
    /// - `snapshot`：当前已发布的认证与归属事实。
    /// - `principal`：已认证或持久记录中原创建者的稳定身份。
    /// - `domain`：被操作的实际领域。
    /// - `action`：工作区风险动作，平台审阅对应领域写权限。
    ///
    /// 返回：主体仍存在且有当前权限才成功；范围未知与越权都不暴露其它域。
    pub(super) fn check(
        &self,
        snapshot: &GatewaySnapshot,
        principal: &str,
        domain: Domain,
        action: Action,
    ) -> Result<(), Error> {
        if AuthorityScope::parse(&self.key)
            .is_some_and(|scope| scope.allows(snapshot, principal, domain, action))
        {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }

    /// 业务作用：冻结与监听地址无关的认证及工作区权威，使同配置的多个 Admin 能复核同一提案。
    ///
    /// 参数说明：
    /// - `snapshot`：创建或审阅时的当前配置。
    ///
    /// 返回：排序和长度分帧后的摘要；凭据仅进入哈希，不进入持久原文或响应。
    pub(super) fn authority(&self, snapshot: &GatewaySnapshot) -> Result<[u8; 32], Error> {
        AuthorityScope::parse(&self.key)
            .and_then(|scope| scope.authority(snapshot))
            .ok_or(Error::Denied)
    }
}
