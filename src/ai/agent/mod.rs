//! MCP 与 A2A 的固定目标、身份隔离与有界生命周期。

pub mod config;

/// 业务作用：把 Agent 文档与凭据纳入同一配置依赖闭包，保证轮换先完整构建再发布。
///
/// 参数说明：
/// - `cfg`：是路由 Agent 配置
/// - `dir`：是相对文件路径的基准目录。
///
/// 返回：精确文件路径，不读取或暴露凭据内容。
pub(crate) fn dependency_paths(
    cfg: &config::AgentCfg,
    dir: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    let mut targets = Vec::new();
    match cfg {
        config::AgentCfg::Mcp(cfg) => {
            targets.extend(cfg.servers.iter().map(|server| &server.target));
            for tool in &cfg.tools {
                if let config::ToolBackendCfg::Rest {
                    target,
                    ..
                } = &tool.backend
                {
                    targets.push(target);
                }
            }
            for catalog in &cfg.openapi {
                paths.push(dir.join(&catalog.file));
                targets.push(&catalog.target);
            }
        }
        config::AgentCfg::A2a(cfg) => targets.push(&cfg.target),
    }
    paths.extend(
        targets
            .into_iter()
            .filter_map(|target| crate::security::secret::dependency_path(&target.api_key, dir)),
    );
    paths
}

#[cfg(feature = "agent-protocols")]
mod a2a;
#[cfg(feature = "ai-governance")]
pub(crate) mod identity;
#[cfg(feature = "agent-protocols")]
mod mcp;
#[cfg(feature = "agent-protocols")]
mod openapi;
#[cfg(feature = "agent-protocols")]
mod tools;
#[cfg(feature = "ai-governance")]
pub(crate) mod transport;

/// 候选快照中的 Agent 终端计划；关闭 feature 时不能构造可执行实例。
pub(crate) struct Plan {
    #[cfg(feature = "agent-protocols")]
    kind: Kind,
}

#[cfg(feature = "agent-protocols")]
enum Kind {
    Mcp(std::sync::Arc<mcp::Plan>),
    A2a(std::sync::Arc<a2a::Plan>),
}

impl Plan {
    /// 业务作用：向管理面展示已编译 Agent 的协议合同，不暴露会话索引、主体或凭据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：协议版本与资源目录摘要；关闭制品无法构建实例。
    pub(crate) fn summary(&self) -> serde_json::Value {
        #[cfg(feature = "agent-protocols")]
        {
            match &self.kind {
                Kind::Mcp(plan) => plan.summary(),
                Kind::A2a(plan) => plan.summary(),
            }
        }
        #[cfg(not(feature = "agent-protocols"))]
        {
            serde_json::Value::Null
        }
    }
    /// 业务作用：在快照构建期执行制品门和协议选择，禁止未编译能力静默退化为代理。
    ///
    /// 参数说明：
    /// - `cfg`：是可选 Agent 路由配置
    /// - `dir`：是本地配置目录。
    ///
    /// 返回：未声明时返回 None；已声明且协议有效时返回计划；制品或配置不支持时拒绝候选。
    pub(crate) fn build(
        cfg: Option<&config::AgentCfg>,
        dir: &std::path::Path,
    ) -> anyhow::Result<Option<std::sync::Arc<Self>>> {
        let Some(cfg) = cfg else {
            return Ok(None);
        };
        #[cfg(not(feature = "agent-protocols"))]
        {
            let _ = (cfg, dir);
            anyhow::bail!("agent route requires agent-protocols feature");
        }
        #[cfg(feature = "agent-protocols")]
        {
            match cfg {
                config::AgentCfg::Mcp(cfg) => Ok(Some(std::sync::Arc::new(Self {
                    kind: Kind::Mcp(mcp::Plan::build(cfg, dir)?),
                }))),
                config::AgentCfg::A2a(cfg) => Ok(Some(std::sync::Arc::new(Self {
                    kind: Kind::A2a(a2a::Plan::build(cfg, dir)?),
                }))),
            }
        }
    }

    /// 业务作用：向入站执行器提供同代 Agent 资源预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只读的路由配额，不提供运行态修改入口。
    #[cfg(feature = "agent-protocols")]
    pub(crate) fn limits(&self) -> &config::LimitsCfg {
        match &self.kind {
            Kind::Mcp(plan) => &plan.limits,
            Kind::A2a(plan) => &plan.limits,
        }
    }

    /// 业务作用：从冻结认证事实构造隔离身份，并执行已编译 Agent 协议。
    ///
    /// 参数说明：
    /// - `parts`：是入站请求
    /// - `body`：是入站请求
    /// - `auth`：是先前认证结果
    /// - `transport`：只允许同代固定目标外呼。
    ///
    /// 返回：协议响应；身份、租户或 Origin 不满足时在任何外呼前拒绝。
    #[cfg(feature = "agent-protocols")]
    pub(crate) async fn handle(
        &self,
        parts: http::request::Parts,
        body: bytes::Bytes,
        auth: VerifiedAuth<'_>,
        transport: std::sync::Arc<dyn transport::Transport>,
    ) -> http::Response<crate::BoxBody> {
        let security = match &self.kind {
            Kind::Mcp(plan) => &plan.security,
            Kind::A2a(plan) => &plan.security,
        };
        let identity = match identity::verify(
            security,
            &parts.headers,
            auth.authenticated,
            auth.consumer,
            auth.claims,
        ) {
            Ok(identity) => identity,
            Err(_) => {
                return crate::text_status(403, "Agent verified identity, tenant or Origin denied")
            }
        };
        match &self.kind {
            Kind::Mcp(plan) => {
                plan.handle(parts.method, parts.headers, body, identity, transport)
                    .await
            }
            Kind::A2a(plan) => plan.handle(parts, body, identity, transport).await,
        }
    }
}

/// 路由本地认证已经冻结的身份事实；不包含原始凭据或可被插件改写的身份头。
#[cfg(feature = "agent-protocols")]
pub(crate) struct VerifiedAuth<'a> {
    pub authenticated: bool,
    pub consumer: Option<&'a str>,
    pub claims: Option<&'a serde_json::Value>,
}
