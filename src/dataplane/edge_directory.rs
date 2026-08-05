//! V8-7 可选 SessionDirectory(架构规范 §25.2.7):定向 push 的**寻址加速**,不是正确性来源。
//!
//! 需要同时编译 `grpc-edge` 与 `redis-runtime`;`session_registry: none`(默认)时本模块
//! 完全不构造,push 走 V8-4 broadcast-probe。
//!
//! 正确性纪律(§25.2.7 逐条对应):
//! - **generation-safe 删除**:key 是 `user`,field 是 `SessionKey{node_id#boot_id#stream_id}`。
//!   旧连接的 `on_done` 只能 `HDEL` 自己那个 field,**结构上不可能删掉重连后的新 lease**——
//!   这就是规范要求的 "unbind_if 校验 session+generation",无需 Lua 也不存在读改写竞态。
//! - **多端**:一个 user 的多条 session 是多个 field,`locate` 返回**节点集合**而非 `Option<Node>`。
//! - **目录永不是单点**:miss/超时/连接失败/命中但零投递,全部回落 broadcast-probe;
//!   脏目录最多多花一次 probe,不改变投递结果。
//! - **TTL 兜底**:进程崩溃来不及 unbind 时,租约随 key TTL 自然过期;在线期间由续租任务刷新。

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nasa::redis::{RedisClient, RedisConfig};

/// 目录操作观测(低基数;/metrics 渲染用)。
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectoryMetricsSnapshot {
    /// locate 命中(返回非空节点集)次数。
    pub hit_total: u64,
    /// locate 未命中(空集)次数。
    pub miss_total: u64,
    /// 目录不可用(连接/命令失败或超时)次数。
    pub error_total: u64,
    /// 因 miss/错误/脏目录零投递而回落 broadcast-probe 的次数。
    pub fallback_total: u64,
    /// 当前已登记的本地 session 租约数。
    pub leases: u64,
}

/// Redis 指路条。所有命令都带硬超时:目录慢绝不能拖慢 push 主路径。
pub struct SessionDirectory {
    client: Arc<RedisClient>,
    prefix: String,
    cluster_id: Box<str>,
    node_id: Arc<str>,
    boot_id: u64,
    ttl: Duration,
    command_timeout: Duration,
    hit_total: AtomicU64,
    miss_total: AtomicU64,
    error_total: AtomicU64,
    fallback_total: AtomicU64,
    leases: AtomicU64,
}

impl SessionDirectory {
    /// 连接 Redis 并返回目录句柄;连接失败即构建失败(启动期 fail fast,不静默降级)。
    ///
    /// # 参数
    /// - `cfg`: `grpc_edge_cluster.session_directory` 配置(URL/namespace/profile/前缀/TTL)。
    /// - `cluster_id`/`node_id`: 目录 key 与 field 的作用域身份,跨集群不串。
    /// - `boot_id`: 本进程代际;进 field 保证重启后的新 lease 与旧 lease 不同名。
    pub async fn connect(
        cfg: &crate::config::model::GrpcEdgeSessionDirectoryCfg,
        cluster_id: &str,
        node_id: &str,
        boot_id: u64,
    ) -> anyhow::Result<Arc<Self>> {
        let profile = match cfg.profile.trim() {
            "RustV2" | "rustv2" | "rust-v2" => nasa::redis::CompatibilityProfile::RustV2,
            "LegacyV1" | "legacyv1" | "legacy-v1" => nasa::redis::CompatibilityProfile::LegacyV1,
            other => {
                anyhow::bail!("unsupported grpc_edge_cluster.session_directory.profile `{other}`")
            }
        };
        let redis_cfg = RedisConfig::new(cfg.url.clone(), cfg.namespace.clone(), profile);
        let client = RedisClient::connect(redis_cfg)
            .await
            .map_err(|error| anyhow::anyhow!("connect edge session directory Redis: {error}"))?;
        Ok(Arc::new(Self {
            client,
            prefix: cfg.prefix.clone(),
            cluster_id: Box::from(cluster_id),
            node_id: Arc::from(node_id),
            boot_id,
            ttl: Duration::from_millis(cfg.ttl_ms),
            command_timeout: Duration::from_millis(cfg.command_timeout_ms),
            hit_total: AtomicU64::new(0),
            miss_total: AtomicU64::new(0),
            error_total: AtomicU64::new(0),
            fallback_total: AtomicU64::new(0),
            leases: AtomicU64::new(0),
        }))
    }

    /// /metrics 快照。
    pub fn metrics(&self) -> DirectoryMetricsSnapshot {
        DirectoryMetricsSnapshot {
            hit_total: self.hit_total.load(Ordering::Relaxed),
            miss_total: self.miss_total.load(Ordering::Relaxed),
            error_total: self.error_total.load(Ordering::Relaxed),
            fallback_total: self.fallback_total.load(Ordering::Relaxed),
            leases: self.leases.load(Ordering::Relaxed),
        }
    }

    /// 记一次回落 broadcast-probe(调用方在 miss/错误/脏命中零投递时计)。
    pub fn note_fallback(&self) {
        self.fallback_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 续租周期:TTL 的三分之一,至少 1 秒——单次 watch 抖动不会让在线 session 过期。
    pub fn renew_interval(&self) -> Duration {
        (self.ttl / 3).max(Duration::from_secs(1))
    }

    fn user_key(&self, tenant: &str, user: &str) -> String {
        format!("{}:{}:{tenant}:{user}", self.prefix, self.cluster_id)
    }

    /// session field = `node_id#boot_id#stream_id`:同时是身份与代际,
    /// 让 unbind 天然只删自己那条(§25.2.7 generation-safe)。
    fn session_field(&self, stream_id: u64) -> String {
        format!("{}#{}#{stream_id}", self.node_id, self.boot_id)
    }

    /// 登记一条本地 session 租约(HSET + 刷新 key TTL)。
    ///
    /// 失败只记错误并返回 Err:调用方据此决定"不建租约但订阅照常"——
    /// 目录不可用绝不能阻断订阅本身。
    async fn bind(&self, tenant: &str, user: &str, stream_id: u64) -> anyhow::Result<()> {
        let key = self.user_key(tenant, user);
        let field = self.session_field(stream_id);
        self.with_timeout(async {
            self.client
                .h_set(&key, &field, self.node_id.as_bytes().to_vec())
                .await?;
            self.client.expire(&key, self.ttl).await?;
            Ok(())
        })
        .await
    }

    /// 刷新一条租约的 key TTL(在线期间周期调用)。
    async fn renew(&self, tenant: &str, user: &str) -> anyhow::Result<()> {
        let key = self.user_key(tenant, user);
        self.with_timeout(async {
            self.client.expire(&key, self.ttl).await?;
            Ok(())
        })
        .await
    }

    /// 摘除一条本地 session 租约:只 HDEL 自己的 field。
    async fn unbind(&self, tenant: &str, user: &str, stream_id: u64) -> anyhow::Result<()> {
        let key = self.user_key(tenant, user);
        let field = self.session_field(stream_id);
        self.with_timeout(async {
            self.client.h_del(&key, &[field.as_str()]).await?;
            Ok(())
        })
        .await
    }

    /// 查询一个 user 当前在线的节点集合(多端 = 多 field → 去重后的 node 集)。
    ///
    /// 返回 `None` 表示**目录不可用或未命中**,调用方必须回落 broadcast-probe;
    /// 返回 `Some(set)` 时 set 一定非空(空集按 miss 处理)。
    pub async fn locate(&self, tenant: &str, user: &str) -> Option<HashSet<Box<str>>> {
        let key = self.user_key(tenant, user);
        // h_get_all 返回 field→value 映射;value 即持有该 session 的 node_id。
        let fields: std::collections::HashMap<String, String> = match self
            .with_timeout_value(async { Ok(self.client.h_get_all(&key).await?) })
            .await
        {
            Ok(fields) => fields,
            Err(_) => {
                self.error_total.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        let nodes: HashSet<Box<str>> = fields
            .into_values()
            .map(|node| Box::from(node.as_str()))
            .collect();
        if nodes.is_empty() {
            self.miss_total.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.hit_total.fetch_add(1, Ordering::Relaxed);
        Some(nodes)
    }

    /// 本节点 id(调用方判断"目标只在本地"从而完全跳过 probe)。
    pub fn node_id(&self) -> &Arc<str> {
        &self.node_id
    }

    async fn with_timeout<F>(&self, op: F) -> anyhow::Result<()>
    where
        F: std::future::Future<Output = anyhow::Result<()>>,
    {
        match tokio::time::timeout(self.command_timeout, op).await {
            Ok(result) => result,
            Err(_) => anyhow::bail!("edge session directory command timed out"),
        }
    }

    async fn with_timeout_value<T, F>(&self, op: F) -> anyhow::Result<T>
    where
        F: std::future::Future<Output = anyhow::Result<T>>,
    {
        match tokio::time::timeout(self.command_timeout, op).await {
            Ok(result) => result,
            Err(_) => anyhow::bail!("edge session directory command timed out"),
        }
    }

    /// 为一条订阅建立租约并启动续租任务;返回的 [`SessionLease`] Drop 即摘除。
    ///
    /// 目录不可用时返回 `None`——订阅照常进行,push 侧回落 broadcast-probe。
    pub fn lease(
        self: &Arc<Self>,
        tenant: Arc<str>,
        user: Arc<str>,
        stream_id: u64,
    ) -> SessionLease {
        let directory = self.clone();
        let renew_tenant = tenant.clone();
        let renew_user = user.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = directory.bind(&renew_tenant, &renew_user, stream_id).await {
                tracing::debug!(error = %error, "edge session directory bind failed; push falls back to probe");
                return;
            }
            directory.leases.fetch_add(1, Ordering::Relaxed);
            let interval = directory.renew_interval();
            loop {
                tokio::time::sleep(interval).await;
                if let Err(error) = directory.renew(&renew_tenant, &renew_user).await {
                    tracing::debug!(error = %error, "edge session directory renew failed");
                }
            }
        });
        SessionLease {
            directory: self.clone(),
            tenant,
            user,
            stream_id,
            task: Some(task),
        }
    }
}

/// 一条本地 session 的目录租约。Drop 时中止续租并异步摘除自己的 field;
/// 进程崩溃来不及摘除时由 key TTL 兜底(§25.2.7:目录只是加速,脏条目只多一次 probe)。
pub struct SessionLease {
    directory: Arc<SessionDirectory>,
    tenant: Arc<str>,
    user: Arc<str>,
    stream_id: u64,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let directory = self.directory.clone();
        let tenant = self.tenant.clone();
        let user = self.user.clone();
        let stream_id = self.stream_id;
        // Drop 不能 await:摘除放后台任务,失败也只降级为"脏目录 + 一次多余 probe"。
        tokio::spawn(async move {
            if directory.unbind(&tenant, &user, stream_id).await.is_ok() {
                directory.leases.fetch_sub(1, Ordering::Relaxed);
            }
        });
    }
}
