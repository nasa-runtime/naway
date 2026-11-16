//! 原生拒绝信号的有界累计与同配置发布权下的临时封禁。

use super::*;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub(super) enum Signal {
    /// 请求限流器的明确拒绝。
    Rate,
    /// WAF 强制模式的明确命中。
    Waf,
    /// 认证链确认的凭据失败或有效签名重放。
    Authentication,
    /// Bot 原生强制挑战或速率拒绝。
    Abnormal,
}

impl Signal {
    /// 业务作用：从当前策略选择对应拒绝信号的独立门槛，零值表示不参与自动封禁。
    ///
    /// 参数说明：
    /// - `cfg`：请求所属配置代的自动封禁声明。
    ///
    /// 返回：该信号需要累计的拒绝次数；不合并其它信号的计数。
    fn threshold(self, cfg: &crate::config::model::AutoBanCfg) -> u64 {
        match self {
            Self::Rate => cfg.limit_req_rejections,
            Self::Waf => cfg.waf_rejections,
            Self::Authentication => cfg.authentication_failures,
            Self::Abnormal => cfg.abnormal_rejections,
        }
    }

    /// 业务作用：为事实源与审计提供固定低基数的原生拒绝原因，不携带请求内容。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与实际执行拒绝分支对应的稳定来源名称。
    fn source(self) -> &'static str {
        match self {
            Self::Rate => "auto_limit_req",
            Self::Waf => "auto_waf",
            Self::Authentication => "auto_authentication",
            Self::Abnormal => "auto_abnormal",
        }
    }

    /// 业务作用：让通知类型与实际原生拒绝保持同一固定来源，不从外部状态或请求头推断。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与当前信号对应的通知来源。
    fn notification_source(self) -> crate::security::blacklist::notification::Source {
        use crate::security::blacklist::notification::Source;
        match self {
            Self::Rate => Source::AutoLimitReq,
            Self::Waf => Source::AutoWaf,
            Self::Authentication => Source::AutoAuthentication,
            Self::Abnormal => Source::AutoAbnormal,
        }
    }
}

#[derive(Default)]
struct Window {
    generation: u64,
    entries: HashMap<(IpAddr, Signal), AutoBanState>,
}

impl Window {
    /// 业务作用：为当前配置代隔离原生拒绝计数，旧请求不能清空或增加较新策略状态。
    ///
    /// 参数说明：
    /// - `generation`：产生拒绝的请求配置版本。
    /// - `client_ip`：请求冻结的规范客户端地址。
    /// - `signal`：当前实际拒绝信号。
    /// - `threshold`：对应信号的触发次数。
    /// - `window`：拒绝计数的有效时长。
    ///
    /// 返回：当前代独立计数达到门槛时为真；旧代、关闭或容量不足时为假。
    fn record(
        &mut self,
        generation: u64,
        client_ip: IpAddr,
        signal: Signal,
        threshold: u64,
        window: Duration,
    ) -> bool {
        if generation < self.generation || threshold == 0 {
            return false;
        }
        if self.generation != generation {
            self.entries.clear();
            self.generation = generation;
        }
        record_auto_ban_rejection(
            &mut self.entries,
            (client_ip, signal),
            Instant::now(),
            threshold,
            window,
            AUTO_BAN_COUNTS_MAX_ENTRIES,
        )
    }
}

pub(super) struct Counters {
    window: Mutex<Window>,
    actions: Arc<Semaphore>,
}

impl Default for Counters {
    /// 业务作用：建立所有拒绝信号共用的计数容量和最多八个未结束封禁动作。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有后台任务的空计数器；只在实际达到门槛时领取动作容量。
    fn default() -> Self {
        Self {
            window: Mutex::new(Window::default()),
            actions: Arc::new(Semaphore::new(8)),
        }
    }
}

impl GatewayProxy {
    /// 业务作用：把当前平台原生拒绝累计为有期限的全局封禁，并隔离旧配置和取消后的副作用。
    ///
    /// 参数说明：
    /// - `parts`：已绑定真实入口与工作区所有者的请求头。
    /// - `generation`：产生拒绝的请求快照版本。
    /// - `client_ip`：请求已冻结的规范客户端地址。
    /// - `signal`：实际原生拒绝分支，不接受上游状态码推断。
    ///
    /// 返回：未启用、非平台、失权或容量不足时不写事实；已受理动作在请求取消后继续持有容量与发布权。
    pub(super) async fn maybe_auto_ban(
        &self,
        parts: &Parts,
        generation: u64,
        client_ip: IpAddr,
        signal: Signal,
    ) {
        if parts
            .extensions
            .get::<crate::control::ownership::Owner>()
            .is_some_and(|owner| owner.workspace != crate::control::ownership::PLATFORM)
        {
            // 工作区拒绝不能升级为平台封禁；来源头和同名路由都没有扩大治理范围的权力。
            return;
        }
        let snapshot = self.snap.load();
        let cfg = snapshot.runtime_state.blacklist.clone();
        let threshold = signal.threshold(&cfg.auto_ban);
        if snapshot.version != generation || !cfg.enabled || !cfg.auto_ban.enabled || threshold == 0
        {
            // 旧请求不能向新策略贡献计数；关闭的信号不创建任何客户端状态。
            return;
        }
        drop(snapshot);
        let client_ip = crate::io::net::canonical_ip(client_ip);
        if self.blacklist.is_exempt(client_ip) {
            return;
        }
        let reached = {
            let mut window = self.auto_ban_counts.window.lock();
            window.record(
                generation,
                client_ip,
                signal,
                threshold,
                Duration::from_millis(cfg.auto_ban.window_ms),
            )
        };
        if !reached {
            return;
        }
        let Ok(permit) = self.auto_ban_counts.actions.clone().try_acquire_owned() else {
            return;
        };
        let snapshots = self.snap.clone();
        let coordinator = self.apply_coordinator.clone();
        let store = self.dynamic_store.clone();
        let blacklist = self.blacklist.clone();
        let connections = self.conn_registry.clone();
        // 动作任务拥有发布许可和受理槽，HTTP取消不会提前放行与事实写入竞争的配置提交。
        let work = tokio::spawn(async move {
            let _permit = permit;
            let Ok(_publication) =
                tokio::time::timeout(Duration::from_secs(2), coordinator.lock_owned()).await
            else {
                return;
            };
            if snapshots.load().version != generation
                || blacklist.is_exempt(client_ip)
                || blacklist.is_blocked(client_ip)
            {
                // 配置换代或手工解封撤销旧拒绝的资格；已有封禁也不能被自动动作缩短。
                return;
            }
            let source = signal.source();
            let notification_plan = blacklist.notifications.plan();
            let expires_at =
                unix_now_ms().saturating_add(cfg.auto_ban.ban_ttl_ms.min(i64::MAX as u64) as i64);
            let event = match blacklist.create_event(
                crate::security::blacklist::notification::Action::Ban,
                client_ip,
                "gateway",
                signal.notification_source(),
                Some(expires_at),
            ) {
                Ok(event) => event,
                Err(_) => {
                    tracing::warn!(source, "auto-ban event identity unavailable");
                    return;
                }
            };
            let value = serde_json::json!({
                "source": source,
                "expire_at_unix_ms": expires_at,
                "notification": &event,
            })
            .to_string();
            if let Err(error) = store
                .put(&cfg.collection, &client_ip.to_string(), value.as_bytes())
                .await
            {
                tracing::warn!(%error, source, "auto-ban dynamic store write failed");
                return;
            }
            blacklist.record_event(&event, Some(cfg.auto_ban.ban_ttl_ms));
            blacklist.notifications.publish(&event, notification_plan);
            // 已确认写入后才刷新和关闭；期限已耗尽时不再向无当前封禁的连接发送关闭信号。
            if let Err(error) = blacklist
                .refresh_from_store(store.as_ref(), &cfg.collection)
                .await
            {
                tracing::warn!(%error, source, "auto-ban blacklist refresh failed");
            }
            let closed = if blacklist.is_blocked(client_ip) {
                connections.close_by_ip(client_ip)
            } else {
                0
            };
            tracing::warn!(ip = %client_ip, source, ttl_ms = cfg.auto_ban.ban_ttl_ms, closed, "client auto-banned after native rejections");
        });
        let _ = tokio::time::timeout(Duration::from_secs(6), work).await;
    }
}
