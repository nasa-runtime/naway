//! 每个已声明Admin只保留一条复用通道与两条有界在途流，故障不积压历史报告。

use super::{catalog, consumers, protocol, telemetry, Plan, RPC_TIMEOUT};
use crate::admin::catalog::Catalog;
use crate::admin::AdminState;
use futures::{stream, StreamExt};
use nasa::grpc::{Channel, Code, Request, Status};
use protocol::node_management_client::NodeManagementClient;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

struct Target {
    client: NodeManagementClient<Channel>,
    session: Vec<u8>,
    expires_at: u64,
    failures: u32,
    next: Instant,
    catalog_generation: Option<(u64, [u8; 32])>,
    catalog_offset: usize,
    catalog_complete: bool,
    consumers: consumers::Upload,
    consumers_supported: bool,
    interest_until: Option<Instant>,
    service_metrics_supported: bool,
    issuer: Option<Arc<super::issuer::Verifier>>,
    #[cfg(feature = "node-actions")]
    actions: super::actions::Channel,
    #[cfg(feature = "node-actions")]
    previews: super::preview::Channel,
}

/// 同次报告借用唯一事实和样本，各目标只保留自己的会话与传输进度。
struct Round<'a> {
    state: &'a Arc<AdminState>,
    plan: &'a Arc<Plan>,
    facts: &'a protocol::NodeFacts,
    baseline: &'a crate::admin::cluster::baseline::Observation,
    catalog: &'a Catalog,
    consumers: &'a crate::admin::consumers::Directory,
    sequence: u64,
    metrics_enabled: bool,
    sample: Option<&'a Arc<telemetry::Upload>>,
}

/// 业务作用：用共享的当前事实向有限管理端点报告，配置代变化或停机撤销旧任务与连接。
///
/// 参数说明：
/// - `owner`：不延长进程管理状态生命周期的弱引用。
///
/// 返回：owner释放或停止时退出；无管理计划时不构造客户端。
pub(super) async fn run(owner: Weak<AdminState>) {
    let mut generation = Weak::<Plan>::new();
    let mut targets = Vec::new();
    let mut sequence = 0u64;
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let Some(state) = owner.upgrade() else {
            return;
        };
        if state.management.stopping.is_cancelled() {
            return;
        }
        let interested = state.management.metrics_interest() > 0;
        state
            .management
            .store
            .lock()
            .prune_samples(Instant::now(), interested);
        let snapshot = state.snap.load_full();
        let Some(plan) = snapshot
            .admin_management
            .as_ref()
            .filter(|plan| !plan.targets.is_empty())
            .cloned()
        else {
            targets.clear();
            state.monitor.remote_interest(None);
            generation = Weak::new();
            set_period(&mut ticker, Duration::from_secs(2));
            continue;
        };
        if !generation
            .upgrade()
            .is_some_and(|old| Arc::ptr_eq(&old, &plan))
        {
            // 目标或凭据来自完整已发布计划，旧通道不能在新身份下继续发送。
            targets = plan
                .targets
                .iter()
                .map(|target| Target {
                    client: NodeManagementClient::new(target.endpoint.connect_lazy())
                        .max_decoding_message_size(super::MAX_MESSAGE)
                        .max_encoding_message_size(super::MAX_MESSAGE),
                    session: Vec::new(),
                    expires_at: target.expires_at,
                    failures: 0,
                    next: Instant::now(),
                    catalog_generation: None,
                    catalog_offset: 0,
                    catalog_complete: false,
                    consumers: consumers::Upload::default(),
                    consumers_supported: false,
                    interest_until: None,
                    service_metrics_supported: false,
                    issuer: target.issuer.clone(),
                    #[cfg(feature = "node-actions")]
                    actions: super::actions::Channel::default(),
                    #[cfg(feature = "node-actions")]
                    previews: super::preview::Channel::default(),
                })
                .collect();
            generation = Arc::downgrade(&plan);
        }
        let Some(next_sequence) = sequence.checked_add(1) else {
            return;
        };
        sequence = next_sequence;
        let facts = protocol::encode(
            crate::admin::cluster::facts::collect(&state, &snapshot),
            &plan.node_id,
        );
        let baseline = crate::admin::cluster::baseline::collect(&state, &snapshot).await;
        if !Arc::ptr_eq(&state.snap.load_full(), &snapshot) {
            // 基线观察跨越配置发布后，整份报告必须从新快照重建。
            continue;
        }
        let catalog = state.catalog.local(&snapshot);
        let consumers = state.consumers.local(&snapshot);
        let metrics_enabled = plan.report_metrics && snapshot.admin_monitor.enabled;
        let sample = metrics_enabled
            .then(|| state.monitor.upload_sample(&state, &snapshot))
            .flatten()
            .map(|(sample, at)| {
                Arc::new(telemetry::Upload {
                    digest: telemetry::digest(&sample, true),
                    legacy_digest: telemetry::digest(&sample, false),
                    sample,
                    at,
                })
            });
        let round = Round {
            state: &state,
            plan: &plan,
            facts: &facts,
            baseline: &baseline,
            catalog: &catalog,
            consumers: &consumers,
            sequence,
            metrics_enabled,
            sample: sample.as_ref(),
        };
        let work =
            stream::iter(targets.iter_mut()).for_each_concurrent(8, |target| send(target, &round));
        tokio::select! {
            _ = state.management.stopping.cancelled() => return,
            _ = changed(&state, &snapshot) => {
                // 配置换代先取消尚未确认的旧调用，不把旧ACK带到新会话，也不排队重放旧报告。
                // 身份不变的业务热更保留连接，但本轮旧配置的目录调用立即取消。
                if !state.snap.load().admin_management.as_ref().is_some_and(|current| Arc::ptr_eq(current, &plan)) {
                    generation = Weak::new();
                }
            }
            _ = work => {}
        }
        if !Arc::ptr_eq(&state.snap.load_full(), &snapshot) {
            for target in &mut targets {
                target.interest_until = None;
            }
        }
        let interest_until = if metrics_enabled {
            targets
                .iter()
                .filter_map(|target| target.interest_until)
                .max()
        } else {
            None
        };
        state.monitor.remote_interest(interest_until);
        // 当前样本按三倍采样周期失效；有效观察期间上报不能更慢，否则正常节点也会周期性失去覆盖。
        // 没有远端兴趣时恢复原心跳频率，不为每个页面或每个目标创建额外调度任务。
        let period = if interest_until.is_some_and(|until| until > Instant::now()) {
            snapshot.admin_monitor.period.min(Duration::from_secs(2))
        } else {
            Duration::from_secs(2)
        };
        set_period(&mut ticker, period);
        if generation.upgrade().is_none() {
            targets.clear();
        }
    }
}

/// 业务作用：让唯一上报任务跟随当前观测需求，频率变化后从新的完整周期开始而不补发积压轮次。
///
/// 参数说明：
/// - `ticker`：该管理上报 owner 唯一持有的周期计时器。
/// - `period`：已发布采样配置与有效远端兴趣决定的一秒或两秒周期。
///
/// 返回：周期不变时保持原计划；周期变化时丢弃旧时刻，只调度下一次当前事实。
fn set_period(ticker: &mut tokio::time::Interval, period: Duration) {
    if ticker.period() != period {
        *ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    }
}

/// 业务作用：让正在发送的低频管理调用在权限换代后尽快取消，不等待整个重试退避窗口。
///
/// 参数说明：
/// - `state`：唯一已发布快照来源。
/// - `snapshot`：本轮冻结的身份、目标和业务配置。
///
/// 返回：当前计划不再相同时完成；正常发送结束时该观察future被直接取消。
async fn changed(state: &AdminState, snapshot: &Arc<crate::config::GatewaySnapshot>) {
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    loop {
        if !Arc::ptr_eq(&state.snap.load_full(), snapshot) {
            return;
        }
        interval.tick().await;
    }
}

/// 业务作用：对单个管理端点提交最新事实，未知ACK不重放旧消息，失败退避不阻塞其它端点。
///
/// 参数说明：
/// - `target`：固定端点的复用通道和接收端会话。
/// - `round`：借用同次完整事实、原文证明、目录、严格递增序号及可选样本，不复制候选正文。
///
/// 返回：成功后保留连接并清除退避；失败最多退避十秒，不保存待发送样本。
async fn send(target: &mut Target, round: &Round<'_>) {
    let Round {
        facts,
        catalog,
        sample,
        metrics_enabled,
        ..
    } = *round;
    if Instant::now() < target.next || super::runtime::unix_seconds() >= target.expires_at {
        return;
    }
    let deadline = tokio::time::Instant::now() + RPC_TIMEOUT;
    let result = tokio::time::timeout_at(deadline, exchange(target, round, deadline)).await;
    if matches!(result, Ok(Ok(()))) {
        target.failures = 0;
        target.next = Instant::now();
        #[cfg(feature = "node-actions")]
        if target.actions.busy() || target.previews.busy() {
            // 动作或预览已经占用第二条 RPC，心跳独立继续，目录和样本不能挤占工作或突破连接预算。
            return;
        }
        // 心跳取得当前会话后，目录与当前样本共享剩余期限并发；任一故障不拖延另一类事实。
        let upload = sample
            .filter(|_| {
                metrics_enabled
                    && target
                        .interest_until
                        .is_some_and(|until| Instant::now() < until)
            })
            .cloned();
        let client = target.client.clone();
        let session = target.session.clone();
        let service_supported = target.service_metrics_supported;
        let metrics = async {
            if let Some(sample) = upload {
                let _ = telemetry::upload(
                    client,
                    sample,
                    facts.node_id.clone(),
                    session,
                    deadline,
                    service_supported,
                )
                .await;
            }
        };
        let _ = tokio::time::timeout_at(deadline, async {
            tokio::join!(
                async {
                    let _ = send_catalog(target, facts, catalog, deadline).await;
                    if target.consumers_supported {
                        // 凭据目录与原对象目录串行复用同一槽，不能增加一条常驻在途RPC。
                        let _ = target
                            .consumers
                            .send(
                                &mut target.client,
                                facts,
                                &target.session,
                                round.consumers,
                                deadline,
                            )
                            .await;
                    }
                },
                metrics
            )
        })
        .await;
    } else {
        target.failures = target.failures.saturating_add(1).min(4);
        target.next = Instant::now() + Duration::from_secs((1u64 << target.failures).min(10));
        if matches!(result, Ok(Err(ref status)) if matches!(status.code(), Code::FailedPrecondition | Code::OutOfRange))
        {
            target.session.clear();
            target.catalog_generation = None;
            target.consumers = consumers::Upload::default();
            #[cfg(feature = "node-actions")]
            target.actions.clear();
            #[cfg(feature = "node-actions")]
            target.previews.clear();
        }
    }
}

/// 业务作用：在心跳剩余预算内推进最多八个目录分片，丢失ACK按相同内容确认而非重复追加。
///
/// 参数说明：
/// - `target`：当前会话的复用通道与已确认偏移。
/// - `facts`：接收端已确认的当前节点和配置身份。
/// - `catalog`：与事实同代的完整目录或容量不足声明。
/// - `deadline`：本轮握手、发行者校验、报告和目录共用的绝对截止时刻。
///
/// 返回：本轮有限进展；目录错误保持心跳独立，下一轮仍先提交最新事实。
async fn send_catalog(
    target: &mut Target,
    facts: &protocol::NodeFacts,
    catalog: &Catalog,
    deadline: tokio::time::Instant,
) -> Result<(), Status> {
    let generation = (catalog.version, catalog.digest);
    if target.catalog_generation != Some(generation) {
        target.catalog_generation = Some(generation);
        target.catalog_offset = 0;
        target.catalog_complete = false;
    }
    for _ in 0..8 {
        if target.catalog_complete {
            break;
        }
        // 首片必须同时携带完整权限证明，限制为一个对象以保持32KiB消息上限。
        let chunk = if target.catalog_offset == 0 {
            1
        } else {
            catalog::CHUNK
        };
        let end = (target.catalog_offset + chunk).min(catalog.entries.len());
        let request = protocol::CatalogRequest {
            node_id: facts.node_id.clone(),
            boot_id: facts.boot_id.clone(),
            session: target.session.clone(),
            config_version: catalog.version,
            config_fingerprint: catalog.fingerprint,
            digest: catalog.digest.to_vec(),
            total: catalog.entries.len() as u32,
            offset: target.catalog_offset as u32,
            capacity: catalog.capacity,
            scope_supported: catalog.scope_supported,
            scope_digest: catalog.scope_digest.to_vec(),
            scopes: if target.catalog_offset == 0 {
                catalog
                    .scopes
                    .iter()
                    .map(|scope| protocol::ScopeAuthority {
                        workspace: scope.workspace.clone(),
                        digest: scope.digest.to_vec(),
                    })
                    .collect()
            } else {
                Vec::new()
            },
            entries: catalog.entries[target.catalog_offset..end]
                .iter()
                .map(catalog::encode)
                .collect(),
        };
        let response = match target
            .client
            .catalog(timed_request(request, deadline)?)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) => {
                if matches!(
                    status.code(),
                    Code::FailedPrecondition | Code::OutOfRange | Code::DataLoss
                ) {
                    // 接收端可能已撤销不完整目录；从相同清单起点重新确认，不把旧偏移带入新槽。
                    target.catalog_offset = 0;
                }
                return Err(status);
            }
        };
        let next = response.next_offset as usize;
        if next < end
            || next > catalog.entries.len()
            || response.complete != (next == catalog.entries.len())
        {
            return Err(Status::data_loss("catalog acknowledgement mismatch"));
        }
        target.catalog_offset = next;
        target.catalog_complete = response.complete;
    }
    Ok(())
}

/// 业务作用：取得boot会话并按显式要求验证发行者，再提交类型化报告；全部RPC共用绝对总期限。
///
/// 参数说明：
/// - `target`：唯一目标通道，不允许自动切换环境或降级认证。
/// - `round`：握手、动作授权与当前事实共用的一轮已发布身份和借用数据。
/// - `deadline`：建立会话、可选发行者证明与报告共同消耗的绝对期限。
///
/// 返回：所需身份证明与当前序号ACK均匹配才成功；任何拒绝保持该目标本轮失败。
async fn exchange(
    target: &mut Target,
    round: &Round<'_>,
    deadline: tokio::time::Instant,
) -> Result<(), Status> {
    let Round {
        state,
        plan,
        facts,
        baseline,
        sequence,
        metrics_enabled,
        ..
    } = *round;
    if state.management.stopping.is_cancelled() {
        return Err(Status::unavailable("node reporter stopped"));
    }
    if target.session.is_empty() {
        let request = timed_request(
            protocol::OpenRequest {
                node_id: facts.node_id.clone(),
                boot_id: facts.boot_id.clone(),
            },
            deadline,
        )?;
        let session = target.client.open(request).await?.into_inner().session;
        if session.len() != 32 {
            return Err(Status::data_loss("invalid management session"));
        }
        if let Some(issuer) = &target.issuer {
            let mut challenge = vec![0_u8; 32];
            getrandom::getrandom(&mut challenge)
                .map_err(|_| Status::unavailable("issuer challenge entropy unavailable"))?;
            let challenge = protocol::IssuerChallenge {
                node_id: facts.node_id.clone(),
                boot_id: facts.boot_id.clone(),
                session: session.clone(),
                challenge,
            };
            let response = target
                .client
                .authenticate_issuer(timed_request(challenge.clone(), deadline)?)
                .await?
                .into_inner();
            // 未验证的会话不能进入复用状态；任何失败都保持下一轮必须重新挑战，不降级为仅TLS。
            issuer.verify(&challenge, &response)?;
        }
        #[cfg(feature = "node-actions")]
        target
            .actions
            .open(plan.clone(), target.issuer.clone(), &session)
            .map_err(|_| Status::permission_denied("node action session denied"))?;
        #[cfg(feature = "node-actions")]
        target
            .previews
            .open(plan.clone(), target.issuer.clone(), &session)
            .map_err(|_| Status::permission_denied("node preview session denied"))?;
        target.session = session;
    }
    let request = timed_request(
        protocol::ReportRequest {
            session: target.session.clone(),
            sequence,
            facts: Some(facts.clone()),
            metrics_supported: true,
            consumers_supported: true,
            metrics_enabled,
            baseline_supported: baseline.availability != "unsupported",
            node_baseline: baseline
                .node_baseline
                .as_deref()
                .and_then(super::baseline::encode),
            local_publication: super::publication::encode(&baseline.local_publication),
            actions_supported: cfg!(feature = "node-actions"),
            actions_enabled: cfg!(feature = "node-actions")
                && plan.actions_enabled
                && state.mode.runs_data(),
            previews_supported: cfg!(feature = "node-actions"),
            previews_enabled: cfg!(feature = "node-actions")
                && plan.previews_enabled
                && state.mode.runs_data(),
        },
        deadline,
    )?;
    let response = target.client.report(request).await?.into_inner();
    if response.accepted_sequence != sequence {
        return Err(Status::data_loss("management acknowledgement mismatch"));
    }
    if response.metrics_interest_ms > telemetry::INTEREST_MS {
        return Err(Status::data_loss("invalid metrics interest"));
    }
    target.interest_until = (metrics_enabled && response.metrics_interest_ms > 0)
        .then(|| Instant::now() + Duration::from_millis(u64::from(response.metrics_interest_ms)));
    // 每次成功心跳重新取得能力；目标降级或切换后不能继续发送新字段及其摘要。
    target.service_metrics_supported = response.service_metrics_supported;
    target.consumers_supported = response.consumers_supported;
    if !target.consumers_supported {
        // 接收端不再支持本领域时撤销原确认偏移，恢复能力后重新交付完整事实。
        target.consumers = consumers::Upload::default();
    }
    #[cfg(feature = "node-actions")]
    match (response.action, response.release, response.preview) {
        (Some(offer), None, None) if !target.previews.busy() => {
            // 无效或忙碌命令不撤销已经成功的心跳；发行端仍须依靠持久结果判断是否重投。
            let _ = target
                .actions
                .start(state.clone(), target.client.clone(), offer);
        }
        (None, Some(offer), None) if !target.previews.busy() => {
            let _ = target
                .actions
                .start_release(state.clone(), target.client.clone(), offer);
        }
        (None, None, Some(offer)) if !target.actions.busy() => {
            let _ = target
                .previews
                .start(state.clone(), target.client.clone(), offer);
        }
        // 单槽不可能合法地同时产生多类声明，矛盾响应不选择其中任意一个执行。
        _ => {}
    }
    Ok(())
}

/// 业务作用：把剩余总期限传播到每次RPC，握手或Open耗时不能让Report重新获得完整预算。
///
/// 参数说明：
/// - `message`：当前即将提交的类型化消息。
/// - `deadline`：本轮唯一绝对期限。
///
/// 返回：仍有预算时返回带grpc-timeout的请求，否则拒绝提交。
pub(super) fn timed_request<T>(
    message: T,
    deadline: tokio::time::Instant,
) -> Result<Request<T>, Status> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(Status::deadline_exceeded("management round expired"));
    }
    let mut request = Request::new(message);
    request.set_timeout(remaining);
    Ok(request)
}
