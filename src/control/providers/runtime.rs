//! 有界来源拉取与到期撤回；来源任务没有直接写快照或写回远端事实源的权限。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{atomic::AtomicU64, Arc};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use arc_swap::ArcSwap;
use futures::{stream::FuturesUnordered, StreamExt};

use super::{
    model::Declaration,
    plan::{Plan, Transport},
    state::Observation,
};
use crate::config::GatewaySnapshot;
use crate::control::{
    history::ConfigHistory,
    reload::{apply_provider, ReloadRuntime},
};

struct Read {
    observation: Observation,
    etag: Option<http::HeaderValue>,
}

struct Schedule {
    due: Instant,
    failures: u32,
    etag: Option<http::HeaderValue>,
}

/// 业务作用：为固定来源启动最多四个并发读取，并让全部新增、更新和到期撤回通过唯一快照事务。
///
/// 参数说明：
/// - `snap`：是活动数据面与发布权威，不向传输 worker 暴露写入口。
/// - `version`：是活动数据面与发布权威，不向传输 worker 暴露写入口。
/// - `runtime`：是活动数据面与发布权威，不向传输 worker 暴露写入口。
/// - `history`：是活动数据面与发布权威，不向传输 worker 暴露写入口。
///
/// 返回：注册一个后台管理任务；进程关闭时由 Tokio 取消，已取得的网络响应不能越过来源代际。
pub(crate) fn spawn(
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    version: Arc<AtomicU64>,
    runtime: ReloadRuntime,
    history: ConfigHistory,
) {
    tokio::spawn(async move {
        let mut signature = None;
        let mut schedules: BTreeMap<String, Schedule> = BTreeMap::new();
        let mut pending = BTreeSet::new();
        let mut reads = FuturesUnordered::new();
        let mut next_expiry = Instant::now();
        loop {
            let active = snap.load_full();
            let providers = active.providers.clone();
            let current_signature = providers
                .as_ref()
                .map(|snapshot| (snapshot.plan.signature, snapshot.plan.incarnation));
            if signature != current_signature {
                // 身份、端点或授权变化先取消旧读源任务；旧 ETag 和重试状态不能转移到新来源。
                reads.clear();
                pending.clear();
                schedules.clear();
                signature = current_signature;
                next_expiry = Instant::now();
            }
            let Some(providers) = providers else {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            };
            let now = Instant::now();
            if !providers.is_fresh() && now >= next_expiry {
                // 到期优先于补拉；数据面还有独立期限门，即使本地文件无效也不会继续转发过期路由。
                let _ = apply_provider(
                    &active.source_config_path,
                    &snap,
                    &version,
                    &runtime,
                    &history,
                    None,
                )
                .await;
                next_expiry = Instant::now() + Duration::from_secs(1);
                continue;
            }
            for id in providers.plan.sources.keys() {
                schedules.entry(id.clone()).or_insert(Schedule {
                    due: now,
                    failures: 0,
                    etag: None,
                });
            }
            let mut ready: Vec<_> = providers
                .plan
                .sources
                .keys()
                .filter(|id| !pending.contains(*id) && schedules[*id].due <= now)
                .cloned()
                .collect();
            // 最早到期者优先，不能让排序靠前的高频来源长期占满四个读取名额。
            ready.sort_by_key(|id| (schedules[id].due, id.clone()));
            for id in &ready {
                if reads.len() >= 4 {
                    break;
                }
                let source = &providers.plan.sources[id];
                let schedule = &schedules[id];
                let plan = providers.plan.clone();
                let id = id.clone();
                let etag = schedule.etag.clone();
                let cached = providers.registry.document(&id);
                let workload = providers.workloads.get(&id).cloned().unwrap_or_default();
                pending.insert(id.clone());
                let deadline = Duration::from_millis(source.config.deadline_ms);
                reads.push(async move {
                    let signature = (plan.signature, plan.incarnation);
                    let result =
                        tokio::time::timeout(deadline, fetch(plan, &id, etag, cached, workload))
                            .await
                            .map_err(|_| anyhow::anyhow!("provider read deadline exceeded"))
                            .and_then(|value| value);
                    (signature, id, result)
                });
            }
            drop(active);
            tokio::select! {
                completed = reads.next(), if !reads.is_empty() => {
                    let Some((observed_signature,id,result))=completed else {
                        continue;
                    };
                    pending.remove(&id);
                    let active=snap.load_full();
                    let Some(current)=active.providers.as_ref().filter(|snapshot| (snapshot.plan.signature,snapshot.plan.incarnation)==observed_signature) else {
                        continue;
                    };
                    let interval=current.plan.sources[&id].config.poll_interval_ms;
                    let outcome=match result {
                        Ok(read)=> {
                            if apply_provider(&active.source_config_path,&snap,&version,&runtime,&history,Some(read.observation)).await {
                                if let Some(schedule)=schedules.get_mut(&id) {
                                    schedule.etag=read.etag;
                                }
                                super::metrics::Outcome::Published
                            } else {
                                super::metrics::Outcome::Rejected
                            }
                        }
                        Err(_)=> {
                            tracing::warn!(source=id,"configuration provider observation unavailable");super::metrics::Outcome::Unavailable
                        }
                    };
                    current.plan.sources[&id].health.lock().record(outcome);
                    let accepted=outcome==super::metrics::Outcome::Published;
                    if let Some(schedule)=schedules.get_mut(&id) {
                        schedule.failures=if accepted {
                            0
                        } else {
                            schedule.failures.saturating_add(1).min(8)
                        };
                        let delay=interval.saturating_mul(1u64<<schedule.failures).min(60000);
                        // 退避只延后重读，不刷新证据期限；来源失联始终按既有最大陈旧期撤回。
                        schedule.due=Instant::now()+Duration::from_millis(delay);
                    }
                }
                _=tokio::time::sleep(Duration::from_millis(100))=>{}
            }
        }
    });
}

/// 业务作用：只读取已固定的事实源，条件成功只能续用同来源上一份已发布全文。
///
/// 参数说明：
/// - `plan`：固定身份与安全预算
/// - `id`：固定身份与安全预算
/// - `etag`：是上一成功提交的条件版本、完整声明和标签水位。
/// - `cached`：是上一成功提交的条件版本、完整声明和标签水位。
/// - `workload`：是上一成功提交的条件版本、完整声明和标签水位。
///
/// 返回：有界已解析观测与候选 ETag；状态错误、压缩、超限、非法文档或无依据的 304 均拒绝。
async fn fetch(
    plan: Arc<Plan>,
    id: &str,
    etag: Option<http::HeaderValue>,
    cached: Option<Declaration>,
    workload: super::workload::State,
) -> Result<Read> {
    let source = plan
        .sources
        .get(id)
        .context("provider source disappeared")?;
    let maximum = source.config.max_body_bytes;
    let mut projected = None;
    let (document, etag) = match &source.transport {
        Transport::Ecs(reader) => {
            let (document, state) = reader
                .read(
                    &source.authority.namespace,
                    &workload,
                    cached.as_ref(),
                    source.config.max_body_bytes,
                )
                .await?;
            projected = Some(state);
            (document, None)
        }
        Transport::Nomad(reader) => {
            let (document, state) = reader
                .read(
                    &source.authority.namespace,
                    &workload,
                    cached.as_ref(),
                    maximum,
                )
                .await?;
            projected = Some(state);
            (document, None)
        }
        Transport::Docker(reader) => {
            let (document, state) = reader
                .read(
                    &source.authority.namespace,
                    &workload,
                    cached.as_ref(),
                    maximum,
                )
                .await?;
            projected = Some(state);
            (document, None)
        }
        Transport::Https {
            client,
            endpoint,
            authorization,
        } => {
            fetch_https(
                client,
                endpoint,
                authorization.as_ref(),
                maximum,
                etag,
                cached,
            )
            .await?
        }
        Transport::Redis(reader) => (reader.read(maximum).await?, None),
        Transport::Consul(reader) => (reader.read(maximum).await?, None),
        Transport::Etcd(reader) => (reader.read(maximum).await?, None),
        Transport::Zookeeper(reader) => (reader.read(maximum).await?, None),
    };
    Ok(Read {
        observation: Observation {
            signature: plan.signature,
            incarnation: plan.incarnation,
            source: id.into(),
            document,
            workload: projected,
            observed: Instant::now(),
        },
        etag,
    })
}

/// 业务作用：读取固定 HTTPS 声明，仅以已发布全文满足条件响应，传输层不提交来源水位。
///
/// 参数说明：
/// - `client`：是本地冻结的信任计划
/// - `endpoint`：是本地冻结的信任计划
/// - `authorization`：是本地冻结的信任计划
/// - `maximum`：限制正文
/// - `etag`：是已提交条件版本。
/// - `cached`：是已提交条件版本。
///
/// 返回：完整声明和候选条件标记；异常状态、超限或无依据的 304 拒绝。
async fn fetch_https(
    client: &reqwest::Client,
    endpoint: &reqwest::Url,
    authorization: Option<&http::HeaderValue>,
    maximum: usize,
    etag: Option<http::HeaderValue>,
    cached: Option<Declaration>,
) -> Result<(Declaration, Option<http::HeaderValue>)> {
    let mut request = client
        .get(endpoint.clone())
        .header(http::header::ACCEPT, "application/json, application/yaml")
        .header(http::header::ACCEPT_ENCODING, "identity");
    if let Some(authorization) = authorization {
        request = request.header(http::header::AUTHORIZATION, authorization.clone());
    }
    if let Some(etag) = &etag {
        request = request.header(http::header::IF_NONE_MATCH, etag.clone());
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("provider transport unavailable"))?;
    let next_etag = response.headers().get(http::header::ETAG).cloned();
    ensure!(
        next_etag
            .as_ref()
            .is_none_or(|value| value.as_bytes().len() <= 512),
        "provider ETag budget reached"
    );
    let document = if response.status() == http::StatusCode::NOT_MODIFIED {
        ensure!(
            etag.is_some(),
            "provider 304 requires a committed conditional version"
        );
        if let Some(next) = &next_etag {
            ensure!(
                Some(next) == etag.as_ref(),
                "provider conditional version changed without content"
            );
        }
        cached.context("provider conditional document missing")?
    } else {
        ensure!(
            response.status() == http::StatusCode::OK,
            "provider document response rejected"
        );
        ensure!(
            response
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .is_none_or(|value| value == "identity"),
            "provider document compression unsupported"
        );
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .unwrap_or("");
        ensure!(
            matches!(
                content_type,
                "application/json" | "application/yaml" | "application/x-yaml" | "text/yaml"
            ),
            "provider document content type rejected"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= maximum as u64),
            "provider document byte budget reached"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("provider document read interrupted"))?
        {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= maximum,
                "provider document byte budget reached"
            );
            bytes.extend_from_slice(&chunk);
        }
        crate::config::document::decode(&bytes, maximum)
            .map_err(|_| anyhow::anyhow!("provider document rejected"))?
    };
    let etag = next_etag.or_else(|| {
        (response.status() == http::StatusCode::NOT_MODIFIED)
            .then_some(etag)
            .flatten()
    });
    Ok((document, etag))
}
