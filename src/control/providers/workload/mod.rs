//! 工作负载标签只声明有限路由意图；完整重读及已发布版本共同决定确定性投影。

pub(super) mod docker;
pub(super) mod ecs;
pub(super) mod nomad;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::model::{identifier, Declaration, Kind, Object};

#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct State {
    marks: BTreeMap<String, Mark>,
    native_index: u64,
    native_digest: [u8; 32],
    ecs_versions: BTreeMap<String, ecs::TaskMark>,
}

#[derive(Clone, PartialEq, Eq)]
struct Mark {
    generation: u64,
    digest: [u8; 32],
    present: bool,
}

#[derive(Clone, Serialize)]
pub(super) struct Rule {
    name: String,
    generation: u64,
    listener: String,
    listen: std::net::SocketAddr,
    server_names: Vec<String>,
    predicates: Vec<String>,
    templates: Vec<String>,
    port: u16,
    scheme: String,
    protocol: String,
    order: i32,
}

pub(super) struct Instance {
    rule: Rule,
    address: std::net::SocketAddr,
}

/// 业务作用：只解析显式开启工作负载的有限标签，未知 naway 字段不能静默降级为较弱策略。
///
/// 参数说明：
/// - `labels`：是 API 返回的标签；其它命名空间的标签不参与网关配置。
///
/// 返回：未开启时无规则；开启时获得有界路由意图，缺失、歧义或非法字段拒绝整个来源观测。
pub(super) fn rule(labels: &BTreeMap<String, String>) -> Result<Option<Rule>> {
    if labels.get("naway.enable").map(String::as_str) != Some("true") {
        return Ok(None);
    }
    let allowed = [
        "enable",
        "name",
        "generation",
        "listener",
        "listen",
        "server_names",
        "predicates",
        "templates",
        "port",
        "scheme",
        "protocol",
        "order",
    ];
    ensure!(
        labels
            .iter()
            .filter(|(key, _)| key.starts_with("naway."))
            .all(|(key, value)| allowed.contains(&&key[6..]) && value.len() <= 4096),
        "unsupported workload label"
    );
    let get = |key: &str| {
        labels
            .get(&format!("naway.{key}"))
            .map(String::as_str)
            .context("required workload label missing")
    };
    let name = get("name")?.to_owned();
    let listener = get("listener")?.to_owned();
    ensure!(
        identifier(&name) && identifier(&listener),
        "invalid workload identity"
    );
    let generation = get("generation")?
        .parse::<u64>()
        .context("invalid workload generation")?;
    let port = get("port")?
        .parse::<u16>()
        .context("invalid workload port")?;
    let listen = get("listen")?
        .parse::<std::net::SocketAddr>()
        .context("invalid workload listener")?;
    ensure!(
        generation > 0 && port > 0 && listen.port() > 0,
        "invalid workload version or port"
    );
    let list = |key: &str, required: bool, maximum: usize| -> Result<Vec<String>> {
        let values: Vec<String> = match labels.get(&format!("naway.{key}")) {
            Some(value) => serde_json::from_str(value).context("invalid workload list")?,
            None if !required => Vec::new(),
            _ => anyhow::bail!("workload list missing"),
        };
        ensure!(
            (!required || !values.is_empty())
                && values.len() <= maximum
                && values.iter().all(|value| !value.is_empty()
                    && value.len() <= 1024
                    && !value.chars().any(char::is_control)),
            "workload list budget reached"
        );
        Ok(values)
    };
    let scheme = labels
        .get("naway.scheme")
        .cloned()
        .unwrap_or_else(|| "http".into());
    let protocol = labels
        .get("naway.protocol")
        .cloned()
        .unwrap_or_else(|| "auto".into());
    ensure!(
        matches!(scheme.as_str(), "http" | "https")
            && matches!(protocol.as_str(), "auto" | "h1" | "h2" | "h2c"),
        "unsupported workload protocol"
    );
    let order = labels
        .get("naway.order")
        .map(|value| value.parse::<i32>())
        .transpose()
        .context("invalid workload order")?
        .unwrap_or(0);
    Ok(Some(Rule {
        name,
        generation,
        listener,
        listen,
        server_names: list("server_names", false, 32)?,
        predicates: list("predicates", true, 64)?,
        templates: list("templates", false, 16)?,
        port,
        scheme,
        protocol,
        order,
    }))
}

/// 业务作用：把完整工作负载集合转换为受限 IR，版本水位只存在于待提交候选而非读源客户端。
///
/// 参数说明：
/// - `namespace`：来自本地权威
/// - `instances`：为完整有限重读
/// - `previous`：是同代已发布投影。
/// - `document`：是同代已发布投影。
///
/// 返回：确定性声明及待提交标签水位；旧版本、同版异文、删除后旧值、容量耗尽均拒绝，不刷新新鲜度。
pub(super) fn project(
    namespace: &str,
    instances: Vec<Instance>,
    previous: &State,
    document: Option<&Declaration>,
) -> Result<(Declaration, State)> {
    ensure!(
        instances.len() <= 1024,
        "workload instance capacity reached"
    );
    let mut groups: BTreeMap<String, (Rule, [u8; 32], BTreeSet<std::net::SocketAddr>)> =
        BTreeMap::new();
    let mut versions = BTreeMap::new();
    for instance in instances {
        let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&instance.rule)?).into();
        let key = instance.rule.name.clone();
        if let Some(existing) = versions.insert((key.clone(), instance.rule.generation), digest) {
            ensure!(existing == digest, "workload rule generation conflict");
        }
        match groups.get_mut(&key) {
            Some((rule, existing, addresses)) => {
                // 滚动部署选择最大标签版本；同版本的策略差异不能按容器返回顺序选赢家。
                if rule.generation < instance.rule.generation {
                    *rule = instance.rule;
                    *existing = digest;
                    addresses.clear();
                    addresses.insert(instance.address);
                } else if rule.generation == instance.rule.generation {
                    ensure!(*existing == digest, "workload rule generation conflict");
                    addresses.insert(instance.address);
                }
            }
            None => {
                groups.insert(
                    key,
                    (instance.rule, digest, BTreeSet::from([instance.address])),
                );
            }
        }
    }
    ensure!(groups.len() <= 512, "workload rule capacity reached");
    let mut next = previous.clone();
    for mark in next.marks.values_mut() {
        mark.present = false;
    }
    let mut objects: BTreeMap<(Kind, String), Value> = BTreeMap::new();
    let mut put = |kind: Kind, name: &str, spec: Value| -> Result<()> {
        if let Some(existing) = objects.insert((kind, name.into()), spec.clone()) {
            ensure!(existing == spec, "workload object identity conflict");
        }
        Ok(())
    };
    for (name, (rule, digest, addresses)) in groups {
        if let Some(old) = previous.marks.get(&name) {
            // 缩为零或撤销 enable 后，必须以更高显式版本重新开放，旧 API 快照不能复活已撤销规则。
            ensure!(
                rule.generation >= old.generation
                    && (rule.generation != old.generation || (old.present && digest == old.digest)),
                "workload generation regressed or reused"
            );
        }
        next.marks.insert(
            name.clone(),
            Mark {
                generation: rule.generation,
                digest,
                present: true,
            },
        );
        ensure!(
            !addresses.is_empty() && addresses.len() <= 256,
            "workload endpoint capacity reached"
        );
        put(
            Kind::Listener,
            &rule.listener,
            json!({
                "listen":rule.listen,
                "server_names":rule.server_names
            }),
        )?;
        put(
            Kind::Service,
            &name,
            json!({
                "instances":addresses.into_iter().map(|address|json!({
                    "uri":format!("{}://{}",rule.scheme,address),
                    "weight":1
                })).collect::<Vec<_>>(),
                "protocol":rule.protocol
            }),
        )?;
        let reference = |kind: &str, name: &str| {
            json!({
                "namespace":namespace,
                "kind":kind,
                "name":name
            })
        };
        let middlewares = if rule.templates.is_empty() {
            Vec::new()
        } else {
            put(
                Kind::Middleware,
                &name,
                json!({
                    "templates":rule.templates
                }),
            )?;
            vec![reference("middleware", &name)]
        };
        put(
            Kind::Route,
            &name,
            json!({
                "listener":reference("listener",&rule.listener),
                "service":reference("service",&name),
                "predicates":rule.predicates,
                "middlewares":middlewares,
                "order":rule.order
            }),
        )?;
    }
    ensure!(
        next.marks.len() <= 2048,
        "workload historical identity capacity reached"
    );
    let unchanged = previous == &next
        && document.is_some_and(|document| {
            document.objects.len() == objects.len()
                && document.objects.iter().all(|object| {
                    objects.get(&(object.kind, object.name.clone())) == object.spec.as_ref()
                })
        });
    if unchanged {
        return Ok((document.expect("present document").clone(), next));
    }
    let revision = document
        .map_or(Some(1), |document| document.revision.checked_add(1))
        .context("workload projection revision exhausted")?;
    let projected = Declaration {
        schema_version: 1,
        revision,
        objects: objects
            .into_iter()
            .map(|((kind, name), spec)| Object {
                kind,
                name,
                generation: revision,
                spec: Some(spec),
            })
            .collect(),
    };
    projected.clone().prepare()?;
    Ok((projected, next))
}

/// 业务作用：对官方 API 的完整 JSON 响应实行预分配与累积字节门，不接受压缩或不完整成功页。
///
/// 参数说明：
/// - `request`：只含固定只读 API
/// - `remaining`：是本轮全部请求共享预算。
///
/// 返回：完整强类型响应和协议头；非成功、压缩、字节超限或 JSON 不合法均拒绝，不回显远端正文。
pub(super) async fn response<T: for<'de> Deserialize<'de>>(
    request: reqwest::RequestBuilder,
    remaining: &mut usize,
) -> Result<(T, http::HeaderMap)> {
    let mut response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("workload API unavailable"))?;
    ensure!(
        response.status() == http::StatusCode::OK
            && response
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .is_none_or(|value| value == "identity"),
        "workload API response rejected"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= *remaining as u64),
        "workload API byte budget reached"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("workload API interrupted"))?
    {
        ensure!(
            chunk.len() <= *remaining,
            "workload API byte budget reached"
        );
        *remaining -= chunk.len();
        bytes.extend_from_slice(&chunk);
    }
    let value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("workload API document rejected"))?;
    Ok((value, response.headers().clone()))
}
