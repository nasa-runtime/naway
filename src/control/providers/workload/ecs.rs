//! ECS 固定服务的只读任务目录；分页闭合、任务范围和本地权限均成立后才产生来源中立声明。

use super::super::model::Declaration;
use super::{project, response, rule, Instance, State};
use crate::security::aws_json::{self, Operation};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

pub(crate) struct Reader {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    settings: Settings,
    task_prefix: String,
}

pub(in crate::control::providers) struct Settings {
    pub region: String,
    pub cluster_arn: String,
    pub service: String,
    pub container: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct TaskMark {
    version: u64,
    present: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    task_arns: Vec<String>,
    next_token: Option<String>,
}

#[derive(Deserialize)]
struct Description {
    tasks: Vec<Task>,
    #[serde(default)]
    failures: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Task {
    task_arn: String,
    cluster_arn: String,
    group: String,
    version: u64,
    desired_status: String,
    last_status: String,
    health_status: Option<String>,
    #[serde(default)]
    tags: Vec<Tag>,
    #[serde(default)]
    containers: Vec<Container>,
}

#[derive(Deserialize)]
struct Tag {
    key: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Container {
    name: String,
    last_status: String,
    health_status: Option<String>,
    #[serde(default)]
    network_interfaces: Vec<NetworkInterface>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkInterface {
    private_ipv4_address: Option<String>,
    ipv6_address: Option<String>,
}

impl Reader {
    /// 业务作用：固定账户、区域、集群、服务和容器，只允许现代完整 task ARN 与两个只读 AWS JSON 操作。
    ///
    /// 参数说明：
    /// - `client`：为本地传输信任
    /// - `endpoint`：为本地传输信任
    /// - `settings`：为固定资源范围及已解析 SecretSource。
    ///
    /// 返回：已验证签名材料的客户端；路径、范围或凭据不合法时拒绝配置，不发出 API 请求。
    pub(in crate::control::providers) fn new(
        client: reqwest::Client,
        endpoint: reqwest::Url,
        settings: Settings,
    ) -> Result<Self> {
        let arn: Vec<_> = settings.cluster_arn.split(':').collect();
        ensure!(
            endpoint.path() == "/"
                && arn.len() == 6
                && arn[0] == "arn"
                && matches!(arn[1], "aws" | "aws-cn" | "aws-us-gov")
                && arn[2] == "ecs"
                && arn[3] == settings.region
                && arn[4].len() == 12
                && arn[4].bytes().all(|byte| byte.is_ascii_digit())
                && arn[5].strip_prefix("cluster/").is_some_and(name)
                && name(&settings.service)
                && name(&settings.container),
            "invalid ECS local resource scope"
        );
        let task_prefix = format!(
            "arn:{}:ecs:{}:{}:task/{}/",
            arn[1],
            arn[3],
            arn[4],
            &arn[5][8..]
        );
        let reader = Self {
            client,
            endpoint,
            settings,
            task_prefix,
        };
        reader
            .request(Operation::ListTasks, &json!({}))?
            .build()
            .context("invalid ECS signing materials")?;
        Ok(reader)
    }

    /// 业务作用：完整列举、批量描述并复验任务集合，只有闭合观测才能撤销或开放工作负载路由。
    ///
    /// 参数说明：
    /// - `namespace`：为网关授权域
    /// - `previous`：为已发布水位
    /// - `document`：为已发布水位
    /// - `maximum`：是全部分页和复验共用字节预算。
    ///
    /// 返回：待提交 IR 与任务/标签水位；分页缺失、任务失败、集合变化、范围越界或版本倒退整轮拒绝。
    pub(in crate::control::providers) async fn read(
        &self,
        namespace: &str,
        previous: &State,
        document: Option<&Declaration>,
        maximum: usize,
    ) -> Result<(Declaration, State)> {
        let mut remaining = maximum;
        let listed = self.list(&mut remaining).await?;
        let arns: Vec<_> = listed.iter().cloned().collect();
        let mut tasks = Vec::new();
        for batch in arns.chunks(100) {
            let (description, _): (Description, _) = response(
                self.request(
                    Operation::DescribeTasks,
                    &json!({
                        "cluster":self.settings.cluster_arn,
                        "tasks":batch,
                        "include":["TAGS"]
                    }),
                )?,
                &mut remaining,
            )
            .await?;
            // AWS 可以在 HTTP 成功中返回逐任务失败；不能把失败任务误当成已经删除。
            ensure!(
                description.failures.is_empty() && description.tasks.len() == batch.len(),
                "incomplete ECS task description"
            );
            let described: BTreeSet<_> = description
                .tasks
                .iter()
                .map(|task| &task.task_arn)
                .collect();
            ensure!(
                described.len() == batch.len() && batch.iter().all(|arn| described.contains(arn)),
                "ECS task batch membership mismatch"
            );
            tasks.extend(description.tasks);
        }
        // ListTasks 不提供事务快照；前后集合变化说明本轮不能作为完整删除证据，重试交给统一退避。
        ensure!(
            listed == self.list(&mut remaining).await?,
            "ECS task collection changed during read"
        );
        let mut instances = Vec::new();
        let mut versions = previous.ecs_versions.clone();
        for mark in versions.values_mut() {
            mark.present = false;
        }
        for task in tasks {
            ensure!(
                task.cluster_arn == self.settings.cluster_arn
                    && task.group == format!("service:{}", self.settings.service)
                    && task.version > 0,
                "ECS task scope or version rejected"
            );
            if let Some(old) = previous.ecs_versions.get(&task.task_arn) {
                // 已删除任务不能以旧 API 内容复活；任务版本并不替代业务标签的显式 generation。
                ensure!(
                    task.version >= old.version && (old.present || task.version > old.version),
                    "ECS task version regressed or reused"
                );
            }
            versions.insert(
                task.task_arn.clone(),
                TaskMark {
                    version: task.version,
                    present: true,
                },
            );
            ensure!(
                versions.len() <= 4096,
                "ECS historical task capacity reached"
            );
            let labels = labels(&task.tags)?;
            let Some(rule) = rule(&labels)? else {
                continue;
            };
            // ListTasks 允许短暂返回停止中的任务；只有两端状态均 RUNNING 才能形成可选后端。
            if task.desired_status != "RUNNING"
                || task.last_status != "RUNNING"
                || task.health_status.as_deref() == Some("UNHEALTHY")
            {
                continue;
            }
            ensure!(
                task.containers.len() <= 32,
                "ECS container capacity reached"
            );
            let matches: Vec<_> = task
                .containers
                .iter()
                .filter(|value| value.name == self.settings.container)
                .collect();
            ensure!(
                matches.len() == 1,
                "ECS selected container missing or ambiguous"
            );
            let container = matches[0];
            if container.last_status != "RUNNING"
                || container.health_status.as_deref() == Some("UNHEALTHY")
            {
                continue;
            }
            ensure!(
                !container.network_interfaces.is_empty() && container.network_interfaces.len() <= 8,
                "ECS requires bounded awsvpc container interfaces"
            );
            let mut addresses = BTreeSet::new();
            for interface in &container.network_interfaces {
                let raw = interface
                    .private_ipv4_address
                    .as_ref()
                    .or(interface.ipv6_address.as_ref())
                    .context("ECS explicit container IP missing")?;
                let ip: IpAddr = raw.parse().context("ECS container IP invalid")?;
                ensure!(
                    !ip.is_unspecified() && !ip.is_multicast(),
                    "ECS container IP rejected"
                );
                addresses.insert(ip);
            }
            ensure!(addresses.len() == 1, "ECS selected container IP ambiguous");
            instances.push(Instance {
                address: SocketAddr::new(*addresses.first().expect("nonempty address"), rule.port),
                rule,
            });
        }
        let (document, mut state) = project(namespace, instances, previous, document)?;
        state.ecs_versions = versions;
        Ok((document, state))
    }

    /// 业务作用：闭合固定服务的 ListTasks 分页，重复任务或续页不能偷偷截断为完整集合。
    ///
    /// 参数说明：
    /// - `remaining`：是含 DescribeTasks 和第二次列举的总预算。
    ///
    /// 返回：最多八页、八百个完整现代 ARN；重复、越域、令牌循环或页数耗尽拒绝。
    async fn list(&self, remaining: &mut usize) -> Result<BTreeSet<String>> {
        let mut arns = BTreeSet::new();
        let mut tokens = BTreeSet::new();
        let mut token: Option<String> = None;
        for _ in 0..8 {
            let mut body = json!({
                "cluster":self.settings.cluster_arn,
                "serviceName":self.settings.service,
                "desiredStatus":"RUNNING",
                "maxResults":100
            });
            if let Some(token) = token.take() {
                body["nextToken"] = token.into();
            }
            let (page, _): (Page, _) =
                response(self.request(Operation::ListTasks, &body)?, remaining).await?;
            ensure!(
                page.task_arns.len() <= 100,
                "ECS page task capacity reached"
            );
            for arn in page.task_arns {
                let id = arn
                    .strip_prefix(&self.task_prefix)
                    .context("ECS task outside local scope")?;
                ensure!(
                    id.len() == 32
                        && id
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                    "ECS modern task ARN required"
                );
                ensure!(arns.insert(arn), "duplicate ECS task across pages");
            }
            let Some(next) = page.next_token else {
                return Ok(arns);
            };
            ensure!(
                !next.is_empty()
                    && next.len() <= 2048
                    && !next.chars().any(char::is_control)
                    && tokens.insert(next.clone()),
                "ECS continuation token rejected"
            );
            token = Some(next);
        }
        anyhow::bail!("ECS complete collection page budget reached")
    }

    /// 业务作用：对固定 ECS 操作和精确 JSON 实体签名，不读取环境凭据链、不执行写操作或重定向。
    ///
    /// 参数说明：
    /// - `operation`：只能由本客户端构造，远端只提供被校验的分页令牌与任务身份。
    /// - `body`：只能由本客户端构造，远端只提供被校验的分页令牌与任务身份。
    ///
    /// 返回：已签名请求，实体和凭据无效时拒绝；真正 I/O 由有界响应读取器执行。
    fn request(
        &self,
        operation: Operation,
        body: &impl Serialize,
    ) -> Result<reqwest::RequestBuilder> {
        let body = serde_json::to_vec(body)?;
        let token = if self.settings.session_token.is_empty() {
            None
        } else {
            Some(
                http::HeaderValue::from_str(&self.settings.session_token)
                    .context("invalid ECS session token")?,
            )
        };
        let request = self
            .client
            .post(self.endpoint.clone())
            .header(http::header::ACCEPT_ENCODING, "identity")
            .body(body.clone());
        aws_json::sign(
            request,
            &self.endpoint,
            aws_json::Scope {
                region: &self.settings.region,
                operation,
            },
            aws_json::Credentials {
                access_key_id: &self.settings.access_key_id,
                secret_access_key: self.settings.secret_access_key.as_bytes(),
                session_token: token.as_ref(),
            },
            &body,
            chrono::Utc::now(),
        )
    }
}

/// 业务作用：限制本地服务、集群与容器名称为精确单项，不接受通配符或路径选择。
///
/// 参数说明：
/// - `value`：是本地资源名。
///
/// 返回：一至一百二十八字节 ASCII 字母、数字、下划线或连字符才允许。
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

/// 业务作用：将有界 ECS 标签转换为共同路由意图；重复键和超限不能按返回顺序覆盖。
///
/// 参数说明：
/// - `tags`：为单任务标签，AWS 与业务命名空间均计入容量。
///
/// 返回：最多五十个唯一标签；键或值不符合字节预算时拒绝整个观测。
fn labels(tags: &[Tag]) -> Result<BTreeMap<String, String>> {
    ensure!(tags.len() <= 50, "ECS task tag capacity reached");
    let mut labels = BTreeMap::new();
    for tag in tags {
        ensure!(
            !tag.key.is_empty()
                && tag.key.len() <= 128
                && tag.value.len() <= 256
                && labels.insert(tag.key.clone(), tag.value.clone()).is_none(),
            "ECS tag rejected"
        );
    }
    Ok(labels)
}
