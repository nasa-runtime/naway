//! 请求只声明原目标，不接受证书内容、私钥、文件路径或可选当前基线。

use crate::{
    admin::management::material::command::Intent,
    config::GatewaySnapshot,
    control::{actions::authorization::Scope, baseline::NodeBaseline, material::authorization},
    tls::targets::Target,
};
use http::StatusCode;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    targets: Vec<Original>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    node_id: String,
    boot_id: String,
    base_version: u64,
    base_fingerprint: String,
    node_baseline: NodeBaseline,
    target: Target,
}

/// 业务作用：明确区分平台和工作区入口，重复或未知参数不能改变范围解释。
///
/// 参数说明：
/// - `raw`：原始查询字符串，只允许一个 workspace 参数。
///
/// 返回：规范 scope；非法字段、空范围或超量输入拒绝。
pub(super) fn scope(raw: Option<&str>) -> Option<String> {
    let Some(raw) = raw else {
        return Some("platform".into());
    };
    if raw.len() > 512 {
        return None;
    }
    let mut pairs = form_urlencoded::parse(raw.as_bytes());
    let (key, value) = pairs.next()?;
    if key != "workspace" || pairs.next().is_some() {
        return None;
    }
    let scope = format!("workspace.{value}");
    Scope::parse(&scope)?;
    Some(scope)
}

/// 业务作用：按节点分组并冻结原索引，同节点基线矛盾或重复身份不能被覆盖或去重成成功。
///
/// 参数说明：
/// - `input`：严格解析的完整请求。
/// - `snapshot`：本次真实认证采用的快照。
/// - `scope`：已通过材料读取权的唯一范围。
/// - `principal`：实际请求者，不能由 JSON 自报。
/// - `query`：本次服务器随机查询身份。
/// - `kind`：由入口路由固定的只读类别，不能由正文替换。
///
/// 返回：共享原生意图；非法字段或当前归属不足整体拒绝，未知节点留给后续明确返回缺席。
pub(super) fn prepare(
    input: Input,
    snapshot: &GatewaySnapshot,
    scope: &str,
    principal: &str,
    query: &str,
    kind: crate::admin::management::material::command::Query,
) -> Result<Vec<Arc<Intent>>, StatusCode> {
    let count = input.targets.len();
    if !(1..=128).contains(&count) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut groups: BTreeMap<String, Intent> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut cluster = None;
    for (index, target) in input.targets.into_iter().enumerate() {
        let fingerprint = u64::from_str_radix(&target.base_fingerprint, 16).ok();
        if !crate::config::operations::token(&target.node_id, 128)
            || !crate::config::operations::token(&target.boot_id, 128)
            || target.base_version == 0
            || !target.node_baseline.valid()
            || !target.target.valid()
            || target.base_fingerprint.len() != 16
            || target
                .base_fingerprint
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
            || fingerprint.is_none()
            || cluster
                .as_ref()
                .is_some_and(|cluster| cluster != &target.node_baseline.cluster_id)
            || !seen.insert((
                target.node_id.clone(),
                target.target.kind as u8,
                target.target.listener.clone(),
                target.target.entry.clone(),
            ))
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        if cluster.is_none() {
            cluster = Some(target.node_baseline.cluster_id.clone());
        }
        authorization::logical_targets(
            scope,
            snapshot,
            &target.node_id,
            std::iter::once(&target.target),
        )
        .ok_or(StatusCode::FORBIDDEN)?;
        let group = groups
            .entry(target.node_id.clone())
            .or_insert_with(|| Intent {
                query_kind: kind,
                query: query.into(),
                count: count as u32,
                indices: Vec::new(),
                targets: Vec::new(),
                node: target.node_id,
                boot: target.boot_id.clone(),
                baseline: target.node_baseline.clone(),
                version: target.base_version,
                fingerprint: fingerprint.expect("validated fingerprint"),
                scope: scope.into(),
                principal: principal.into(),
                authority: [0; 32],
            });
        if group.boot != target.boot_id
            || group.baseline != target.node_baseline
            || group.version != target.base_version
            || Some(group.fingerprint) != fingerprint
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        group.indices.push(index as u32);
        group.targets.push(target.target);
    }
    groups
        .into_values()
        .map(|mut group| {
            group.authority = authorization::logical_authority(scope, snapshot, &group.targets)
                .ok_or(StatusCode::FORBIDDEN)?;
            Ok(Arc::new(group))
        })
        .collect()
}
