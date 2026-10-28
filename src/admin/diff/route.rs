//! 路由差异用代理与路由的二元身份索引，名称转义只发生在输出阶段。

use std::collections::BTreeMap;

use crate::{config::GatewaySnapshot, routing::Route};

type Identity<'a> = (&'a str, &'a str);
type Index<'a> = BTreeMap<Identity<'a>, (usize, &'a Route)>;

/// 业务作用：比较路由摘要、基础策略参数与有效选择次序，避免拼接身份覆盖其它合法对象。
///
/// 参数说明：
/// - `current`：冻结的活动快照。
/// - `candidate`：同基线构建的候选快照。
///
/// 返回：排序且转义后的增删改名称；响应不包含头值、响应正文或变量内容。
pub(super) fn changes(
    current: &GatewaySnapshot,
    candidate: &GatewaySnapshot,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let variables_changed = current.variables != candidate.variables;
    let current = index(current);
    let candidate = index(candidate);
    let mut added: Vec<_> = candidate
        .keys()
        .filter(|key| !current.contains_key(*key))
        .map(name)
        .collect();
    let mut removed: Vec<_> = current
        .keys()
        .filter(|key| !candidate.contains_key(*key))
        .map(name)
        .collect();
    let mut changed: Vec<_> = current
        .iter()
        .filter_map(|(key, (position, current))| {
            let (next_position, next) = candidate.get(key)?;
            (variables_changed
                || position != next_position
                || !current.same_basic_configuration(next)
                || !current.same_authentication_configuration(next)
                || !current.same_local_security_configuration(next)
                || !current.same_content_configuration(next)
                || !current.same_traffic_configuration(next)
                || current.admin_semantic_json() != next.admin_semantic_json())
            .then(|| name(key))
        })
        .collect();
    added.sort_unstable();
    removed.sort_unstable();
    changed.sort_unstable();
    (added, removed, changed)
}

/// 业务作用：保存已编译路由的实际位置与借用引用，不把名字中的分隔符当作身份边界。
///
/// 参数说明：
/// - `snapshot`：已验证同代理路由身份唯一的快照。
///
/// 返回：按代理和路由名称索引的有效顺序，不复制路由计划。
fn index(snapshot: &GatewaySnapshot) -> Index<'_> {
    snapshot
        .proxies
        .iter()
        .flat_map(|proxy| {
            proxy
                .router
                .routes()
                .iter()
                .enumerate()
                .map(|(position, route)| {
                    (
                        (proxy.id.as_str(), route.id.as_str()),
                        (position, route.as_ref()),
                    )
                })
        })
        .collect()
}

/// 业务作用：为复合路由名称编码真实分隔符，保持普通名称兼容且不同身份不会同名输出。
///
/// 参数说明：
/// - `identity`：原始代理、路由二元名称。
///
/// 返回：段内百分号与斜线分别转义后的 proxy/route 字符串。
fn name(identity: &Identity<'_>) -> String {
    let mut output = String::with_capacity(identity.0.len() + identity.1.len() + 1);
    for (index, segment) in [identity.0, identity.1].into_iter().enumerate() {
        if index > 0 {
            output.push('/');
        }
        for character in segment.chars() {
            match character {
                '%' => output.push_str("%25"),
                '/' => output.push_str("%2F"),
                character => output.push(character),
            }
        }
    }
    output
}
