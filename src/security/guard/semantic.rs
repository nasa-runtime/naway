//! 静态守卫比较只借用已编译规则，动态禁用缓存不属于配置候选事实。

use super::{GuardPathMatcher, GuardRule, InterfaceGuard, RespTemplate};
use http::Method;
use std::collections::BTreeMap;

#[derive(PartialEq, Eq)]
enum Path<'a> {
    Exact(&'a str),
    Prefix(&'a str),
    Glob(&'a str),
}

#[derive(PartialEq, Eq)]
struct Entry<'a> {
    order: Option<usize>,
    enabled: bool,
    path: Path<'a>,
    methods: &'a [Method],
    response: &'a RespTemplate,
}

/// 业务作用：按规则身份索引实际匹配和响应，同时保留启用规则的首命中执行次序。
///
/// 参数说明：
/// - `guard`：已验证唯一身份、规范方法集合并解析默认响应的静态守卫。
///
/// 返回：不复制路径、方法、响应头或正文的借用索引，禁用规则不占执行位置。
fn index(guard: &InterfaceGuard) -> BTreeMap<&str, Entry<'_>> {
    let InterfaceGuard {
        rules,
    } = guard;
    let mut order = 0;
    rules
        .iter()
        .map(|rule| {
            let GuardRule {
                id,
                enabled,
                path,
                methods,
                response,
            } = rule;
            let order = enabled.then(|| {
                order += 1;
                order
            });
            let path = match path {
                GuardPathMatcher::Exact(value) => Path::Exact(value),
                GuardPathMatcher::Prefix(value) => Path::Prefix(value),
                GuardPathMatcher::Glob(value) => Path::Glob(value.glob().glob()),
            };
            (
                id.as_str(),
                Entry {
                    order,
                    enabled: *enabled,
                    path,
                    methods,
                    response,
                },
            )
        })
        .collect()
}

impl InterfaceGuard {
    /// 业务作用：识别静态规则增删改及有效顺序变化，不把声明形式或动态缓存当成配置变化。
    ///
    /// 参数说明：
    /// - `candidate`：与活动守卫分别经过完整构建的候选守卫。
    ///
    /// 返回：按原始 id 字典序排列的借用列表，不包含匹配路径、响应内容或运行状态。
    pub(crate) fn configuration_changes<'a>(
        &'a self,
        candidate: &'a Self,
    ) -> (Vec<&'a str>, Vec<&'a str>, Vec<&'a str>) {
        let current = index(self);
        let candidate = index(candidate);
        let added = candidate
            .keys()
            .filter(|key| !current.contains_key(*key))
            .copied()
            .collect();
        let removed = current
            .keys()
            .filter(|key| !candidate.contains_key(*key))
            .copied()
            .collect();
        let changed = current
            .iter()
            .filter_map(|(key, entry)| {
                candidate
                    .get(key)
                    .filter(|next| *next != entry)
                    .map(|_| *key)
            })
            .collect();
        (added, removed, changed)
    }
}
