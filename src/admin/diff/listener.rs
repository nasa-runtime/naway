//! 业务监听策略的类型化差异，比较期间只借用已编译快照。

use std::collections::BTreeMap;

use crate::config::{GatewaySnapshot, ProxyRuntime, StreamProtocolRuntime, StreamRuntime};

type Identity<'a> = (&'static str, &'a str, &'static str);

enum Listener<'a> {
    Proxy(&'a ProxyRuntime),
    Stream(&'a StreamRuntime),
}

/// 业务作用：按业务入口稳定身份识别完整配置变化，不复制 TLS 材料或运行策略。
///
/// 参数说明：
/// - `current`：请求冻结的活动快照。
/// - `candidate`：同一基线下完整构建的候选快照。
///
/// 返回：按身份排序的增删改名称；运行观测及 HTTP 路由内容由各自领域处理。
pub(super) fn changes(
    current: &GatewaySnapshot,
    candidate: &GatewaySnapshot,
) -> (Vec<String>, Vec<String>, Vec<String>) {
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
        .filter_map(|(key, current)| {
            let next = candidate.get(key)?;
            let same = match (current, next) {
                (Listener::Proxy(current), Listener::Proxy(next)) => same_proxy(current, next),
                (Listener::Stream(current), Listener::Stream(next)) => current == next,
                _ => false,
            };
            (!same).then(|| name(key))
        })
        .collect();
    added.sort_unstable();
    removed.sort_unstable();
    changed.sort_unstable();
    (added, removed, changed)
}

/// 业务作用：用借用的类型与名称建立索引，避免克隆证书策略及拼接身份发生歧义。
///
/// 参数说明：
/// - `snapshot`：已验证入口身份唯一的不可变快照。
///
/// 返回：按类型、声明名称及协议排序的业务监听索引。
fn index(snapshot: &GatewaySnapshot) -> BTreeMap<Identity<'_>, Listener<'_>> {
    snapshot
        .proxies
        .iter()
        .map(|proxy| (("proxy", proxy.id.as_str(), ""), Listener::Proxy(proxy)))
        .chain(snapshot.stream_listeners.iter().map(|stream| {
            let protocol = match stream.protocol {
                StreamProtocolRuntime::Tcp => "tcp",
                StreamProtocolRuntime::Udp => "udp",
            };
            (
                ("stream", stream.id.as_str(), protocol),
                Listener::Stream(stream),
            )
        }))
        .collect()
}

/// 业务作用：仅为响应中的变化对象生成公开名称，不序列化入口安全策略。
///
/// 参数说明：
/// - `identity`：已匹配的业务入口身份。
///
/// 返回：与监听目录一致的 proxy 或 stream 名称。
fn name(identity: &Identity<'_>) -> String {
    match identity {
        (kind, id, "") => format!("{kind}:{id}"),
        (kind, id, protocol) => format!("{kind}:{id}:{protocol}"),
    }
}

/// 业务作用：穷尽比较 HTTP 入口的不可变策略，路由内容单独归属路由差异。
///
/// 参数说明：
/// - `current`：活动同名 HTTP 入口。
/// - `candidate`：候选同名 HTTP 入口。
///
/// 返回：接入、安全、资源和传输策略一致时为真，不读取流量或连接统计。
fn same_proxy(current: &ProxyRuntime, candidate: &ProxyRuntime) -> bool {
    let ProxyRuntime {
        #[cfg(feature = "xds-client-extensions")]
        xds_extension_bound,
        id: _,
        listen,
        plain_enabled,
        tls,
        http3,
        server_names,
        gateway_listeners,
        proxy_protocol,
        trusted_proxies,
        limits,
        timeouts,
        redirect_https,
        hsts_header,
        router: _,
    } = current;
    #[cfg(feature = "xds-client-extensions")]
    if xds_extension_bound != &candidate.xds_extension_bound {
        return false;
    }
    listen == &candidate.listen
        && plain_enabled == &candidate.plain_enabled
        && tls == &candidate.tls
        && http3 == &candidate.http3
        && server_names == &candidate.server_names
        && gateway_listeners == &candidate.gateway_listeners
        && proxy_protocol == &candidate.proxy_protocol
        && trusted_proxies == &candidate.trusted_proxies
        && limits == &candidate.limits
        && timeouts == &candidate.timeouts
        && redirect_https == &candidate.redirect_https
        && hsts_header == &candidate.hsts_header
}
