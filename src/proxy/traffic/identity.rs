//! 流量治理只接收认证阶段冻结的主体；外部鉴权或插件改写不能重建计费身份。

use super::*;

#[derive(Clone)]
struct VerifiedApiKey(Arc<str>);

#[derive(Clone)]
struct VerifiedConsumer(Arc<str>);

/// 业务作用：为后续额度与缓存借用认证阶段冻结的凭据指纹，不再解释已被改写的请求头。
///
/// 参数说明：
/// - `parts`：已经过本地认证的请求。
///
/// 返回：可信指纹；没有实际认证事实时为空。
pub(in crate::proxy) fn api_key_identity(parts: &Parts) -> Option<&str> {
    parts
        .extensions
        .get::<VerifiedApiKey>()
        .map(|key| key.0.as_ref())
}

/// 业务作用：为共享治理借用已经过归属校验的主体，避免后续扩展或身份头替换其计费边界。
///
/// 参数说明：
/// - `parts`：已经过本地认证的请求。
///
/// 返回：可信主体；外部授权未建立本地主体时为空。
pub(in crate::proxy) fn consumer_identity(parts: &Parts) -> Option<&str> {
    parts
        .extensions
        .get::<VerifiedConsumer>()
        .map(|subject| subject.0.as_ref())
}

/// 业务作用：在外部授权与身份头生成之前冻结已验证的计费主体，不保留原始秘密。
///
/// 参数说明：
/// - `parts`：本地认证所见的请求与内部扩展。
/// - `route`：冻结的认证与限额策略。
/// - `authenticated`：本地认证链实际成功，不能来自客户端身份头。
/// - `consumer`：已通过归属校验的本地认证主体。
///
/// 返回：存入可供子层继承的认证成功事实；重新鉴权前总是撤下前一路由凭据。
pub(in crate::proxy) fn freeze_identity(
    parts: &mut Parts,
    route: &Route,
    authenticated: bool,
    consumer: Option<&Arc<str>>,
) {
    // 内部跳转可能再次经过认证链，旧路由凭据不能成为新路由的计费权威。
    parts.extensions.remove::<VerifiedApiKey>();
    parts.extensions.remove::<VerifiedConsumer>();
    if authenticated {
        if let Some(consumer) = consumer {
            parts.extensions.insert(VerifiedConsumer(consumer.clone()));
        }
        // 父层可只负责认证，子层才声明额度；冻结事实不取决于当前层是否使用流控。
        if let Some(fingerprint) = route.authenticated_api_key_identity(parts) {
            parts.extensions.insert(VerifiedApiKey(fingerprint));
        }
    }
}

/// 业务作用：读取流量主体，受信维度只借用认证阶段的内部事实，不重新验证可被改写的头。
///
/// 参数说明：
/// - `parts`：认证完成的请求。
/// - `route`：普通 route 维度所需的冻结标识。
/// - `client_ip`：可信传输链确定的地址。
/// - `key`：编译后维度。
///
/// 返回：明确维度值；缺少受信事实返回 None，调用方必须拒绝而非降级匿名主体。
pub(super) fn dimension<'a>(
    parts: &'a Parts,
    route: &Route,
    client_ip: IpAddr,
    key: &crate::routing::traffic::Key,
) -> Option<std::borrow::Cow<'a, str>> {
    use crate::routing::traffic::Key;
    match key {
        Key::Request(key) => Some(std::borrow::Cow::Owned(limit_dimension(
            parts, route, client_ip, key,
        ))),
        Key::Consumer => consumer_identity(parts).map(std::borrow::Cow::Borrowed),
        Key::ApiCredential => api_key_identity(parts).map(std::borrow::Cow::Borrowed),
    }
}
