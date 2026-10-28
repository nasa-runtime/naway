//! 认证配置比较只读取已冻结声明与材料身份，不触碰会话、JWKS 缓存或刷新锁。

use crate::routing::{JwtVerifier, OidcRpPolicy, RemoteJwks, Route};

impl Route {
    /// 业务作用：识别同名路由的本地认证、身份验证与外部鉴权声明变化，包含实际解析后的凭据。
    ///
    /// 参数说明：
    /// - `candidate`：完成构建的同身份候选路由。
    ///
    /// 返回：受支持的认证策略与组合方式一致时为真；不复制或序列化凭据，不比较会话状态。
    pub(crate) fn same_authentication_configuration(&self, candidate: &Self) -> bool {
        self.basic_auth == candidate.basic_auth
            && self.digest_auth == candidate.digest_auth
            && self.api_keys == candidate.api_keys
            && self.hmac_auth == candidate.hmac_auth
            && self.jwt_auth == candidate.jwt_auth
            && self.oidc_rp == candidate.oidc_rp
            && self.ext_authz == candidate.ext_authz
            && self.satisfy == candidate.satisfy
    }
}

impl PartialEq for JwtVerifier {
    /// 业务作用：按算法来源与实际材料比较 JWT 验证器，避免路径相同掩盖公钥轮换。
    ///
    /// 参数说明：
    /// - `other`：候选验证器，其材料身份和密码对象来自同一次读取。
    ///
    /// 返回：固定密钥或远程声明一致时为真；远端返回的当前 key 集属于运行事实。
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Hs256(current), Self::Hs256(candidate)) => current == candidate,
            (Self::Static(_, current), Self::Static(_, candidate)) => current == candidate,
            (Self::Remote(current), Self::Remote(candidate)) => current == candidate,
            _ => false,
        }
    }
}

impl Eq for JwtVerifier {}

impl PartialEq for RemoteJwks {
    /// 业务作用：穷尽比较 JWKS 获取与信任声明，缓存刷新不能被报告为配置修改。
    ///
    /// 参数说明：
    /// - `other`：同一快照基线下构建的远端验证计划。
    ///
    /// 返回：端点、信任、算法和全部期限一致时为真，不获取状态锁或发起网络请求。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            endpoint,
            issuer,
            algorithm,
            ca_identity,
            timeout,
            min_ttl,
            max_ttl,
            stale_ttl,
            negative_ttl,
            // client 的固定信任材料由 ca_identity 表达；连接池、当前 key 与刷新互斥属于运行状态。
            client: _,
            state: _,
            refresh: _,
        } = self;
        endpoint == &other.endpoint
            && issuer == &other.issuer
            && algorithm == &other.algorithm
            && ca_identity == &other.ca_identity
            && timeout == &other.timeout
            && min_ttl == &other.min_ttl
            && max_ttl == &other.max_ttl
            && stale_ttl == &other.stale_ttl
            && negative_ttl == &other.negative_ttl
    }
}

impl Eq for RemoteJwks {}

impl PartialEq for OidcRpPolicy {
    /// 业务作用：比较完整 OIDC 登录与身份策略，同时保持当前登录和会话状态独立。
    ///
    /// 参数说明：
    /// - `other`：已编译候选 RP，尚未接纳登录请求。
    ///
    /// 返回：身份、端点、Cookie、信任、资源与期限全部相同时为真；不读取会话或 pending 锁。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            introspection_endpoint,
            issuer,
            client_id,
            client_secret,
            client_auth,
            scope,
            redirect_uri,
            callback_path,
            logout_path,
            post_logout_uri,
            cookie_name,
            session_ttl,
            pending_ttl,
            max_pending,
            max_sessions,
            timeout,
            ca_identity,
            id_token_verifier,
            identity_headers,
            // 连接池和认证会话由本代运行任务持有，不能改变配置审查的等价结论。
            client: _,
            pending: _,
            sessions: _,
        } = self;
        authorization_endpoint == &other.authorization_endpoint
            && token_endpoint == &other.token_endpoint
            && userinfo_endpoint == &other.userinfo_endpoint
            && introspection_endpoint == &other.introspection_endpoint
            && issuer == &other.issuer
            && client_id == &other.client_id
            && client_secret == &other.client_secret
            && client_auth == &other.client_auth
            && scope == &other.scope
            && redirect_uri == &other.redirect_uri
            && callback_path == &other.callback_path
            && logout_path == &other.logout_path
            && post_logout_uri == &other.post_logout_uri
            && cookie_name == &other.cookie_name
            && session_ttl == &other.session_ttl
            && pending_ttl == &other.pending_ttl
            && max_pending == &other.max_pending
            && max_sessions == &other.max_sessions
            && timeout == &other.timeout
            && ca_identity == &other.ca_identity
            && id_token_verifier == &other.id_token_verifier
            && identity_headers == &other.identity_headers
    }
}

impl Eq for OidcRpPolicy {}

#[cfg(feature = "enterprise-jwe")]
impl PartialEq for crate::routing::JweLayer {
    /// 业务作用：比较 JWE 密钥来源和实体上限，不读取密码对象内部表示。
    ///
    /// 参数说明：
    /// - `other`：同次材料读取产生的候选解密器及身份。
    ///
    /// 返回：材料身份与预算一致时为真；摘要仅供审查，不授予解密或认证权限。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            decrypter: _,
            key_identity,
            max_compact_bytes,
        } = self;
        key_identity == &other.key_identity && max_compact_bytes == &other.max_compact_bytes
    }
}

#[cfg(feature = "enterprise-jwe")]
impl Eq for crate::routing::JweLayer {}
