//! 企业身份比较借用已验证声明，不读取防重放缓存或 LDAP 连接池。

#[cfg(feature = "enterprise-ldap")]
use super::LdapPolicy;
#[cfg(feature = "enterprise-saml")]
use super::SamlPolicy;

#[cfg(feature = "enterprise-saml")]
impl PartialEq for SamlPolicy {
    /// 业务作用：识别 SAML 信任、身份映射与验证边界变化，保持已消费断言与配置声明独立。
    ///
    /// 参数说明：
    /// - `other`：完整构建并通过固定 metadata 签名校验的候选策略。
    ///
    /// 返回：全部声明相同时为真；不获取重放锁，不输出材料或摘要。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            acs,
            trust_identity,
            source_header,
            mappings,
            owned_headers,
            clock_skew_secs,
            replay_ttl,
            max_assertion_bytes,
            // SP/IdP 固定策略及材料由 trust_identity 和 acs 表达，容差由实际秒数表达。
            sp: _,
            idp: _,
            clock_skew: _,
            // 已消费断言是运行事实，比较不能重置或等待其控制权威。
            replay: _,
        } = self;
        acs == &other.acs
            && trust_identity == &other.trust_identity
            && source_header == &other.source_header
            && mappings == &other.mappings
            && owned_headers == &other.owned_headers
            && clock_skew_secs == &other.clock_skew_secs
            && replay_ttl == &other.replay_ttl
            && max_assertion_bytes == &other.max_assertion_bytes
    }
}

#[cfg(feature = "enterprise-saml")]
impl Eq for SamlPolicy {}

#[cfg(feature = "enterprise-ldap")]
impl PartialEq for LdapPolicy {
    /// 业务作用：比较目录身份、查询、传输信任与资源边界，识别同路径服务凭据或 CA 轮换。
    ///
    /// 参数说明：
    /// - `other`：已解析真实 SecretSource 与 TLS 材料的候选目录计划。
    ///
    /// 返回：所有声明相同时为真；不连接目录、不读取连接池或占用认证许可。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            url,
            starttls,
            ca_identity,
            bind_dn,
            bind_password,
            base_dn,
            user_filter,
            mappings,
            owned_headers,
            timeout,
            max_connections,
            // settings 的全部可配置内容由 starttls、ca_identity 和 timeout 表达。
            settings: _,
            // 许可占用与已建立连接属于运行事实，不能改变声明等价性。
            permits: _,
            pool: _,
        } = self;
        url == &other.url
            && starttls == &other.starttls
            && ca_identity == &other.ca_identity
            && bind_dn == &other.bind_dn
            && bind_password == &other.bind_password
            && base_dn == &other.base_dn
            && user_filter == &other.user_filter
            && mappings == &other.mappings
            && owned_headers == &other.owned_headers
            && timeout == &other.timeout
            && max_connections == &other.max_connections
    }
}

#[cfg(feature = "enterprise-ldap")]
impl Eq for LdapPolicy {}
