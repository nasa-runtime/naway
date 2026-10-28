//! 授权比较只读取冻结声明，当前决定、正在求值的请求与退避观测保持独立。

#[cfg(feature = "opa-embedded")]
use super::EmbeddedOpa;
use super::{OpaBackoff, OpaDecisionCache, OpaPolicy};

impl PartialEq for OpaPolicy {
    /// 业务作用：穷尽比较外部或内嵌 OPA 的授权、输入权限、缓存与故障边界。
    ///
    /// 参数说明：
    /// - `other`：已经完成材料验证和输入计划编译的候选策略。
    ///
    /// 返回：全部声明相同时为真；不获取缓存或 flight 锁，不执行 Rego 或外部请求。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            upstream,
            path,
            timeout,
            fail_open,
            authorization,
            include_headers,
            max_header_value_bytes,
            max_input_bytes,
            max_response_bytes,
            require_identity,
            policy_salt,
            revision,
            cache,
            input,
            obligations,
            engine,
            singleflight,
            singleflight_wait,
            singleflight_max_keys,
            distributed,
            backoff,
            // 请求所属工作区及正在执行的求值属于运行事实，不能改变声明等价性。
            workspace_budget: _,
            flights: _,
        } = self;
        upstream == &other.upstream
            && path == &other.path
            && timeout == &other.timeout
            && fail_open == &other.fail_open
            && authorization == &other.authorization
            && include_headers == &other.include_headers
            && max_header_value_bytes == &other.max_header_value_bytes
            && max_input_bytes == &other.max_input_bytes
            && max_response_bytes == &other.max_response_bytes
            && require_identity == &other.require_identity
            && policy_salt == &other.policy_salt
            && revision == &other.revision
            && cache == &other.cache
            && input == &other.input
            && obligations == &other.obligations
            && engine == &other.engine
            && singleflight == &other.singleflight
            && singleflight_wait == &other.singleflight_wait
            && singleflight_max_keys == &other.singleflight_max_keys
            && distributed == &other.distributed
            && backoff == &other.backoff
    }
}

impl Eq for OpaPolicy {}

impl PartialEq for OpaDecisionCache {
    /// 业务作用：比较允许、拒绝决定的缓存期限与容量，不把命中和过期淘汰当成配置修改。
    ///
    /// 参数说明：
    /// - `other`：候选缓存声明，条目内容不参与比较。
    ///
    /// 返回：期限与声明容量一致时为真，不扫描或复制缓存。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            entries,
            allow_ttl,
            deny_ttl,
        } = self;
        entries.capacity() == other.entries.capacity()
            && allow_ttl == &other.allow_ttl
            && deny_ttl == &other.deny_ttl
    }
}

impl Eq for OpaDecisionCache {}

impl PartialEq for OpaBackoff {
    /// 业务作用：比较依赖故障的退避边界，同时排除当前连续失败计数与下一次重试时刻。
    ///
    /// 参数说明：
    /// - `other`：候选退避计划。
    ///
    /// 返回：初始和最大间隔相同时为真，不改变现有退避状态。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            initial,
            max,
            failures: _,
            retry_after_millis: _,
        } = self;
        initial == &other.initial && max == &other.max
    }
}

impl Eq for OpaBackoff {}

#[cfg(feature = "opa-embedded")]
impl PartialEq for EmbeddedOpa {
    /// 业务作用：比较内嵌求值入口与实际签名 bundle，识别同路径策略或信任轮换。
    ///
    /// 参数说明：
    /// - `other`：已编译候选引擎，材料身份来自同一次读取和验签。
    ///
    /// 返回：query、材料、公钥与构建预算全部一致时为真，不克隆或调用引擎。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            query,
            bundle,
            template: _,
        } = self;
        query == &other.query && bundle == &other.bundle
    }
}

#[cfg(feature = "opa-embedded")]
impl Eq for EmbeddedOpa {}
