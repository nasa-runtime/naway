//! 跨配置域共用的缺省值；不承担运行期策略裁决。

/// 业务作用：为未显式声明的 `group` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_nacos_group() -> String {
    "DEFAULT_GROUP".to_string()
}

/// 业务作用：提供 Nacos discovery 与配置客户端的默认应用名，保持注册和配置身份一致。
///
/// 参数说明: 无。
///
/// 返回：返回 `naway`；部署可通过 Nacos 配置覆盖。
pub(super) fn default_nacos_app_name() -> String {
    "naway".to_string()
}

/// 业务作用：为未显式声明的 `reconnect_backoff_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_nacos_reconnect_backoff_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `plain_enabled` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_true() -> bool {
    true
}
