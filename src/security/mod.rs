//! 已验证身份、访问控制、内容防护与凭据管理。

pub mod auth;
pub(crate) mod aws_json;
pub mod blacklist;
pub(crate) mod bot;
pub(crate) mod casbin_auth;
pub(crate) mod csrf;
pub(crate) mod digest;
pub(crate) mod dlp;
pub(crate) mod enterprise_identity;
pub mod external_crypto;
pub(crate) mod geoip;
pub mod guard;
pub(crate) mod opa;
pub(crate) mod remote_secret;
pub mod scopes;
pub mod secret;
pub(crate) mod upstream_credential;
pub(crate) mod waf;
