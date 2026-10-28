//! 固定脚本入口与 CGI transport 的声明和构建期边界。

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Fastcgi,
    Uwsgi,
    Scgi,
}

/// FastCGI 标准流终止与 PHP-FPM 的 END_REQUEST 收尾不能隐式混用。
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FastcgiTermination {
    #[default]
    Streams,
    PhpFpm,
}

impl Protocol {
    /// 业务作用：提供稳定协议名并避免使用客户端输入选择 codec。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置、池键和低基数观测共用的协议名。
    pub fn name(self) -> &'static str {
        match self {
            Self::Fastcgi => "fastcgi",
            Self::Uwsgi => "uwsgi",
            Self::Scgi => "scgi",
        }
    }

    /// 业务作用：在候选构建时确认制品确实包含所声明的记录协议。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：对应独立 feature 已启用时成功，否则拒绝候选。
    pub fn validate_feature(self) -> Result<()> {
        let enabled = match self {
            Self::Fastcgi => cfg!(feature = "fastcgi"),
            Self::Uwsgi => cfg!(feature = "uwsgi"),
            Self::Scgi => cfg!(feature = "scgi"),
        };
        ensure!(enabled, "CGI transport requires feature `{}`", self.name());
        Ok(())
    }
}

/// 单个路由只能进入一个固定脚本，不能把请求路径拼成文件名。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CgiCfg {
    pub protocol: Protocol,
    pub script_root: String,
    pub script_filename: String,
    pub script_name: String,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    #[serde(default)]
    pub server_port: Option<u16>,
    #[serde(default = "default_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_headers")]
    pub max_headers: usize,
    #[serde(default = "default_params")]
    pub max_params: usize,
    #[serde(default = "default_param_bytes")]
    pub max_param_bytes: usize,
    #[serde(default = "default_stderr_bytes")]
    pub max_stderr_bytes: usize,
    #[serde(default = "default_inflight")]
    pub max_inflight: usize,
    #[serde(default)]
    pub keep_conn: bool,
    #[serde(default)]
    pub fastcgi_termination: FastcgiTermination,
    #[serde(default = "default_idle")]
    pub idle_timeout_ms: u64,
    #[serde(default)]
    pub request_headers: Vec<String>,
}

// 默认预算均为每请求或每路由的硬门，不按实体大小扩大。
/// 业务作用：限制响应头暂存。
///
/// 参数说明: 无。
///
/// 返回：默认字节上限。
fn default_header_bytes() -> usize {
    16 * 1024
}
/// 业务作用：限制响应头数量。
///
/// 参数说明: 无。
///
/// 返回：默认条数。
fn default_headers() -> usize {
    64
}
/// 业务作用：限制环境变量数量。
///
/// 参数说明: 无。
///
/// 返回：默认条数。
fn default_params() -> usize {
    64
}
/// 业务作用：限制环境变量编码空间。
///
/// 参数说明: 无。
///
/// 返回：默认字节上限。
fn default_param_bytes() -> usize {
    32 * 1024
}
/// 业务作用：限制后端诊断流消耗。
///
/// 参数说明: 无。
///
/// 返回：默认字节上限。
fn default_stderr_bytes() -> usize {
    64 * 1024
}
/// 业务作用：限制路由同时进行的记录会话。
///
/// 参数说明: 无。
///
/// 返回：默认并发上限。
fn default_inflight() -> usize {
    64
}
/// 业务作用：回收静默的池连接并限制无进展 I/O。
///
/// 参数说明: 无。
///
/// 返回：默认毫秒上限。
fn default_idle() -> u64 {
    30_000
}
/// 业务作用：为未声明业务虚拟主机的 CGI 提供固定名称，避免采信任意 Host。
///
/// 参数说明: 无。
///
/// 返回：固定服务标识。
fn default_server_name() -> String {
    "naway".into()
}

impl CgiCfg {
    /// 业务作用：冻结脚本入口与预算，阻止动态脚本执行和环境变量覆盖。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：路径均为规范绝对路径、脚本严格位于根内、预算和白名单合法时成功。
    pub fn validate(&self) -> Result<()> {
        self.protocol.validate_feature()?;
        ensure!(
            !self.server_name.is_empty()
                && self.server_name.len() <= 255
                && self
                    .server_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
                && self.server_port != Some(0),
            "CGI server identity must be a fixed hostname and nonzero port"
        );
        ensure!(
            self.protocol == Protocol::Fastcgi
                || self.fastcgi_termination == FastcgiTermination::Streams,
            "PHP-FPM termination applies only to FastCGI"
        );
        for path in [&self.script_root, &self.script_filename, &self.script_name] {
            ensure!(
                path.starts_with('/')
                    && path.len() <= 4096
                    && !path.contains(['\\', '%', '$', '?', '#'])
                    && !path.bytes().any(|b| b <= 32 || b == 127)
                    && !path[1..]
                        .split('/')
                        .any(|p| p.is_empty() || p == "." || p == ".."),
                "CGI script paths must be canonical absolute literal paths"
            );
        }
        ensure!(
            self.script_filename
                .strip_prefix(&self.script_root)
                .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1),
            "CGI script_filename must be strictly inside script_root"
        );
        ensure!(
            (1024..=65536).contains(&self.max_header_bytes)
                && (1..=128).contains(&self.max_headers),
            "CGI response header budget out of range"
        );
        ensure!(
            (16..=128).contains(&self.max_params) && (1024..=65535).contains(&self.max_param_bytes),
            "CGI parameter budget out of range"
        );
        ensure!(
            self.max_stderr_bytes <= 1024 * 1024
                && (1..=1024).contains(&self.max_inflight)
                && (100..=60_000).contains(&self.idle_timeout_ms),
            "CGI stream budget out of range"
        );
        ensure!(
            !self.keep_conn || self.protocol == Protocol::Fastcgi,
            "keep_conn is only supported by FastCGI without multiplexing"
        );
        ensure!(
            self.request_headers.len() <= 32,
            "CGI header allowlist exceeds 32 entries"
        );
        let mut names = std::collections::BTreeSet::new();
        for raw in &self.request_headers {
            let header = http::HeaderName::from_bytes(raw.as_bytes())
                .context("invalid CGI request header")?;
            let name = header.as_str();
            ensure!(
                !name.contains('_')
                    && !matches!(
                        name,
                        "proxy"
                            | "connection"
                            | "transfer-encoding"
                            | "content-length"
                            | "content-type"
                            | "upgrade"
                            | "te"
                            | "trailer"
                            | "keep-alive"
                            | "proxy-connection"
                    )
                    && names.insert(name.to_owned()),
                "ambiguous or reserved CGI request header"
            );
        }
        Ok(())
    }
}

/// 业务作用：把 CGI 脚本与服务协议绑定到同一个完整候选，避免 HTTP 与记录协议混用。
///
/// 参数说明：
/// - `cfg`：完成声明展开后的候选。
///
/// 返回：每个 CGI route 指向匹配协议的固定 service 时成功，否则不允许发布。
pub(crate) fn validate_services(cfg: &super::model::GatewayConfig) -> Result<()> {
    for route in cfg
        .routes
        .iter()
        .chain(cfg.proxies.iter().flat_map(|p| &p.routes))
    {
        let service = route
            .uri
            .strip_prefix("lb://")
            .and_then(|name| cfg.upstreams.services.get(name));
        let protocol = service
            .and_then(|s| s.protocol.as_deref())
            .unwrap_or("auto");
        if let Some(cgi) = &route.cgi {
            cgi.validate()?;
            ensure!(
                service.is_some() && protocol == cgi.protocol.name(),
                "CGI route `{}` requires a fixed lb service with matching protocol",
                route.id
            );
        } else {
            ensure!(
                !matches!(protocol, "fastcgi" | "uwsgi" | "scgi"),
                "route `{}` requires an explicit CGI script configuration",
                route.id
            );
        }
    }
    Ok(())
}
