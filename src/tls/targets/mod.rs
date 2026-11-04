//! 材料动作只接受已发布配置中的逻辑身份，不由调用者提供文件路径。

use crate::config::{GatewaySnapshot, SniCertRuntime, TlsRuntimeCfg};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Proxy,
    Stream,
}

/// SNI 声明序号仅在原配置代内有效；名称匹配顺序不授予另一个声明的写入权。
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub kind: Kind,
    pub listener: String,
    pub entry: String,
}

impl Target {
    /// 业务作用：统一 HTTP 与 TCP 证书对象的归属键，SNI 条目继承所属监听的证书对象边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：归属目录中对应命名空间的唯一键，不包含文件路径。
    #[cfg(feature = "admin-operations-pgsql")]
    pub(crate) fn object_key(&self) -> String {
        let kind = match self.kind {
            Kind::Proxy => "certificate",
            Kind::Stream => "stream_certificate",
        };
        format!("{kind}:{}", self.listener)
    }

    /// 业务作用：把材料目标限定为当前逻辑入口中的默认身份或规范 SNI 声明序号。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：入口与条目格式均合法时为真；路径、别名序号和任意选证名称均不被接受。
    pub(crate) fn valid(&self) -> bool {
        !self.listener.is_empty()
            && self.listener.len() <= 128
            && !self.listener.chars().any(char::is_control)
            && (self.entry == "default" || self.sni_index().is_some())
    }

    /// 业务作用：从同一已发布配置重新解析确切来源，数组重排必须由配置条件门拒绝旧意图。
    ///
    /// 参数说明：
    /// - `snapshot`：已经冻结并由调用方检查版本的完整配置。
    ///
    /// 返回：当前唯一文件来源计划；未知入口或条目返回空，外部来源仍保留其拒绝依据。
    pub(crate) fn resolve(&self, snapshot: &GatewaySnapshot) -> Option<TlsRuntimeCfg> {
        if !self.valid() {
            return None;
        }
        let tls = match self.kind {
            Kind::Proxy => snapshot
                .proxies
                .iter()
                .find(|proxy| proxy.id == self.listener)?
                .tls
                .as_ref()?,
            Kind::Stream => snapshot
                .stream_listeners
                .iter()
                .find(|listener| listener.id == self.listener)?
                .tls
                .as_ref()?,
        };
        if self.entry == "default" {
            return Some(tls.clone());
        }
        // 动态身份拥有整份 listener 选证器，不能通过虚构 SNI 文件条目绕过其来源所有权。
        if tls.in_memory.is_some() || tls.spire.is_some() {
            return None;
        }
        Some(sni_source(tls, tls.certs.get(self.sni_index()?)?))
    }

    /// 业务作用：严格解释声明位置，拒绝带符号、前导零和超出选证上界的等价写法。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法的零起始 SNI 下标；默认身份与非法形式均返回空。
    fn sni_index(&self) -> Option<usize> {
        let text = self.entry.strip_prefix("sni-")?;
        if text.is_empty()
            || text.len() > 3
            || !text.bytes().all(|byte| byte.is_ascii_digit())
            || (text.len() > 1 && text.starts_with('0'))
        {
            return None;
        }
        text.parse().ok().filter(|index| *index < 512)
    }
}

/// 业务作用：投影单个 SNI 文件身份，不能继承默认身份的 manifest、ACME 或 OCSP 权威。
///
/// 参数说明：
/// - `parent`：包含该 SNI 声明的完整监听器。
/// - `sni`：已经解析的独立 SNI 证书来源。
///
/// 返回：只包含该身份材料和自身策略的安装计划；完整监听策略由父计划另行预检。
pub(crate) fn sni_source(parent: &TlsRuntimeCfg, sni: &SniCertRuntime) -> TlsRuntimeCfg {
    TlsRuntimeCfg {
        listen: parent.listen.clone(),
        cert_file: sni.cert_file.clone(),
        key_file: sni.key_file.clone(),
        private_key_provider: sni.private_key_provider.clone(),
        spire: None,
        keypair_manifest_file: None,
        certs: Vec::new(),
        client_auth: None,
        ocsp_stapling: sni.ocsp_stapling.clone(),
        session_tickets: None,
        acme: None,
        in_memory: None,
    }
}

/// 业务作用：统一判断手工材料动作是否拥有本地文件身份，外部提供者不能被上传旁路接管。
///
/// 参数说明：
/// - `tls`：默认或已投影的 SNI 来源。
///
/// 返回：只有本地文件或 manifest 身份为真；不读取秘密或解析磁盘路径。
pub(crate) fn writable(tls: &TlsRuntimeCfg) -> bool {
    tls.in_memory.is_none() && tls.spire.is_none() && tls.private_key_provider.is_none()
}
