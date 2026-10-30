//! 差异结果保留原生对象身份，仅在 HTTP 响应边界选择并编码展示领域。

use serde::Serialize;

#[derive(Serialize)]
pub(super) struct Changes {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

pub(super) struct Summary {
    pub current_version: u64,
    pub candidate_version: u64,
    pub routes: Changes,
    pub upstreams: Changes,
    pub listeners: Changes,
    pub sentinel: Changes,
    pub interface_guard: Changes,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Domain {
    All,
    Routes,
    Upstreams,
    Listeners,
    Sentinel,
    InterfaceGuard,
}

#[derive(Serialize)]
pub(super) struct View<'a> {
    current_version: u64,
    candidate_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    routes: Option<&'a Changes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstreams: Option<&'a Changes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listeners: Option<&'a Changes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sentinel: Option<&'a Changes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_guard: Option<&'a Changes>,
}

#[derive(Serialize)]
pub(super) struct LocalResponse<'a> {
    pub ok: bool,
    pub scope: &'static str,
    pub diff: View<'a>,
}

impl Summary {
    /// 业务作用：借用完整比较结果生成所选领域的展示投影，不复制对象身份或构造中间 JSON。
    ///
    /// 参数说明：
    /// - `domain`：管理请求已识别的差异领域，All 包含全部比较领域。
    ///
    /// 返回：保留两个配置版本的借用视图，未选择的领域不参与响应编码。
    pub fn view(&self, domain: Domain) -> View<'_> {
        View {
            current_version: self.current_version,
            candidate_version: self.candidate_version,
            routes: matches!(domain, Domain::All | Domain::Routes).then_some(&self.routes),
            upstreams: matches!(domain, Domain::All | Domain::Upstreams).then_some(&self.upstreams),
            listeners: matches!(domain, Domain::All | Domain::Listeners).then_some(&self.listeners),
            sentinel: matches!(domain, Domain::All | Domain::Sentinel).then_some(&self.sentinel),
            interface_guard: matches!(domain, Domain::All | Domain::InterfaceGuard)
                .then_some(&self.interface_guard),
        }
    }
}
