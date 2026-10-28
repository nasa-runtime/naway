//! 无业务副作用的层级选择推演；只验证本地身份和 head 条件，不消耗额度或访问后端。

use super::{context::Context, Plan};
use crate::control::ownership::OwnershipCatalog;
use crate::routing::Route;
use http::request::Parts;
use serde_json::{json, Value};
use std::{net::IpAddr, sync::Arc};

impl Plan {
    /// 业务作用：用真实本地验签结果推演层级选择，明确区分可选中叶子与业务执行获准。
    ///
    /// 参数说明：
    /// - `root`：是待推演入口
    /// - `parts`：是待推演入口
    /// - `client_ip`：是待推演入口
    /// - `ownership`：提供候选归属；不接受伪造的身份或风险上下文。
    /// - `proxy`：提供候选归属；不接受伪造的身份或风险上下文。
    ///
    /// 返回：每个已访问层及同级匹配结果、终止原因与可能叶子；不返回主体或 claim 值，不执行额度、计费或后端。
    pub(crate) async fn explain(
        &self,
        root: Arc<Route>,
        mut parts: Parts,
        client_ip: IpAddr,
        ownership: &OwnershipCatalog,
        proxy: &str,
    ) -> Value {
        let mut route = root;
        let mut context = Context::default();
        let mut chain = Vec::new();
        let (status, leaf) = loop {
            let node = &self.topology.nodes[&route.id];
            chain.push(json!({
                "id":route.id,
                "branch":node.config.branch,
                "public_match":true,
                "filters":route.admin_filter_chain(),
                "context_match":true,
                "policy_result":"pending"
            }));
            let entry = chain.last_mut().expect("visited route");
            if let Some(subject) = &context.consumer {
                if !ownership
                    .resolve_consumer(proxy, &route.id, subject.clone())
                    .is_ok_and(|resolved| resolved == *subject)
                {
                    entry["policy_result"] = json!("consumer_denied");
                    break ("rejected", None);
                }
            }
            if !node.config.branch {
                break ("selected", Some(route.id.clone()));
            }
            if !route.permits_ip(client_ip)
                || !route.permits_referer(&parts)
                || !route.permits_method(&parts)
            {
                entry["policy_result"] = json!("access_denied");
                break ("rejected", None);
            }
            if let Some(waf) = &route.waf {
                let matched = waf.inspect_head(&parts).is_some();
                context.observe_waf(matched);
                if matched && waf.enforces() {
                    entry["policy_result"] = json!("waf_denied");
                    break ("rejected", None);
                }
            }
            if !context.authenticated {
                let auth = route.resolved_auth_state(&parts, None, None).await;
                if !auth.ok {
                    entry["policy_result"] = json!("authentication_denied");
                    break ("rejected", None);
                }
                context.authenticated = auth.configured;
                context.consumer = match auth.consumer {
                    Some(subject) => match ownership.resolve_consumer(proxy, &route.id, subject) {
                        Ok(subject) => Some(subject),
                        Err(_) => {
                            entry["policy_result"] = json!("consumer_denied");
                            break ("rejected", None);
                        }
                    },
                    None => None,
                };
                context.claims = auth.jwt_claims;
                route.apply_identity_headers(&mut parts, &auth.identity_headers);
            }
            entry["policy_result"] = json!("local_security_allowed");
            if route.cors.is_some()
                && parts.method == http::Method::OPTIONS
                && parts.headers.contains_key(http::header::ORIGIN)
                && parts
                    .headers
                    .contains_key(http::header::ACCESS_CONTROL_REQUEST_METHOD)
            {
                break ("preflight", None);
            }
            if context.append(&node.config.context).is_err() {
                entry["policy_result"] = json!("context_unavailable");
                break ("rejected", None);
            }
            entry["children"] = json!(self.topology.children[&route.id]
                .iter()
                .map(|id| {
                    let child = &self.routes[id];
                    json!({
                        "id":id,
                        "public_match":child.predicates.iter().all(|p|p.matches(&parts)),
                        "context_match":context.matches(&self.topology.nodes[id].config.matches)
                    })
                })
                .collect::<Vec<_>>());
            let Some(child) = self.select(&route.id, &parts, &context) else {
                break ("no_child", None);
            };
            route = child;
        };
        json!({
            "mode":"selection_preview",
            "status":status,
            "leaf":leaf,
            "chain":chain,
            "not_executed":["scoped_authorization","quota","leaf_policies","metering","backend"],
            "authorizes_execution":false
        })
    }
}
