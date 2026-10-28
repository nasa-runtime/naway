//! 从同一配置冻结对象身份与路由计数，容量不足只撤下观测域，不关闭业务路由。

use super::Totals;
use crate::config::GatewaySnapshot;
use serde::{Deserialize, Serialize};

pub(crate) const MAX_ROUTES: usize = 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub capacity: bool,
    pub rows: Vec<Reading>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reading {
    pub proxy: String,
    pub route: String,
    pub workspace: String,
    pub totals: Totals,
}

/// 业务作用：只观察当前配置持有的路由，不用已退出所有者或请求头推导对象归属。
///
/// 参数说明：
/// - `snapshot`：本轮事实采样绑定的唯一配置快照。
///
/// 返回：完整有界路由目录；超预算时只返回capacity，不提供被截断的部分零流量。
pub(crate) fn capture(snapshot: &GatewaySnapshot) -> Snapshot {
    let mut result = Snapshot::default();
    for proxy in snapshot.proxies.iter() {
        for route in proxy.router.routes() {
            let workspace = snapshot
                .ownership
                .route_owner(&proxy.id, &route.id)
                .map_or("platform", |owner| owner.workspace.as_str());
            if result.rows.len() == MAX_ROUTES
                || [&proxy.id, &route.id, workspace]
                    .into_iter()
                    .any(|id| !valid_id(id))
            {
                return Snapshot {
                    capacity: true,
                    rows: Vec::new(),
                };
            }
            result.rows.push(Reading {
                proxy: proxy.id.clone(),
                route: route.id.clone(),
                workspace: workspace.into(),
                totals: route.traffic.read(),
            });
        }
    }
    result
        .rows
        .sort_unstable_by(|a, b| (&a.proxy, &a.route).cmp(&(&b.proxy, &b.route)));
    result
}

impl Snapshot {
    /// 业务作用：验证本机或远端路由目录完整性，重复身份及容量态夹带旧值不能进入聚合。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：数量、字段与严格顺序均满足合同为true；失败由调用方拒绝整个当前样本。
    pub(crate) fn valid(&self) -> bool {
        self.rows.len() <= MAX_ROUTES
            && (!self.capacity || self.rows.is_empty())
            && self.rows.iter().all(|row| {
                [&row.proxy, &row.route, &row.workspace]
                    .into_iter()
                    .all(|id| valid_id(id))
            })
            && self
                .rows
                .windows(2)
                .all(|pair| (&pair[0].proxy, &pair[0].route) < (&pair[1].proxy, &pair[1].route))
    }

    /// 业务作用：将身份字符串与整行容量纳入现有采样内存预算，不能只计算编码后的字节数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前容器与所有owned字段的保守字节成本。
    pub(crate) fn retained_bytes(&self) -> usize {
        self.rows.capacity() * std::mem::size_of::<Reading>()
            + self
                .rows
                .iter()
                .map(|row| row.proxy.capacity() + row.route.capacity() + row.workspace.capacity())
                .sum::<usize>()
    }
}

/// 业务作用：限制观测身份的输出预算和控制字符，不从合法路由名提取客户维度。
///
/// 参数说明：
/// - `value`：配置中的对象身份。
///
/// 返回：非空且不超过128字节的可显示身份为true，否则撤下该观测域。
fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
