//! HTTP接入入口的当前守卫拒绝事实，不推断尚未匹配的路由或公开全局规则内容。

use crate::config::GatewaySnapshot;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const MAX_ENTRIES: usize = 128;

#[derive(Default)]
pub(crate) struct Counters {
    rejections: [AtomicU64; 2],
}

#[derive(Clone, Copy)]
pub(crate) enum Rejection {
    Static = 0,
    Dynamic = 1,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub capacity: bool,
    pub rows: Vec<Reading>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reading {
    pub listener: String,
    pub workspace: String,
    pub rejections: [u64; 2],
}

impl Counters {
    /// 业务作用：在实际守卫拒绝处累计接入入口事实，响应状态和请求声明都不能产生计数。
    ///
    /// 参数说明：
    /// - `reason`：静态守卫或动态接口禁用的明确裁决。
    ///
    /// 返回：只更新本入口原配置所有者的一个固定累计，不保存规则、请求或客户身份。
    pub(crate) fn reject(&self, reason: Rejection) {
        self.rejections[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：观察当前入口固定两类累计，不持锁或枚举请求。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：弱一致累计快照，读取区间仍须检查全部计数单调性。
    fn read(&self) -> [u64; 2] {
        std::array::from_fn(|index| self.rejections[index].load(Ordering::Relaxed))
    }
}

/// 业务作用：从唯一已发布快照捕获HTTP入口及其可信归属，守卫规则保持平台所有。
///
/// 参数说明：
/// - `snapshot`：本轮配置、目录与入口计数共同绑定的不可变快照。
///
/// 返回：完整有界目录；超量或身份不能安全显示时只返回容量态，业务入口不受影响。
pub(crate) fn capture(snapshot: &GatewaySnapshot) -> Snapshot {
    if snapshot.proxies.len() > MAX_ENTRIES {
        return Snapshot {
            capacity: true,
            rows: Vec::new(),
        };
    }
    let mut result = Snapshot::default();
    for proxy in snapshot.proxies.iter() {
        let key = format!("proxy:{}", proxy.id);
        let workspace = snapshot
            .ownership
            .object_owner(&key)
            .map_or("platform", |owner| owner.workspace.as_str());
        if !valid_id(&proxy.id) || !valid_id(workspace) {
            return Snapshot {
                capacity: true,
                rows: Vec::new(),
            };
        }
        result.rows.push(Reading {
            listener: proxy.id.clone(),
            workspace: workspace.into(),
            rejections: proxy.ingress_protection.read(),
        });
    }
    result
        .rows
        .sort_unstable_by(|left, right| left.listener.cmp(&right.listener));
    result
}

impl Snapshot {
    /// 业务作用：拒绝截断、重复或不安全身份的入口事实，不能从部分清单推断其它入口缺席。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：容量、数量、字段和严格顺序均合法时为真。
    pub(crate) fn valid(&self) -> bool {
        self.rows.len() <= MAX_ENTRIES
            && (!self.capacity || self.rows.is_empty())
            && self
                .rows
                .iter()
                .all(|row| valid_id(&row.listener) && valid_id(&row.workspace))
            && self
                .rows
                .windows(2)
                .all(|pair| pair[0].listener < pair[1].listener)
    }

    /// 业务作用：把入口身份和整行容量计入既有共享采样预算，不能只按计数字段核算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：容器容量和全部owned字符串的保守字节成本。
    pub(crate) fn retained_bytes(&self) -> usize {
        self.rows.capacity() * std::mem::size_of::<Reading>()
            + self
                .rows
                .iter()
                .map(|row| row.listener.capacity() + row.workspace.capacity())
                .sum::<usize>()
    }
}

/// 业务作用：只允许有界可显示的配置身份，不提取请求维度或截断归属字段。
///
/// 参数说明：
/// - `value`：当前配置中的入口或工作区身份。
///
/// 返回：非空、不含控制字符且最多128字节为真。
fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
