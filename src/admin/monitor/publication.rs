//! 当前样本共享结构化事实，只有HTTP观察者需要时才编码相应视图。

use super::model;
use bytes::Bytes;
use serde::Serialize;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

pub(super) struct Publication {
    pub at: Instant,
    pub sample: Arc<model::Sample>,
    previous: Option<Arc<model::Sample>>,
    document: OnceLock<Option<Bytes>>,
    raw: OnceLock<Option<Bytes>>,
}

#[derive(Serialize)]
struct Coverage {
    total: usize,
    reachable: usize,
    valid: usize,
    unknown: usize,
}

#[derive(Serialize)]
struct View<'a> {
    schema_version: u8,
    boot_id: &'a str,
    scope: &'static str,
    sample_id: u64,
    sampled_at_ms: u64,
    sampling_period_ms: u64,
    interval_ms: Option<u64>,
    availability: &'static str,
    coverage: Coverage,
    node: &'a model::NodeState,
    capabilities: &'a std::collections::BTreeMap<String, bool>,
    summary: serde_json::Value,
    latency: model::Latency,
    metrics: Vec<model::Point<'a>>,
}

impl Publication {
    /// 业务作用：发布同一份当前累计事实及必要相邻基线，纯内部共享不构造HTTP响应。
    ///
    /// 参数说明：
    /// - `sample`：已经通过固定目录与容量校验的当前样本。
    /// - `previous`：上一份成功样本，跨配置或不连续时不会继续持有。
    /// - `at`：开始读取原子事实时的本机单调时刻。
    ///
    /// 返回：尚未编码的共享发布对象；最多保留当前与一个有效基线，不保存历史队列。
    pub(super) fn new(
        sample: Arc<model::Sample>,
        previous: Option<Arc<model::Sample>>,
        at: Instant,
    ) -> Self {
        let previous = previous.filter(|old| model::interval(&sample, Some(old)).is_some());
        Self {
            at,
            sample,
            previous,
            document: OnceLock::new(),
            raw: OnceLock::new(),
        }
    }

    /// 业务作用：在对应HTTP读面首次访问时编码一次，其后仅共享不可变Bytes。
    ///
    /// 参数说明：
    /// - `raw`：内部抓取使用累计事实，页面使用当前有效区间。
    ///
    /// 返回：有界完整响应；编码超限记录为不可用，不重试放大相同样本的编码开销。
    pub(super) fn body(&self, raw: bool) -> Option<Bytes> {
        if raw {
            self.raw
                .get_or_init(|| super::encode(self.sample.as_ref()))
                .clone()
        } else {
            self.document.get_or_init(|| self.encode_view()).clone()
        }
    }

    /// 业务作用：借用当前样本直接编码区间读模型，不将完整指标表中转为JSON值树。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最多1MiB的完整页面响应；没有连续基线时速率与延迟保持未知。
    fn encode_view(&self) -> Option<Bytes> {
        let current = &self.sample;
        let elapsed = model::interval(current, self.previous.as_deref());
        let points = model::points(current, self.previous.as_deref());
        let latency = model::latency(
            &current.latency,
            self.previous.as_ref().map(|sample| &sample.latency),
        );
        let value = View {
            schema_version: 1,
            boot_id: &current.boot_id,
            scope: "local",
            sample_id: current.sample_id,
            sampled_at_ms: current.sampled_at_ms,
            sampling_period_ms: current.sampling_period_ms,
            interval_ms: elapsed,
            availability: if elapsed.is_some() {
                "available"
            } else {
                "sampling"
            },
            coverage: Coverage {
                total: 1,
                reachable: 1,
                valid: usize::from(elapsed.is_some()),
                unknown: usize::from(elapsed.is_none()),
            },
            node: &current.state,
            capabilities: &current.capabilities,
            summary: super::summary(&points),
            latency,
            metrics: points,
        };
        super::encode(&value)
    }
}
