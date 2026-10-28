//! 配置提供者先进入统一声明模型，来源水位与完整网关候选共同提交。

mod compile;
mod consul;
mod etcd;
mod inspection;
pub(crate) mod metrics;
mod model;
mod plan;
mod redis;
mod runtime;
mod state;
mod workload;
mod zookeeper;

pub(crate) use plan::dependency_paths;
pub(crate) use runtime::spawn;
pub(crate) use state::{Input, Observation, Snapshot};
mod registry;
