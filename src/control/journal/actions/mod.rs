//! 节点目录内的单一动作事实，与本地文件决定共用提交权威。

mod absence;
mod application;
mod candidate;
mod prepare;
mod query;
mod rejection;
mod release;
mod settlement;

pub(crate) use application::Application;
pub(crate) use model::Stage;
pub(crate) use prepare::Preparation;
pub(crate) use query::EffectState;
mod lifecycle;
mod materials;
pub(super) mod model;
mod publication;
