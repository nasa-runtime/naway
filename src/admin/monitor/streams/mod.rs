//! 当前监听器读面复用唯一对象采样轮次，目录与工作区证据缺席时不分摊全局流量。

mod aggregate;
mod read;
mod scope;
pub(in crate::admin) use read::read;

use super::model;
use super::routes::{Node, Publication};
