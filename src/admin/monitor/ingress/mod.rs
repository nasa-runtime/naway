//! HTTP入口守卫的当前读面复用唯一采样轮次，工作区只读取已证明的接入入口归属。

mod aggregate;
mod read;
mod scope;
pub(in crate::admin) use read::read;

use super::routes::{Node, Publication};
