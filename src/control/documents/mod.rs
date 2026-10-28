//! 配置文件的目录能力、原文身份与进程内暂存。

mod staging;
mod target;

pub(in crate::control) use staging::Staged;
pub(in crate::control) use target::{Fingerprint, Original, Target};

const LIMIT: usize = crate::config::document::MAX_DOCUMENT_BYTES;
