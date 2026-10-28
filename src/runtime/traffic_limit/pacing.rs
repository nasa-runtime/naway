//! 请求方向的本地整形事实，避免把网关自己的等待归因给上游。

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Default)]
pub(crate) struct RequestPacing(Arc<AtomicBool>);

impl RequestPacing {
    /// 业务作用：在请求实体因本地带宽暂停时留下不可回退的本次转发事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：后续观察均能识别混入本地等待的响应头时长，不由客户端头赋值。
    pub(crate) fn mark_wait(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// 业务作用：判断本次转发是否经过本地请求整形等待，保护后端延迟学习与超时归因。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：出现本地等待后恒为 true；未启用整形时无需创建该对象。
    pub(crate) fn was_delayed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
