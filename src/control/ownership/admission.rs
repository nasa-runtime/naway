//! 工作区公平在途预算；名额覆盖认证外呼和完整响应生命周期。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::Body as _;

use super::{Owner, OwnershipCatalog, ReservationDenied, PLATFORM};

#[derive(Default)]
pub struct Runtime {
    counters: parking_lot::Mutex<BTreeMap<String, Arc<AtomicUsize>>>,
}

#[derive(Clone)]
pub struct Permit {
    _lease: Arc<Lease>,
}

struct Lease {
    counter: Arc<AtomicUsize>,
}

impl Runtime {
    /// 业务作用：为命中路由获取本域在途名额，未获名额前不能进入身份外呼或业务上游。
    ///
    /// 参数说明：
    /// - `catalog`：为请求冻结配置
    /// - `owner`：为配置确定的路由归属。
    ///
    /// 返回：平台入口不附加名额；工作区容量或常驻表满时失败，不借用其它工作区预留。
    pub fn acquire(
        &self,
        catalog: &OwnershipCatalog,
        owner: &Owner,
    ) -> Result<Option<Permit>, ReservationDenied> {
        if owner.workspace == PLATFORM {
            return Ok(None);
        }
        // 同名 workspace 可以更换 tenant/environment；旧归属不能使用当前域的容量权威。
        if catalog
            .binding(&owner.workspace)
            .is_none_or(|binding| binding.owner != *owner)
        {
            return Err(ReservationDenied);
        }
        let quota = &catalog
            .workspaces
            .get(&owner.workspace)
            .ok_or(ReservationDenied)?
            .quota;
        self.acquire_limit(owner, quota.max_inflight).map(Some)
    }

    /// 业务作用：为管理读写或 watch 提供独立的每工作区并发预算，不与业务在途容量争抢。
    ///
    /// 参数说明：
    /// - `catalog`：为当前权限目录
    /// - `workspace`：是已授权域
    /// - `limit`：是服务端固定上限。
    ///
    /// 返回：持有期间独占一个域内名额；域消失或容量耗尽时失败。
    pub fn acquire_admin(
        &self,
        catalog: &OwnershipCatalog,
        workspace: &str,
        limit: usize,
    ) -> Result<Permit, ReservationDenied> {
        let binding = catalog.binding(workspace).ok_or(ReservationDenied)?;
        self.reconcile(catalog);
        self.acquire_limit(&binding.owner, limit)
    }

    /// 业务作用：原子取得常驻计数器内的名额，避免换代或并发检查突破硬上限。
    ///
    /// 参数说明：
    /// - `owner`：固定归属
    /// - `limit`：为该类操作的容量。
    ///
    /// 返回：成功返回唯一释放凭证；无剩余空间时不排队。
    fn acquire_limit(&self, owner: &Owner, limit: usize) -> Result<Permit, ReservationDenied> {
        let key = owner.namespace();
        let counter = {
            let mut counters = self.counters.lock();
            if !counters.contains_key(&key) {
                // 活动旧代仍持有名额时不得删除后重建计数器，否则 reload 会凭空扩大容量。
                if counters.len() >= 256 {
                    return Err(ReservationDenied);
                }
                counters.insert(key.clone(), Arc::new(AtomicUsize::new(0)));
            }
            counters[&key].clone()
        };
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value < limit).then_some(value + 1)
            })
            .map_err(|_| ReservationDenied)?;
        Ok(Permit {
            _lease: Arc::new(Lease {
                counter,
            }),
        })
    }

    /// 业务作用：在换版时回收已退休且没有在途持有者的计数器，保留旧流的实际占用。
    ///
    /// 参数说明：
    /// - `catalog`：为刚发布的归属目录。
    ///
    /// 返回：只回收失效空项，不重置仍存在的工作区预算。
    pub fn reconcile(&self, catalog: &OwnershipCatalog) {
        let active: BTreeSet<_> = catalog
            .workspaces
            .iter()
            .map(|(id, cfg)| {
                Owner {
                    workspace: id.clone(),
                    tenant: cfg.tenant.clone(),
                    environment: cfg.environment.clone(),
                }
                .namespace()
            })
            .collect();
        self.counters.lock().retain(|key, counter| {
            active.contains(key)
                || Arc::strong_count(counter) > 1
                || counter.load(Ordering::Acquire) != 0
        });
    }
}

impl Owner {
    /// 业务作用：将配置归属编码为无歧义状态命名空间，阻断同名主体、owner 转移后的状态复用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅含受限配置标识的稳定命名空间，不采用用户 header 或显示名。
    pub fn namespace(&self) -> String {
        format!("{}:{}:{}", self.workspace, self.tenant, self.environment)
    }
}

impl Permit {
    /// 业务作用：把在途名额移交响应正文，慢客户端或取消不会提前释放并发容量。
    ///
    /// 参数说明：
    /// - `body`：是完成响应变换后的下游正文。
    ///
    /// 返回：逐帧透传正文；空正文立即归还名额，其它正文在 EOF、错误或 Drop 时归还。
    pub fn wrap(self, body: crate::BoxBody) -> crate::BoxBody {
        if body.is_end_stream() {
            return body;
        }
        OwnedBody {
            inner: body,
            permit: Some(self),
        }
        .boxed()
    }
}

impl Drop for Lease {
    /// 业务作用：最后一个请求或隧道持有者结束后释放唯一名额，避免握手结束提前归还容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原子减少所属工作区计数，不影响其它 owner。
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

struct OwnedBody {
    inner: crate::BoxBody,
    permit: Option<Permit>,
}

impl hyper::body::Body for OwnedBody {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;

    /// 业务作用：不预读、不复制地传递正文，结束帧和错误只释放一次在途权威。
    ///
    /// 参数说明：
    /// - `cx`：为下游 backpressure 的轮询上下文。
    ///
    /// 返回：原正文帧；完整结束或错误时归还工作区名额。
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(result, std::task::Poll::Ready(None | Some(Err(_))))
            || this.inner.is_end_stream()
        {
            this.permit.take();
        }
        result
    }

    /// 业务作用：保留 HTTP 空正文与终止语义。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原正文结束提示。
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    /// 业务作用：保留原始 framing 长度提示，不把提示当作已交付量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原正文长度提示。
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
