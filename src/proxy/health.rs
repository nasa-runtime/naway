//! HTTP 上游观察与独占恢复探测的统一响应头边界。

use super::forward::ForwardError;
use crate::upstream::passive::window::Attempt;
use http::Response;
use std::future::Future;
use std::time::Duration;

/// 业务作用：在统一响应头边界记录上游健康，正常转发与扩展外呼共用相同的期限和本地拒绝排除规则。
///
/// 参数说明：
/// - `attempt`：当前目录授予的窗口观察或恢复探测凭据。
/// - `operation`：真实上游响应头操作；错误已经映射为网关错误分类。
/// - `timeout_ms`：当前外呼的响应头期限，0 表示不额外限制普通调用。
///
/// 返回：原始响应或错误；本地容量及输入拒绝不计后端失败，实际响应头超时计失败且取消 I/O。
pub(super) fn observe<F, B>(
    attempt: Option<Attempt>,
    operation: F,
    timeout_ms: u64,
) -> impl Future<Output = Result<Response<B>, ForwardError>>
where
    F: Future<Output = Result<Response<B>, ForwardError>>,
{
    observe_request(attempt, operation, timeout_ms, None)
}

/// 业务作用：在上游观察中排除本地请求整形的混合延迟和混合超时，仍保留真实失败状态证据。
///
/// 参数说明：
/// - `attempt`：本次窗口观察或独占探测权威。
/// - `operation`：真实上游响应头操作。
/// - `timeout_ms`：外呼响应头期限。
/// - `pacing`：仅网关数据面可生成的请求等待事实。
///
/// 返回：响应或已分类的拒绝；本地等待不产生慢响应样本，也不能证明后端已经恢复。
pub(super) fn observe_request<F, B>(
    attempt: Option<Attempt>,
    operation: F,
    timeout_ms: u64,
    pacing: Option<crate::runtime::traffic_limit::pacing::RequestPacing>,
) -> impl Future<Output = Result<Response<B>, ForwardError>>
where
    F: Future<Output = Result<Response<B>, ForwardError>>,
{
    let timeout_pacing = pacing.clone();
    let authority_pacing = pacing.clone();
    let probe_pacing = pacing.clone();
    let operation = async move {
        if timeout_ms == 0 {
            operation.await
        } else {
            tokio::time::timeout(Duration::from_millis(timeout_ms), operation)
                .await
                .map_err(|_| ForwardError::timeout_for(timeout_pacing.as_ref()))?
        }
    };
    let observed = Attempt::observe_classified(
        attempt,
        operation,
        move |result| match result {
            Ok(response)
                if !response.status().is_server_error()
                    && pacing.as_ref().is_some_and(|pacing| pacing.was_delayed()) =>
            {
                None
            }
            Ok(response) => Some(response.status().is_server_error()),
            Err(error) if !error.is_upstream_error() => None,
            Err(_) => Some(true),
        },
        move || {
            !probe_pacing
                .as_ref()
                .is_some_and(|pacing| pacing.was_delayed())
        },
    );
    async move {
        observed
            .await
            .unwrap_or_else(|_| Err(ForwardError::timeout_for(authority_pacing.as_ref())))
    }
}
