//! 内容契约、转换与缓存比较直接借用编译计划，不读取请求或响应实体。

use super::Route;

impl Route {
    /// 业务作用：识别同名路由的请求与响应契约、正文转换、公共缓存和 GraphQL 策略变化。
    ///
    /// 参数说明：
    /// - `candidate`：完整构建且通过引用、预算和协议组合校验的候选路由。
    ///
    /// 返回：全部受支持内容声明一致时为真，不复制 Schema、query、literal 或缓存正文。
    pub(crate) fn same_content_configuration(&self, candidate: &Self) -> bool {
        self.http_cache == candidate.http_cache
            && self.request_validation == candidate.request_validation
            && self.response_contract == candidate.response_contract
            && self.request_transform == candidate.request_transform
            && self.response_transform == candidate.response_transform
            && self.graphql_guard == candidate.graphql_guard
            && self.degraphql == candidate.degraphql
    }
}
