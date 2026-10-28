//! 沙箱比较借用冻结执行计划，共享状态、HTTP 连接池和 Wasmtime 内部对象不参与判断。

use super::{CalloutCluster, WasmPlugin, WasmSharedState};

impl PartialEq for WasmPlugin {
    /// 业务作用：识别实际模块、配置字节、来源权限和沙箱预算变化，不重建客体实例。
    ///
    /// 参数说明：
    /// - `other`：已经完成模块、证明与 ABI 校验的候选插件。
    ///
    /// 返回：全部冻结声明一致时为真；编译器对象由同次模块材料摘要代表。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            id,
            module: _,
            module_digest,
            module_file,
            remote_source,
            max_module_bytes,
            config,
            fail_open,
            limits,
            callout_clusters,
            shared,
        } = self;
        id == &other.id
            && module_digest == &other.module_digest
            && module_file == &other.module_file
            && remote_source == &other.remote_source
            && max_module_bytes == &other.max_module_bytes
            && config == &other.config
            && fail_open == &other.fail_open
            && limits == &other.limits
            && callout_clusters == &other.callout_clusters
            && shared == &other.shared
    }
}

impl Eq for WasmPlugin {}

impl PartialEq for CalloutCluster {
    /// 业务作用：比较客体外呼的固定目标、传输选择和实际 CA，避免连接复用掩盖权限变化。
    ///
    /// 参数说明：
    /// - `other`：已经验证 origin 与信任材料的候选外呼能力。
    ///
    /// 返回：所有冻结传输参数相同时为真，不读取连接池或发送请求。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            origin,
            client: _,
            allow_cleartext,
            http2_prior_knowledge,
            ca_identity,
        } = self;
        origin == &other.origin
            && allow_cleartext == &other.allow_cleartext
            && http2_prior_knowledge == &other.http2_prior_knowledge
            && ca_identity == &other.ca_identity
    }
}

impl Eq for CalloutCluster {}

impl PartialEq for WasmSharedState {
    /// 业务作用：比较共享目录的真实归属和容量声明，不把客体运行产生的数据当成配置变更。
    ///
    /// 参数说明：
    /// - `other`：同一路由候选中的共享目录计划。
    ///
    /// 返回：namespace 与全部上限相同时为真，不获取数据、队列、指标或租约锁。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            namespace,
            limits,
            inner: _,
        } = self;
        namespace == &other.namespace && limits == &other.limits
    }
}

impl Eq for WasmSharedState {}
