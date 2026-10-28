//! Wasm、外部处理器与固定业务扩展声明。

use super::*;

/// InferencePool 后端的请求期 EPP 选择约束。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct InferencePoolRouteCfg {
    /// 单次 EPP 决策允许返回的 endpoint 数量上限，防止 header 或 metadata 扩大选择扫描成本。
    #[serde(default = "default_inference_pool_max_selected_endpoints")]
    pub max_selected_endpoints: usize,
}

/// 业务作用：限制 EPP 单次可交给负载均衡器的 endpoint 子集规模。
///
/// 参数说明: 无。
///
/// 返回：默认允许六十四个候选 endpoint。
pub(super) const fn default_inference_pool_max_selected_endpoints() -> usize {
    64
}

/// route 级 descriptor 驱动 protobuf JSON 转码契约。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcTranscodingCfg {
    /// 受信本地 `FileDescriptorSet` 文件；相对路径以 `gateway.yml` 所在目录解析。
    pub descriptor_set_file: String,
    /// 允许暴露的 protobuf service full name；必须显式列出，空数组会 fail closed。
    pub services: Vec<String>,
    /// 可选 method full name 白名单；空表示允许上述 service 的全部 method。
    #[serde(default)]
    pub methods: Vec<String>,
    /// 是否启用 `google.api.http` path/query/body 映射。
    #[serde(default)]
    pub google_http: bool,
    /// 是否启用 Connect unary/streaming JSON。
    #[serde(default = "default_true")]
    pub connect_json: bool,
    /// JSON 中出现 descriptor 未声明字段时是否拒绝；安全默认不静默丢字段。
    #[serde(default = "default_true")]
    pub reject_unknown_fields: bool,
    /// descriptor 文件有界读取上限。
    #[serde(default = "default_grpc_descriptor_bytes")]
    pub max_descriptor_bytes: usize,
    /// 单条输入 protobuf message 解码后的最大字节数。
    #[serde(default = "default_grpc_input_message_bytes")]
    pub max_input_message_bytes: usize,
    /// 单条输出 protobuf message 解码前允许的最大字节数。
    #[serde(default = "default_grpc_output_message_bytes")]
    pub max_output_message_bytes: usize,
    /// 单条 JSON document 的最大字节数；不能超过对应 protobuf message 上限。
    #[serde(default = "default_grpc_json_bytes")]
    pub max_json_bytes: usize,
    /// 单个 streaming RPC 允许转换的最大消息数，防止无限流永久占用 descriptor 慢路径。
    #[serde(default = "default_grpc_stream_messages")]
    pub max_stream_messages: u64,
    /// 单 stream codec 可保留的未完成 envelope/JSON 字节上限。
    #[serde(default = "default_grpc_stream_buffer_bytes")]
    pub max_stream_buffer_bytes: usize,
}

/// 业务作用：提供 descriptor 文件的默认有界读取预算，避免控制面按文件长度无界分配。
///
/// 参数说明: 无。
///
/// 返回：16 MiB descriptor 上限。
pub(super) fn default_grpc_descriptor_bytes() -> usize {
    16 * 1024 * 1024
}

/// 业务作用：提供单条 gRPC 输入消息的默认转码预算。
///
/// 参数说明: 无。
///
/// 返回：4 MiB 输入消息上限。
pub(super) fn default_grpc_input_message_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：提供单条 gRPC 输出消息的默认转码预算。
///
/// 参数说明: 无。
///
/// 返回：4 MiB 输出消息上限。
pub(super) fn default_grpc_output_message_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：提供单条 protobuf JSON document 的默认转码预算。
///
/// 参数说明: 无。
///
/// 返回：4 MiB JSON 上限。
pub(super) fn default_grpc_json_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：限制单个长流可转换的消息总数，避免未设业务 deadline 时无限占用慢路径状态。
///
/// 参数说明: 无。
///
/// 返回：默认最多一百万条消息。
pub(super) fn default_grpc_stream_messages() -> u64 {
    1_000_000
}

/// 业务作用：限制 streaming codec 为跨 DATA frame 拼接保留的未完成数据。
///
/// 参数说明: 无。
///
/// 返回：默认 4 MiB stream 暂存上限。
pub(super) fn default_grpc_stream_buffer_bytes() -> usize {
    4 * 1024 * 1024
}

/// 一个 route 绑定的 Proxy-Wasm ABI v0.2.1 插件。
///
/// 只有显式选择 request/response body 相位才会进入有界聚合慢路径；header 相位与未配置
/// route 仍保持流式。运行时不挂 WASI，也不给文件、socket 或环境变量能力。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WasmPluginCfg {
    /// 稳定插件 id，仅用于构建报错和低基数日志。
    pub id: String,
    /// 本地 `.wasm` 文件，相对于 gateway.yml 所在目录；与 `module_source` 必须二选一。
    #[serde(default)]
    pub module_file: String,
    /// 受验证的 HTTPS 或 OCI 远程模块；候选快照构建期获取，不进入请求路径。
    #[serde(default)]
    pub module_source: Option<WasmModuleSourceCfg>,
    /// 执行相位。
    pub phase: WasmPluginPhaseCfg,
    /// 传给 `proxy_on_configure` 的 JSON 值；构建期序列化并执行 64KiB 硬上限。
    #[serde(default)]
    pub config: serde_json::Value,
    /// 插件 trap/超时/越界时是否跳过本插件。默认 false，安全故障关闭。
    #[serde(default)]
    pub fail_open: bool,
    /// wasm 文件最大字节数。
    #[serde(default = "default_wasm_max_module_bytes")]
    pub max_module_bytes: usize,
    /// 单次实例线性内存上限。
    #[serde(default = "default_wasm_max_memory_bytes")]
    pub max_memory_bytes: usize,
    /// 单次调用可消耗的 Wasmtime fuel。
    #[serde(default = "default_wasm_max_fuel")]
    pub max_fuel: u64,
    /// 单次调用墙钟上限；epoch 中断防止 host call/非预期路径绕过 fuel 预算。
    #[serde(default = "default_wasm_timeout_ms")]
    pub timeout_ms: u64,
    /// 单次调用允许的 header/local-response 变更次数。
    #[serde(default = "default_wasm_max_mutations")]
    pub max_mutations: usize,
    /// 插件可见并可交付的整份 header map 上限。
    #[serde(default = "default_wasm_max_header_bytes")]
    pub max_header_bytes: usize,
    /// request/response body 相位可聚合、读取和改写的 data 字节上限。
    #[serde(default = "default_wasm_max_body_bytes")]
    pub max_body_bytes: usize,
    /// `proxy_send_local_response` 响应体上限；本地响应是插件唯一可生成的 body。
    #[serde(default = "default_wasm_max_local_response_body_bytes")]
    pub max_local_response_body_bytes: usize,
    /// 客体可使用的固定 HTTP/gRPC callout 上游白名单。
    #[serde(default)]
    pub callout_clusters: Vec<WasmCalloutClusterCfg>,
    /// 单次 invocation 可登记的 callout 总数。
    #[serde(default = "default_wasm_max_callouts")]
    pub max_callouts: usize,
    /// 单个 callout 响应体可进入客体内存的字节上限。
    #[serde(default = "default_wasm_max_callout_response_bytes")]
    pub max_callout_response_bytes: usize,
    /// 固定租户/业务命名空间；运行时叠加 route、插件 id 与模块摘要实现版本隔离。
    #[serde(default)]
    pub shared_namespace: String,
    /// shared-data key 数量硬上限。
    #[serde(default = "default_wasm_max_shared_entries")]
    pub max_shared_entries: usize,
    /// shared data、property 与 queue payload 合计驻留字节硬上限。
    #[serde(default = "default_wasm_max_shared_bytes")]
    pub max_shared_bytes: usize,
    /// 可注册 shared queue 数量硬上限。
    #[serde(default = "default_wasm_max_shared_queues")]
    pub max_shared_queues: usize,
    /// 单条 shared queue 消息数硬上限。
    #[serde(default = "default_wasm_max_queue_entries")]
    pub max_queue_entries: usize,
    /// 可定义内部 metric 数量硬上限。
    #[serde(default = "default_wasm_max_metrics")]
    pub max_metrics: usize,
}

/// Proxy-Wasm 远程制品来源与供应链验证声明。
///
/// `sha256` 固定最终 wasm 原始字节；OCI tag 还必须固定 `manifest_sha256`。远程模块必须
/// 配置 detached Ed25519 signature、签名 in-toto statement，或同时配置两者。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WasmModuleSourceCfg {
    /// 固定 HTTPS URL，或 `oci://registry/repository:tag|@sha256:...` reference。
    pub reference: String,
    /// 最终 wasm 原始字节的 SHA-256 十六进制摘要。
    pub sha256: String,
    /// OCI manifest 摘要；使用 tag 时必填，使用 digest reference 时可省略但不得冲突。
    #[serde(default)]
    pub manifest_sha256: String,
    /// HTTP Authorization 完整值；支持 SecretSource，不会发送给模块来源以外的目标。
    #[serde(default)]
    pub authorization: String,
    /// 附加 TLS 根证书 PEM；支持 SecretSource，平台根证书仍保留。
    #[serde(default)]
    pub ca_certificate: String,
    /// 内容寻址离线缓存目录；相对路径以 gateway.yml 所在目录解析，空值关闭磁盘缓存。
    #[serde(default)]
    pub cache_dir: String,
    /// connect、response head 与完整 body 共用的固定 deadline。
    #[serde(default = "default_wasm_source_timeout_ms")]
    pub timeout_ms: u64,
    /// detached Ed25519 signature 的 Base64 SecretSource；必须与 `public_key` 同时配置。
    #[serde(default)]
    pub signature: String,
    /// detached signature 对应的 32-byte Ed25519 public key Base64 SecretSource。
    #[serde(default)]
    pub public_key: String,
    /// 可选签名 in-toto statement；存在时同时验证 statement 签名、subject 摘要和 provenance。
    #[serde(default)]
    pub attestation: Option<WasmAttestationCfg>,
}

/// 签名 in-toto Statement v1 的最小可信约束。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WasmAttestationCfg {
    /// 原始 JSON statement SecretSource；detached signature 精确覆盖这些 UTF-8 字节。
    pub statement: String,
    /// statement detached Ed25519 signature 的 Base64 SecretSource。
    pub signature: String,
    /// statement signer 的 32-byte Ed25519 public key Base64 SecretSource。
    pub public_key: String,
    /// 必须精确匹配 statement `predicateType` 的受信类型。
    pub predicate_type: String,
    /// 必须精确匹配 statement `predicate.builder.id` 的受信构建者身份。
    pub builder_id: String,
    /// 可选 subject name；空值只要求至少一个 subject 的 SHA-256 匹配模块。
    #[serde(default)]
    pub subject_name: String,
}

/// 业务作用：为远程 Wasm 获取提供足够实际部署、又能限制挂起时间的默认 deadline。
///
/// 参数说明: 无。
///
/// 返回：默认十秒 deadline。
pub(super) const fn default_wasm_source_timeout_ms() -> u64 {
    10_000
}

/// Proxy-Wasm callout 的固定上游能力声明。
///
/// 客体只能引用 `name`，不能提供 URL 或直接打开 socket；实际 origin 与 TLS 信任材料在
/// 候选快照构建期固定，从而把网络权限收敛为可审计白名单。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WasmCalloutClusterCfg {
    /// 客体在 `proxy_http_call`/`proxy_grpc_call` 中使用的稳定名称。
    pub name: String,
    /// 固定 `http://` 或 `https://` origin，不允许 path、query、fragment 或 userinfo。
    pub origin: String,
    /// 自定义 CA certificate bundle 的 SecretSource；空时使用平台根证书。
    #[serde(default)]
    pub ca_certificate: String,
    /// 是否显式允许明文 HTTP；默认只接受 HTTPS。
    #[serde(default)]
    pub allow_cleartext: bool,
    /// 对受控明文 origin 强制使用 HTTP/2 prior knowledge；主要用于内网 h2c gRPC 服务。
    #[serde(default)]
    pub http2_prior_knowledge: bool,
}

/// 一个 route 绑定的外部 HTTP 头部插件。
///
/// 插件 endpoint 收到固定 JSON contract，返回 `continue` 头部变更或有界
/// `local_response`。所有可见头和可修改头都必须显式声明；认证凭据只通过独立的
/// `authorization` SecretSource 注入，不会混入业务请求头集合。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExternalPluginCfg {
    /// 稳定插件 id，仅用于配置错误和结构化日志，不进入 Prometheus label。
    pub id: String,
    /// `http(s)://host[:port]` 或 `lb://service` origin。
    pub target: String,
    /// endpoint 固定绝对 path，不允许 query。
    #[serde(default = "default_external_plugin_path")]
    pub path: String,
    /// 执行相位。
    pub phase: ExternalPluginPhaseCfg,
    /// response head + body 的共同 deadline。
    #[serde(default = "default_external_plugin_timeout_ms")]
    pub timeout_ms: u64,
    /// transport、非 2xx 或畸形响应时是否丢弃本插件结果并继续；默认故障关闭。
    #[serde(default)]
    pub fail_open: bool,
    /// 发给插件 endpoint 的完整 Authorization 值；支持 SecretSource，默认不发送。
    #[serde(default)]
    pub authorization: String,
    /// 插件可以读取的请求头 allowlist。响应相位只快照这些头，不 clone 整份请求 head。
    #[serde(default)]
    pub include_request_headers: Vec<String>,
    /// 响应相位插件可以读取的响应头 allowlist；请求相位必须为空。
    #[serde(default)]
    pub include_response_headers: Vec<String>,
    /// `continue.set_headers/remove_headers` 可以修改的当前相位头 allowlist。
    #[serde(default)]
    pub mutation_headers: Vec<String>,
    /// 单个可见/返回 header value 的 UTF-8 字节上限。
    #[serde(default = "default_external_plugin_max_header_value_bytes")]
    pub max_header_value_bytes: usize,
    /// 发给插件的 JSON 硬上限；转义扩张也在有界 writer 内检查。
    #[serde(default = "default_external_plugin_max_input_bytes")]
    pub max_input_bytes: usize,
    /// 插件响应 body 硬上限。
    #[serde(default = "default_external_plugin_max_response_bytes")]
    pub max_response_bytes: usize,
    /// `local_response.body` UTF-8 字节硬上限。
    #[serde(default = "default_external_plugin_max_local_response_body_bytes")]
    pub max_local_response_body_bytes: usize,
}

/// 外部 HTTP 插件执行相位。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalPluginPhaseCfg {
    /// 本地认证/OPA/Casbin/Proxy-Wasm 之后，请求体校验之前。
    RequestHeaders,
    /// 内部跳转、error_page 和声明式响应过滤之后，Proxy-Wasm/压缩之前。
    ResponseHeaders,
}

/// route 绑定的 Envoy External Processing 双向流契约。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExtProcCfg {
    /// `http(s)://host[:port]` 或 `lb://service` 扩展服务。
    pub target: String,
    /// 依赖连接、超时或服务不可用时是否继续；协议拒绝与非法 mutation 永不放行。
    #[serde(default)]
    pub fail_open: bool,
    /// 可选 gRPC Authorization metadata；支持 SecretSource，且不会进入下游可见头。
    #[serde(default)]
    pub authorization: String,
    /// 是否把 request headers 发送给处理器。
    #[serde(default = "default_true")]
    pub request_headers: bool,
    /// 是否把 response headers 发送给处理器。
    #[serde(default = "default_true")]
    pub response_headers: bool,
    /// request body 的传递方式。
    #[serde(default)]
    pub request_body: ExtProcBodyModeCfg,
    /// response body 的传递方式。
    #[serde(default)]
    pub response_body: ExtProcBodyModeCfg,
    /// 是否发送 request trailers。
    #[serde(default)]
    pub request_trailers: bool,
    /// 是否发送 response trailers。
    #[serde(default)]
    pub response_trailers: bool,
    /// 单个 phase 等待匹配响应的 deadline。
    #[serde(default = "default_ext_proc_message_timeout_ms")]
    pub message_timeout_ms: u64,
    /// 整条处理流的总生命周期上限。
    #[serde(default = "default_ext_proc_total_timeout_ms")]
    pub total_timeout_ms: u64,
    /// 单条 protobuf payload 的编码后字节上限。
    #[serde(default = "default_ext_proc_max_message_bytes")]
    pub max_message_bytes: usize,
    /// 一条业务请求在扩展流双向累计传输的字节上限。
    #[serde(default = "default_ext_proc_max_total_bytes")]
    pub max_total_bytes: usize,
    /// buffered body 的聚合上限，也是 streamed body 的累计上限。
    #[serde(default = "default_ext_proc_max_body_bytes")]
    pub max_body_bytes: usize,
    /// 单 route 可同时占用的处理流数量；满额立即执行依赖失败策略。
    #[serde(default = "default_ext_proc_max_in_flight")]
    pub max_in_flight: usize,
    /// 连续依赖失败达到该值后打开 circuit；成功响应会清零。
    #[serde(default = "default_ext_proc_failure_threshold")]
    pub failure_threshold: u32,
    /// circuit 打开后允许下一次探测前的冷却时间。
    #[serde(default = "default_ext_proc_reset_timeout_ms")]
    pub reset_timeout_ms: u64,
    /// 处理器可 set/remove 的普通 header allowlist。
    #[serde(default)]
    pub mutation_headers: Vec<String>,
    /// 允许写入当前请求动态 metadata 的顶层 namespace allowlist。
    #[serde(default)]
    pub writable_metadata_namespaces: Vec<String>,
}

/// External Processing body 的交付模式。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExtProcBodyModeCfg {
    /// 不发送 body，也不允许 body mutation。
    #[default]
    None,
    /// 聚合到显式上限后发送单条完整 body。
    Buffered,
    /// 按原始 DATA frame 顺序发送，并逐条等待匹配响应形成背压。
    Streamed,
}

/// 业务作用：限制扩展处理器单个 phase 占用请求任务的时间。
///
/// 参数说明: 无。
///
/// 返回：默认 200ms。
pub(super) const fn default_ext_proc_message_timeout_ms() -> u64 {
    200
}

/// 业务作用：限制一条 External Processing 双向流的总生命周期。
///
/// 参数说明: 无。
///
/// 返回：默认 30 秒。
pub(super) const fn default_ext_proc_total_timeout_ms() -> u64 {
    30_000
}

/// 业务作用：限制单条 protobuf 消息，避免处理器制造超大分配。
///
/// 参数说明: 无。
///
/// 返回：默认 1 MiB。
pub(super) const fn default_ext_proc_max_message_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制单请求扩展流的双向累计流量。
///
/// 参数说明: 无。
///
/// 返回：默认 16 MiB。
pub(super) const fn default_ext_proc_max_total_bytes() -> usize {
    16 * 1024 * 1024
}

/// 业务作用：限制显式进入扩展处理路径的业务实体总量。
///
/// 参数说明: 无。
///
/// 返回：默认 8 MiB。
pub(super) const fn default_ext_proc_max_body_bytes() -> usize {
    8 * 1024 * 1024
}

/// 业务作用：为单 route 提供有界 External Processing 在途预算。
///
/// 参数说明: 无。
///
/// 返回：默认 64 条并发流。
pub(super) const fn default_ext_proc_max_in_flight() -> usize {
    64
}

/// 业务作用：限制依赖连续失败后仍继续尝试建流的次数。
///
/// 参数说明: 无。
///
/// 返回：默认连续五次失败后打开 circuit。
pub(super) const fn default_ext_proc_failure_threshold() -> u32 {
    5
}

/// 业务作用：为已打开的扩展依赖 circuit 提供有界恢复探测间隔。
///
/// 参数说明: 无。
///
/// 返回：默认一秒。
pub(super) const fn default_ext_proc_reset_timeout_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `path` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_external_plugin_path() -> String {
    "/v1/plugin".to_owned()
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_external_plugin_timeout_ms() -> u64 {
    200
}

/// 业务作用：为未显式声明的 `max_header_value_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_external_plugin_max_header_value_bytes() -> usize {
    16 * 1024
}

/// 业务作用：为未显式声明的 `max_input_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_external_plugin_max_input_bytes() -> usize {
    256 * 1024
}

/// 业务作用：为未显式声明的 `max_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_external_plugin_max_response_bytes() -> usize {
    256 * 1024
}

/// 业务作用：为未显式声明的 `max_local_response_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_external_plugin_max_local_response_body_bytes() -> usize {
    64 * 1024
}

/// 一条 BFF 聚合 route 的资源预算与子请求列表。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BffAggregationCfg {
    /// 有序子请求列表；每个 target id 对应聚合 JSON 的一个键。
    pub targets: Vec<BffTargetCfg>,
    /// 聚合 JSON 最大编码字节数。
    #[serde(default = "default_bff_max_total_response_bytes")]
    pub max_total_response_bytes: usize,
    /// 所有 fan-out 的共同总 deadline。
    #[serde(default = "default_bff_total_timeout_ms")]
    pub total_timeout_ms: u64,
}

/// BFF 中一个只读 HTTP 子请求。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BffTargetCfg {
    /// 合并结果中的稳定 key。
    pub id: String,
    /// `http(s)://` 或 `lb://service`。
    pub uri: String,
    /// 固定 origin path；不接受 query/模板，避免客户端参数越权扇出。
    #[serde(default = "default_bff_path")]
    pub path: String,
    /// 单子请求 deadline。
    #[serde(default = "default_bff_target_timeout_ms")]
    pub timeout_ms: u64,
    /// 单子响应 body 上限。
    #[serde(default = "default_bff_max_target_response_bytes")]
    pub max_response_bytes: usize,
    /// true：失败使整个聚合失败；false：结果 key 为 null，并在 `_errors` 给固定状态。
    #[serde(default = "default_true")]
    pub required: bool,
    /// 从已认证下游 head 转发的非敏感 header allowlist；默认空。
    #[serde(default)]
    pub forward_headers: Vec<String>,
}

/// HTTP JSON→Dubbo2 generic invocation。service/method/type 全由 route 固定，客户端只提供
/// `arguments`，避免把公网输入升级成任意 RPC 调用器。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DubboRouteCfg {
    /// Dubbo service interface 全限定名。
    pub interface: String,
    /// 实际业务 method；wire method 固定为 `$invoke`。
    pub method: String,
    /// 与 arguments 一一对应的 Java 参数类型名。
    #[serde(default)]
    pub parameter_types: Vec<String>,
    /// Dubbo service version。
    #[serde(default)]
    pub version: String,
    /// Dubbo service group。
    #[serde(default)]
    pub group: String,
    /// wire serialization；`json` 使用 id=6，`hessian2` 使用 id=2 且需要对应制品 feature。
    #[serde(default)]
    pub serialization: DubboSerializationCfg,
    /// 下游 JSON body 上限。
    #[serde(default = "default_dubbo_max_request_body_bytes")]
    pub max_request_body_bytes: u64,
    /// 编码后 Dubbo request frame body 上限，独立约束序列化膨胀。
    #[serde(default = "default_dubbo_max_request_frame_bytes")]
    pub max_request_frame_bytes: usize,
    /// Dubbo response frame body 上限。
    #[serde(default = "default_dubbo_max_response_body_bytes")]
    pub max_response_body_bytes: usize,
    /// Hessian2 单值最大字符串 UTF-8 字节数。
    #[serde(default = "default_dubbo_max_hessian_string_bytes")]
    pub max_hessian_string_bytes: usize,
    /// Hessian2 单值最大 binary 字节数；HTTP JSON 使用标准 Base64 表示 binary。
    #[serde(default = "default_dubbo_max_hessian_binary_bytes")]
    pub max_hessian_binary_bytes: usize,
    /// Hessian2 单 frame 可遍历的 collection/object 字段总数。
    #[serde(default = "default_dubbo_max_hessian_collection_items")]
    pub max_hessian_collection_items: usize,
    /// Hessian2 collection/object 最大递归深度。
    #[serde(default = "default_dubbo_max_hessian_depth")]
    pub max_hessian_depth: usize,
    /// TCP connect 上限。
    #[serde(default = "default_dubbo_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// write + response header/body 总 deadline。
    #[serde(default = "default_dubbo_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// 每个 endpoint 的空闲连接上限；0 禁用复用。
    #[serde(default = "default_dubbo_max_idle_connections")]
    pub max_idle_connections: usize,
    /// 固定 Dubbo attachments；值支持 SecretSource，构建期解析。
    #[serde(default)]
    pub attachments: HashMap<String, String>,
}

/// Dubbo2 wire 序列化类型。
#[derive(Debug, Deserialize, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum DubboSerializationCfg {
    /// Dubbo serialization id 6；provider 必须显式支持 `json`。
    #[default]
    Json,
    /// Dubbo serialization id 2；使用 provider 默认 Hessian2 泛化调用协议。
    Hessian2,
}

/// 业务作用：提供下游 Dubbo JSON envelope 的保守默认字节门。
///
/// 参数说明: 无。
///
/// 返回：返回 1 MiB 请求体上限。
pub(super) const fn default_dubbo_max_request_body_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：提供序列化后 Dubbo request frame 的独立默认上限，隔离编码膨胀。
///
/// 参数说明: 无。
///
/// 返回：返回 4 MiB frame body 上限。
pub(super) const fn default_dubbo_max_request_frame_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：提供 Dubbo response frame 的默认读取硬门。
///
/// 参数说明: 无。
///
/// 返回：返回 4 MiB frame body 上限。
pub(super) const fn default_dubbo_max_response_body_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：限制单个 Hessian2 字符串的默认 UTF-8 字节数。
///
/// 参数说明: 无。
///
/// 返回：返回 1 MiB 单字符串上限。
pub(super) const fn default_dubbo_max_hessian_string_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制单个 Hessian2 binary 的默认真实字节数。
///
/// 参数说明: 无。
///
/// 返回：返回 1 MiB 单 binary 上限。
pub(super) const fn default_dubbo_max_hessian_binary_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制单个 Hessian2 frame 内 collection/object 的默认累计元素数。
///
/// 参数说明: 无。
///
/// 返回：返回 65,536 个元素的累计上限。
pub(super) const fn default_dubbo_max_hessian_collection_items() -> usize {
    65_536
}

/// 业务作用：限制 Hessian2 collection/object 的默认递归深度。
///
/// 参数说明: 无。
///
/// 返回：返回 32 层递归上限。
pub(super) const fn default_dubbo_max_hessian_depth() -> usize {
    32
}

/// 业务作用：提供 Dubbo TCP 建连的默认 deadline。
///
/// 参数说明: 无。
///
/// 返回：返回 1000 毫秒。
pub(super) const fn default_dubbo_connect_timeout_ms() -> u64 {
    1000
}

/// 业务作用：提供一次 Dubbo 写入与完整响应读取的默认总 deadline。
///
/// 参数说明: 无。
///
/// 返回：返回 3000 毫秒。
pub(super) const fn default_dubbo_request_timeout_ms() -> u64 {
    3000
}

/// 业务作用：提供每个 Dubbo endpoint 的默认空闲连接容量。
///
/// 参数说明: 无。
///
/// 返回：返回 8 条空闲连接。
pub(super) const fn default_dubbo_max_idle_connections() -> usize {
    8
}

/// 构建期编译为固定响应的 API mock。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MockResponseCfg {
    /// 固定 HTTP 状态码。
    #[serde(default = "default_mock_status")]
    pub status: u16,
    /// 构建期验证并编译的固定响应头。
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// 固定 UTF-8 响应体。
    #[serde(default)]
    pub body: String,
}

/// route 级显式 chaos 注入。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FaultInjectionCfg {
    /// 0..=10000 basis points；10000 表示每次命中。
    pub percentage_bps: u16,
    /// 命中后异步延迟，不阻塞 Tokio worker。
    #[serde(default)]
    pub delay_ms: u64,
    /// 延迟后返回的固定错误；空表示只注入延迟后继续原后端。
    #[serde(default)]
    pub abort_status: Option<u16>,
    /// 注入固定错误时返回的 UTF-8 body。
    #[serde(default)]
    pub abort_body: String,
}

/// 业务作用：为未显式声明的 `max_total_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_bff_max_total_response_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `total_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_bff_total_timeout_ms() -> u64 {
    2_000
}

/// 业务作用：为未显式声明的 `path` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_bff_path() -> String {
    "/".to_owned()
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_bff_target_timeout_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `max_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_bff_max_target_response_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `status` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_mock_status() -> u16 {
    200
}

/// Proxy-Wasm HTTP 回调相位。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WasmPluginPhaseCfg {
    /// 认证与 OPA 通过后、请求体校验/限流/上游前。
    RequestHeaders,
    /// 请求头插件提交后、外部策略与上游转发前；显式有界聚合完整请求 body。
    RequestBody,
    /// 请求 body 逐 DATA frame 回调；每次只暴露当前 frame，并以 body poll 自然施加背压。
    RequestBodyStream,
    /// 内部跳转与 error_page 完成后、压缩/限速前。
    ResponseHeaders,
    /// 响应头插件提交后、压缩/限速前；显式有界聚合完整响应 body。
    ResponseBody,
    /// 响应 body 逐 DATA frame 回调；不聚合完整响应，适合长流与无限流。
    ResponseBodyStream,
}

/// 业务作用：为未显式声明的 `max_module_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_wasm_max_module_bytes() -> usize {
    16 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `max_memory_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_wasm_max_memory_bytes() -> usize {
    8 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `max_fuel` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_wasm_max_fuel() -> u64 {
    10_000_000
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_wasm_timeout_ms() -> u64 {
    10
}

/// 业务作用：为未显式声明的 `max_mutations` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_wasm_max_mutations() -> usize {
    64
}

/// 业务作用：为未显式声明的 `max_header_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_wasm_max_header_bytes() -> usize {
    64 * 1024
}

/// 业务作用：为未显式声明的 `max_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_wasm_max_body_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `max_local_response_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_wasm_max_local_response_body_bytes() -> usize {
    64 * 1024
}

/// 业务作用：限制单次 Proxy-Wasm invocation 可登记的异步 callout 数量，避免客体制造出站扇出。
///
/// 参数说明: 无。
///
/// 返回：默认最多 4 个受控 callout。
pub(super) const fn default_wasm_max_callouts() -> usize {
    4
}

/// 业务作用：限制单个 callout 响应可进入客体内存的字节数。
///
/// 参数说明: 无。
///
/// 返回：默认 1 MiB 响应上限。
pub(super) const fn default_wasm_max_callout_response_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制插件命名空间内可同时存在的 shared-data key 数量。
///
/// 参数说明: 无。
///
/// 返回：默认 1024 个条目。
pub(super) const fn default_wasm_max_shared_entries() -> usize {
    1024
}

/// 业务作用：限制插件命名空间内 shared data、property 与 queue payload 的合计驻留字节。
///
/// 参数说明: 无。
///
/// 返回：默认 4 MiB 驻留上限。
pub(super) const fn default_wasm_max_shared_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：限制单个插件命名空间可注册的 shared queue 数量。
///
/// 参数说明: 无。
///
/// 返回：默认 64 条队列。
pub(super) const fn default_wasm_max_shared_queues() -> usize {
    64
}

/// 业务作用：限制单条 shared queue 的待消费消息数，防止慢消费者造成无界堆积。
///
/// 参数说明: 无。
///
/// 返回：默认 1024 条消息。
pub(super) const fn default_wasm_max_queue_entries() -> usize {
    1024
}

/// 业务作用：限制插件可定义的内部 metric 数量，控制指标名称基数。
///
/// 参数说明: 无。
///
/// 返回：默认 256 个 metric。
pub(super) const fn default_wasm_max_metrics() -> usize {
    256
}
