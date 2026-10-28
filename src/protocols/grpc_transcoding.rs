//! Descriptor 驱动的 protobuf JSON 转码计划。
//!
//! 文件读取、descriptor 校验和 RPC 白名单编译只发生在快照 build/reload。普通 route 不创建
//! 本计划；未编 `grpc-descriptor` feature 的制品遇到配置会在任何数据面副作用前 fail closed。

use std::path::Path;

use anyhow::Result;

use crate::config::model::GrpcTranscodingCfg;

#[cfg(feature = "grpc-descriptor")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "grpc-descriptor")]
use std::path::PathBuf;
#[cfg(feature = "grpc-descriptor")]
use std::sync::Arc;

#[cfg(feature = "grpc-descriptor")]
use anyhow::Context;
#[cfg(feature = "grpc-descriptor")]
use bytes::Bytes;
#[cfg(feature = "grpc-descriptor")]
use http::{Method, StatusCode, Uri};
#[cfg(feature = "grpc-descriptor")]
use percent_encoding::percent_decode_str;
#[cfg(feature = "grpc-descriptor")]
use prost::Message;
#[cfg(feature = "grpc-descriptor")]
use prost_reflect::{
    DescriptorPool, DeserializeOptions, DynamicMessage, FieldDescriptor, Kind, MessageDescriptor,
    MethodDescriptor, SerializeOptions,
};
#[cfg(feature = "grpc-descriptor")]
use regex::Regex;

#[cfg(feature = "grpc-descriptor")]
const MAX_DESCRIPTOR_FILES: usize = 256;
#[cfg(feature = "grpc-descriptor")]
const MAX_DESCRIPTOR_SERVICES: usize = 1024;
#[cfg(feature = "grpc-descriptor")]
const MAX_DESCRIPTOR_METHODS: usize = 8192;
#[cfg(feature = "grpc-descriptor")]
const MAX_CONFIGURED_SERVICES: usize = 128;
#[cfg(feature = "grpc-descriptor")]
const MAX_CONFIGURED_METHODS: usize = 2048;
#[cfg(feature = "grpc-descriptor")]
const MAX_DESCRIPTOR_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "grpc-descriptor")]
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
#[cfg(feature = "grpc-descriptor")]
const MAX_STREAM_MESSAGES: u64 = 10_000_000;
#[cfg(feature = "grpc-descriptor")]
const MAX_HTTP_BINDINGS_PER_METHOD: usize = 64;
#[cfg(feature = "grpc-descriptor")]
const MAX_HTTP_PATH_TEMPLATE_BYTES: usize = 2048;
#[cfg(feature = "grpc-descriptor")]
const MAX_HTTP_PATH_VARIABLES: usize = 32;

/// 快照内只读的 descriptor/RPC 白名单计划。
#[derive(Debug)]
pub(crate) struct GrpcTranscodingPlan {
    #[cfg(feature = "grpc-descriptor")]
    methods: Arc<[Arc<ResolvedGrpcMethod>]>,
    #[cfg(feature = "grpc-descriptor")]
    connect_json: bool,
    #[cfg(feature = "grpc-descriptor")]
    google_http: bool,
}

/// 单个已授权 RPC 的不可变动态消息计划；克隆只增加 `Arc` 引用计数。
#[cfg(feature = "grpc-descriptor")]
#[derive(Debug)]
pub(crate) struct ResolvedGrpcMethod {
    method: MethodDescriptor,
    rpc_path: Arc<str>,
    reject_unknown_fields: bool,
    max_input_message_bytes: usize,
    max_output_message_bytes: usize,
    max_json_bytes: usize,
    max_stream_messages: u64,
    max_stream_buffer_bytes: usize,
    http_bindings: Arc<[GoogleHttpBinding]>,
}

/// 一个已编译 `google.api.http` binding；regex 和字段路径只在 build 阶段生成。
#[cfg(feature = "grpc-descriptor")]
#[derive(Clone, Debug)]
struct GoogleHttpBinding {
    method: Method,
    path_regex: Regex,
    path_fields: Arc<[Arc<str>]>,
    body_field: Arc<str>,
}

/// 单次 REST/JSON 请求匹配后的 method/binding 与已解码 URI 字段。
#[cfg(feature = "grpc-descriptor")]
#[derive(Debug)]
pub(crate) struct ResolvedGoogleRequest {
    method: Arc<ResolvedGrpcMethod>,
    binding: GoogleHttpBinding,
    path_values: Arc<[(Arc<str>, Arc<str>)]>,
    query: Option<Arc<str>>,
}

/// descriptor JSON 转码错误；固定低敏消息由浏览器协议层映射为 HTTP 响应。
#[cfg(feature = "grpc-descriptor")]
#[derive(Debug)]
pub(crate) struct GrpcTranscodingError {
    status: StatusCode,
    message: &'static str,
}

#[cfg(feature = "grpc-descriptor")]
impl GrpcTranscodingError {
    /// 业务作用：向代理错误层提供稳定 HTTP 分类，不泄漏 JSON/protobuf 载荷。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：客户端 schema/大小错误为 4xx，上游 payload 错误为 502。
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    /// 业务作用：向浏览器协议错误响应提供固定低基数原因。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不含 descriptor 路径、字段值或业务 payload 的静态文本。
    pub(crate) fn message(&self) -> &'static str {
        self.message
    }
}

#[cfg(feature = "grpc-descriptor")]
impl std::fmt::Display for GrpcTranscodingError {
    /// 业务作用：展示已经分类的转码失败原因，不在格式化阶段重新解释请求载荷。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

#[cfg(feature = "grpc-descriptor")]
impl std::error::Error for GrpcTranscodingError {}

impl GrpcTranscodingPlan {
    /// 业务作用：在候选快照发布前有界读取并编译 descriptor，锁定 route 可暴露的 RPC 集合；
    /// core 制品显式拒绝配置，避免运行时才发现 feature 缺失。
    ///
    /// 参数说明：
    /// - `cfg`：是 route 的可选转码声明
    /// - `config_dir`：是相对文件基准
    /// - `route_id`：只用于低敏错误定位。
    ///
    /// 返回：未配置返回 None；带 feature 且所有 schema/预算合法时返回只读计划；否则拒绝候选快照。
    pub(crate) fn build(
        cfg: Option<&GrpcTranscodingCfg>,
        config_dir: &Path,
        route_id: &str,
    ) -> Result<Option<Self>> {
        let Some(cfg) = cfg else {
            return Ok(None);
        };
        Self::build_enabled(cfg, config_dir, route_id).map(Some)
    }

    #[cfg(not(feature = "grpc-descriptor"))]
    /// 业务作用：在未携带反射依赖的 core 制品中拒绝 descriptor 配置，保证默认制品零隐式降级。
    ///
    /// 参数说明：
    /// - `_cfg`：仅用于保持跨 feature 构建接口一致。
    /// - `_config_dir`：仅用于保持跨 feature 构建接口一致。
    /// - `route_id`：仅用于保持跨 feature 构建接口一致。
    ///
    /// 返回：固定返回 feature 缺失错误。
    fn build_enabled(
        _cfg: &GrpcTranscodingCfg,
        _config_dir: &Path,
        route_id: &str,
    ) -> Result<Self> {
        anyhow::bail!("route `{route_id}` grpc_transcoding requires the `grpc-descriptor` feature")
    }

    #[cfg(feature = "grpc-descriptor")]
    /// 业务作用：把受信 `FileDescriptorSet` 编译为有界 RPC allowlist，阻止 descriptor 中未授权
    /// service 因热换或新增文件自动暴露。
    ///
    /// 参数说明：
    /// - `cfg`：提供文件、协议开关和资源预算
    /// - `config_dir`：解析相对路径
    /// - `route_id`：用于错误定位。
    ///
    /// 返回：合法时返回不可变 method descriptor 集合；文件、schema、白名单或预算非法时失败。
    fn build_enabled(cfg: &GrpcTranscodingCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
        validate_config(cfg, route_id)?;
        let source_path = resolve_source_path(config_dir, &cfg.descriptor_set_file);
        let bytes = crate::io::bounded_io::read_file(
            &source_path,
            cfg.max_descriptor_bytes,
            "gRPC descriptor set",
        )?;
        let pool = DescriptorPool::decode(bytes.as_slice()).with_context(|| {
            format!(
                "route `{route_id}` decode descriptor set {}",
                source_path.display()
            )
        })?;
        validate_pool_shape(&pool, route_id)?;
        let methods = select_methods(&pool, cfg, route_id)?;
        let mut compiled = Vec::with_capacity(methods.len());
        for method in methods {
            let http_bindings = compile_google_http_bindings(&pool, &method, cfg, route_id)?;
            let rpc_path = Arc::<str>::from(format!(
                "/{}/{}",
                method.parent_service().full_name(),
                method.name()
            ));
            compiled.push(Arc::new(ResolvedGrpcMethod {
                method,
                rpc_path,
                reject_unknown_fields: cfg.reject_unknown_fields,
                max_input_message_bytes: cfg.max_input_message_bytes,
                max_output_message_bytes: cfg.max_output_message_bytes,
                max_json_bytes: cfg.max_json_bytes,
                max_stream_messages: cfg.max_stream_messages,
                max_stream_buffer_bytes: cfg.max_stream_buffer_bytes,
                http_bindings: http_bindings.into(),
            }));
        }
        Ok(Self {
            methods: compiled.into(),
            connect_json: cfg.connect_json,
            google_http: cfg.google_http,
        })
    }

    /// 业务作用：向快照摘要提供已授权 RPC 数量，不暴露 service/method 名称。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：feature 制品返回编译后的 method 数；core 制品因无法构造计划恒为零。
    pub(crate) fn method_count(&self) -> usize {
        #[cfg(feature = "grpc-descriptor")]
        {
            self.methods.len()
        }
        #[cfg(not(feature = "grpc-descriptor"))]
        {
            0
        }
    }

    /// 业务作用：按 Connect 标准 RPC path 解析一个 unary JSON 调用，未知 schema 在读取 body
    /// 前早拒，不能猜测 message 类型。
    ///
    /// 参数说明：
    /// - `path`：是下游 URI path，格式应为 `/package.Service/Method`。
    ///
    /// 返回：命中显式 allowlist 时返回共享 method 计划；未启用或未命中返回 None。
    #[cfg(feature = "grpc-descriptor")]
    pub(crate) fn resolve_connect_json(&self, path: &str) -> Option<Arc<ResolvedGrpcMethod>> {
        self.connect_json.then(|| {
            self.methods
                .iter()
                .find(|method| method.rpc_path.as_ref() == path)
                .cloned()
        })?
    }

    /// 业务作用：按已编译 `google.api.http` method/path 匹配 REST JSON 请求，并在读 body 前
    /// 解码全部 path variable；普通 JSON path 未命中时保持普通 HTTP route 语义。
    ///
    /// 参数说明：
    /// - `method`：是原始下游请求目标。
    /// - `uri`：是原始下游请求目标。
    ///
    /// 返回：命中时返回请求级共享计划；未命中为 None；非法 percent-encoding 返回 400。
    #[cfg(feature = "grpc-descriptor")]
    pub(crate) fn resolve_google_json(
        &self,
        method: &Method,
        uri: &Uri,
    ) -> Result<Option<Arc<ResolvedGoogleRequest>>, GrpcTranscodingError> {
        if !self.google_http {
            return Ok(None);
        }
        for rpc in self.methods.iter() {
            for binding in rpc.http_bindings.iter() {
                if binding.method != *method {
                    continue;
                }
                let Some(captures) = binding.path_regex.captures(uri.path()) else {
                    continue;
                };
                let mut path_values = Vec::with_capacity(binding.path_fields.len());
                for (index, field) in binding.path_fields.iter().enumerate() {
                    let raw = captures
                        .get(index + 1)
                        .expect("compiled path variable capture remains present")
                        .as_str();
                    let decoded = percent_decode_str(raw).decode_utf8().map_err(|_| {
                        GrpcTranscodingError {
                            status: StatusCode::BAD_REQUEST,
                            message: "gRPC-JSON path variable is not valid UTF-8",
                        }
                    })?;
                    path_values.push((field.clone(), Arc::<str>::from(decoded.as_ref())));
                }
                return Ok(Some(Arc::new(ResolvedGoogleRequest {
                    method: rpc.clone(),
                    binding: binding.clone(),
                    path_values: path_values.into(),
                    query: uri.query().map(Arc::from),
                })));
            }
        }
        Ok(None)
    }
}

#[cfg(feature = "grpc-descriptor")]
impl ResolvedGrpcMethod {
    /// 业务作用：判断当前 RPC 是否可由 unary JSON 慢路径完整表达，streaming 留给增量 codec。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：client/server 均非 streaming 时为 true。
    pub(crate) fn is_unary(&self) -> bool {
        !self.is_client_streaming() && !self.is_server_streaming()
    }

    /// 业务作用：向 streaming codec 提供 descriptor 声明的客户端流形态，约束请求消息基数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：client-streaming 或 bidi method 返回 true；unary/server-streaming 返回 false。
    pub(crate) fn is_client_streaming(&self) -> bool {
        self.method
            .method_descriptor_proto()
            .client_streaming
            .unwrap_or(false)
    }

    /// 业务作用：向 streaming codec 提供 descriptor 声明的服务端流形态，约束响应消息基数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：server-streaming 或 bidi method 返回 true；unary/client-streaming 返回 false。
    pub(crate) fn is_server_streaming(&self) -> bool {
        self.method
            .method_descriptor_proto()
            .server_streaming
            .unwrap_or(false)
    }

    /// 业务作用：把 route 级消息数和未完成 envelope 暂存硬门交给逐消息 codec，避免长流绕过
    /// unary 的 JSON/protobuf 大小限制后形成无界驻留。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置构建期已验证的最大消息数与 codec 暂存字节数。
    pub(crate) fn stream_limits(&self) -> (u64, usize) {
        (self.max_stream_messages, self.max_stream_buffer_bytes)
    }

    /// 业务作用：提供已验证 native gRPC path，浏览器 JSON 请求必须重写到该 RPC 而非沿用 REST path。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`/package.Service/Method` 形式的共享字符串。
    pub(crate) fn rpc_path(&self) -> &str {
        self.rpc_path.as_ref()
    }

    /// 业务作用：按 protobuf canonical JSON 规则把 Connect unary JSON 编码为单条 protobuf
    /// message，并执行 JSON/input 双预算与 unknown-field 策略。
    ///
    /// 参数说明：
    /// - `json`：是已在浏览器层有界聚合的单个 JSON document。
    ///
    /// 返回：合法时返回 protobuf payload；坏 JSON/schema 为 400，超预算为 413。
    pub(crate) fn encode_json_request(&self, json: &[u8]) -> Result<Bytes, GrpcTranscodingError> {
        if json.len() > self.max_json_bytes {
            return Err(GrpcTranscodingError {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                message: "protobuf JSON request exceeds configured limit",
            });
        }
        let mut deserializer = serde_json::Deserializer::from_slice(json);
        let options = DeserializeOptions::new().deny_unknown_fields(self.reject_unknown_fields);
        let message = DynamicMessage::deserialize_with_options(
            self.method.input(),
            &mut deserializer,
            &options,
        )
        .map_err(|_| GrpcTranscodingError {
            status: StatusCode::BAD_REQUEST,
            message: "invalid protobuf JSON request",
        })?;
        deserializer.end().map_err(|_| GrpcTranscodingError {
            status: StatusCode::BAD_REQUEST,
            message: "protobuf JSON request contains trailing data",
        })?;
        if message.encoded_len() > self.max_input_message_bytes {
            return Err(GrpcTranscodingError {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                message: "protobuf request message exceeds configured limit",
            });
        }
        Ok(Bytes::from(message.encode_to_vec()))
    }

    /// 业务作用：把上游 unary protobuf payload 解码为 canonical protobuf JSON，保持 enum、bytes、
    /// int64 与 well-known type 的标准语义，并约束 output/JSON 双预算。
    ///
    /// 参数说明：
    /// - `payload`：是去除 5-byte gRPC envelope 后的唯一响应 message。
    ///
    /// 返回：合法时返回 JSON bytes；上游 protobuf 畸形或输出超限时返回 502。
    pub(crate) fn decode_json_response(
        &self,
        payload: &[u8],
    ) -> Result<Bytes, GrpcTranscodingError> {
        if payload.len() > self.max_output_message_bytes {
            return Err(GrpcTranscodingError {
                status: StatusCode::BAD_GATEWAY,
                message: "protobuf response message exceeds configured limit",
            });
        }
        let message = DynamicMessage::decode(self.method.output(), payload).map_err(|_| {
            GrpcTranscodingError {
                status: StatusCode::BAD_GATEWAY,
                message: "invalid protobuf response message",
            }
        })?;
        let mut json = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut json);
        message
            .serialize_with_options(&mut serializer, &SerializeOptions::new())
            .map_err(|_| GrpcTranscodingError {
                status: StatusCode::BAD_GATEWAY,
                message: "protobuf response JSON encoding failed",
            })?;
        if json.len() > self.max_json_bytes {
            return Err(GrpcTranscodingError {
                status: StatusCode::BAD_GATEWAY,
                message: "protobuf JSON response exceeds configured limit",
            });
        }
        Ok(Bytes::from(json))
    }
}

#[cfg(feature = "grpc-descriptor")]
impl ResolvedGoogleRequest {
    /// 业务作用：判断匹配到的 annotated RPC 是否属于当前 unary 转码阶段。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：client/server 均非 streaming 时为 true。
    pub(crate) fn is_unary(&self) -> bool {
        self.method.is_unary()
    }

    /// 业务作用：提供 annotation 所属的真实 native gRPC path。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`/package.Service/Method` 形式 path。
    pub(crate) fn rpc_path(&self) -> &str {
        self.method.rpc_path()
    }

    /// 业务作用：按 `google.api.http` body/path/query 所有权合并 REST JSON，并交给 canonical
    /// protobuf JSON codec；path 覆盖 body，query 不得重复占有 body/path 字段。
    ///
    /// 参数说明：
    /// - `body`：是有界聚合的 HTTP JSON body，GET/无 body binding 可为空。
    ///
    /// 返回：合法时返回 protobuf message；字段冲突、未知 query、坏标量或坏 JSON 返回 400。
    pub(crate) fn encode_json_request(&self, body: &[u8]) -> Result<Bytes, GrpcTranscodingError> {
        if body.len() > self.method.max_json_bytes {
            return Err(GrpcTranscodingError {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                message: "gRPC-JSON request body exceeds configured limit",
            });
        }
        let body_field = self.binding.body_field.as_ref();
        let has_body = body.iter().any(|byte| !byte.is_ascii_whitespace());
        let mut root = serde_json::Value::Object(serde_json::Map::new());
        match body_field {
            "" if has_body => {
                return Err(GrpcTranscodingError {
                    status: StatusCode::BAD_REQUEST,
                    message: "gRPC-JSON binding does not allow an HTTP body",
                });
            }
            "" => {}
            "*" => {
                root = if has_body {
                    serde_json::from_slice(body).map_err(|_| GrpcTranscodingError {
                        status: StatusCode::BAD_REQUEST,
                        message: "invalid gRPC-JSON request body",
                    })?
                } else {
                    serde_json::Value::Object(serde_json::Map::new())
                };
                if !root.is_object() {
                    return Err(GrpcTranscodingError {
                        status: StatusCode::BAD_REQUEST,
                        message: "gRPC-JSON wildcard body must be an object",
                    });
                }
            }
            field => {
                if !has_body {
                    return Err(GrpcTranscodingError {
                        status: StatusCode::BAD_REQUEST,
                        message: "gRPC-JSON binding requires an HTTP body",
                    });
                }
                let value = serde_json::from_slice(body).map_err(|_| GrpcTranscodingError {
                    status: StatusCode::BAD_REQUEST,
                    message: "invalid gRPC-JSON request body",
                })?;
                set_json_path(&mut root, field, value, false)?;
            }
        }

        for (field, raw) in self.path_values.iter() {
            let (_, descriptor) = normalize_field_path(&self.method.method.input(), field)?;
            let value = query_scalar_json(&descriptor, raw.as_ref())?;
            set_json_path(&mut root, field, value, true)?;
        }

        let path_fields = self
            .path_values
            .iter()
            .map(|(field, _)| field.as_ref())
            .collect::<HashSet<_>>();
        let mut query_values = HashMap::<String, Vec<String>>::new();
        if let Some(query) = self.query.as_deref() {
            for (raw_field, raw_value) in form_urlencoded::parse(query.as_bytes()) {
                let (field, _) = normalize_field_path(&self.method.method.input(), &raw_field)?;
                if path_fields.contains(field.as_str())
                    || body_field == "*"
                    || (!body_field.is_empty()
                        && (field == body_field || field.starts_with(&format!("{body_field}."))))
                {
                    return Err(GrpcTranscodingError {
                        status: StatusCode::BAD_REQUEST,
                        message: "gRPC-JSON query field conflicts with path or body binding",
                    });
                }
                query_values
                    .entry(field)
                    .or_default()
                    .push(raw_value.into_owned());
            }
        }
        for (field, values) in query_values {
            let (_, descriptor) = normalize_field_path(&self.method.method.input(), &field)?;
            let value = if descriptor.is_list() {
                serde_json::Value::Array(
                    values
                        .iter()
                        .map(|value| query_scalar_json(&descriptor, value))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            } else {
                if values.len() != 1 {
                    return Err(GrpcTranscodingError {
                        status: StatusCode::BAD_REQUEST,
                        message: "gRPC-JSON scalar query field appears more than once",
                    });
                }
                query_scalar_json(&descriptor, &values[0])?
            };
            set_json_path(&mut root, &field, value, false)?;
        }
        let json = serde_json::to_vec(&root).map_err(|_| GrpcTranscodingError {
            status: StatusCode::BAD_REQUEST,
            message: "gRPC-JSON request encoding failed",
        })?;
        self.method.encode_json_request(&json)
    }

    /// 业务作用：把 annotated unary RPC 的 protobuf response 按 canonical JSON 返回。
    ///
    /// 参数说明：
    /// - `payload`：是唯一响应 protobuf message。
    ///
    /// 返回：合法 JSON bytes 或稳定 502 转码错误。
    pub(crate) fn decode_json_response(
        &self,
        payload: &[u8],
    ) -> Result<Bytes, GrpcTranscodingError> {
        self.method.decode_json_response(payload)
    }
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：把 proto/json field path 规范化为 canonical JSON name，并验证每一级 descriptor 关系。
///
/// 参数说明：
/// - `root`：是 RPC input message
/// - `path`：是点分字段路径。
///
/// 返回：规范路径与末级字段；未知字段、穿越 scalar/repeated/map 时返回 400。
fn normalize_field_path(
    root: &MessageDescriptor,
    path: &str,
) -> Result<(String, FieldDescriptor), GrpcTranscodingError> {
    if path.is_empty() || path.split('.').any(str::is_empty) {
        return Err(GrpcTranscodingError {
            status: StatusCode::BAD_REQUEST,
            message: "gRPC-JSON field path is empty or malformed",
        });
    }
    let mut message = root.clone();
    let mut normalized = Vec::new();
    let segments = path.split('.').collect::<Vec<_>>();
    let mut terminal = None;
    for (index, segment) in segments.iter().enumerate() {
        let field = message
            .get_field_by_name(segment)
            .or_else(|| message.get_field_by_json_name(segment))
            .ok_or(GrpcTranscodingError {
                status: StatusCode::BAD_REQUEST,
                message: "gRPC-JSON field is absent from descriptor",
            })?;
        normalized.push(field.json_name().to_owned());
        if index + 1 < segments.len() {
            if field.is_list() || field.is_map() {
                return Err(GrpcTranscodingError {
                    status: StatusCode::BAD_REQUEST,
                    message: "gRPC-JSON field path cannot traverse repeated or map fields",
                });
            }
            message = match field.kind() {
                Kind::Message(next) => next,
                _ => {
                    return Err(GrpcTranscodingError {
                        status: StatusCode::BAD_REQUEST,
                        message: "gRPC-JSON field path traverses a scalar",
                    });
                }
            };
        }
        terminal = Some(field);
    }
    Ok((
        normalized.join("."),
        terminal.expect("non-empty field path has a terminal"),
    ))
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：把 path/query 文本按末级 protobuf 类型转换成 canonical JSON scalar。
///
/// 参数说明：
/// - `field`：是已验证末级字段
/// - `raw`：是 percent/form 解码后的 UTF-8 文本。
///
/// 返回：类型合法时返回 JSON scalar；message/map 或非法数字/布尔值返回 400。
fn query_scalar_json(
    field: &FieldDescriptor,
    raw: &str,
) -> Result<serde_json::Value, GrpcTranscodingError> {
    let invalid = || GrpcTranscodingError {
        status: StatusCode::BAD_REQUEST,
        message: "gRPC-JSON path/query value does not match protobuf field type",
    };
    if field.is_map() {
        return Err(invalid());
    }
    match field.kind() {
        Kind::String | Kind::Bytes | Kind::Enum(_) => Ok(serde_json::Value::String(raw.to_owned())),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 | Kind::Uint64 | Kind::Fixed64 => raw
            .parse::<i128>()
            .map(|_| serde_json::Value::String(raw.to_owned()))
            .map_err(|_| invalid()),
        Kind::Bool => match raw {
            "true" => Ok(serde_json::Value::Bool(true)),
            "false" => Ok(serde_json::Value::Bool(false)),
            _ => Err(invalid()),
        },
        Kind::Int32
        | Kind::Sint32
        | Kind::Sfixed32
        | Kind::Uint32
        | Kind::Fixed32
        | Kind::Float
        | Kind::Double => serde_json::from_str(raw)
            .ok()
            .filter(serde_json::Value::is_number)
            .ok_or_else(invalid),
        Kind::Message(_) => Err(invalid()),
    }
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：向 JSON object 的点分字段写入值，并控制 path variable 是否可覆盖 body 值。
///
/// 参数说明：
/// - `root`：是 request object
/// - `path`：已规范化
/// - `value`：是 typed JSON
/// - `overwrite`：只允许 path binding 覆盖 body。
///
/// 返回：成功原地写入；字段重复或中间节点非 object 时返回 400。
fn set_json_path(
    root: &mut serde_json::Value,
    path: &str,
    value: serde_json::Value,
    overwrite: bool,
) -> Result<(), GrpcTranscodingError> {
    let segments = path.split('.').collect::<Vec<_>>();
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        let object = current.as_object_mut().ok_or(GrpcTranscodingError {
            status: StatusCode::BAD_REQUEST,
            message: "gRPC-JSON field binding crosses a non-object value",
        })?;
        current = object
            .entry((*segment).to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    let object = current.as_object_mut().ok_or(GrpcTranscodingError {
        status: StatusCode::BAD_REQUEST,
        message: "gRPC-JSON field binding target is not an object",
    })?;
    let terminal = segments.last().expect("non-empty normalized field path");
    if object.contains_key(*terminal) && !overwrite {
        return Err(GrpcTranscodingError {
            status: StatusCode::BAD_REQUEST,
            message: "gRPC-JSON field is assigned by more than one binding",
        });
    }
    object.insert((*terminal).to_owned(), value);
    Ok(())
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：从 method options 的 `google.api.http` extension 编译全部主/附加 binding；未启用
/// google_http 时不查询 extension，也不为 Connect-only route 分配 regex。
///
/// 参数说明：
/// - `pool`：来自同一 descriptor
/// - `method`：来自同一 descriptor
/// - `cfg`：是 route 开关
/// - `route_id`：用于错误定位。
///
/// 返回：合法 binding 列表；缺失 annotation 定义、custom verb、response_body、嵌套 additional
/// binding 或非法字段/path 模板会拒绝候选快照。
fn compile_google_http_bindings(
    pool: &DescriptorPool,
    method: &MethodDescriptor,
    cfg: &GrpcTranscodingCfg,
    route_id: &str,
) -> Result<Vec<GoogleHttpBinding>> {
    if !cfg.google_http {
        return Ok(Vec::new());
    }
    let extension = pool
        .get_extension_by_name("google.api.http")
        .context("grpc_transcoding.google_http requires google.api.http in descriptor set")?;
    let options = method.options();
    if !options.has_extension(&extension) {
        return Ok(Vec::new());
    }
    let value = options.get_extension(&extension);
    let rule = value.as_message().with_context(|| {
        format!(
            "route `{route_id}` method `{}` google.api.http is not an HttpRule message",
            method.full_name()
        )
    })?;
    let mut bindings = Vec::new();
    compile_http_rule(rule, method, route_id, false, &mut bindings)?;
    anyhow::ensure!(
        bindings.len() <= MAX_HTTP_BINDINGS_PER_METHOD,
        "route `{route_id}` method `{}` exceeds {MAX_HTTP_BINDINGS_PER_METHOD} google.api.http bindings",
        method.full_name()
    );
    Ok(bindings)
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：递归展开一个 `HttpRule` 的主 binding 与一层 `additional_bindings`，并冻结 body/path
/// 字段所有权；标准禁止 additional binding 再嵌套，必须显式拒绝而非静默忽略。
///
/// 参数说明：
/// - `rule`：是动态 HttpRule
/// - `method`：锁定 input schema
/// - `route_id`：用于错误定位
/// - `is_additional`：标记递归层级
/// - `out`：收集编译结果。
///
/// 返回：规则完整合法时成功，否则拒绝候选快照。
fn compile_http_rule(
    rule: &DynamicMessage,
    method: &MethodDescriptor,
    route_id: &str,
    is_additional: bool,
    out: &mut Vec<GoogleHttpBinding>,
) -> Result<()> {
    anyhow::ensure!(
        !rule.has_field_by_name("custom"),
        "route `{route_id}` method `{}` google.api.http custom verbs are outside the compatibility matrix",
        method.full_name()
    );
    let mut patterns = Vec::new();
    for (field, verb) in [
        ("get", Method::GET),
        ("put", Method::PUT),
        ("post", Method::POST),
        ("delete", Method::DELETE),
        ("patch", Method::PATCH),
    ] {
        if rule.has_field_by_name(field) {
            let path = rule
                .get_field_by_name(field)
                .and_then(|value| value.as_str().map(str::to_owned))
                .context("google.api.http pattern must be a string")?;
            patterns.push((verb, path));
        }
    }
    anyhow::ensure!(
        patterns.len() == 1,
        "route `{route_id}` method `{}` google.api.http must set exactly one standard HTTP pattern",
        method.full_name()
    );
    let response_body = rule
        .get_field_by_name("response_body")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    anyhow::ensure!(
        response_body.is_empty(),
        "route `{route_id}` method `{}` google.api.http response_body is outside the current compatibility matrix",
        method.full_name()
    );
    let raw_body = rule
        .get_field_by_name("body")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let body_field = if raw_body.is_empty() || raw_body == "*" {
        raw_body
    } else {
        normalize_field_path(&method.input(), &raw_body)
            .map_err(|error| anyhow::anyhow!(error.message()))?
            .0
    };
    let (verb, path) = patterns.pop().expect("exactly one HTTP pattern");
    let (path_regex, path_fields) = compile_http_path_template(&method.input(), &path)
        .with_context(|| format!("route `{route_id}` method `{}`", method.full_name()))?;
    out.push(GoogleHttpBinding {
        method: verb,
        path_regex,
        path_fields: path_fields.into(),
        body_field: Arc::from(body_field),
    });

    let additional = rule
        .get_field_by_name("additional_bindings")
        .and_then(|value| value.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();
    anyhow::ensure!(
        !is_additional || additional.is_empty(),
        "route `{route_id}` method `{}` nests google.api.http additional_bindings",
        method.full_name()
    );
    for value in additional {
        let nested = value
            .as_message()
            .context("google.api.http additional_bindings entry must be an HttpRule message")?;
        compile_http_rule(nested, method, route_id, true, out)?;
    }
    Ok(())
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：把 Google path template 编译为锚定 regex 与规范化字段列表，运行时只做匹配和
/// percent decode；模板变量支持 `{field}`、`*`、`**` 与 literal/`*` 资源路径组合。
///
/// 参数说明：
/// - `input`：是 RPC input schema
/// - `template`：是 annotation path。
///
/// 返回：合法时返回无内部捕获组的 regex 和按组序字段；超长、未知字段或非法 pattern 失败。
fn compile_http_path_template(
    input: &MessageDescriptor,
    template: &str,
) -> Result<(Regex, Vec<Arc<str>>)> {
    anyhow::ensure!(
        template.starts_with('/')
            && !template.contains('?')
            && !template.contains('#')
            && template.len() <= MAX_HTTP_PATH_TEMPLATE_BYTES,
        "google.api.http path template must start with `/`, exclude query/fragment, and fit {MAX_HTTP_PATH_TEMPLATE_BYTES} bytes"
    );
    let mut regex = String::from("^");
    let mut fields = Vec::new();
    let mut cursor = 0;
    while let Some(relative_open) = template[cursor..].find('{') {
        let open = cursor + relative_open;
        let literal = &template[cursor..open];
        anyhow::ensure!(
            !literal.contains('}'),
            "google.api.http path template has an unmatched `}}`"
        );
        regex.push_str(&regex::escape(literal));
        let close = template[open + 1..]
            .find('}')
            .map(|index| open + 1 + index)
            .context("google.api.http path template has an unclosed variable")?;
        let expression = &template[open + 1..close];
        anyhow::ensure!(
            !expression.contains('{'),
            "google.api.http path template cannot nest variables"
        );
        let (raw_field, pattern) = expression.split_once('=').unwrap_or((expression, "*"));
        let (field, descriptor) = normalize_field_path(input, raw_field)
            .map_err(|error| anyhow::anyhow!(error.message()))?;
        anyhow::ensure!(
            !descriptor.is_list()
                && !descriptor.is_map()
                && !matches!(descriptor.kind(), Kind::Message(_)),
            "google.api.http path variable `{raw_field}` must end at a singular scalar field"
        );
        anyhow::ensure!(
            fields.len() < MAX_HTTP_PATH_VARIABLES,
            "google.api.http path template exceeds {MAX_HTTP_PATH_VARIABLES} variables"
        );
        regex.push('(');
        for (index, atom) in pattern.split('/').enumerate() {
            if index > 0 {
                regex.push('/');
            }
            match atom {
                "*" => regex.push_str("[^/]+"),
                "**" => {
                    anyhow::ensure!(
                        index + 1 == pattern.split('/').count(),
                        "google.api.http `**` must be the last path atom"
                    );
                    regex.push_str(".+");
                }
                literal => {
                    anyhow::ensure!(
                        !literal.is_empty() && !literal.contains('{') && !literal.contains('}'),
                        "google.api.http variable path pattern contains an invalid literal"
                    );
                    regex.push_str(&regex::escape(literal));
                }
            }
        }
        regex.push(')');
        fields.push(Arc::from(field));
        cursor = close + 1;
    }
    let tail = &template[cursor..];
    anyhow::ensure!(
        !tail.contains('}'),
        "google.api.http path template has an unmatched `}}`"
    );
    regex.push_str(&regex::escape(tail));
    regex.push('$');
    Ok((
        Regex::new(&regex).context("compile google.api.http path regex")?,
        fields,
    ))
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：校验 route 级 descriptor/消息/stream 预算，防止配置扩大到无界控制面或慢路径内存。
///
/// 参数说明：
/// - `cfg`：是声明
/// - `route_id`：用于错误定位。
///
/// 返回：全部预算和协议开关合法时成功，否则返回明确字段错误。
fn validate_config(cfg: &GrpcTranscodingCfg, route_id: &str) -> Result<()> {
    anyhow::ensure!(
        !cfg.descriptor_set_file.trim().is_empty(),
        "route `{route_id}` grpc_transcoding.descriptor_set_file must be non-empty"
    );
    anyhow::ensure!(
        cfg.google_http || cfg.connect_json,
        "route `{route_id}` grpc_transcoding must enable google_http or connect_json"
    );
    anyhow::ensure!(
        !cfg.services.is_empty() && cfg.services.len() <= MAX_CONFIGURED_SERVICES,
        "route `{route_id}` grpc_transcoding.services must contain 1..={MAX_CONFIGURED_SERVICES} entries"
    );
    anyhow::ensure!(
        cfg.methods.len() <= MAX_CONFIGURED_METHODS,
        "route `{route_id}` grpc_transcoding.methods exceeds {MAX_CONFIGURED_METHODS} entries"
    );
    anyhow::ensure!(
        (1024..=MAX_DESCRIPTOR_BYTES).contains(&cfg.max_descriptor_bytes),
        "route `{route_id}` grpc_transcoding.max_descriptor_bytes must be within 1024..={MAX_DESCRIPTOR_BYTES}"
    );
    for (field, value) in [
        ("max_input_message_bytes", cfg.max_input_message_bytes),
        ("max_output_message_bytes", cfg.max_output_message_bytes),
        ("max_json_bytes", cfg.max_json_bytes),
        ("max_stream_buffer_bytes", cfg.max_stream_buffer_bytes),
    ] {
        anyhow::ensure!(
            (1..=MAX_MESSAGE_BYTES).contains(&value),
            "route `{route_id}` grpc_transcoding.{field} must be within 1..={MAX_MESSAGE_BYTES}"
        );
    }
    anyhow::ensure!(
        cfg.max_json_bytes <= cfg.max_input_message_bytes
            && cfg.max_json_bytes <= cfg.max_output_message_bytes,
        "route `{route_id}` grpc_transcoding.max_json_bytes cannot exceed input/output message limits"
    );
    anyhow::ensure!(
        cfg.max_stream_buffer_bytes
            <= cfg
                .max_input_message_bytes
                .max(cfg.max_output_message_bytes),
        "route `{route_id}` grpc_transcoding.max_stream_buffer_bytes exceeds message limits"
    );
    anyhow::ensure!(
        (1..=MAX_STREAM_MESSAGES).contains(&cfg.max_stream_messages),
        "route `{route_id}` grpc_transcoding.max_stream_messages must be within 1..={MAX_STREAM_MESSAGES}"
    );
    validate_unique_names("services", &cfg.services, route_id)?;
    validate_unique_names("methods", &cfg.methods, route_id)
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：拒绝空白、含路径分隔符或重复的 descriptor 符号白名单，避免 RPC path 歧义和误暴露。
///
/// 参数说明：
/// - `field`：是错误定位字段
/// - `values`：是 service/method full name
/// - `route_id`：是 route id。
///
/// 返回：名称集合规范且唯一时成功，否则失败。
fn validate_unique_names(field: &str, values: &[String], route_id: &str) -> Result<()> {
    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        anyhow::ensure!(
            !value.is_empty()
                && value.trim() == value
                && !value.contains('/')
                && !value.chars().any(char::is_whitespace),
            "route `{route_id}` grpc_transcoding.{field} contains invalid protobuf full name `{value}`"
        );
        anyhow::ensure!(
            seen.insert(value.as_str()),
            "route `{route_id}` grpc_transcoding.{field} repeats `{value}`"
        );
    }
    Ok(())
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：按主配置目录解析 descriptor 文件，保证 build、指纹与 watcher 使用同一目标。
///
/// 参数说明：
/// - `config_dir`：是 `gateway.yml` 目录
/// - `configured`：是绝对或相对路径。
///
/// 返回：可直接有界读取的文件路径。
fn resolve_source_path(config_dir: &Path, configured: &str) -> PathBuf {
    let path = Path::new(configured);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    }
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：对完整 descriptor pool 执行文件/service/method 总量硬门，避免少量 route 白名单掩盖
/// 敌意 descriptor 的解析和驻留成本。
///
/// 参数说明：
/// - `pool`：是已完成结构校验的反射池
/// - `route_id`：用于错误定位。
///
/// 返回：总量在硬门内且至少存在一个 RPC 时成功，否则失败。
fn validate_pool_shape(pool: &DescriptorPool, route_id: &str) -> Result<()> {
    let files = pool.files().count();
    let services = pool.services().count();
    let methods = pool
        .services()
        .map(|service| service.methods().count())
        .sum::<usize>();
    anyhow::ensure!(
        (1..=MAX_DESCRIPTOR_FILES).contains(&files),
        "route `{route_id}` descriptor contains {files} files; expected 1..={MAX_DESCRIPTOR_FILES}"
    );
    anyhow::ensure!(
        (1..=MAX_DESCRIPTOR_SERVICES).contains(&services),
        "route `{route_id}` descriptor contains {services} services; expected 1..={MAX_DESCRIPTOR_SERVICES}"
    );
    anyhow::ensure!(
        (1..=MAX_DESCRIPTOR_METHODS).contains(&methods),
        "route `{route_id}` descriptor contains {methods} methods; expected 1..={MAX_DESCRIPTOR_METHODS}"
    );
    Ok(())
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：把显式 service/method 白名单解析成 method descriptor，阻止文件热换新增 RPC 自动开放。
///
/// 参数说明：
/// - `pool`：是已验证 descriptor
/// - `cfg`：是白名单
/// - `route_id`：用于错误定位。
///
/// 返回：按配置 service 顺序稳定排列的非空 method 集合；未知或越权 method 失败。
fn select_methods(
    pool: &DescriptorPool,
    cfg: &GrpcTranscodingCfg,
    route_id: &str,
) -> Result<Vec<MethodDescriptor>> {
    let requested_methods = cfg
        .methods
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut selected = Vec::new();
    for service_name in &cfg.services {
        let service = pool.get_service_by_name(service_name).with_context(|| {
            format!(
                "route `{route_id}` grpc_transcoding service `{service_name}` is absent from descriptor"
            )
        })?;
        for method in service.methods() {
            if requested_methods.is_empty() || requested_methods.contains(method.full_name()) {
                selected.push(method);
            }
        }
    }
    if !requested_methods.is_empty() {
        let selected_names = selected
            .iter()
            .map(MethodDescriptor::full_name)
            .collect::<HashSet<_>>();
        for method in &cfg.methods {
            anyhow::ensure!(
                selected_names.contains(method.as_str()),
                "route `{route_id}` grpc_transcoding method `{method}` is absent or outside services allowlist"
            );
        }
    }
    anyhow::ensure!(
        !selected.is_empty(),
        "route `{route_id}` grpc_transcoding allowlist selects no RPC methods"
    );
    Ok(selected)
}
