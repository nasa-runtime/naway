//! HTTP JSON→Dubbo2 generic invocation。
//!
//! 这里实现 Dubbo2 16-byte frame，以及 JSON(id=6) 与可选 Hessian2(id=2) 的 `$invoke`。
//! 公网请求不能指定 interface/method/type/attachments，只能提交与 route 固定类型数组
//! 等长的 arguments；二进制反序列化不会加载 Java class，也不会实例化任意对象。

#[cfg(feature = "dubbo-hessian2")]
mod hessian2;

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::model::{DubboRouteCfg, DubboSerializationCfg};

const DUBBO_HEADER_BYTES: usize = 16;
const DUBBO_MAGIC: [u8; 2] = [0xda, 0xbb];
const DUBBO_JSON_SERIALIZATION_ID: u8 = 6;
#[cfg(feature = "dubbo-hessian2")]
const DUBBO_HESSIAN2_SERIALIZATION_ID: u8 = 2;
const DUBBO_STATUS_OK: u8 = 20;
const MAX_PARAMETER_COUNT: usize = 64;
const MAX_POOL_ENDPOINTS: usize = 256;
const GENERIC_DESCRIPTOR: &str = "Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/Object;";

#[derive(Clone, Copy)]
enum DubboWireSerialization {
    Json,
    #[cfg(feature = "dubbo-hessian2")]
    Hessian2(hessian2::HessianLimits),
}

pub(crate) struct DubboPlan {
    interface: Arc<str>,
    method: Arc<str>,
    parameter_types: Vec<String>,
    version: Arc<str>,
    group: Arc<str>,
    attachments: Vec<(Arc<str>, Arc<str>)>,
    serialization: DubboWireSerialization,
    max_request_body_bytes: u64,
    max_request_frame_bytes: usize,
    max_response_body_bytes: usize,
    connect_timeout: Duration,
    request_timeout: Duration,
    max_idle_connections: usize,
    next_request_id: AtomicU64,
    idle: Mutex<HashMap<Arc<str>, Vec<TcpStream>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpInvocation {
    arguments: Vec<Value>,
}

pub(crate) enum DubboResult {
    Value(Bytes),
    Null,
}

/// 已在下游输入阶段完成唯一一次 wire 编码的调用，避免客户端错误进入 upstream 健康语义。
pub(crate) struct DubboInvocation {
    payload: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum DubboError {
    InvalidInput(&'static str),
    Connect,
    Timeout,
    Transport,
    Protocol(&'static str),
    Remote {
        status: u8,
    },
    RemoteException,
}

impl DubboWireSerialization {
    /// 业务作用：给 Dubbo2 frame header 提供与已编译 codec 唯一对应的 serialization id，
    /// 防止 header 与 body 使用不同协议而触发 provider 误解码。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：JSON 返回 6，Hessian2 返回 2。
    const fn id(self) -> u8 {
        match self {
            Self::Json => DUBBO_JSON_SERIALIZATION_ID,
            #[cfg(feature = "dubbo-hessian2")]
            Self::Hessian2(_) => DUBBO_HESSIAN2_SERIALIZATION_ID,
        }
    }
}

/// 业务作用：把公开 serialization 配置编译为数据面枚举，并在 Hessian2 制品能力缺失时
/// fail-fast，避免路由发布后才以 5xx 暴露配置错误。
///
/// 参数说明：
/// - `cfg`：提供 serialization 与 Hessian2 资源预算
/// - `route_id`：用于定位错误。
///
/// 返回：配置与当前制品匹配时返回 wire codec；否则拒绝快照构建。
fn compile_serialization(cfg: &DubboRouteCfg, route_id: &str) -> Result<DubboWireSerialization> {
    match cfg.serialization {
        DubboSerializationCfg::Json => Ok(DubboWireSerialization::Json),
        DubboSerializationCfg::Hessian2 => compile_hessian2_serialization(cfg, route_id),
    }
}

#[cfg(feature = "dubbo-hessian2")]
/// 业务作用：校验 Hessian2 递归、collection、字符串和 binary 预算，并把它们固化到不可变
/// codec limits，确保不可信 provider 响应不能在解码时扩大资源面。
///
/// 参数说明：
/// - `cfg`：提供 Hessian2 预算
/// - `route_id`：用于定位越界配置。
///
/// 返回：预算全部位于硬范围内时返回 Hessian2 wire codec，否则拒绝快照构建。
fn compile_hessian2_serialization(
    cfg: &DubboRouteCfg,
    route_id: &str,
) -> Result<DubboWireSerialization> {
    anyhow::ensure!(
        (1..=128).contains(&cfg.max_hessian_depth),
        "route `{route_id}` Dubbo max_hessian_depth must be within 1..=128"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&cfg.max_hessian_collection_items),
        "route `{route_id}` Dubbo max_hessian_collection_items must be within 1..=1000000"
    );
    anyhow::ensure!(
        (1..=16 * 1024 * 1024).contains(&cfg.max_hessian_string_bytes),
        "route `{route_id}` Dubbo max_hessian_string_bytes must be within 1..=16777216"
    );
    anyhow::ensure!(
        (1..=16 * 1024 * 1024).contains(&cfg.max_hessian_binary_bytes),
        "route `{route_id}` Dubbo max_hessian_binary_bytes must be within 1..=16777216"
    );
    Ok(DubboWireSerialization::Hessian2(hessian2::HessianLimits {
        max_depth: cfg.max_hessian_depth,
        max_collection_items: cfg.max_hessian_collection_items,
        max_string_bytes: cfg.max_hessian_string_bytes,
        max_binary_bytes: cfg.max_hessian_binary_bytes,
    }))
}

#[cfg(not(feature = "dubbo-hessian2"))]
/// 业务作用：在 core 制品中明确拒绝 Hessian2 route，保证关闭 feature 时没有隐式降级为 JSON
/// 或运行期失败路径。
///
/// 参数说明：
/// - `_cfg`：仅用于保持构建接口一致
/// - `route_id`：标识被拒绝的 route。
///
/// 返回：始终返回缺少 `dubbo-hessian2` feature 的构建错误。
fn compile_hessian2_serialization(
    _cfg: &DubboRouteCfg,
    route_id: &str,
) -> Result<DubboWireSerialization> {
    anyhow::bail!(
        "route `{route_id}` uses Dubbo Hessian2 but this binary was built without feature `dubbo-hessian2`"
    )
}

impl DubboPlan {
    /// 业务作用：把可信 route 配置编译为不可变 Dubbo 调用计划，并在开放业务路由前拒绝缺失
    /// feature、越界资源预算或可被客户端利用的 locator/attachment。
    ///
    /// 参数说明：
    /// - `cfg`：是 route 的 Dubbo 配置
    /// - `config_dir`：用于解析 SecretSource
    /// - `route_id`：用于生成可定位的构建错误。
    ///
    /// 返回：所有 wire 契约与资源门通过时返回可共享计划；否则返回错误且该快照不发布。
    pub(crate) fn build(
        cfg: &DubboRouteCfg,
        config_dir: &std::path::Path,
        route_id: &str,
    ) -> Result<Self> {
        validate_dubbo_name(&cfg.interface, 256, "interface")?;
        validate_dubbo_name(&cfg.method, 128, "method")?;
        anyhow::ensure!(
            cfg.parameter_types.len() <= MAX_PARAMETER_COUNT,
            "route `{route_id}` Dubbo parameter_types supports at most {MAX_PARAMETER_COUNT} entries"
        );
        for parameter in &cfg.parameter_types {
            validate_dubbo_name(parameter, 256, "parameter type")?;
        }
        validate_optional_text(&cfg.version, 128, "version")?;
        validate_optional_text(&cfg.group, 128, "group")?;
        let serialization = compile_serialization(cfg, route_id)?;
        anyhow::ensure!(
            (1..=16 * 1024 * 1024).contains(&cfg.max_request_body_bytes),
            "route `{route_id}` Dubbo max_request_body_bytes must be within 1..=16777216"
        );
        anyhow::ensure!(
            (1..=16 * 1024 * 1024).contains(&cfg.max_request_frame_bytes),
            "route `{route_id}` Dubbo max_request_frame_bytes must be within 1..=16777216"
        );
        anyhow::ensure!(
            (1..=16 * 1024 * 1024).contains(&cfg.max_response_body_bytes),
            "route `{route_id}` Dubbo max_response_body_bytes must be within 1..=16777216"
        );
        anyhow::ensure!(
            (10..=120_000).contains(&cfg.connect_timeout_ms)
                && (10..=120_000).contains(&cfg.request_timeout_ms),
            "route `{route_id}` Dubbo timeouts must be within 10..=120000ms"
        );
        anyhow::ensure!(
            cfg.max_idle_connections <= 64,
            "route `{route_id}` Dubbo max_idle_connections must be <= 64"
        );
        anyhow::ensure!(
            cfg.attachments.len() <= 32,
            "route `{route_id}` Dubbo supports at most 32 custom attachments"
        );
        let reserved = ["path", "interface", "version", "group", "generic"];
        let mut attachments: Vec<(Arc<str>, Arc<str>)> = Vec::with_capacity(cfg.attachments.len());
        for (name, raw) in &cfg.attachments {
            validate_dubbo_name(name, 128, "attachment name")?;
            anyhow::ensure!(
                !reserved.contains(&name.as_str()),
                "route `{route_id}` Dubbo attachment `{name}` is reserved"
            );
            let value = crate::security::secret::resolve_text(
                raw,
                config_dir,
                &format!("route `{route_id}` Dubbo attachment `{name}`"),
            )?;
            validate_optional_text(&value, 64 * 1024, "attachment value")?;
            attachments.push((Arc::from(name.as_str()), Arc::from(value)));
        }
        attachments.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Ok(Self {
            interface: Arc::from(cfg.interface.as_str()),
            method: Arc::from(cfg.method.as_str()),
            parameter_types: cfg.parameter_types.clone(),
            version: Arc::from(cfg.version.as_str()),
            group: Arc::from(cfg.group.as_str()),
            attachments,
            serialization,
            max_request_body_bytes: cfg.max_request_body_bytes,
            max_request_frame_bytes: cfg.max_request_frame_bytes,
            max_response_body_bytes: cfg.max_response_body_bytes,
            connect_timeout: Duration::from_millis(cfg.connect_timeout_ms),
            request_timeout: Duration::from_millis(cfg.request_timeout_ms),
            max_idle_connections: cfg.max_idle_connections,
            next_request_id: AtomicU64::new(1),
            idle: Mutex::new(HashMap::new()),
        })
    }

    /// 业务作用：向 HTTP body 聚合层暴露该 route 的可信请求上限，避免在进入 Dubbo codec
    /// 前已经形成无界分配。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：允许聚合的最大下游 JSON 字节数。
    pub(crate) fn max_request_body_bytes(&self) -> u64 {
        self.max_request_body_bytes
    }

    /// 业务作用：把不可信 HTTP JSON envelope 收敛为已经过类型与总 frame 预算校验的 Dubbo
    /// 调用，并在选择 upstream 前完成唯一一次 wire 编码。
    ///
    /// 参数说明：
    /// - `body`：是已经过总字节门的完整 HTTP 请求体。
    ///
    /// 返回：格式、参数个数、类型与资源预算合法时返回预编码调用；否则返回可映射为 4xx 的
    /// 输入错误，且不会产生连接或健康状态副作用。
    pub(crate) fn parse_http_body(
        &self,
        body: &Bytes,
    ) -> std::result::Result<DubboInvocation, DubboError> {
        let invocation: HttpInvocation = serde_json::from_slice(body)
            .map_err(|_| DubboError::InvalidInput("invalid Dubbo invocation JSON"))?;
        if invocation.arguments.len() != self.parameter_types.len() {
            return Err(DubboError::InvalidInput(
                "Dubbo arguments length does not match parameter_types",
            ));
        }
        // 输入值必须在占用 upstream reservation 前完成类型、递归和 frame 门禁，避免客户端错误
        // 被误记为 provider 5xx 或触发被动摘除。
        let payload = self.encode_payload(&invocation.arguments)?;
        Ok(DubboInvocation {
            payload,
        })
    }

    /// 业务作用：在单一总 deadline 内完成 Dubbo frame 编码、连接获取、请求发送和响应解码，
    /// 并只把协议完整消费的健康连接归还有界空闲池。
    ///
    /// 参数说明：
    /// - `endpoint`：是路由选择后的可信 upstream URI
    /// - `invocation`：已在 HTTP 输入 阶段完成类型、资源预算与 wire 编码校验。
    ///
    /// 返回：成功时返回 JSON 响应值或 null；连接、超时、协议及 provider 异常保持分类返回。
    pub(crate) async fn invoke(
        &self,
        endpoint: Arc<str>,
        invocation: &DubboInvocation,
    ) -> std::result::Result<DubboResult, DubboError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let body_length =
            u32::try_from(invocation.payload.len()).expect("Dubbo frame limit is below u32::MAX");
        let mut header = [0_u8; DUBBO_HEADER_BYTES];
        header[..2].copy_from_slice(&DUBBO_MAGIC);
        header[2] = 0x80 | 0x40 | self.serialization.id();
        header[3] = 0;
        header[4..12].copy_from_slice(&request_id.to_be_bytes());
        header[12..16].copy_from_slice(&body_length.to_be_bytes());

        let operation = async {
            let mut stream = self.take_or_connect(endpoint.clone()).await?;
            if stream.write_all(&header).await.is_err()
                || stream
                    .write_all(invocation.payload.as_slice())
                    .await
                    .is_err()
                || stream.flush().await.is_err()
            {
                return Err(DubboError::Transport);
            }
            let result = self.read_response(&mut stream, request_id).await;
            if result.is_ok() {
                self.return_idle(endpoint, stream);
            }
            result
        };
        tokio::time::timeout(self.request_timeout, operation)
            .await
            .map_err(|_| DubboError::Timeout)?
    }

    /// 业务作用：依据快照中冻结的 serialization 选择唯一 codec，并确保最终 request frame
    /// 不超过独立 frame 预算。
    ///
    /// 参数说明：
    /// - `arguments`：是已经通过 route 参数个数门的 JSON 值。
    ///
    /// 返回：成功时返回可直接写入 Dubbo frame 的 body；输入无法表达或编码膨胀时返回错误。
    fn encode_payload(&self, arguments: &[Value]) -> std::result::Result<Vec<u8>, DubboError> {
        match self.serialization {
            DubboWireSerialization::Json => self.encode_json_payload(arguments),
            #[cfg(feature = "dubbo-hessian2")]
            DubboWireSerialization::Hessian2(limits) => {
                hessian2::encode_request(hessian2::HessianInvocation {
                    interface: self.interface.as_ref(),
                    method: self.method.as_ref(),
                    parameter_types: &self.parameter_types,
                    version: self.version.as_ref(),
                    group: self.group.as_ref(),
                    attachments: &self.attachments,
                    arguments,
                    max_frame_bytes: self.max_request_frame_bytes,
                    limits,
                })
            }
        }
    }

    /// 业务作用：编码 Dubbo JSON 泛化调用并保留现有 newline 分隔 wire 契约，使显式启用
    /// JSON 的 provider 在加入 Hessian2 后仍保持原行为。
    ///
    /// 参数说明：
    /// - `arguments`：是已经通过 route 参数个数门的 JSON 值。
    ///
    /// 返回：frame 预算内返回 JSON id=6 body，否则返回输入过大错误。
    fn encode_json_payload(&self, arguments: &[Value]) -> std::result::Result<Vec<u8>, DubboError> {
        let mut writer = BoundedWriter::new(self.max_request_frame_bytes);
        for value in [
            "2.0.2",
            self.interface.as_ref(),
            self.version.as_ref(),
            "$invoke",
            GENERIC_DESCRIPTOR,
            self.method.as_ref(),
        ] {
            write_json_line(&mut writer, &value)?;
        }
        write_json_line(&mut writer, &self.parameter_types)?;
        write_json_line(&mut writer, &arguments)?;
        self.write_attachments(&mut writer)?;
        Ok(writer.finish())
    }

    /// 业务作用：把 route 固定 locator 与定制 attachment 编入 JSON 调用，客户端无法覆盖
    /// path/interface/version/group/generic 等控制字段。
    ///
    /// 参数说明：
    /// - `writer`：是受 request frame 总预算约束的输出缓冲。
    ///
    /// 返回：完整写入 attachment object 时成功；任何预算越界都返回输入错误。
    fn write_attachments(&self, writer: &mut BoundedWriter) -> std::result::Result<(), DubboError> {
        writer
            .write_all(b"{")
            .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))?;
        let mut first = true;
        for (name, value) in [
            ("path", self.interface.as_ref()),
            ("interface", self.interface.as_ref()),
            ("version", self.version.as_ref()),
            ("group", self.group.as_ref()),
            ("generic", "true"),
        ]
        .into_iter()
        .chain(
            self.attachments
                .iter()
                .map(|(name, value)| (name.as_ref(), value.as_ref())),
        ) {
            if value.is_empty() {
                continue;
            }
            if !first {
                writer
                    .write_all(b",")
                    .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))?;
            }
            first = false;
            serde_json::to_writer(&mut *writer, name)
                .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))?;
            writer
                .write_all(b":")
                .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))?;
            serde_json::to_writer(&mut *writer, value)
                .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))?;
        }
        writer
            .write_all(b"}\n")
            .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))?;
        Ok(())
    }

    /// 业务作用：优先复用同 endpoint 的健康空闲连接，否则在 connect deadline 内建立新连接，
    /// 避免每次泛化调用都承担 TCP 握手。
    ///
    /// 参数说明：
    /// - `endpoint`：是路由选择后的可信 upstream URI。
    ///
    /// 返回：返回可独占执行一次请求的连接；URI、超时或建连失败保持分类返回。
    async fn take_or_connect(
        &self,
        endpoint: Arc<str>,
    ) -> std::result::Result<TcpStream, DubboError> {
        if let Some(stream) = self
            .idle
            .lock()
            .expect("Dubbo idle pool poisoned")
            .get_mut(endpoint.as_ref())
            .and_then(Vec::pop)
        {
            return Ok(stream);
        }
        let authority = endpoint_authority(endpoint.as_ref())?;
        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect(authority))
            .await
            .map_err(|_| DubboError::Timeout)?
            .map_err(|_| DubboError::Connect)?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    /// 业务作用：只把已完整消费响应的连接放回分 endpoint 有界池，并限制 endpoint key 数量，
    /// 防止动态发现抖动留下无界空闲连接。
    ///
    /// 参数说明：
    /// - `endpoint`：是连接所属 upstream
    /// - `stream`：是本次调用后仍可复用的连接。
    ///
    /// 返回：无返回值；池关闭、endpoint 总数或单 endpoint 容量达到上限时直接丢弃连接。
    fn return_idle(&self, endpoint: Arc<str>, stream: TcpStream) {
        if self.max_idle_connections == 0 {
            return;
        }
        let mut idle = self.idle.lock().expect("Dubbo idle pool poisoned");
        if !idle.contains_key(endpoint.as_ref()) && idle.len() >= MAX_POOL_ENDPOINTS {
            return;
        }
        let connections = idle.entry(endpoint).or_default();
        if connections.len() < self.max_idle_connections {
            connections.push(stream);
        }
    }

    /// 业务作用：完整读取并校验 Dubbo response header/body，绑定 request id 与 serialization，
    /// 然后交给对应 codec 解码，避免错帧或协议混淆进入 HTTP 下游。
    ///
    /// 参数说明：
    /// - `stream`：是当前调用独占连接
    /// - `request_id`：是本次 request frame 的关联 id。
    ///
    /// 返回：协议完整且 provider 状态成功时返回业务结果；超限、错 id、错 codec 或远端异常分类返回。
    async fn read_response(
        &self,
        stream: &mut TcpStream,
        request_id: u64,
    ) -> std::result::Result<DubboResult, DubboError> {
        let mut header = [0_u8; DUBBO_HEADER_BYTES];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| DubboError::Transport)?;
        if header[..2] != DUBBO_MAGIC
            || header[2] & 0x80 != 0
            || header[2] & 0x1f != self.serialization.id()
        {
            return Err(DubboError::Protocol("invalid Dubbo response header"));
        }
        if u64::from_be_bytes(header[4..12].try_into().expect("fixed request id")) != request_id {
            return Err(DubboError::Protocol("Dubbo response request id mismatch"));
        }
        let length =
            u32::from_be_bytes(header[12..16].try_into().expect("fixed body length")) as usize;
        if length > self.max_response_body_bytes {
            return Err(DubboError::Protocol(
                "Dubbo response exceeds max_response_body_bytes",
            ));
        }
        let mut body = vec![0_u8; length];
        stream
            .read_exact(body.as_mut_slice())
            .await
            .map_err(|_| DubboError::Transport)?;
        if header[3] != DUBBO_STATUS_OK {
            return Err(DubboError::Remote {
                status: header[3],
            });
        }
        let body = Bytes::from(body);
        match self.serialization {
            DubboWireSerialization::Json => decode_json_response(body),
            #[cfg(feature = "dubbo-hessian2")]
            DubboWireSerialization::Hessian2(limits) => {
                hessian2::decode_response(body, limits, self.max_response_body_bytes)
            }
        }
    }
}

/// 业务作用：解析 Dubbo JSON response type 与业务值，同时以 `Bytes::slice` 保留成功值的
/// 零二次正文拷贝路径。
///
/// 参数说明：
/// - `body`：是已经过 frame 总字节门的完整 response body。
///
/// 返回：1/4 返回已验证 JSON，2/5 返回 null，0/3 映射远端异常，其余格式返回协议错误。
fn decode_json_response(body: Bytes) -> std::result::Result<DubboResult, DubboError> {
    let Some(first_newline) = body.iter().position(|byte| *byte == b'\n') else {
        return Err(DubboError::Protocol("Dubbo JSON response type is missing"));
    };
    let response_type: u8 = serde_json::from_slice(&body[..first_newline])
        .map_err(|_| DubboError::Protocol("Dubbo JSON response type is invalid"))?;
    match response_type {
        2 | 5 => Ok(DubboResult::Null),
        0 | 3 => Err(DubboError::RemoteException),
        1 | 4 => {
            let start = first_newline + 1;
            let end = body[start..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| start + offset)
                .unwrap_or(body.len());
            if start >= end {
                return Err(DubboError::Protocol("Dubbo JSON response value is missing"));
            }
            serde_json::from_slice::<Value>(&body[start..end])
                .map_err(|_| DubboError::Protocol("Dubbo JSON response value is invalid"))?;
            // `Bytes::slice` 只增加同一 response allocation 的引用计数；HTTP 下游直接复用
            // 已验证 JSON value，不做 deserialize→serialize 的第二份正文拷贝。
            Ok(DubboResult::Value(body.slice(start..end)))
        }
        _ => Err(DubboError::Protocol("unknown Dubbo response type")),
    }
}

/// 业务作用：从可信 upstream URI 提取 TCP authority，并拒绝没有 authority 的相对 URI，
/// 避免连接目标在数据面被含糊解释。
///
/// 参数说明：
/// - `endpoint`：是路由选择后的 upstream URI 文本。
///
/// 返回：合法时返回 host:port authority；否则返回 Dubbo 协议配置错误。
fn endpoint_authority(endpoint: &str) -> std::result::Result<String, DubboError> {
    let uri: http::Uri = endpoint
        .parse()
        .map_err(|_| DubboError::Protocol("invalid Dubbo upstream URI"))?;
    uri.authority()
        .map(|authority| authority.as_str().to_owned())
        .ok_or(DubboError::Protocol("Dubbo upstream URI has no authority"))
}

/// 业务作用：按 Dubbo JSON serialization 的 newline 分隔契约写入单个值，并继承总 frame
/// 预算而不创建中间字符串。
///
/// 参数说明：
/// - `writer`：是有界 frame 缓冲
/// - `value`：是当前 wire 字段。
///
/// 返回：字段与分隔符完整写入时成功；编码或容量失败统一返回输入过大错误。
fn write_json_line<T: serde::Serialize>(
    writer: &mut BoundedWriter,
    value: &T,
) -> std::result::Result<(), DubboError> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))?;
    writer
        .write_all(b"\n")
        .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))
}

/// 业务作用：校验会进入服务定位与 Java signature 的名称只含安全 ASCII，防止控制字符或
/// 含糊分隔符改变 provider 对调用目标的解释。
///
/// 参数说明：
/// - `value`：是候选名称
/// - `max`：是字节上限
/// - `label`：用于构建错误定位。
///
/// 返回：非空、安全且不超限时成功，否则拒绝快照构建。
fn validate_dubbo_name(value: &str, max: usize, label: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= max
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'$' | b'[' | b']' | b';' | b'/')),
        "Dubbo {label} must be 1..={max} safe ASCII bytes"
    );
    Ok(())
}

/// 业务作用：校验可选 version/group/attachment 文本的大小与控制字符边界，避免把 NUL 或
/// 行控制字符带入 wire locator。
///
/// 参数说明：
/// - `value`：是候选文本
/// - `max`：是字节上限
/// - `label`：用于构建错误定位。
///
/// 返回：文本不超限且不含控制字符时成功，否则拒绝快照构建。
fn validate_optional_text(value: &str, max: usize, label: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() <= max && !value.bytes().any(|byte| byte == 0 || byte < 0x20),
        "Dubbo {label} must be <={max} bytes without controls"
    );
    Ok(())
}

struct BoundedWriter {
    bytes: Vec<u8>,
    max: usize,
}

impl BoundedWriter {
    /// 业务作用：创建带硬字节上限的 frame 输出缓冲，确保 serializer 无法因输入结构产生
    /// 无界 Vec 增长。
    ///
    /// 参数说明：
    /// - `max`：是该 frame 允许写入的最大字节数。
    ///
    /// 返回：返回预分配受控的空 writer，不会按最大上限一次性分配。
    fn new(max: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max.min(16 * 1024)),
            max,
        }
    }

    /// 业务作用：在编码全部成功后移交已完成 frame body，防止半完成缓冲进入网络发送路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回实际写入字节，长度必不超过构造时的硬上限。
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    /// 业务作用：执行每次增量写入前复验 frame 总容量，任何加法溢出或越界都在改变缓冲前失败。
    ///
    /// 参数说明：
    /// - `bytes`：是 serializer 本次追加的 wire 片段。
    ///
    /// 返回：成功时返回完整写入长度；越界时返回 I/O 错误且不写入该片段。
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("Dubbo frame too large"))?;
        if next > self.max {
            return Err(std::io::Error::other("Dubbo frame too large"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// 业务作用：满足同步 serializer 的 `Write` 契约；内存缓冲无需外部 flush，也不会产生副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：始终成功。
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
