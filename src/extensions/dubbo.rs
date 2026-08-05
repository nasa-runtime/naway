//! V7 HTTP JSON→Dubbo2 generic invocation。
//!
//! 这里实现 Dubbo2 16-byte frame 与 serialization id=6(JSON) 的 `$invoke`。公网请求不能
//! 指定 interface/method/type/attachments，只能提交与 route 固定类型数组等长的 arguments。
//! provider 必须显式启用 Dubbo JSON serialization；Hessian2 不在此 codec 中宽松猜测。

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
const DUBBO_STATUS_OK: u8 = 20;
const MAX_PARAMETER_COUNT: usize = 64;
const MAX_POOL_ENDPOINTS: usize = 256;
const GENERIC_DESCRIPTOR: &str = "Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/Object;";

pub(crate) struct DubboPlan {
    interface: Arc<str>,
    method: Arc<str>,
    parameter_types: Vec<String>,
    version: Arc<str>,
    group: Arc<str>,
    attachments: Vec<(Arc<str>, Arc<str>)>,
    max_request_body_bytes: u64,
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

#[derive(Debug)]
pub(crate) enum DubboError {
    InvalidInput(&'static str),
    Connect,
    Timeout,
    Transport,
    Protocol(&'static str),
    Remote { status: u8 },
    RemoteException,
}

impl DubboPlan {
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
        anyhow::ensure!(
            matches!(cfg.serialization, DubboSerializationCfg::Json),
            "route `{route_id}` unsupported Dubbo serialization"
        );
        anyhow::ensure!(
            (1..=16 * 1024 * 1024).contains(&cfg.max_request_body_bytes),
            "route `{route_id}` Dubbo max_request_body_bytes must be within 1..=16777216"
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
            let value = crate::secret::resolve_text(
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
            max_request_body_bytes: cfg.max_request_body_bytes,
            max_response_body_bytes: cfg.max_response_body_bytes,
            connect_timeout: Duration::from_millis(cfg.connect_timeout_ms),
            request_timeout: Duration::from_millis(cfg.request_timeout_ms),
            max_idle_connections: cfg.max_idle_connections,
            next_request_id: AtomicU64::new(1),
            idle: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn max_request_body_bytes(&self) -> u64 {
        self.max_request_body_bytes
    }

    pub(crate) fn parse_http_body(
        &self,
        body: &Bytes,
    ) -> std::result::Result<Vec<Value>, DubboError> {
        let invocation: HttpInvocation = serde_json::from_slice(body)
            .map_err(|_| DubboError::InvalidInput("invalid Dubbo invocation JSON"))?;
        if invocation.arguments.len() != self.parameter_types.len() {
            return Err(DubboError::InvalidInput(
                "Dubbo arguments length does not match parameter_types",
            ));
        }
        Ok(invocation.arguments)
    }

    pub(crate) async fn invoke(
        &self,
        endpoint: Arc<str>,
        arguments: &[Value],
    ) -> std::result::Result<DubboResult, DubboError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let payload = self.encode_payload(arguments)?;
        let body_length = u32::try_from(payload.len())
            .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))?;
        let mut header = [0_u8; DUBBO_HEADER_BYTES];
        header[..2].copy_from_slice(&DUBBO_MAGIC);
        header[2] = 0x80 | 0x40 | DUBBO_JSON_SERIALIZATION_ID;
        header[3] = 0;
        header[4..12].copy_from_slice(&request_id.to_be_bytes());
        header[12..16].copy_from_slice(&body_length.to_be_bytes());

        let operation = async {
            let mut stream = self.take_or_connect(endpoint.clone()).await?;
            if stream.write_all(&header).await.is_err()
                || stream.write_all(payload.as_slice()).await.is_err()
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

    fn encode_payload(&self, arguments: &[Value]) -> std::result::Result<Vec<u8>, DubboError> {
        let max = usize::try_from(self.max_request_body_bytes)
            .unwrap_or(usize::MAX)
            .saturating_add(256 * 1024)
            .min(16 * 1024 * 1024);
        let mut writer = BoundedWriter::new(max);
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
            || header[2] & 0x1f != DUBBO_JSON_SERIALIZATION_ID
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
            return Err(DubboError::Remote { status: header[3] });
        }
        decode_json_response(Bytes::from(body))
    }
}

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

fn endpoint_authority(endpoint: &str) -> std::result::Result<String, DubboError> {
    let uri: http::Uri = endpoint
        .parse()
        .map_err(|_| DubboError::Protocol("invalid Dubbo upstream URI"))?;
    uri.authority()
        .map(|authority| authority.as_str().to_owned())
        .ok_or(DubboError::Protocol("Dubbo upstream URI has no authority"))
}

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
    fn new(max: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max.min(16 * 1024)),
            max,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
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

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
