//! 响应契约与声明式实体转换。
//!
//! 所有 schema、字段路径和 XML namespace 都在候选快照构建期编译。请求或响应只有在
//! route 显式配置后才进入有界慢路径；未配置 route 不读取 body，也不增加解析状态。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use ed25519_dalek::{Signature, VerifyingKey};
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE};
use http::request::Parts;
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use quick_xml::Writer;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::config::loader;
use crate::config::model::{
    BodyFormatCfg, BodyTransformCfg, JsonTransformOperationCfg, JsonValueTypeCfg,
    ResponseContractCfg, ResponseContractModeCfg, SchemaRegistryDocumentCfg, SoapFaultMappingCfg,
    XmlEmitCfg, XmlFieldMappingCfg, XmlValueTypeCfg,
};
use crate::metrics::{BodyTransformMetric, Metrics, ResponseContractMetric};
use crate::{full_body, BoxBody, BoxError};

use super::forward::ForwardBody;
use super::request_validation::{buffered_body, collect_bounded, CollectError};
use super::{normalize_content_length, strip_body_integrity_headers};

const MAX_CONTRACT_BODY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CONTRACT_CATALOG_DOCUMENTS: usize = 32;
const MAX_CONTRACT_CATALOG_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCHEMA_REFERENCE_DEPTH: usize = 32;
const MAX_TRANSFORM_OPERATIONS: usize = 256;
const MAX_TRANSFORM_MAPPINGS: usize = 256;
const MAX_TRANSFORM_PATH_SEGMENTS: usize = 64;
const MAX_TRANSFORM_LITERAL_BYTES: usize = 1024 * 1024;
const MAX_SCHEMA_REGISTRY_CACHE_ENTRIES: usize = 64;

static SCHEMA_REGISTRY_CACHE: OnceLock<Mutex<HashMap<String, CachedRegistryDocument>>> =
    OnceLock::new();

struct CachedRegistryDocument {
    loaded_at: Instant,
    bytes: Arc<[u8]>,
}

/// 编译后的响应契约计划。
pub(crate) struct ResponseContractPlan {
    mode: ResponseContractModeCfg,
    responses: Vec<ResponseStatusContract>,
    max_body_bytes: u64,
    replacement_status: StatusCode,
    replacement_body: Bytes,
}

struct ResponseStatusContract {
    selector: StatusSelector,
    media: Vec<ResponseMediaContract>,
}

struct ResponseMediaContract {
    media_type: String,
    validator: Arc<jsonschema::Validator>,
}

#[derive(Clone, Copy)]
enum StatusSelector {
    Exact(u16),
    Class(u16),
    Default,
}

struct SelectedResponseContract {
    validator: Option<Arc<jsonschema::Validator>>,
    expects_empty: bool,
}

/// 编译后的 request/response body 转换计划。
pub(crate) struct BodyTransformPlan {
    input: BodyFormatCfg,
    output: BodyFormatCfg,
    max_body_bytes: u64,
    max_output_bytes: usize,
    operations: Vec<JsonOperation>,
    xml: XmlTransformPlan,
    soap_action: Option<HeaderValue>,
}

enum JsonOperation {
    Rename {
        from: JsonPointer,
        to: JsonPointer,
    },
    Add {
        path: JsonPointer,
        value: Value,
    },
    Remove {
        path: JsonPointer,
    },
    Default {
        path: JsonPointer,
        value: Value,
    },
    TypeCheck {
        path: JsonPointer,
        expected: JsonValueTypeCfg,
    },
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct JsonPointer {
    source: String,
    tokens: Vec<String>,
}

struct XmlTransformPlan {
    namespaces: BTreeMap<String, String>,
    extract: Vec<XmlExtractPlan>,
    emit: Option<XmlEmitPlan>,
    fault: Option<XmlPath>,
    fault_status: Option<StatusCode>,
    max_depth: usize,
    max_nodes: usize,
    max_attributes: usize,
    max_text_bytes: usize,
}

struct XmlExtractPlan {
    from: XmlPath,
    to: JsonPointer,
    required: bool,
    value_type: XmlValueTypeCfg,
}

struct XmlEmitPlan {
    root: XmlName,
    fields: Vec<XmlEmitFieldPlan>,
}

struct XmlEmitFieldPlan {
    from: JsonPointer,
    path: Vec<XmlName>,
    required: bool,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct XmlPath(Vec<XmlName>);

#[derive(Clone)]
struct XmlName {
    qname: String,
    namespace: Option<String>,
    local: String,
}

impl PartialEq for XmlName {
    /// 业务作用：按 namespace URI 与 local name 比较元素身份，使不同 prefix 的等价 QName 正确匹配。
    ///
    /// 参数说明：`other` 是另一编译或解析得到的元素名。
    ///
    /// 返回：expanded name 相等时返回 true；序列化用 prefix 不参与身份比较。
    fn eq(&self, other: &Self) -> bool {
        self.namespace == other.namespace && self.local == other.local
    }
}

impl Eq for XmlName {}

impl std::hash::Hash for XmlName {
    /// 业务作用：按 expanded name 生成与相等语义一致的哈希，供路径去重和 Fault 匹配使用。
    ///
    /// 参数说明：`state` 是调用方哈希状态。
    ///
    /// 返回：无；只写入 namespace URI 和 local name。
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.namespace, state);
        std::hash::Hash::hash(&self.local, state);
    }
}

struct ParsedXml {
    value: Value,
    fault: bool,
}

/// 数据面转换结果。
pub(super) enum TransformOutcome {
    Transformed {
        body: BoxBody,
        media_type: &'static str,
        soap_fault_status: Option<StatusCode>,
    },
    TooLarge,
    ReadFailed,
    Invalid(&'static str),
}

enum ContractValidation {
    Valid,
    Invalid,
}

/// observe 模式的透传包装体：边发送边保留受限副本，流结束后只记录契约结论。
struct ObservedContractBody {
    inner: BoxBody,
    validator: Option<Arc<jsonschema::Validator>>,
    expects_empty: bool,
    max_body_bytes: usize,
    captured: BytesMut,
    oversized: bool,
    completed: bool,
    metrics: Arc<Metrics>,
}

impl ResponseContractPlan {
    /// 业务作用：按 OpenAPI operation 编译全部 status/media type 响应 schema，并冻结失败动作。
    ///
    /// 参数说明：`cfg` 是 route 契约声明；`config_dir` 是受信本地文件解析根；`route_id`
    /// 用于候选错误定位。
    ///
    /// 返回：全部 schema 与引用通过预算和编译门时返回只读计划；否则拒绝候选快照。
    pub(crate) fn build(
        cfg: &ResponseContractCfg,
        config_dir: &Path,
        route_id: &str,
    ) -> Result<Self> {
        if !(1..=MAX_CONTRACT_BODY_BYTES).contains(&cfg.max_body_bytes) {
            bail!(
                "route `{route_id}` response_contract max_body_bytes must be within 1..={MAX_CONTRACT_BODY_BYTES}"
            );
        }
        let selector = OperationSelector::new(
            cfg.operation_id.as_deref(),
            cfg.operation_path.as_deref(),
            cfg.operation_method.as_deref(),
            route_id,
        )?;
        let root_path = resolve_path(config_dir, cfg.openapi_file.as_str());
        let catalog = SchemaCatalog::load(
            &root_path,
            &cfg.catalog_files,
            &cfg.registry_documents,
            config_dir,
        )
        .with_context(|| format!("route `{route_id}` response contract catalog"))?;
        let root_id = SchemaDocumentId::Local(root_path.clone());
        let root = catalog
            .documents
            .get(&root_id)
            .context("OpenAPI root document is absent from schema catalog")?;
        let operation = find_operation(root, selector)
            .with_context(|| format!("route `{route_id}` response contract operation"))?;
        let response_object = operation
            .get("responses")
            .and_then(Value::as_object)
            .context("OpenAPI operation requires object `responses`")?;
        let mut responses = Vec::with_capacity(response_object.len());
        let mut selectors = HashSet::new();
        for (status, raw_response) in response_object {
            let selector = StatusSelector::parse(status)?;
            if !selectors.insert(selector.identity()) {
                bail!("duplicate OpenAPI response status selector `{status}`");
            }
            let response =
                catalog.expand_reference_value(&root_id, raw_response, &mut Vec::new(), 0)?;
            let response = response
                .as_object()
                .context("OpenAPI response must be an object")?;
            let mut media = Vec::new();
            if let Some(content) = response.get("content") {
                let content = content
                    .as_object()
                    .context("OpenAPI response content must be an object")?;
                for (media_type, media_value) in content {
                    if !is_json_media_type(media_type) {
                        continue;
                    }
                    let schema = media_value.get("schema").with_context(|| {
                        format!(
                            "OpenAPI response `{status}` media type `{media_type}` requires schema"
                        )
                    })?;
                    let expanded =
                        catalog.expand_reference_value(&root_id, schema, &mut Vec::new(), 0)?;
                    let validator = jsonschema::validator_for(&expanded).with_context(|| {
                        format!(
                            "compile OpenAPI response `{status}` media type `{media_type}` schema"
                        )
                    })?;
                    media.push(ResponseMediaContract {
                        media_type: normalize_media_type(media_type),
                        validator: Arc::new(validator),
                    });
                }
                if media.is_empty() && !content.is_empty() {
                    bail!(
                        "OpenAPI response `{status}` has no JSON media type supported by response_contract"
                    );
                }
            }
            media.sort_by(|left, right| left.media_type.cmp(&right.media_type));
            responses.push(ResponseStatusContract { selector, media });
        }
        if responses.is_empty() {
            bail!("OpenAPI operation must define at least one response");
        }
        responses.sort_by_key(|contract| contract.selector.sort_key());

        let replacement_status = StatusCode::from_u16(cfg.replacement_status)
            .context("response_contract replacement_status must be a valid HTTP status")?;
        if cfg.mode == ResponseContractModeCfg::ReplaceError && replacement_status.is_success() {
            bail!("response_contract replace_error status must not be successful");
        }
        if cfg.replacement_body.len() > 4096 {
            bail!("response_contract replacement_body exceeds 4096 bytes");
        }
        Ok(Self {
            mode: cfg.mode,
            responses,
            max_body_bytes: cfg.max_body_bytes,
            replacement_status,
            replacement_body: Bytes::copy_from_slice(cfg.replacement_body.as_bytes()),
        })
    }

    /// 业务作用：对最终下游响应执行声明的 observe/block/replace-error 契约动作。
    ///
    /// 参数说明：`response` 是响应插件和声明式转换后的实体；`request_method` 用于 HEAD
    /// 空实体语义；`metrics` 记录固定低基数终态。
    ///
    /// 返回：observe 始终返回原响应的透传包装；阻断模式在不符合契约、超限或读取失败时
    /// 返回不含原实体的本地错误响应。
    pub(super) async fn enforce(
        &self,
        response: Response<BoxBody>,
        request_method: &Method,
        metrics: Arc<Metrics>,
    ) -> Response<BoxBody> {
        let selected = match self.select(response.status(), response.headers(), request_method) {
            Ok(selected) => selected,
            Err(_message) => {
                metrics.inc_response_contract(match self.mode {
                    ResponseContractModeCfg::Observe => ResponseContractMetric::Invalid,
                    ResponseContractModeCfg::Block => ResponseContractMetric::Blocked,
                    ResponseContractModeCfg::ReplaceError => ResponseContractMetric::Replaced,
                });
                return match self.mode {
                    ResponseContractModeCfg::Observe => response,
                    ResponseContractModeCfg::Block => contract_error_response(
                        StatusCode::BAD_GATEWAY,
                        "upstream response does not satisfy contract",
                    ),
                    ResponseContractModeCfg::ReplaceError => self.replacement_response(),
                };
            }
        };
        if self.mode == ResponseContractModeCfg::Observe {
            if encoded_body(response.headers()) {
                metrics.inc_response_contract(ResponseContractMetric::Unsupported);
                return response;
            }
            let (parts, body) = response.into_parts();
            let body = ObservedContractBody {
                inner: body,
                validator: selected.validator,
                expects_empty: selected.expects_empty,
                max_body_bytes: self.max_body_bytes as usize,
                captured: BytesMut::new(),
                oversized: false,
                completed: false,
                metrics,
            }
            .boxed();
            return Response::from_parts(parts, body);
        }
        if encoded_body(response.headers()) {
            metrics.inc_response_contract(ResponseContractMetric::Unsupported);
            return self.failure_response();
        }
        if declared_length(response.headers()).is_some_and(|length| length > self.max_body_bytes) {
            metrics.inc_response_contract(ResponseContractMetric::TooLarge);
            return self.failure_response();
        }
        let (parts, body) = response.into_parts();
        let collected = match collect_bounded(body, self.max_body_bytes).await {
            Ok(collected) => collected,
            Err(CollectError::TooLarge) => {
                metrics.inc_response_contract(ResponseContractMetric::TooLarge);
                return self.failure_response();
            }
            Err(CollectError::Read) => {
                metrics.inc_response_contract(ResponseContractMetric::ReadError);
                return self.failure_response();
            }
        };
        match validate_contract_bytes(&selected, &collected.bytes) {
            ContractValidation::Valid => {
                metrics.inc_response_contract(ResponseContractMetric::Valid);
                Response::from_parts(parts, buffered_body(collected))
            }
            ContractValidation::Invalid => {
                metrics.inc_response_contract(match self.mode {
                    ResponseContractModeCfg::ReplaceError => ResponseContractMetric::Replaced,
                    _ => ResponseContractMetric::Blocked,
                });
                self.failure_response()
            }
        }
    }

    /// 业务作用：按精确状态、状态类、default 的稳定优先级选择响应 schema 和空实体契约。
    ///
    /// 参数说明：`status`、`headers` 是最终响应 head；`request_method` 决定 HEAD 是否强制空实体。
    ///
    /// 返回：找到唯一 status/media type 时返回选择结果；未声明、缺失或不匹配时返回低敏错误。
    fn select(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        request_method: &Method,
    ) -> std::result::Result<SelectedResponseContract, &'static str> {
        let status = status.as_u16();
        let contract = self
            .responses
            .iter()
            .find(|candidate| candidate.selector.matches_exact(status))
            .or_else(|| {
                self.responses
                    .iter()
                    .find(|candidate| candidate.selector.matches_class(status))
            })
            .or_else(|| {
                self.responses
                    .iter()
                    .find(|candidate| matches!(candidate.selector, StatusSelector::Default))
            })
            .ok_or("response status is not declared by OpenAPI contract")?;
        let no_entity = request_method == Method::HEAD
            || matches!(status, 100..=199 | 204 | 304)
            || contract.media.is_empty();
        if no_entity {
            return Ok(SelectedResponseContract {
                validator: None,
                expects_empty: true,
            });
        }
        let media_type = response_media_type(headers)
            .ok_or("response content-type is required by OpenAPI contract")?;
        let media = contract
            .media
            .iter()
            .find(|candidate| {
                media_type_matches(candidate.media_type.as_str(), media_type.as_str())
            })
            .ok_or("response content-type is not declared by OpenAPI contract")?;
        Ok(SelectedResponseContract {
            validator: Some(media.validator.clone()),
            expects_empty: false,
        })
    }

    /// 业务作用：构造不泄露 schema 路径或上游实体的 replace-error 响应。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回配置的非成功状态、纯文本类型和固定实体。
    fn replacement_response(&self) -> Response<BoxBody> {
        let mut response = Response::new(full_body(self.replacement_body.clone()));
        *response.status_mut() = self.replacement_status;
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        normalize_content_length(response.headers_mut(), self.replacement_body.len());
        response
    }

    /// 业务作用：把配置动作映射成唯一失败响应，确保原上游实体在失败闭合时不会写入下游。
    ///
    /// 参数说明：无。
    ///
    /// 返回：block 返回固定 502；replace-error 返回配置响应。
    fn failure_response(&self) -> Response<BoxBody> {
        match self.mode {
            ResponseContractModeCfg::Observe => {
                contract_error_response(StatusCode::BAD_GATEWAY, "response contract error")
            }
            ResponseContractModeCfg::Block => contract_error_response(
                StatusCode::BAD_GATEWAY,
                "upstream response does not satisfy contract",
            ),
            ResponseContractModeCfg::ReplaceError => self.replacement_response(),
        }
    }
}

impl BodyTransformPlan {
    /// 业务作用：编译声明式 body 转换、路径冲突和 XML 资源预算，防止运行期解释任意脚本或模糊路径。
    ///
    /// 参数说明：`cfg` 是 route 转换配置；`route_id` 用于候选错误定位；`direction`
    /// 区分 request/response 专属的 SOAP Fault 语义。
    ///
    /// 返回：配置确定、无冲突且资源有界时返回只读计划；否则拒绝候选快照。
    pub(crate) fn build(cfg: &BodyTransformCfg, route_id: &str, direction: &str) -> Result<Self> {
        if !(1..=MAX_CONTRACT_BODY_BYTES).contains(&cfg.max_body_bytes)
            || !(1..=MAX_CONTRACT_BODY_BYTES).contains(&cfg.max_output_bytes)
        {
            bail!(
                "route `{route_id}` {direction}_transform body/output limits must be within 1..={MAX_CONTRACT_BODY_BYTES}"
            );
        }
        if cfg.operations.len() > MAX_TRANSFORM_OPERATIONS {
            bail!("route `{route_id}` {direction}_transform has too many operations");
        }
        if cfg.xml_extract.len() > MAX_TRANSFORM_MAPPINGS
            || cfg
                .xml_emit
                .as_ref()
                .is_some_and(|emit| emit.fields.len() > MAX_TRANSFORM_MAPPINGS)
        {
            bail!("route `{route_id}` {direction}_transform has too many XML mappings");
        }
        if !(1..=256).contains(&cfg.max_xml_depth)
            || !(1..=1_000_000).contains(&cfg.max_xml_nodes)
            || !(1..=4096).contains(&cfg.max_xml_attributes)
            || !(1..=MAX_CONTRACT_BODY_BYTES as usize).contains(&cfg.max_xml_text_bytes)
        {
            bail!("route `{route_id}` {direction}_transform XML limits are outside safe bounds");
        }
        let operations = compile_json_operations(&cfg.operations)?;
        let xml = XmlTransformPlan::build(cfg, direction)?;
        validate_format_plan(cfg, &xml, direction)?;
        let soap_action = cfg
            .soap_action
            .as_deref()
            .map(|value| {
                if value.len() > 1024 || value.contains(['\r', '\n']) {
                    bail!("SOAPAction exceeds limit or contains a line break");
                }
                HeaderValue::from_str(value).context("SOAPAction is not a valid HTTP header value")
            })
            .transpose()?;
        if cfg.soap_fault.is_some() && direction != "response" {
            bail!("soap_fault is only valid for response_transform");
        }
        Ok(Self {
            input: cfg.input,
            output: cfg.output,
            max_body_bytes: cfg.max_body_bytes,
            max_output_bytes: cfg.max_output_bytes as usize,
            operations,
            xml,
            soap_action,
        })
    }

    /// 业务作用：转换下游请求实体并同步重建 Content-Type、长度、摘要和 SOAPAction 元数据。
    ///
    /// 参数说明：`parts` 是待转发请求 head；`body` 是请求实体唯一所有权。
    ///
    /// 返回：成功返回转换后的有界实体；输入、媒体类型、编码、SOAP 或资源门不符合时返回明确终态。
    pub(super) async fn transform_request(
        &self,
        parts: &mut Parts,
        body: ForwardBody,
    ) -> TransformOutcome {
        // 分段上传的偏移与完整实体绑定；重新序列化会使 Content-Range 失真，因此不能静默转成普通请求。
        if parts.headers.contains_key(CONTENT_RANGE) {
            return TransformOutcome::Invalid("body transform does not accept partial content");
        }
        if let Err(message) = self.validate_input_headers(&parts.headers, true) {
            return TransformOutcome::Invalid(message);
        }
        let transformed = self.transform_body(body).await;
        if let TransformOutcome::Transformed {
            body, media_type, ..
        } = transformed
        {
            strip_body_integrity_headers(&mut parts.headers);
            parts.headers.remove(CONTENT_ENCODING);
            parts
                .headers
                .insert(CONTENT_TYPE, HeaderValue::from_static(media_type));
            if let Some(length) = body.size_hint().exact() {
                normalize_content_length(&mut parts.headers, length as usize);
            }
            if self.output == BodyFormatCfg::Soap {
                if let Some(action) = &self.soap_action {
                    parts.headers.insert("soapaction", action.clone());
                }
            }
            TransformOutcome::Transformed {
                body,
                media_type,
                soap_fault_status: None,
            }
        } else {
            transformed
        }
    }

    /// 业务作用：转换最终响应实体并同步重建 representation 元数据及可选 SOAP Fault 状态。
    ///
    /// 参数说明：`response` 是尚未写入下游的响应。
    ///
    /// 返回：转换成功返回新响应；任何输入、解析或资源错误都返回失败终态且不发送半个原实体。
    pub(super) async fn transform_response(
        &self,
        response: Response<BoxBody>,
    ) -> std::result::Result<Response<BoxBody>, TransformOutcome> {
        // 206 与 Content-Range 描述原 representation 的字节区间；转换后已不是同一可寻址实体，必须失败闭合。
        if response.status() == StatusCode::PARTIAL_CONTENT
            || response.headers().contains_key(CONTENT_RANGE)
        {
            return Err(TransformOutcome::Invalid(
                "body transform does not accept partial content",
            ));
        }
        if let Err(message) = self.validate_input_headers(response.headers(), false) {
            return Err(TransformOutcome::Invalid(message));
        }
        let (mut parts, body) = response.into_parts();
        match self.transform_body(body).await {
            TransformOutcome::Transformed {
                body,
                media_type,
                soap_fault_status,
            } => {
                strip_body_integrity_headers(&mut parts.headers);
                parts.headers.remove(CONTENT_ENCODING);
                parts
                    .headers
                    .insert(CONTENT_TYPE, HeaderValue::from_static(media_type));
                if let Some(length) = body.size_hint().exact() {
                    normalize_content_length(&mut parts.headers, length as usize);
                }
                if let Some(status) = soap_fault_status {
                    parts.status = status;
                }
                Ok(Response::from_parts(parts, body))
            }
            failure => Err(failure),
        }
    }

    /// 业务作用：执行一次有界实体读取、结构解析、字段操作和确定性序列化事务。
    ///
    /// 参数说明：`body` 是本次转换唯一可消费的实体流。
    ///
    /// 返回：全部阶段成功时返回单一新实体；超限、读取、语法、字段或 SOAP 约束失败时返回对应终态。
    async fn transform_body(&self, body: BoxBody) -> TransformOutcome {
        let collected = match collect_bounded(body, self.max_body_bytes).await {
            Ok(collected) => collected,
            Err(CollectError::TooLarge) => return TransformOutcome::TooLarge,
            Err(CollectError::Read) => return TransformOutcome::ReadFailed,
        };
        if collected.has_trailers() {
            return TransformOutcome::Invalid("body transform does not accept trailers");
        }
        let (mut value, fault) = match self.input {
            BodyFormatCfg::Json => match serde_json::from_slice(&collected.bytes) {
                Ok(value) => (value, false),
                Err(_) => {
                    return TransformOutcome::Invalid("body transform input is not valid JSON")
                }
            },
            BodyFormatCfg::Xml | BodyFormatCfg::Soap => {
                match self
                    .xml
                    .parse(&collected.bytes, self.input == BodyFormatCfg::Soap)
                {
                    Ok(parsed) => (parsed.value, parsed.fault),
                    Err(_) => {
                        return TransformOutcome::Invalid("body transform input is not valid XML")
                    }
                }
            }
        };
        if apply_json_operations(&mut value, &self.operations).is_err() {
            return TransformOutcome::Invalid("body transform field operation failed");
        }
        let output = match self.output {
            BodyFormatCfg::Json => match serde_json::to_vec(&value) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return TransformOutcome::Invalid("body transform JSON serialization failed")
                }
            },
            BodyFormatCfg::Xml | BodyFormatCfg::Soap => {
                match self.xml.emit(&value, self.output == BodyFormatCfg::Soap) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return TransformOutcome::Invalid("body transform XML serialization failed")
                    }
                }
            }
        };
        if output.len() > self.max_output_bytes {
            return TransformOutcome::TooLarge;
        }
        TransformOutcome::Transformed {
            body: full_body(Bytes::from(output)),
            media_type: self.xml.output_media_type(self.output),
            soap_fault_status: fault.then_some(self.xml.fault_status).flatten(),
        }
    }

    /// 业务作用：在消费实体前复验媒体类型、内容编码和 SOAPAction，避免按错误表示解释字节。
    ///
    /// 参数说明：`headers` 是输入 head；`request` 表示是否允许并要求请求侧 SOAPAction。
    ///
    /// 返回：输入表示与编译计划一致时成功；不支持的编码、media type 或 SOAPAction 返回低敏错误。
    fn validate_input_headers(
        &self,
        headers: &HeaderMap,
        request: bool,
    ) -> std::result::Result<(), &'static str> {
        if encoded_body(headers) {
            return Err("body transform requires identity content encoding");
        }
        let media = response_media_type(headers).ok_or("body transform requires content-type")?;
        if !format_accepts_media_type(self.input, media.as_str()) {
            return Err("body transform content-type does not match input format");
        }
        if request && self.input == BodyFormatCfg::Soap {
            if let Some(expected) = &self.soap_action {
                let actual = headers
                    .get("soapaction")
                    .ok_or("SOAP input requires configured SOAPAction")?;
                if actual != expected {
                    return Err("SOAPAction does not match configured action");
                }
            }
        }
        Ok(())
    }
}

impl XmlTransformPlan {
    /// 业务作用：编译 namespace-aware XML 提取、输出和 Fault 路径，并冻结全部结构预算。
    ///
    /// 参数说明：`cfg` 提供 namespace、映射和限制；`direction` 约束响应专属 Fault 状态。
    ///
    /// 返回：所有 QName、路径和目标唯一且有界时返回计划；冲突或非法路径返回错误。
    fn build(cfg: &BodyTransformCfg, direction: &str) -> Result<Self> {
        validate_namespaces(&cfg.namespaces)?;
        let mut extract = Vec::with_capacity(cfg.xml_extract.len());
        let mut extract_sources = HashSet::new();
        let mut extract_targets = HashSet::new();
        for field in &cfg.xml_extract {
            let plan = compile_xml_extract(field, &cfg.namespaces)?;
            if !extract_sources.insert(plan.from.clone()) {
                bail!("duplicate xml_extract source path `{}`", field.from);
            }
            if !extract_targets.insert(plan.to.clone()) {
                bail!("duplicate xml_extract target `{}`", field.to);
            }
            extract.push(plan);
        }
        let emit = cfg
            .xml_emit
            .as_ref()
            .map(|emit| compile_xml_emit(emit, &cfg.namespaces))
            .transpose()?;
        let (fault, fault_status) = cfg
            .soap_fault
            .as_ref()
            .map(|fault| compile_soap_fault(fault, &cfg.namespaces, direction))
            .transpose()?
            .map_or((None, None), |(path, status)| (Some(path), Some(status)));
        Ok(Self {
            namespaces: cfg.namespaces.clone(),
            extract,
            emit,
            fault,
            fault_status,
            max_depth: cfg.max_xml_depth,
            max_nodes: cfg.max_xml_nodes,
            max_attributes: cfg.max_xml_attributes,
            max_text_bytes: cfg.max_xml_text_bytes,
        })
    }

    /// 业务作用：按已解析 namespace URI 匹配固定 XML 路径，并把叶文本写入中间 JSON。
    ///
    /// 参数说明：`bytes` 是已通过实体字节门的 XML；`soap` 要求合法 SOAP Envelope/Body。
    ///
    /// 返回：结构、预算、唯一性和必填映射全部成立时返回 JSON 与 Fault 标记；否则返回错误。
    fn parse(&self, bytes: &[u8], soap: bool) -> Result<ParsedXml> {
        let mut reader = NsReader::from_reader(bytes);
        reader.config_mut().trim_text(false);
        let mut current = Vec::<XmlName>::new();
        let mut captures = vec![String::new(); self.extract.len()];
        let mut seen = vec![0usize; self.extract.len()];
        let mut fault = false;
        let mut nodes = 0usize;
        let mut text_bytes = 0usize;
        let mut saw_root = false;
        let mut closed_root = false;
        let mut soap_root: Option<XmlName> = None;
        let mut soap_body_seen = false;
        loop {
            let (namespace, event) = reader.read_resolved_event().context("parse XML event")?;
            nodes = nodes.saturating_add(1);
            if nodes > self.max_nodes {
                bail!("XML node budget exceeded");
            }
            match event {
                Event::Start(element) => {
                    if closed_root || current.is_empty() && saw_root {
                        bail!("XML document has multiple root elements");
                    }
                    if current.is_empty() {
                        saw_root = true;
                    }
                    validate_xml_attributes(&element, self.max_attributes)?;
                    current.push(resolved_xml_name(namespace, &element)?);
                    if current.len() > self.max_depth {
                        bail!("XML depth budget exceeded");
                    }
                    if current.len() == 1 {
                        soap_root = current.first().cloned();
                    } else if current.len() == 2 {
                        soap_body_seen = current[1].local == "Body"
                            && current[1].namespace == current[0].namespace;
                    }
                    if self.fault.as_ref().is_some_and(|path| path.0 == current) {
                        fault = true;
                    }
                }
                Event::Empty(element) => {
                    if closed_root || current.is_empty() && saw_root {
                        bail!("XML document has multiple root elements");
                    }
                    validate_xml_attributes(&element, self.max_attributes)?;
                    let name = resolved_xml_name(namespace, &element)?;
                    current.push(name);
                    if current.len() > self.max_depth {
                        bail!("XML depth budget exceeded");
                    }
                    if current.len() == 1 {
                        soap_root = current.first().cloned();
                    } else if current.len() == 2 {
                        soap_body_seen = soap_body_seen
                            || current[1].local == "Body"
                                && current[1].namespace == current[0].namespace;
                    }
                    for (index, plan) in self.extract.iter().enumerate() {
                        if plan.from.0 == current {
                            seen[index] = seen[index].saturating_add(1);
                        }
                    }
                    if self.fault.as_ref().is_some_and(|path| path.0 == current) {
                        fault = true;
                    }
                    current.pop();
                    if current.is_empty() {
                        saw_root = true;
                        closed_root = true;
                    }
                }
                Event::Text(text) => {
                    let decoded = text.decode().context("decode XML text")?;
                    text_bytes = text_bytes.saturating_add(decoded.len());
                    if text_bytes > self.max_text_bytes {
                        bail!("XML text budget exceeded");
                    }
                    for (index, plan) in self.extract.iter().enumerate() {
                        if plan.from.0 == current {
                            captures[index].push_str(decoded.as_ref());
                        }
                    }
                }
                Event::CData(text) => {
                    let decoded = text.decode().context("decode XML CDATA")?;
                    text_bytes = text_bytes.saturating_add(decoded.len());
                    if text_bytes > self.max_text_bytes {
                        bail!("XML text budget exceeded");
                    }
                    for (index, plan) in self.extract.iter().enumerate() {
                        if plan.from.0 == current {
                            captures[index].push_str(decoded.as_ref());
                        }
                    }
                }
                Event::End(_) => {
                    for (index, plan) in self.extract.iter().enumerate() {
                        if plan.from.0 == current {
                            seen[index] = seen[index].saturating_add(1);
                        }
                    }
                    if current.pop().is_none() {
                        bail!("XML end element has no matching start");
                    }
                    if current.is_empty() {
                        closed_root = true;
                    }
                }
                Event::DocType(_) | Event::PI(_) => {
                    bail!("XML DTD and processing instructions are forbidden");
                }
                Event::GeneralRef(reference) => {
                    if !safe_xml_reference(reference.as_ref()) {
                        bail!("XML custom entity is forbidden");
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if !saw_root || !closed_root || !current.is_empty() {
            bail!("XML document is incomplete");
        }
        if soap {
            validate_soap_envelope_path(&self.extract, self.fault.as_ref())?;
            validate_actual_soap_envelope(soap_root.as_ref(), soap_body_seen)?;
        }
        let mut value = Value::Object(Map::new());
        for (index, plan) in self.extract.iter().enumerate() {
            if seen[index] > 1 {
                bail!("XML extraction path matched more than once");
            }
            if seen[index] == 0 {
                if plan.required {
                    bail!("required XML extraction path is absent");
                }
                continue;
            }
            let field = xml_scalar(captures[index].trim(), plan.value_type)?;
            insert_json_value(&mut value, &plan.to, field, false)?;
        }
        Ok(ParsedXml { value, fault })
    }

    /// 业务作用：从中间 JSON 的精确字段构造固定 XML 或 SOAP 树，禁止动态元素名和无界输出。
    ///
    /// 参数说明：`value` 是字段操作后的 JSON；`soap` 决定是否包裹标准 Envelope/Body。
    ///
    /// 返回：所有必填字段存在且为标量时返回 XML 字节；缺失、类型或输出错误返回失败。
    fn emit(&self, value: &Value, soap: bool) -> Result<Vec<u8>> {
        let plan = self.emit.as_ref().context("XML output requires xml_emit")?;
        let mut root = XmlOutputNode::new(plan.root.clone());
        for field in &plan.fields {
            let Some(field_value) = value.pointer(field.from.source.as_str()) else {
                if field.required {
                    bail!("required XML output field is absent");
                }
                continue;
            };
            let text = json_scalar_text(field_value)?;
            root.insert_path(&field.path, text)?;
        }
        let mut writer = Writer::new(Vec::new());
        if soap {
            let soap_namespace = self
                .namespaces
                .get("soap")
                .map(String::as_str)
                .unwrap_or("http://www.w3.org/2003/05/soap-envelope");
            if !matches!(
                soap_namespace,
                "http://schemas.xmlsoap.org/soap/envelope/"
                    | "http://www.w3.org/2003/05/soap-envelope"
            ) {
                bail!("SOAP namespace is not a supported envelope URI");
            }
            let mut envelope = BytesStart::new("soap:Envelope");
            envelope.push_attribute(("xmlns:soap", soap_namespace));
            for (prefix, uri) in &self.namespaces {
                if prefix != "soap" {
                    let name = if prefix.is_empty() {
                        "xmlns".to_string()
                    } else {
                        format!("xmlns:{prefix}")
                    };
                    envelope.push_attribute((name.as_str(), uri.as_str()));
                }
            }
            writer.write_event(Event::Start(envelope))?;
            writer.write_event(Event::Start(BytesStart::new("soap:Body")))?;
            root.write(&mut writer, false, &self.namespaces)?;
            writer.write_event(Event::End(BytesEnd::new("soap:Body")))?;
            writer.write_event(Event::End(BytesEnd::new("soap:Envelope")))?;
        } else {
            root.write(&mut writer, true, &self.namespaces)?;
        }
        Ok(writer.into_inner())
    }

    /// 业务作用：使 SOAP 输出的 Content-Type 与实际 Envelope namespace 版本保持一致。
    ///
    /// 参数说明：`format` 是已编译输出格式。
    ///
    /// 返回：JSON/XML 返回固定类型；SOAP 1.1 返回 text/xml，SOAP 1.2 返回 application/soap+xml。
    fn output_media_type(&self, format: BodyFormatCfg) -> &'static str {
        match format {
            BodyFormatCfg::Json => "application/json",
            BodyFormatCfg::Xml => "application/xml",
            BodyFormatCfg::Soap
                if self.namespaces.get("soap").is_some_and(|namespace| {
                    namespace == "http://schemas.xmlsoap.org/soap/envelope/"
                }) =>
            {
                "text/xml"
            }
            BodyFormatCfg::Soap => "application/soap+xml",
        }
    }
}

#[derive(Clone)]
struct XmlOutputNode {
    name: XmlName,
    text: Option<String>,
    children: Vec<XmlOutputNode>,
}

impl XmlOutputNode {
    /// 业务作用：创建一个只能由已编译 QName 标识的输出节点。
    ///
    /// 参数说明：`name` 是经过 namespace 配置复验的固定元素名。
    ///
    /// 返回：返回空文本、空子节点的构建节点。
    fn new(name: XmlName) -> Self {
        Self {
            name,
            text: None,
            children: Vec::new(),
        }
    }

    /// 业务作用：把一个 JSON 标量写入固定 XML 路径，拒绝重复叶写和叶/父角色冲突。
    ///
    /// 参数说明：`path` 是相对输出根的已编译路径；`text` 是待转义的标量文本。
    ///
    /// 返回：唯一确定地插入时成功；冲突或空路径返回错误。
    fn insert_path(&mut self, path: &[XmlName], text: String) -> Result<()> {
        let (first, rest) = path
            .split_first()
            .context("XML output path must not be empty")?;
        if self.text.is_some() {
            bail!("XML output path tries to add a child below a text leaf");
        }
        let index = if let Some(index) = self.children.iter().position(|child| child.name == *first)
        {
            index
        } else {
            self.children.push(XmlOutputNode::new(first.clone()));
            self.children.len() - 1
        };
        let child = &mut self.children[index];
        if rest.is_empty() {
            if child.text.is_some() || !child.children.is_empty() {
                bail!("XML output path is written more than once");
            }
            child.text = Some(text);
            return Ok(());
        }
        child.insert_path(rest, text)
    }

    /// 业务作用：按固定声明顺序序列化 XML 节点，并只在受信根写入静态 namespace 声明。
    ///
    /// 参数说明：`writer` 接收输出；`declare_namespaces` 控制本节点是否为文档根；
    /// `namespaces` 是已验证的 prefix 映射。
    ///
    /// 返回：所有事件成功写入返回成功；writer 错误返回失败。
    fn write(
        &self,
        writer: &mut Writer<Vec<u8>>,
        declare_namespaces: bool,
        namespaces: &BTreeMap<String, String>,
    ) -> Result<()> {
        let mut start = BytesStart::new(self.name.qname.as_str());
        if declare_namespaces {
            for (prefix, uri) in namespaces {
                let name = if prefix.is_empty() {
                    "xmlns".to_string()
                } else {
                    format!("xmlns:{prefix}")
                };
                start.push_attribute((name.as_str(), uri.as_str()));
            }
        }
        writer.write_event(Event::Start(start))?;
        if let Some(text) = &self.text {
            writer.write_event(Event::Text(BytesText::new(text)))?;
        }
        for child in &self.children {
            child.write(writer, false, namespaces)?;
        }
        writer.write_event(Event::End(BytesEnd::new(self.name.qname.as_str())))?;
        Ok(())
    }
}

impl Body for ObservedContractBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：原样透传响应 frame，同时只保留上限内副本用于流结束后的观察性契约校验。
    ///
    /// 参数说明：`cx` 是下游背压唤醒上下文。
    ///
    /// 返回：保持原 body 的 frame、错误与 pending 语义；校验结论只写低基数指标。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if !self.oversized {
                        if self.captured.len().saturating_add(data.len()) > self.max_body_bytes {
                            self.oversized = true;
                            self.captured.clear();
                            self.metrics
                                .inc_response_contract(ResponseContractMetric::TooLarge);
                        } else {
                            self.captured.extend_from_slice(data);
                        }
                    }
                }
                if self.inner.is_end_stream() {
                    self.complete_observation();
                }
            }
            Poll::Ready(Some(Err(_))) => {
                if !self.completed {
                    self.completed = true;
                    self.metrics
                        .inc_response_contract(ResponseContractMetric::ReadError);
                }
            }
            Poll::Ready(None) => {
                self.complete_observation();
            }
            Poll::Pending => {}
        }
        polled
    }

    /// 业务作用：保持被包装响应的结束判断，避免 observe 模式改变下游调度。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回内部 body 的原始结束状态。
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    /// 业务作用：保持被包装响应的长度提示，使 observe 模式不改变 framing 决策。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回内部 body 的原始大小提示。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl ObservedContractBody {
    /// 业务作用：在显式 EOF 或已知长度最后一帧后只执行一次 observe 契约校验。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无；未超限时写入 valid/invalid，超限已在达到字节门时记录。
    fn complete_observation(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        if self.oversized {
            return;
        }
        let selected = SelectedResponseContract {
            validator: self.validator.clone(),
            expects_empty: self.expects_empty,
        };
        let metric = match validate_contract_bytes(&selected, &self.captured) {
            ContractValidation::Valid => ResponseContractMetric::Valid,
            ContractValidation::Invalid => ResponseContractMetric::Invalid,
        };
        self.metrics.inc_response_contract(metric);
    }
}

#[derive(Clone, Copy)]
struct OperationSelector<'a> {
    operation_id: Option<&'a str>,
    path: Option<&'a str>,
    method: Option<&'a str>,
}

impl<'a> OperationSelector<'a> {
    /// 业务作用：把两种互斥的 OpenAPI operation 选择方式收敛成无歧义编译条件。
    ///
    /// 参数说明：`operation_id` 或 `path`+`method` 来自 route；`route_id` 用于错误定位。
    ///
    /// 返回：恰好一种选择方式完整时返回 selector；缺失、混用或半配置时返回错误。
    fn new(
        operation_id: Option<&'a str>,
        path: Option<&'a str>,
        method: Option<&'a str>,
        route_id: &str,
    ) -> Result<Self> {
        if path.is_some() != method.is_some() || operation_id.is_some() == path.is_some() {
            bail!(
                "route `{route_id}` response_contract requires exactly one selector: operation_id or operation_path+operation_method"
            );
        }
        Ok(Self {
            operation_id,
            path,
            method,
        })
    }

    /// 业务作用：判断一个 OpenAPI operation 是否与编译期 selector 完全匹配。
    ///
    /// 参数说明：`path`、`method` 和 `operation` 来自同一 OpenAPI 文档。
    ///
    /// 返回：operationId 或 path+method 命中时返回 true。
    fn matches(&self, path: &str, method: &str, operation: &Value) -> bool {
        self.operation_id.is_some_and(|expected| {
            operation.get("operationId").and_then(Value::as_str) == Some(expected)
        }) || self.path == Some(path)
            && self
                .method
                .is_some_and(|expected| expected.eq_ignore_ascii_case(method))
    }
}

struct SchemaCatalog {
    documents: HashMap<SchemaDocumentId, Value>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
enum SchemaDocumentId {
    Local(PathBuf),
    Https(String),
}

impl SchemaCatalog {
    /// 业务作用：读取根文档、受信本地 catalog 和已验签 HTTPS 文档，并执行统一资源门。
    ///
    /// 参数说明：`root` 是 OpenAPI 根；`catalog_files` 是唯一允许外部引用的本地文档；
    /// `registry_documents` 是固定 URL 的签名远端文档；`config_dir` 是相对路径根。
    ///
    /// 返回：全部文档可规范化、读取和解析时返回 catalog；重复、缺失或超预算时返回错误。
    fn load(
        root: &Path,
        catalog_files: &[String],
        registry_documents: &[SchemaRegistryDocumentCfg],
        config_dir: &Path,
    ) -> Result<Self> {
        if catalog_files
            .len()
            .saturating_add(registry_documents.len())
            .saturating_add(1)
            > MAX_CONTRACT_CATALOG_DOCUMENTS
        {
            bail!("response contract schema catalog has too many documents");
        }
        let mut paths = Vec::with_capacity(catalog_files.len() + 1);
        paths.push(root.to_path_buf());
        paths.extend(
            catalog_files
                .iter()
                .map(|path| resolve_path(config_dir, path)),
        );
        let mut documents = HashMap::new();
        let mut total_bytes = 0usize;
        for path in paths {
            let id = SchemaDocumentId::Local(path.clone());
            if documents.contains_key(&id) {
                bail!(
                    "response contract schema catalog contains duplicate path {}",
                    path.display()
                );
            }
            let metadata = std::fs::metadata(&path)
                .with_context(|| format!("stat schema document {}", path.display()))?;
            let length =
                usize::try_from(metadata.len()).context("schema document length overflow")?;
            total_bytes = total_bytes
                .checked_add(length)
                .context("schema catalog byte count overflow")?;
            if total_bytes > MAX_CONTRACT_CATALOG_BYTES {
                bail!("response contract schema catalog exceeds byte budget");
            }
            let document: Value = loader(&path)
                .preserve_unresolved_placeholders(true)
                .load()
                .with_context(|| format!("load schema document {}", path.display()))?;
            documents.insert(id, document);
        }
        for registry in registry_documents {
            let url = normalize_registry_url(registry.url.as_str())?;
            let id = SchemaDocumentId::Https(url.clone());
            if documents.contains_key(&id) {
                bail!("response contract schema registry contains duplicate URL");
            }
            let bytes = load_registry_document(registry, config_dir, url.as_str())?;
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .context("schema catalog byte count overflow")?;
            if total_bytes > MAX_CONTRACT_CATALOG_BYTES {
                bail!("response contract schema catalog exceeds byte budget");
            }
            let document = serde_yml::from_slice(bytes.as_ref())
                .context("parse signed HTTPS schema document")?;
            documents.insert(id, document);
        }
        Ok(Self { documents })
    }

    /// 业务作用：递归展开受信 catalog 内的 `$ref`，阻止网络、未登记文件、循环和深度放大。
    ///
    /// 参数说明：`document_id` 标识当前本地路径或 HTTPS 基准；`value` 是待展开节点；`active`
    /// 保存引用栈；`depth` 是当前递归层级。
    ///
    /// 返回：所有引用唯一解析且预算内时返回独立 schema；违反信任或资源门时返回错误。
    fn expand_reference_value(
        &self,
        document_id: &SchemaDocumentId,
        value: &Value,
        active: &mut Vec<String>,
        depth: usize,
    ) -> Result<Value> {
        if depth > MAX_SCHEMA_REFERENCE_DEPTH {
            bail!("schema reference depth exceeds {MAX_SCHEMA_REFERENCE_DEPTH}");
        }
        if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
            let (target_id, pointer) = resolve_schema_reference(document_id, reference)?;
            if !self.documents.contains_key(&target_id) {
                bail!(
                    "schema reference `{reference}` targets a document outside the explicit catalog"
                );
            }
            let identity = format!("{}#{pointer}", target_id.identity());
            if active.iter().any(|entry| entry == &identity) {
                bail!("schema reference cycle detected at `{identity}`");
            }
            active.push(identity);
            let document = self
                .documents
                .get(&target_id)
                .context("schema catalog target disappeared")?;
            let target = if pointer.is_empty() {
                document
            } else {
                document
                    .pointer(pointer.as_str())
                    .with_context(|| format!("schema reference `{reference}` is unresolved"))?
            };
            let expanded = self.expand_reference_value(&target_id, target, active, depth + 1)?;
            active.pop();
            return Ok(expanded);
        }
        match value {
            Value::Object(object) => {
                let mut expanded = Map::with_capacity(object.len());
                for (key, child) in object {
                    if key == "$dynamicRef" {
                        bail!("schema $dynamicRef is not supported by the bounded catalog");
                    }
                    expanded.insert(
                        key.clone(),
                        self.expand_reference_value(document_id, child, active, depth + 1)?,
                    );
                }
                Ok(Value::Object(expanded))
            }
            Value::Array(values) => values
                .iter()
                .map(|child| self.expand_reference_value(document_id, child, active, depth + 1))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array),
            _ => Ok(value.clone()),
        }
    }
}

impl StatusSelector {
    /// 业务作用：解析 OpenAPI response key，限定为精确状态、状态类或 default。
    ///
    /// 参数说明：`raw` 是 OpenAPI responses map 的 key。
    ///
    /// 返回：合法且可确定匹配的 selector；非法状态或范围返回错误。
    fn parse(raw: &str) -> Result<Self> {
        if raw.eq_ignore_ascii_case("default") {
            return Ok(Self::Default);
        }
        if raw.len() == 3
            && raw.as_bytes()[0].is_ascii_digit()
            && raw[1..].eq_ignore_ascii_case("XX")
        {
            let class = u16::from(raw.as_bytes()[0] - b'0');
            if (1..=5).contains(&class) {
                return Ok(Self::Class(class));
            }
        }
        let status = raw
            .parse::<u16>()
            .with_context(|| format!("invalid OpenAPI response status `{raw}`"))?;
        StatusCode::from_u16(status)
            .with_context(|| format!("invalid OpenAPI response status `{raw}`"))?;
        Ok(Self::Exact(status))
    }

    /// 业务作用：生成构建期去重身份，避免大小写不同的 default 或等价状态选择器共存。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回 selector 类型与数值组成的稳定身份。
    fn identity(&self) -> (u8, u16) {
        match self {
            Self::Exact(status) => (0, *status),
            Self::Class(class) => (1, *class),
            Self::Default => (2, 0),
        }
    }

    /// 业务作用：提供精确、状态类、default 的稳定排序优先级。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回可用于确定性排序的 key。
    fn sort_key(&self) -> (u8, u16) {
        self.identity()
    }

    /// 业务作用：判断 selector 是否精确匹配当前 HTTP 状态。
    ///
    /// 参数说明：`status` 是响应状态数值。
    ///
    /// 返回：仅 Exact 且值相等时返回 true。
    fn matches_exact(&self, status: u16) -> bool {
        matches!(self, Self::Exact(expected) if *expected == status)
    }

    /// 业务作用：判断 selector 是否按百位状态类匹配当前 HTTP 状态。
    ///
    /// 参数说明：`status` 是响应状态数值。
    ///
    /// 返回：仅 Class 且百位相等时返回 true。
    fn matches_class(&self, status: u16) -> bool {
        matches!(self, Self::Class(expected) if *expected == status / 100)
    }
}

/// 业务作用：定位唯一 OpenAPI operation，防止重复 operationId 被任意选择。
///
/// 参数说明：`document` 是 OpenAPI 根；`selector` 是已复验的选择方式。
///
/// 返回：恰好一个 operation 命中时返回引用；无命中或多命中返回错误。
fn find_operation<'a>(document: &'a Value, selector: OperationSelector<'_>) -> Result<&'a Value> {
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .context("OpenAPI document requires object `paths`")?;
    let mut found = None;
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        for method in [
            "get", "put", "post", "delete", "options", "head", "patch", "trace",
        ] {
            let Some(operation) = item.get(method) else {
                continue;
            };
            if selector.matches(path, method, operation) {
                if found.is_some() {
                    bail!("OpenAPI operation selector matches more than once");
                }
                found = Some(operation);
            }
        }
    }
    found.context("OpenAPI response operation not found")
}

impl SchemaDocumentId {
    /// 业务作用：生成不含 schema 内容的稳定引用身份，供循环检测和错误定位使用。
    ///
    /// 参数说明：无。
    ///
    /// 返回：本地文档返回规范路径；远端文档返回固定 HTTPS URL。
    fn identity(&self) -> String {
        match self {
            Self::Local(path) => path.display().to_string(),
            Self::Https(url) => url.clone(),
        }
    }
}

/// 业务作用：把 schema 引用解析为显式 catalog 文档和 RFC 6901 pointer，只允许本地或 HTTPS。
///
/// 参数说明：`current` 是当前文档身份；`reference` 是 `$ref` 原值。
///
/// 返回：本地或显式 HTTPS 引用返回文档身份与 pointer；降级 HTTP、其它 scheme 或非法 fragment 返回错误。
fn resolve_schema_reference(
    current: &SchemaDocumentId,
    reference: &str,
) -> Result<(SchemaDocumentId, String)> {
    let (file, fragment) = reference.split_once('#').unwrap_or((reference, ""));
    let target = if file.is_empty() {
        current.clone()
    } else if file.starts_with("https://") {
        SchemaDocumentId::Https(normalize_registry_url(file)?)
    } else if file.contains("://") {
        bail!("schema reference uses a forbidden transport scheme");
    } else {
        match current {
            SchemaDocumentId::Local(current) => {
                let base = current.parent().unwrap_or_else(|| Path::new("."));
                SchemaDocumentId::Local(resolve_path(base, file))
            }
            SchemaDocumentId::Https(current) => {
                let base = reqwest::Url::parse(current).context("parse HTTPS schema base URL")?;
                let joined = base
                    .join(file)
                    .context("resolve relative HTTPS schema reference")?;
                SchemaDocumentId::Https(normalize_registry_url(joined.as_str())?)
            }
        }
    };
    let pointer = if fragment.is_empty() {
        String::new()
    } else if fragment.starts_with('/') {
        fragment.to_string()
    } else {
        bail!("schema reference fragment must be an RFC 6901 pointer");
    };
    Ok((target, pointer))
}

/// 业务作用：规范化显式 schema registry URL，并拒绝降级、凭据、fragment 与异常 authority。
///
/// 参数说明：`raw` 是配置或远端文档中的 URL。
///
/// 返回：合法 HTTPS URL 返回无 fragment 的规范字符串；其它输入返回错误。
fn normalize_registry_url(raw: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(raw).context("schema registry URL is invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("schema registry URL must be credential-free HTTPS without fragment");
    }
    url.set_fragment(None);
    Ok(url.to_string())
}

/// 业务作用：从已验签有界缓存或固定 HTTPS URL取得 schema 原始字节，并在返回前重新复验身份。
///
/// 参数说明：`cfg` 冻结 URL、摘要、签名和资源门；`config_dir` 解析本地信任材料；
/// `url` 是已规范化的固定地址。
///
/// 返回：摘要与 detached signature 都匹配时返回共享字节；网络、TLS、超限或验签失败返回错误。
fn load_registry_document(
    cfg: &SchemaRegistryDocumentCfg,
    config_dir: &Path,
    url: &str,
) -> Result<Arc<[u8]>> {
    if !(1..=4 * 1024 * 1024).contains(&cfg.max_bytes)
        || !(100..=30_000).contains(&cfg.timeout_ms)
        || !(1..=24 * 60 * 60 * 1_000).contains(&cfg.cache_ttl_ms)
    {
        bail!("schema registry byte, timeout, or cache TTL limit is outside safe bounds");
    }
    validate_sha256(cfg.sha256.as_str())?;
    let cache_key = format!("{url}\0{}", cfg.sha256.to_ascii_lowercase());
    let cache = SCHEMA_REGISTRY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(bytes) = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("schema registry cache lock is poisoned"))?
        .get(cache_key.as_str())
        .filter(|entry| entry.loaded_at.elapsed() <= Duration::from_millis(cfg.cache_ttl_ms))
        .map(|entry| entry.bytes.clone())
    {
        verify_registry_document(bytes.as_ref(), cfg, config_dir)?;
        return Ok(bytes);
    }

    let fetch_cfg = cfg.clone();
    let fetch_dir = config_dir.to_path_buf();
    let fetch_url = url.to_string();
    // reqwest blocking client 必须在专用控制面线程中运行；候选构建可以等待其有界 deadline，
    // 但不能在 Tokio worker 内创建嵌套 runtime，也不能把网络调用带入请求热路径。
    let bytes =
        std::thread::spawn(move || fetch_registry_document(fetch_cfg, fetch_dir, fetch_url))
            .join()
            .map_err(|_| anyhow::anyhow!("schema registry fetch worker panicked"))??;
    verify_registry_document(bytes.as_ref(), cfg, config_dir)?;

    let mut cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("schema registry cache lock is poisoned"))?;
    if cache.len() >= MAX_SCHEMA_REGISTRY_CACHE_ENTRIES && !cache.contains_key(&cache_key) {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.loaded_at)
            .map(|(key, _)| key.clone())
        {
            cache.remove(oldest.as_str());
        }
    }
    cache.insert(
        cache_key,
        CachedRegistryDocument {
            loaded_at: Instant::now(),
            bytes: bytes.clone(),
        },
    );
    Ok(bytes)
}

/// 业务作用：在隔离线程内执行一次无 redirect 的 HTTPS schema GET，并严格限制 CA 和响应字节。
///
/// 参数说明：`cfg` 是完整 registry 声明；`config_dir` 解析可选 CA；`url` 是固定目标。
///
/// 返回：HTTP 成功且响应未超过上限时返回原始字节；TLS、状态、读取或超限返回错误。
fn fetch_registry_document(
    cfg: SchemaRegistryDocumentCfg,
    config_dir: PathBuf,
    url: String,
) -> Result<Arc<[u8]>> {
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("naway-schema-registry/1")
        .https_only(true);
    if let Some(ca_file) = cfg.ca_file.as_deref() {
        let path = resolve_path(&config_dir, ca_file);
        let metadata = std::fs::metadata(&path)
            .with_context(|| format!("stat schema registry CA {}", path.display()))?;
        if metadata.len() > 1024 * 1024 {
            bail!("schema registry CA exceeds 1 MiB");
        }
        let pem = std::fs::read(&path)
            .with_context(|| format!("read schema registry CA {}", path.display()))?;
        let certificate =
            reqwest::Certificate::from_pem(&pem).context("parse schema registry CA PEM")?;
        builder = builder.add_root_certificate(certificate);
    }
    let client = builder
        .build()
        .context("build schema registry HTTPS client")?;
    let mut response = client
        .get(url)
        .header(
            reqwest::header::ACCEPT,
            "application/yaml, application/json",
        )
        .send()
        .context("fetch schema registry document")?;
    if !response.status().is_success() {
        bail!("schema registry returned non-success status");
    }
    if response
        .content_length()
        .is_some_and(|length| length > cfg.max_bytes as u64)
    {
        bail!("schema registry response exceeds max_bytes");
    }
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(cfg.max_bytes as u64) as usize,
    );
    response
        .by_ref()
        .take(cfg.max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read schema registry response")?;
    if bytes.len() > cfg.max_bytes {
        bail!("schema registry response exceeds max_bytes");
    }
    Ok(Arc::from(bytes))
}

/// 业务作用：复验 HTTPS schema 原始字节的固定摘要与 detached Ed25519 signature。
///
/// 参数说明：`bytes` 是响应原文；`cfg` 提供摘要和 SecretSource；`config_dir` 解析本地来源。
///
/// 返回：两种身份校验都通过时成功；格式、摘要、key 或签名不符合时返回错误。
fn verify_registry_document(
    bytes: &[u8],
    cfg: &SchemaRegistryDocumentCfg,
    config_dir: &Path,
) -> Result<()> {
    validate_sha256(cfg.sha256.as_str())?;
    let digest = Sha256::digest(bytes);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !actual.eq_ignore_ascii_case(cfg.sha256.as_str()) {
        bail!("schema registry response digest does not match pinned sha256");
    }
    let signature = crate::secret::resolve_text(
        cfg.signature.as_str(),
        config_dir,
        "schema registry signature",
    )?;
    let public_key = crate::secret::resolve_text(
        cfg.public_key.as_str(),
        config_dir,
        "schema registry public key",
    )?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature.trim())
        .context("decode schema registry signature")?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .context("decode schema registry public key")?;
    let signature = Signature::from_slice(signature.as_slice())
        .context("schema registry signature must be 64 bytes")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("schema registry public key must be 32 bytes"))?;
    let public_key =
        VerifyingKey::from_bytes(&public_key).context("decode schema registry public key")?;
    public_key
        .verify_strict(bytes, &signature)
        .context("verify schema registry signature")
}

/// 业务作用：验证固定 SHA-256 十六进制格式，避免摘要比较接受截断或歧义编码。
///
/// 参数说明：`digest` 是配置声明值。
///
/// 返回：恰好 64 个十六进制字符时成功；其它格式返回错误。
fn validate_sha256(digest: &str) -> Result<()> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("schema registry sha256 must contain exactly 64 hexadecimal characters");
    }
    Ok(())
}

/// 业务作用：把配置相对路径词法归一，确保 catalog 身份不因 `.`/`..` 写法分叉。
///
/// 参数说明：`base` 是解析根；`raw` 是配置路径。
///
/// 返回：返回不要求目标预先存在的词法归一路径。
fn resolve_path(base: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    normalize_path(&joined)
}

/// 业务作用：消除路径中的当前目录和可安全回退的父目录段，生成稳定 watcher/catalog identity。
///
/// 参数说明：`path` 是绝对或相对文件路径。
///
/// 返回：返回词法规范化路径，不访问文件系统或展开符号链接。
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !output.pop() {
                    output.push(component.as_os_str());
                }
            }
            _ => output.push(component.as_os_str()),
        }
    }
    output
}

/// 业务作用：验证契约选择后的原始字节，不在错误中暴露实例值或 schema 路径。
///
/// 参数说明：`selected` 是 status/media type 计划；`bytes` 是上限内完整实体。
///
/// 返回：空实体或 JSON Schema 完全符合时返回 Valid；其它情况返回 Invalid。
fn validate_contract_bytes(
    selected: &SelectedResponseContract,
    bytes: &[u8],
) -> ContractValidation {
    if selected.expects_empty {
        return if bytes.is_empty() {
            ContractValidation::Valid
        } else {
            ContractValidation::Invalid
        };
    }
    let Some(validator) = &selected.validator else {
        return ContractValidation::Invalid;
    };
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return ContractValidation::Invalid;
    };
    if validator.is_valid(&value) {
        ContractValidation::Valid
    } else {
        ContractValidation::Invalid
    }
}

/// 业务作用：编译 JSON 字段操作并提前拒绝重复写、路径包含和 rename 循环。
///
/// 参数说明：`operations` 是配置声明顺序。
///
/// 返回：无歧义时返回运行计划；非法 pointer、冲突写或循环返回错误。
fn compile_json_operations(operations: &[JsonTransformOperationCfg]) -> Result<Vec<JsonOperation>> {
    let mut output = Vec::with_capacity(operations.len());
    let mut writes = Vec::<JsonPointer>::new();
    let mut rename_edges = HashMap::<JsonPointer, JsonPointer>::new();
    let mut literal_bytes = 0usize;
    for operation in operations {
        let compiled = match operation {
            JsonTransformOperationCfg::Rename { from, to } => {
                let from = JsonPointer::parse(from)?;
                let to = JsonPointer::parse(to)?;
                if from.overlaps(&to) {
                    bail!("JSON rename source and target must not contain each other");
                }
                reject_write_conflict(&writes, &to)?;
                writes.push(to.clone());
                rename_edges.insert(from.clone(), to.clone());
                JsonOperation::Rename { from, to }
            }
            JsonTransformOperationCfg::Add { path, value } => {
                let path = JsonPointer::parse(path)?;
                literal_bytes = add_literal_budget(literal_bytes, value)?;
                reject_write_conflict(&writes, &path)?;
                writes.push(path.clone());
                JsonOperation::Add {
                    path,
                    value: value.clone(),
                }
            }
            JsonTransformOperationCfg::Remove { path } => JsonOperation::Remove {
                path: JsonPointer::parse(path)?,
            },
            JsonTransformOperationCfg::Default { path, value } => {
                let path = JsonPointer::parse(path)?;
                literal_bytes = add_literal_budget(literal_bytes, value)?;
                reject_write_conflict(&writes, &path)?;
                writes.push(path.clone());
                JsonOperation::Default {
                    path,
                    value: value.clone(),
                }
            }
            JsonTransformOperationCfg::TypeCheck { path, expected } => JsonOperation::TypeCheck {
                path: JsonPointer::parse(path)?,
                expected: *expected,
            },
        };
        output.push(compiled);
    }
    for source in rename_edges.keys() {
        let mut current = source;
        let mut visited = HashSet::new();
        while let Some(next) = rename_edges.get(current) {
            if !visited.insert(current) || next == source {
                bail!("JSON rename operations contain a cycle");
            }
            current = next;
        }
    }
    Ok(output)
}

impl JsonPointer {
    /// 业务作用：编译精确 RFC 6901 JSON Pointer，并限制深度和 segment 大小。
    ///
    /// 参数说明：`raw` 是配置 pointer。
    ///
    /// 返回：合法非根 pointer 返回 token 计划；通配、非法转义、过深或空根写返回错误。
    fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty() || !raw.starts_with('/') {
            bail!("JSON transform pointer must be a non-root RFC 6901 path");
        }
        let tokens = raw[1..]
            .split('/')
            .map(|token| decode_pointer_token(token))
            .collect::<Result<Vec<_>>>()?;
        if tokens.len() > MAX_TRANSFORM_PATH_SEGMENTS
            || tokens
                .iter()
                .any(|token| token.len() > 1024 || token == "-")
        {
            bail!("JSON transform pointer exceeds path budget or uses array append");
        }
        Ok(Self {
            source: raw.to_string(),
            tokens,
        })
    }

    /// 业务作用：判断本 pointer 是否等于或包含另一写目标，供构建期拒绝父子覆盖冲突。
    ///
    /// 参数说明：`other` 是另一候选写路径。
    ///
    /// 返回：任一 token 前缀包含另一个时返回 true。
    fn overlaps(&self, other: &Self) -> bool {
        let shared = self.tokens.len().min(other.tokens.len());
        self.tokens[..shared] == other.tokens[..shared]
    }
}

/// 业务作用：解码单个 JSON Pointer token，严格拒绝非 `~0`/`~1` 转义。
///
/// 参数说明：`raw` 是斜杠间的原始 token。
///
/// 返回：合法时返回解码 token；孤立或未知 `~` 转义返回错误。
fn decode_pointer_token(raw: &str) -> Result<String> {
    let mut output = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '~' {
            output.push(ch);
            continue;
        }
        match chars.next() {
            Some('0') => output.push('~'),
            Some('1') => output.push('/'),
            _ => bail!("JSON transform pointer contains invalid escape"),
        }
    }
    Ok(output)
}

/// 业务作用：拒绝两个字段操作写入相同或父子包含路径，避免执行顺序隐藏覆盖关系。
///
/// 参数说明：`existing` 是已登记写目标；`candidate` 是新目标。
///
/// 返回：互不包含时成功；重叠时返回错误。
fn reject_write_conflict(existing: &[JsonPointer], candidate: &JsonPointer) -> Result<()> {
    if existing.iter().any(|path| path.overlaps(candidate)) {
        bail!("JSON transform operations contain conflicting write paths");
    }
    Ok(())
}

/// 业务作用：累计配置内联 JSON 值的序列化字节，防止多个小操作共同携带超大常量。
///
/// 参数说明：`current` 是前序累计字节；`value` 是 add/default 的固定值。
///
/// 返回：累计长度不超过预算时返回新总量；超限、溢出或无法序列化时返回错误。
fn add_literal_budget(current: usize, value: &Value) -> Result<usize> {
    let total = current
        .checked_add(serde_json::to_vec(value)?.len())
        .context("JSON transform literal byte count overflow")?;
    if total > MAX_TRANSFORM_LITERAL_BYTES {
        bail!("JSON transform literal exceeds byte budget");
    }
    Ok(total)
}

/// 业务作用：按配置顺序执行已编译 JSON 操作，每次写入都保持对象/数组边界明确。
///
/// 参数说明：`value` 是可变中间树；`operations` 是无冲突运行计划。
///
/// 返回：全部字段存在性、目标空闲和类型约束成立时成功；否则返回错误。
fn apply_json_operations(value: &mut Value, operations: &[JsonOperation]) -> Result<()> {
    for operation in operations {
        match operation {
            JsonOperation::Rename { from, to } => {
                let moved = remove_json_value(value, from, true)?
                    .context("JSON rename source is absent")?;
                insert_json_value(value, to, moved, false)?;
            }
            JsonOperation::Add { path, value: added } => {
                insert_json_value(value, path, added.clone(), false)?;
            }
            JsonOperation::Remove { path } => {
                let _ = remove_json_value(value, path, false)?;
            }
            JsonOperation::Default {
                path,
                value: default,
            } => {
                if value.pointer(path.source.as_str()).is_none() {
                    insert_json_value(value, path, default.clone(), false)?;
                }
            }
            JsonOperation::TypeCheck { path, expected } => {
                let field = value
                    .pointer(path.source.as_str())
                    .context("JSON type_check field is absent")?;
                if !json_type_matches(field, *expected) {
                    bail!("JSON type_check field has unexpected type");
                }
            }
        }
    }
    Ok(())
}

/// 业务作用：把 JSON 值写入精确对象字段或现有数组索引，不隐式创建数组或覆盖已有值。
///
/// 参数说明：`root` 是中间树；`path` 是目标；`value` 是新值；`overwrite`
/// 控制是否允许替换现有叶值。
///
/// 返回：父对象可确定且目标符合覆盖规则时成功；路径类型、索引或冲突返回错误。
fn insert_json_value(
    root: &mut Value,
    path: &JsonPointer,
    value: Value,
    overwrite: bool,
) -> Result<()> {
    let (leaf, parents) = path
        .tokens
        .split_last()
        .context("JSON pointer has no leaf")?;
    let mut current = root;
    for token in parents {
        match current {
            Value::Object(object) => {
                current = object
                    .entry(token.clone())
                    .or_insert_with(|| Value::Object(Map::new()));
            }
            Value::Array(array) => {
                let index = parse_array_index(token, array.len())?;
                current = &mut array[index];
            }
            _ => bail!("JSON transform parent is not a container"),
        }
    }
    match current {
        Value::Object(object) => {
            if !overwrite && object.contains_key(leaf) {
                bail!("JSON transform target already exists");
            }
            object.insert(leaf.clone(), value);
        }
        Value::Array(array) => {
            let index = parse_array_index(leaf, array.len())?;
            if !overwrite {
                bail!("JSON transform cannot add over an existing array element");
            }
            array[index] = value;
        }
        _ => bail!("JSON transform target parent is not a container"),
    }
    Ok(())
}

/// 业务作用：从精确 JSON Pointer 删除并取出字段，不允许模糊数组索引。
///
/// 参数说明：`root` 是中间树；`path` 是目标；`required` 控制缺失是否失败。
///
/// 返回：命中时返回被删除值；可选缺失返回 None；路径非法或必填缺失返回错误。
fn remove_json_value(
    root: &mut Value,
    path: &JsonPointer,
    required: bool,
) -> Result<Option<Value>> {
    let (leaf, parents) = path
        .tokens
        .split_last()
        .context("JSON pointer has no leaf")?;
    let mut current = root;
    for token in parents {
        current = match current {
            Value::Object(object) => match object.get_mut(token) {
                Some(value) => value,
                None if !required => return Ok(None),
                None => bail!("JSON transform source parent is absent"),
            },
            Value::Array(array) => {
                let index = match token.parse::<usize>() {
                    Ok(index) if index < array.len() => index,
                    _ if !required => return Ok(None),
                    _ => bail!("JSON transform array index is invalid"),
                };
                &mut array[index]
            }
            _ if !required => return Ok(None),
            _ => bail!("JSON transform source parent is not a container"),
        };
    }
    let removed = match current {
        Value::Object(object) => object.remove(leaf),
        Value::Array(array) => {
            let index = match leaf.parse::<usize>() {
                Ok(index) if index < array.len() => index,
                _ if !required => return Ok(None),
                _ => bail!("JSON transform array index is invalid"),
            };
            Some(array.remove(index))
        }
        _ if !required => None,
        _ => bail!("JSON transform source parent is not a container"),
    };
    if required && removed.is_none() {
        bail!("JSON transform source is absent");
    }
    Ok(removed)
}

/// 业务作用：解析既有数组索引并拒绝越界、前导加号和 append 语义。
///
/// 参数说明：`token` 是 pointer token；`length` 是当前数组长度。
///
/// 返回：合法现有索引返回 usize；其它输入返回错误。
fn parse_array_index(token: &str, length: usize) -> Result<usize> {
    let index = token
        .parse::<usize>()
        .context("JSON transform array index is invalid")?;
    if index >= length {
        bail!("JSON transform array index is out of bounds");
    }
    Ok(index)
}

/// 业务作用：按声明类型检查 JSON 值，integer 只接受无小数表示。
///
/// 参数说明：`value` 是待检查字段；`expected` 是固定类型。
///
/// 返回：值属于声明类型时返回 true。
fn json_type_matches(value: &Value, expected: JsonValueTypeCfg) -> bool {
    match expected {
        JsonValueTypeCfg::Null => value.is_null(),
        JsonValueTypeCfg::Boolean => value.is_boolean(),
        JsonValueTypeCfg::Number => value.is_number(),
        JsonValueTypeCfg::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
        JsonValueTypeCfg::String => value.is_string(),
        JsonValueTypeCfg::Array => value.is_array(),
        JsonValueTypeCfg::Object => value.is_object(),
    }
}

/// 业务作用：复验输入/输出格式所需的映射和 SOAP 专属字段，拒绝无效或无作用配置。
///
/// 参数说明：`cfg` 是原始转换声明；`xml` 是已编译 XML 计划；`direction` 用于错误定位。
///
/// 返回：格式与映射闭合时成功；缺映射、多余 SOAP 字段或空转换返回错误。
fn validate_format_plan(
    cfg: &BodyTransformCfg,
    xml: &XmlTransformPlan,
    direction: &str,
) -> Result<()> {
    if cfg.input != BodyFormatCfg::Json && xml.extract.is_empty() {
        bail!("{direction}_transform XML/SOAP input requires xml_extract");
    }
    if cfg.output != BodyFormatCfg::Json && xml.emit.is_none() {
        bail!("{direction}_transform XML/SOAP output requires xml_emit");
    }
    if cfg.input == BodyFormatCfg::Json
        && cfg.output == BodyFormatCfg::Json
        && cfg.operations.is_empty()
    {
        bail!("{direction}_transform JSON to JSON requires at least one operation");
    }
    if cfg.input != BodyFormatCfg::Soap
        && cfg.output != BodyFormatCfg::Soap
        && (cfg.soap_action.is_some() || cfg.soap_fault.is_some())
    {
        bail!("SOAPAction/Fault mapping requires SOAP input or output");
    }
    Ok(())
}

/// 业务作用：复验 namespace prefix/URI，确保 XML path 不依赖未声明或可变绑定。
///
/// 参数说明：`namespaces` 是 route 固定映射。
///
/// 返回：prefix、URI 唯一且受限时成功；保留前缀、空 URI 或非法字符返回错误。
fn validate_namespaces(namespaces: &BTreeMap<String, String>) -> Result<()> {
    if namespaces.len() > 64 {
        bail!("XML namespace map exceeds 64 entries");
    }
    let mut uris = HashSet::new();
    for (prefix, uri) in namespaces {
        if prefix == "xmlns"
            || prefix.len() > 64
            || !prefix.is_empty() && !valid_xml_name(prefix)
            || uri.is_empty()
            || uri.len() > 1024
            || !uris.insert(uri)
        {
            bail!("XML namespace mapping is invalid or ambiguous");
        }
    }
    Ok(())
}

/// 业务作用：编译一条 XML 提取映射的 namespace path、JSON 目标和标量类型。
///
/// 参数说明：`field` 是映射声明；`namespaces` 提供 prefix 权威。
///
/// 返回：全部路径合法时返回运行计划；未知 prefix 或非法 pointer 返回错误。
fn compile_xml_extract(
    field: &XmlFieldMappingCfg,
    namespaces: &BTreeMap<String, String>,
) -> Result<XmlExtractPlan> {
    Ok(XmlExtractPlan {
        from: compile_xml_path(field.from.as_str(), namespaces, true)?,
        to: JsonPointer::parse(field.to.as_str())?,
        required: field.required,
        value_type: field.value_type,
    })
}

/// 业务作用：编译固定 XML 输出根和字段路径，并拒绝重复来源或父子写冲突。
///
/// 参数说明：`emit` 是输出声明；`namespaces` 提供 prefix 权威。
///
/// 返回：输出结构确定时返回计划；路径冲突、未知 prefix 或非法 JSON Pointer 返回错误。
fn compile_xml_emit(
    emit: &XmlEmitCfg,
    namespaces: &BTreeMap<String, String>,
) -> Result<XmlEmitPlan> {
    let root = compile_xml_name(emit.root.as_str(), namespaces)?;
    let mut fields = Vec::with_capacity(emit.fields.len());
    let mut sources = HashSet::new();
    let mut paths = Vec::<Vec<XmlName>>::new();
    for field in &emit.fields {
        let from = JsonPointer::parse(field.from.as_str())?;
        if !sources.insert(from.clone()) {
            bail!("duplicate xml_emit JSON source `{}`", field.from);
        }
        let path = compile_relative_xml_path(field.to.as_str(), namespaces)?;
        if paths
            .iter()
            .any(|existing| xml_paths_overlap(existing, &path))
        {
            bail!("xml_emit paths contain duplicate or parent/child conflict");
        }
        paths.push(path.clone());
        fields.push(XmlEmitFieldPlan {
            from,
            path,
            required: field.required,
        });
    }
    Ok(XmlEmitPlan { root, fields })
}

/// 业务作用：编译响应侧 SOAP Fault 路径与非成功 HTTP 状态。
///
/// 参数说明：`fault` 是固定映射；`namespaces` 提供 path prefix；`direction`
/// 必须是 response。
///
/// 返回：路径和状态合法时返回二元组；成功状态或请求侧使用返回错误。
fn compile_soap_fault(
    fault: &SoapFaultMappingCfg,
    namespaces: &BTreeMap<String, String>,
    direction: &str,
) -> Result<(XmlPath, StatusCode)> {
    if direction != "response" {
        bail!("SOAP Fault mapping is only valid on response_transform");
    }
    let status = StatusCode::from_u16(fault.status).context("SOAP Fault status is invalid")?;
    if status.is_success() {
        bail!("SOAP Fault status must not be successful");
    }
    Ok((
        compile_xml_path(fault.path.as_str(), namespaces, true)?,
        status,
    ))
}

/// 业务作用：编译绝对 XML path，每段固定为已声明 namespace 和合法 local name。
///
/// 参数说明：`raw` 是配置路径；`namespaces` 提供 prefix；`absolute` 要求前导 `/`。
///
/// 返回：路径非空且深度受限时返回计划；非法格式或未知 prefix 返回错误。
fn compile_xml_path(
    raw: &str,
    namespaces: &BTreeMap<String, String>,
    absolute: bool,
) -> Result<XmlPath> {
    if absolute && !raw.starts_with('/') {
        bail!("XML extraction path must be absolute");
    }
    let trimmed = raw.trim_start_matches('/');
    let segments = trimmed
        .split('/')
        .map(|segment| compile_xml_name(segment, namespaces))
        .collect::<Result<Vec<_>>>()?;
    if segments.is_empty() || segments.len() > MAX_TRANSFORM_PATH_SEGMENTS {
        bail!("XML path is empty or exceeds depth budget");
    }
    Ok(XmlPath(segments))
}

/// 业务作用：编译相对输出路径，不允许空段、`.`、`..` 或绝对写法改变固定根。
///
/// 参数说明：`raw` 是相对 QName 路径；`namespaces` 提供 prefix。
///
/// 返回：合法非空路径返回 QName 列表；其它输入返回错误。
fn compile_relative_xml_path(
    raw: &str,
    namespaces: &BTreeMap<String, String>,
) -> Result<Vec<XmlName>> {
    if raw.starts_with('/') || raw.is_empty() {
        bail!("xml_emit field path must be non-empty and relative");
    }
    let path = compile_xml_path(raw, namespaces, false)?;
    Ok(path.0)
}

/// 业务作用：把固定 QName 解析为 prefix 对应 URI 和 local name，不接受运行期动态绑定。
///
/// 参数说明：`raw` 是单个 QName；`namespaces` 提供受信 prefix 映射。
///
/// 返回：合法 QName 返回 expanded name；未知 prefix、多冒号或非法名称返回错误。
fn compile_xml_name(raw: &str, namespaces: &BTreeMap<String, String>) -> Result<XmlName> {
    let mut parts = raw.split(':');
    let first = parts.next().unwrap_or_default();
    let second = parts.next();
    if parts.next().is_some() || first.is_empty() {
        bail!("XML QName is invalid");
    }
    let (prefix, local) = match second {
        Some(local) => (Some(first), local),
        None => (None, first),
    };
    if !valid_xml_name(local) || prefix.is_some_and(|prefix| !valid_xml_name(prefix)) {
        bail!("XML QName contains unsupported characters");
    }
    let namespace = match prefix {
        Some(prefix) => Some(
            namespaces
                .get(prefix)
                .with_context(|| format!("XML QName uses unknown prefix `{prefix}`"))?
                .clone(),
        ),
        None => namespaces.get("").cloned(),
    };
    Ok(XmlName {
        qname: raw.to_string(),
        namespace,
        local: local.to_string(),
    })
}

/// 业务作用：限定可序列化 XML 名称字符，避免控制字符、空白或 markup 注入元素名。
///
/// 参数说明：`name` 是 prefix 或 local name。
///
/// 返回：ASCII 名称由字母/下划线开头且其余为字母数字、点、横线或下划线时返回 true。
fn valid_xml_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

/// 业务作用：把 NsReader 的实际 URI 与 local name转成可与编译路径比较的 expanded name。
///
/// 参数说明：`namespace` 是当前事件解析结果；`element` 提供 local/QName。
///
/// 返回：prefix 已绑定且名称为 UTF-8 时返回 expanded name；未知 prefix 或非法 UTF-8 返回错误。
fn resolved_xml_name(
    namespace: ResolveResult<'_>,
    element: &quick_xml::events::BytesStart<'_>,
) -> Result<XmlName> {
    let namespace = match namespace {
        ResolveResult::Bound(namespace) => Some(
            std::str::from_utf8(namespace.as_ref())
                .context("XML namespace URI is not UTF-8")?
                .to_string(),
        ),
        ResolveResult::Unbound => None,
        ResolveResult::Unknown(_) => bail!("XML element uses an unknown namespace prefix"),
    };
    let qname = std::str::from_utf8(element.name().as_ref())
        .context("XML QName is not UTF-8")?
        .to_string();
    let local = std::str::from_utf8(element.local_name().as_ref())
        .context("XML local name is not UTF-8")?
        .to_string();
    Ok(XmlName {
        qname,
        namespace,
        local,
    })
}

/// 业务作用：限制单元素属性数量并要求所有属性语法可解析，不读取外部资源。
///
/// 参数说明：`element` 是 start/empty 元素；`max_attributes` 是单元素硬上限。
///
/// 返回：属性数和语法都合法时成功；超限或解析错误返回失败。
fn validate_xml_attributes(
    element: &quick_xml::events::BytesStart<'_>,
    max_attributes: usize,
) -> Result<()> {
    let mut count = 0usize;
    for attribute in element.attributes() {
        attribute.context("parse XML attribute")?;
        count = count.saturating_add(1);
        if count > max_attributes {
            bail!("XML element attribute budget exceeded");
        }
    }
    Ok(())
}

/// 业务作用：只允许 XML 预定义实体与数值字符引用，拒绝自定义实体扩展。
///
/// 参数说明：`reference` 是不含 `&`/`;` 的实体名。
///
/// 返回：预定义或合法十进制/十六进制数值引用返回 true。
fn safe_xml_reference(reference: &[u8]) -> bool {
    matches!(reference, b"amp" | b"lt" | b"gt" | b"apos" | b"quot")
        || reference
            .strip_prefix(b"#x")
            .is_some_and(|value| !value.is_empty() && value.iter().all(u8::is_ascii_hexdigit))
        || reference
            .strip_prefix(b"#")
            .is_some_and(|value| !value.is_empty() && value.iter().all(u8::is_ascii_digit))
}

/// 业务作用：把 XML 叶文本按声明类型转成 JSON 标量，不接受非有限数值或宽松布尔值。
///
/// 参数说明：`text` 是已解码文本；`value_type` 是固定目标类型。
///
/// 返回：严格解析成功返回 JSON 标量；不符合声明返回错误。
fn xml_scalar(text: &str, value_type: XmlValueTypeCfg) -> Result<Value> {
    match value_type {
        XmlValueTypeCfg::String => Ok(Value::String(text.to_string())),
        XmlValueTypeCfg::Integer => text
            .parse::<i64>()
            .map(Value::from)
            .context("XML integer field is invalid"),
        XmlValueTypeCfg::Number => text
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .context("XML number field is invalid or non-finite"),
        XmlValueTypeCfg::Boolean => match text {
            "true" | "1" => Ok(Value::Bool(true)),
            "false" | "0" => Ok(Value::Bool(false)),
            _ => bail!("XML boolean field is invalid"),
        },
    }
}

/// 业务作用：把 JSON 标量稳定转换为 XML 文本，拒绝对象、数组和 null 的歧义表示。
///
/// 参数说明：`value` 是映射命中的 JSON 字段。
///
/// 返回：字符串、布尔和有限数字返回文本；其它类型返回错误。
fn json_scalar_text(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        _ => bail!("XML output field must be a JSON string, boolean, or number"),
    }
}

/// 业务作用：判断两个 XML 输出路径是否重复或存在父子包含，防止叶节点同时承担容器角色。
///
/// 参数说明：`left`、`right` 是相对输出根的 QName 路径。
///
/// 返回：任一路径是另一路径前缀时返回 true。
fn xml_paths_overlap(left: &[XmlName], right: &[XmlName]) -> bool {
    let shared = left.len().min(right.len());
    left[..shared] == right[..shared]
}

/// 业务作用：确认 SOAP 提取或 Fault 路径确实锚定标准 Envelope/Body，避免普通 XML 冒充 SOAP。
///
/// 参数说明：`extract` 是全部输入映射；`fault` 是可选 Fault 路径。
///
/// 返回：所有路径前两段都是标准 SOAP Envelope/Body 时成功；否则返回错误。
fn validate_soap_envelope_path(extract: &[XmlExtractPlan], fault: Option<&XmlPath>) -> Result<()> {
    for path in extract
        .iter()
        .map(|field| &field.from)
        .chain(fault.into_iter())
    {
        let [envelope, body, ..] = path.0.as_slice() else {
            bail!("SOAP mapping path must include Envelope and Body");
        };
        let namespace = envelope.namespace.as_deref();
        if envelope.local != "Envelope"
            || body.local != "Body"
            || namespace != body.namespace.as_deref()
            || !matches!(
                namespace,
                Some("http://schemas.xmlsoap.org/soap/envelope/")
                    | Some("http://www.w3.org/2003/05/soap-envelope")
            )
        {
            bail!("SOAP mapping path is not anchored to a standard Envelope/Body");
        }
    }
    Ok(())
}

/// 业务作用：复验输入文档自身的 SOAP 根与直接 Body 子元素，不只依赖配置映射声明。
///
/// 参数说明：`root` 是解析到的唯一根元素；`body_seen` 表示根下出现同 namespace 的 Body。
///
/// 返回：标准 SOAP 1.1/1.2 Envelope 与 Body 同时成立时成功；其它 XML 结构返回错误。
fn validate_actual_soap_envelope(root: Option<&XmlName>, body_seen: bool) -> Result<()> {
    let root = root.context("SOAP document has no root element")?;
    if root.local != "Envelope"
        || !matches!(
            root.namespace.as_deref(),
            Some("http://schemas.xmlsoap.org/soap/envelope/")
                | Some("http://www.w3.org/2003/05/soap-envelope")
        )
        || !body_seen
    {
        bail!("SOAP document requires a standard Envelope and direct Body child");
    }
    Ok(())
}

/// 业务作用：构造固定低敏契约错误响应，不回显 schema、operation、字段或上游实体。
///
/// 参数说明：`status` 是失败状态；`message` 是编译期固定文本。
///
/// 返回：返回带纯文本类型和准确长度的本地响应。
fn contract_error_response(status: StatusCode, message: &'static str) -> Response<BoxBody> {
    let bytes = Bytes::from_static(message.as_bytes());
    let mut response = Response::new(full_body(bytes));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    normalize_content_length(response.headers_mut(), message.len());
    response
}

/// 业务作用：读取规范化 media type，忽略参数但拒绝非 UTF-8 header。
///
/// 参数说明：`headers` 是请求或响应 head。
///
/// 返回：存在且可解析时返回小写 media type；其它情况返回 None。
fn response_media_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(normalize_media_type)
}

/// 业务作用：统一 media type 大小写和空白，供构建与运行期执行同一比较语义。
///
/// 参数说明：`media_type` 是配置或 header 中不含可信参数的媒体类型。
///
/// 返回：返回 trim 后 ASCII 小写字符串。
fn normalize_media_type(media_type: &str) -> String {
    media_type.trim().to_ascii_lowercase()
}

/// 业务作用：判断 media type 是否属于 JSON 或结构化 `+json` 表示。
///
/// 参数说明：`media_type` 是规范化前后的媒体类型。
///
/// 返回：application/json 或 application/*+json 返回 true。
fn is_json_media_type(media_type: &str) -> bool {
    let media = normalize_media_type(media_type);
    media == "application/json" || media.starts_with("application/") && media.ends_with("+json")
}

/// 业务作用：按 OpenAPI 精确类型与结构化 JSON 后缀规则匹配响应媒体类型。
///
/// 参数说明：`declared` 是编译期类型；`actual` 是响应类型。
///
/// 返回：精确相等，或双方都是 JSON 且声明为 application/json 时返回 true。
fn media_type_matches(declared: &str, actual: &str) -> bool {
    declared.eq_ignore_ascii_case(actual)
        || declared == "application/json" && is_json_media_type(actual)
}

/// 业务作用：判断输入 media type 是否与声明式转换格式一致，防止错误 parser 解释实体。
///
/// 参数说明：`format` 是编译格式；`media_type` 是规范化输入类型。
///
/// 返回：JSON/XML/SOAP 各自允许类型命中时返回 true。
fn format_accepts_media_type(format: BodyFormatCfg, media_type: &str) -> bool {
    match format {
        BodyFormatCfg::Json => is_json_media_type(media_type),
        BodyFormatCfg::Xml => {
            matches!(media_type, "application/xml" | "text/xml")
                || media_type.starts_with("application/") && media_type.ends_with("+xml")
        }
        BodyFormatCfg::Soap => {
            matches!(media_type, "text/xml" | "application/soap+xml")
        }
    }
}

/// 业务作用：拒绝网关未解码的压缩或多层编码实体，防止 schema/转换检查原始压缩字节。
///
/// 参数说明：`headers` 是请求或响应 head。
///
/// 返回：存在非 identity Content-Encoding 时返回 true。
fn encoded_body(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity"))
}

/// 业务作用：读取可信 Content-Length 提示用于聚合前快速拒绝，实际字节仍由 collect 硬门复验。
///
/// 参数说明：`headers` 是请求或响应 head。
///
/// 返回：恰好一个合法 u64 长度时返回 Some；缺失或非法返回 None。
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let first = values.next()?.to_str().ok()?.parse().ok()?;
    values.next().is_none().then_some(first)
}

/// 业务作用：把 response_contract 的本地 schema 与 HTTPS registry 信任材料加入统一精确 watcher。
///
/// 参数说明：`config_dir` 是相对路径根；`contract`、`request_transform`、`response_transform`
/// 是 route 可选声明。
///
/// 返回：返回需要参与配置指纹的 OpenAPI、catalog、CA、signature 和 public-key 文件路径。
pub(crate) fn dependency_paths(
    config_dir: &Path,
    contract: Option<&ResponseContractCfg>,
    _request_transform: Option<&BodyTransformCfg>,
    _response_transform: Option<&BodyTransformCfg>,
) -> Vec<PathBuf> {
    let Some(contract) = contract else {
        return Vec::new();
    };
    let mut paths = Vec::with_capacity(
        contract.catalog_files.len() + contract.registry_documents.len() * 3 + 1,
    );
    paths.push(resolve_path(config_dir, contract.openapi_file.as_str()));
    paths.extend(
        contract
            .catalog_files
            .iter()
            .map(|path| resolve_path(config_dir, path)),
    );
    for registry in &contract.registry_documents {
        if let Some(ca_file) = registry.ca_file.as_deref() {
            paths.push(resolve_path(config_dir, ca_file));
        }
        for source in [&registry.signature, &registry.public_key] {
            if let Some(path) = crate::secret::dependency_path(source, config_dir) {
                paths.push(path);
            }
        }
    }
    paths
}

/// 业务作用：把转换终态映射到固定低基数指标，供请求和响应入口共用。
///
/// 参数说明：`metrics` 是共享指标；`outcome` 是尚未被消费的转换结果引用。
///
/// 返回：无；只增加一个固定结果计数。
pub(super) fn record_transform_failure(metrics: &Metrics, outcome: &TransformOutcome) {
    let metric = match outcome {
        TransformOutcome::TooLarge => BodyTransformMetric::TooLarge,
        TransformOutcome::ReadFailed => BodyTransformMetric::ReadError,
        TransformOutcome::Invalid(_) => BodyTransformMetric::Invalid,
        TransformOutcome::Transformed { .. } => BodyTransformMetric::Transformed,
    };
    metrics.inc_body_transform(metric);
}
