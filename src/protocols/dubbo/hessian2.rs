//! Dubbo2 Hessian2 泛化调用的有界 wire codec。
//!
//! codec 只在 JSON 值、Hessian2 基础值与无类型 collection 之间转换。解码 class definition
//! 时仅保留字段布局，不按远端 type name 加载 class，也不执行构造函数或反射逻辑。

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use serde_json::{Map, Number, Value};

use super::{BoundedWriter, DubboError, DubboResult, GENERIC_DESCRIPTOR};

const MAX_CLASS_DEFINITIONS: usize = 256;
const MAX_VALUE_REFERENCES: usize = 65_536;
const MAX_STRING_CHUNK_UNITS: usize = 32 * 1024;
const MAX_BINARY_CHUNK_BYTES: usize = u16::MAX as usize;

/// Hessian2 编解码的 route 级硬资源预算。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct HessianLimits {
    pub(super) max_depth: usize,
    pub(super) max_collection_items: usize,
    pub(super) max_string_bytes: usize,
    pub(super) max_binary_bytes: usize,
}

/// 一次 Hessian2 泛化调用所需的可信 route 字段与不可信 arguments。
pub(super) struct HessianInvocation<'a> {
    pub(super) interface: &'a str,
    pub(super) method: &'a str,
    pub(super) parameter_types: &'a [String],
    pub(super) version: &'a str,
    pub(super) group: &'a str,
    pub(super) attachments: &'a [(Arc<str>, Arc<str>)],
    pub(super) arguments: &'a [Value],
    pub(super) max_frame_bytes: usize,
    pub(super) limits: HessianLimits,
}

/// 业务作用：按 Apache Dubbo `$invoke` 的 Hessian2 字段顺序编码完整 request body，并把
/// `String[]`、`Object[]` 与 attachments 写成 Java provider 可识别的 wire 类型。
///
/// 参数说明：
/// - `invocation`：包含 route 固定 locator、资源预算和已通过参数个数门的 JSON 值。
///
/// 返回：编码结果不超过 request frame 上限时返回 body；类型不兼容或任何预算越界时返回输入错误。
pub(super) fn encode_request(invocation: HessianInvocation<'_>) -> Result<Vec<u8>, DubboError> {
    let mut encoder = HessianEncoder::new(invocation.max_frame_bytes, invocation.limits);
    encoder.write_string("2.0.2")?;
    encoder.write_string(invocation.interface)?;
    encoder.write_string(invocation.version)?;
    encoder.write_string("$invoke")?;
    encoder.write_string(GENERIC_DESCRIPTOR)?;
    encoder.write_string(invocation.method)?;
    encoder.write_string_array(invocation.parameter_types)?;
    encoder.write_argument_array(invocation.arguments, invocation.parameter_types)?;
    encoder.write_attachments(
        invocation.interface,
        invocation.version,
        invocation.group,
        invocation.attachments,
    )?;
    Ok(encoder.finish())
}

/// 业务作用：解析 Hessian2 response type、业务值与可选 attachments，在输出 HTTP JSON 前
/// 执行深度、collection、字符串、binary、引用环和最终 JSON 字节上限复验。
///
/// 参数说明：
/// - `body`：是已通过 Dubbo frame 上限的完整正文
/// - `limits`：是 route 固定的 Hessian2 预算
/// - `max_output_bytes`：同时限制转换后的 HTTP JSON 大小。
///
/// 返回：正常值或 null 返回 `DubboResult`，provider exception 返回 `RemoteException`，畸形或
/// 超限 wire 返回协议错误。
pub(super) fn decode_response(
    body: Bytes,
    limits: HessianLimits,
    max_output_bytes: usize,
) -> Result<DubboResult, DubboError> {
    let mut decoder = HessianDecoder::new(body.as_ref(), limits);
    let response_type = decoder.read_required_int()?;
    let result = match response_type {
        0 => {
            decoder.discard_remote_exception()?;
            Err(DubboError::RemoteException)
        }
        1 => {
            let value = decoder.read_value(0)?;
            let value = decoder.render_json(&value)?;
            encode_json_response(value, max_output_bytes)
        }
        2 => Ok(DubboResult::Null),
        3 => {
            decoder.discard_remote_exception()?;
            Err(DubboError::RemoteException)
        }
        4 => {
            let value = decoder.read_value(0)?;
            decoder.read_value(0)?;
            let value = decoder.render_json(&value)?;
            encode_json_response(value, max_output_bytes)
        }
        5 => {
            decoder.read_value(0)?;
            Ok(DubboResult::Null)
        }
        _ => Err(DubboError::Protocol("unknown Dubbo Hessian2 response type")),
    };
    decoder.finish()?;
    result
}

/// 业务作用：把已安全降级为 `serde_json::Value` 的 Hessian2 返回值编码为下游 JSON，并用
/// 独立 writer 上限阻止 binary Base64 或引用展开造成响应膨胀。
///
/// 参数说明：
/// - `value`：是无 class 实例化的 JSON 值
/// - `max_output_bytes`：是允许的最终正文上限。
///
/// 返回：预算内返回 HTTP JSON bytes；编码膨胀或异常返回协议错误。
fn encode_json_response(value: Value, max_output_bytes: usize) -> Result<DubboResult, DubboError> {
    let mut writer = BoundedWriter::new(max_output_bytes);
    serde_json::to_writer(&mut writer, &value)
        .map_err(|_| DubboError::Protocol("Dubbo Hessian2 response JSON exceeds limit"))?;
    Ok(DubboResult::Value(Bytes::from(writer.finish())))
}

struct HessianEncoder {
    writer: BoundedWriter,
    limits: HessianLimits,
    collection_items: usize,
}

impl HessianEncoder {
    /// 业务作用：创建共享 frame 与结构预算的 Hessian2 encoder，所有后续字段写入都经过同一
    /// 组硬门而不是各自分配无界缓冲。
    ///
    /// 参数说明：
    /// - `max_frame_bytes`：限制最终 wire body
    /// - `limits`：限制递归结构与单值大小。
    ///
    /// 返回：返回空 encoder，初始 collection 消耗为零。
    fn new(max_frame_bytes: usize, limits: HessianLimits) -> Self {
        Self {
            writer: BoundedWriter::new(max_frame_bytes),
            limits,
            collection_items: 0,
        }
    }

    /// 业务作用：仅在整次编码成功后移交 request body，防止半完成 Hessian2 值进入发送路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回长度不超过 frame 上限的完整 wire bytes。
    fn finish(self) -> Vec<u8> {
        self.writer.finish()
    }

    /// 业务作用：编码泛化签名要求的 Java `String[]`，显式写入 `[string` type，避免 provider
    /// 把普通 JSON list 误解为不兼容的 collection。
    ///
    /// 参数说明：
    /// - `values`：是 route 固定的 Java 参数类型名数组。
    ///
    /// 返回：类型与元素完整写入时成功；collection、字符串或 frame 越界时失败。
    fn write_string_array(&mut self, values: &[String]) -> Result<(), DubboError> {
        self.consume_items(values.len())?;
        self.write_typed_list_header(values.len(), "[string")?;
        for value in values {
            self.write_string(value)?;
        }
        Ok(())
    }

    /// 业务作用：编码泛化签名要求的 Java `Object[]`，并只对 route 明确声明为 `byte[]` 的
    /// 顶层参数接受标准 Base64，从而避免把普通字符串含糊转换为 binary。
    ///
    /// 参数说明：
    /// - `values`：是不可信 JSON 参数
    /// - `parameter_types`：是 route 固定 Java 类型。
    ///
    /// 返回：所有参数均可安全表达且预算内时成功，否则返回输入错误。
    fn write_argument_array(
        &mut self,
        values: &[Value],
        parameter_types: &[String],
    ) -> Result<(), DubboError> {
        self.consume_items(values.len())?;
        self.write_typed_list_header(values.len(), "[object")?;
        for (value, parameter_type) in values.iter().zip(parameter_types) {
            if is_binary_parameter(parameter_type) {
                let encoded = value.as_str().ok_or(DubboError::InvalidInput(
                    "Dubbo Hessian2 byte[] argument must be a Base64 string",
                ))?;
                let bytes = BASE64_STANDARD.decode(encoded).map_err(|_| {
                    DubboError::InvalidInput(
                        "Dubbo Hessian2 byte[] argument is not standard Base64",
                    )
                })?;
                self.write_binary(&bytes)?;
            } else {
                self.write_json_value(value, 0)?;
            }
        }
        Ok(())
    }

    /// 业务作用：写入 route 固定的 Dubbo attachments，并强制 `generic=true` 与 locator 字段
    /// 由可信配置产生，公网 JSON 不能覆盖控制面语义。
    ///
    /// 参数说明：
    /// - `interface`：均来自已验证 route 配置。
    /// - `version`：均来自已验证 route 配置。
    /// - `group`：均来自已验证 route 配置。
    /// - `custom`：均来自已验证 route 配置。
    ///
    /// 返回：非空 attachment 在 collection、字符串与 frame 预算内完整写入时成功。
    fn write_attachments(
        &mut self,
        interface: &str,
        version: &str,
        group: &str,
        custom: &[(Arc<str>, Arc<str>)],
    ) -> Result<(), DubboError> {
        let standard = [
            ("path", interface),
            ("interface", interface),
            ("version", version),
            ("group", group),
            ("generic", "true"),
        ];
        let item_count = standard
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .count()
            + custom.iter().filter(|(_, value)| !value.is_empty()).count();
        self.consume_items(item_count)?;
        self.write_byte(0x48)?;
        for (name, value) in standard.into_iter().chain(
            custom
                .iter()
                .map(|(name, value)| (name.as_ref(), value.as_ref())),
        ) {
            if value.is_empty() {
                continue;
            }
            self.write_string(name)?;
            self.write_string(value)?;
        }
        self.write_byte(0x5a)
    }

    /// 业务作用：把 JSON 值映射为 Hessian2 安全子集，不生成 class definition、任意 type name
    /// 或 value reference，保证客户端只能表达数据而不能选择 Java 实例化路径。
    ///
    /// 参数说明：
    /// - `value`：是当前 JSON 节点
    /// - `depth`：是其 collection/object 递归深度。
    ///
    /// 返回：值在深度、collection、字符串、binary 与 frame 门内时写入成功，否则返回输入错误。
    fn write_json_value(&mut self, value: &Value, depth: usize) -> Result<(), DubboError> {
        if depth > self.limits.max_depth {
            return Err(DubboError::InvalidInput(
                "Dubbo Hessian2 argument exceeds max_hessian_depth",
            ));
        }
        match value {
            Value::Null => self.write_byte(0x4e),
            Value::Bool(true) => self.write_byte(0x54),
            Value::Bool(false) => self.write_byte(0x46),
            Value::Number(number) => self.write_number(number),
            Value::String(value) => self.write_string(value),
            Value::Array(values) => {
                self.consume_items(values.len())?;
                self.write_untyped_list_header(values.len())?;
                for value in values {
                    self.write_json_value(value, depth + 1)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                self.consume_items(values.len())?;
                self.write_byte(0x48)?;
                for (name, value) in values {
                    self.write_string(name)?;
                    self.write_json_value(value, depth + 1)?;
                }
                self.write_byte(0x5a)
            }
        }
    }

    /// 业务作用：按数值实际范围选择 Hessian2 int、long 或 double，拒绝超出有符号 64 位的
    /// JSON unsigned integer，避免静默截断改变业务参数。
    ///
    /// 参数说明：
    /// - `number`：是 serde 已验证的 JSON number。
    ///
    /// 返回：可无损表示时写入成功；超出 Hessian2 数值范围时返回输入错误。
    fn write_number(&mut self, number: &Number) -> Result<(), DubboError> {
        if let Some(value) = number.as_i64() {
            if let Ok(value) = i32::try_from(value) {
                return self.write_int(value);
            }
            return self.write_long(value);
        }
        if let Some(value) = number.as_u64() {
            let value = i64::try_from(value).map_err(|_| {
                DubboError::InvalidInput("Dubbo Hessian2 integer exceeds signed 64-bit range")
            })?;
            return self.write_long(value);
        }
        let value = number
            .as_f64()
            .ok_or(DubboError::InvalidInput("invalid Dubbo Hessian2 number"))?;
        self.write_double(value)
    }

    /// 业务作用：写入 Hessian2 compact int，保持与 Java Hessian2Output 的范围编码一致。
    ///
    /// 参数说明：
    /// - `value`：是有符号 32 位整数。
    ///
    /// 返回：完整写入 compact 或 full int 时成功；frame 越界时失败。
    fn write_int(&mut self, value: i32) -> Result<(), DubboError> {
        if (-16..=47).contains(&value) {
            self.write_byte((value + 0x90) as u8)
        } else if (-2048..=2047).contains(&value) {
            self.write_bytes(&[(0xc8 + (value >> 8)) as u8, value as u8])
        } else if (-262_144..=262_143).contains(&value) {
            self.write_bytes(&[
                (0xd4 + (value >> 16)) as u8,
                (value >> 8) as u8,
                value as u8,
            ])
        } else {
            self.write_byte(0x49)?;
            self.write_bytes(&value.to_be_bytes())
        }
    }

    /// 业务作用：写入 Hessian2 compact long，覆盖 Java long 泛化参数且不缩窄为 32 位。
    ///
    /// 参数说明：
    /// - `value`：是有符号 64 位整数。
    ///
    /// 返回：完整写入 compact 或 full long 时成功；frame 越界时失败。
    fn write_long(&mut self, value: i64) -> Result<(), DubboError> {
        if (-8..=15).contains(&value) {
            self.write_byte((value + 0xe0) as u8)
        } else if (-2048..=2047).contains(&value) {
            self.write_bytes(&[(0xf8 + (value >> 8)) as u8, value as u8])
        } else if (-262_144..=262_143).contains(&value) {
            self.write_bytes(&[
                (0x3c + (value >> 16)) as u8,
                (value >> 8) as u8,
                value as u8,
            ])
        } else if let Ok(value) = i32::try_from(value) {
            self.write_byte(0x59)?;
            self.write_bytes(&value.to_be_bytes())
        } else {
            self.write_byte(0x4c)?;
            self.write_bytes(&value.to_be_bytes())
        }
    }

    /// 业务作用：以 Hessian2 64-bit double 写入 JSON 浮点数，保留精度并避免实现相关的压缩
    /// 取整改变值。
    ///
    /// 参数说明：
    /// - `value`：是 JSON parser 接受的有限双精度值。
    ///
    /// 返回：完整写入 IEEE-754 bytes 时成功；frame 越界时失败。
    fn write_double(&mut self, value: f64) -> Result<(), DubboError> {
        self.write_byte(0x44)?;
        self.write_bytes(&value.to_bits().to_be_bytes())
    }

    /// 业务作用：按 Hessian2 UTF-16 code-unit 长度编码字符串，并使用 Java Hessian 实现的
    /// 单 `char` 1/2/3-byte wire 形式，确保 surrogate pair 不会被错误写成标准 UTF-8 4-byte scalar。
    ///
    /// 参数说明：
    /// - `value`：是待编码 UTF-8 文本。
    ///
    /// 返回：单值字符串与 frame 均不超限时成功，否则返回输入错误。
    fn write_string(&mut self, value: &str) -> Result<(), DubboError> {
        if value.len() > self.limits.max_string_bytes {
            return Err(DubboError::InvalidInput(
                "Dubbo Hessian2 string exceeds max_hessian_string_bytes",
            ));
        }
        if value.is_empty() {
            return self.write_byte(0x00);
        }
        let mut start = 0;
        while start < value.len() {
            let mut units = 0;
            let mut end = start;
            for (offset, character) in value[start..].char_indices() {
                let next_units = units + character.len_utf16();
                if next_units > MAX_STRING_CHUNK_UNITS && units != 0 {
                    break;
                }
                units = next_units;
                end = start + offset + character.len_utf8();
                if units == MAX_STRING_CHUNK_UNITS {
                    break;
                }
            }
            let final_chunk = end == value.len();
            self.write_string_header(units, final_chunk)?;
            self.write_hessian_utf16(&value[start..end])?;
            start = end;
        }
        Ok(())
    }

    /// 业务作用：把 Rust Unicode scalar 展开为 Java UTF-16 code units，并逐个使用 Hessian2
    /// 兼容的 1/2/3-byte 形式写入；非 BMP scalar 因而成为两个 3-byte surrogate 序列。
    ///
    /// 参数说明：
    /// - `value`：是已经按 Unicode scalar 边界切分的当前 string chunk。
    ///
    /// 返回：全部 UTF-16 units 写入 frame 时成功；frame 预算不足时返回输入错误。
    fn write_hessian_utf16(&mut self, value: &str) -> Result<(), DubboError> {
        for unit in value.encode_utf16() {
            if unit < 0x80 {
                self.write_byte(unit as u8)?;
            } else if unit < 0x800 {
                self.write_bytes(&[0xc0 | (unit >> 6) as u8, 0x80 | (unit & 0x3f) as u8])?;
            } else {
                self.write_bytes(&[
                    0xe0 | (unit >> 12) as u8,
                    0x80 | ((unit >> 6) & 0x3f) as u8,
                    0x80 | (unit & 0x3f) as u8,
                ])?;
            }
        }
        Ok(())
    }

    /// 业务作用：为一个已分好 Unicode 边界的字符串 chunk 写入 compact 或标准 header，保证
    /// 长度字段使用 UTF-16 code units 而不是 UTF-8 bytes。
    ///
    /// 参数说明：
    /// - `units`：是当前 chunk 的 UTF-16 单元数
    /// - `final_chunk`：标识是否结束该字符串。
    ///
    /// 返回：header 在协议范围且 frame 有容量时成功，否则返回输入错误。
    fn write_string_header(&mut self, units: usize, final_chunk: bool) -> Result<(), DubboError> {
        let units = u16::try_from(units).map_err(|_| {
            DubboError::InvalidInput("Dubbo Hessian2 string chunk exceeds protocol limit")
        })?;
        if !final_chunk {
            self.write_byte(0x52)?;
            return self.write_bytes(&units.to_be_bytes());
        }
        if units <= 31 {
            self.write_byte(units as u8)
        } else if units <= 1023 {
            self.write_bytes(&[0x30 + (units >> 8) as u8, units as u8])
        } else {
            self.write_byte(0x53)?;
            self.write_bytes(&units.to_be_bytes())
        }
    }

    /// 业务作用：把显式 `byte[]` 参数编码为 Hessian2 binary chunks，并独立限制解码后的真实
    /// binary 大小而非 Base64 文本长度。
    ///
    /// 参数说明：
    /// - `bytes`：是已从标准 Base64 严格解码的数据。
    ///
    /// 返回：binary 与 frame 均不超限时成功，否则返回输入错误。
    fn write_binary(&mut self, bytes: &[u8]) -> Result<(), DubboError> {
        if bytes.len() > self.limits.max_binary_bytes {
            return Err(DubboError::InvalidInput(
                "Dubbo Hessian2 binary exceeds max_hessian_binary_bytes",
            ));
        }
        if bytes.is_empty() {
            return self.write_byte(0x20);
        }
        let mut offset = 0;
        while bytes.len() - offset > MAX_BINARY_CHUNK_BYTES {
            let length = MAX_BINARY_CHUNK_BYTES;
            self.write_byte(0x41)?;
            self.write_bytes(&(length as u16).to_be_bytes())?;
            self.write_bytes(&bytes[offset..offset + length])?;
            offset += length;
        }
        let remaining = bytes.len() - offset;
        if remaining <= 15 {
            self.write_byte(0x20 + remaining as u8)?;
        } else if remaining <= 1023 {
            self.write_bytes(&[0x34 + (remaining >> 8) as u8, remaining as u8])?;
        } else {
            self.write_byte(0x42)?;
            self.write_bytes(&(remaining as u16).to_be_bytes())?;
        }
        self.write_bytes(&bytes[offset..])
    }

    /// 业务作用：写入固定长度 typed list header；泛化调用只在协议要求的数组容器使用 type，
    /// 不允许公网输入指定任意 Java type name。
    ///
    /// 参数说明：
    /// - `length`：是元素数
    /// - `list_type`：是编译期固定的 `[string` 或 `[object`。
    ///
    /// 返回：长度可由 Hessian2 int 表示且 header 写入成功时返回成功。
    fn write_typed_list_header(
        &mut self,
        length: usize,
        list_type: &str,
    ) -> Result<(), DubboError> {
        if length <= 7 {
            self.write_byte(0x70 + length as u8)?;
            return self.write_string(list_type);
        }
        let length = i32::try_from(length).map_err(|_| {
            DubboError::InvalidInput("Dubbo Hessian2 list length exceeds protocol limit")
        })?;
        self.write_byte(0x56)?;
        self.write_string(list_type)?;
        self.write_int(length)
    }

    /// 业务作用：把普通 JSON array 写成固定长度 untyped Hessian2 list，防止客户端借 type name
    /// 触发 provider class 选择。
    ///
    /// 参数说明：
    /// - `length`：是 JSON array 元素数。
    ///
    /// 返回：长度可由 Hessian2 int 表示且 header 写入成功时返回成功。
    fn write_untyped_list_header(&mut self, length: usize) -> Result<(), DubboError> {
        if length <= 7 {
            return self.write_byte(0x78 + length as u8);
        }
        let length = i32::try_from(length).map_err(|_| {
            DubboError::InvalidInput("Dubbo Hessian2 list length exceeds protocol limit")
        })?;
        self.write_byte(0x58)?;
        self.write_int(length)
    }

    /// 业务作用：累计整帧 collection/object 元素消耗，在开始写入结构前拒绝超限，避免大量
    /// 小容器绕过单容器上限。
    ///
    /// 参数说明：
    /// - `count`：是当前容器新增的元素或字段数。
    ///
    /// 返回：累计值不溢出且不超过 route 总预算时成功，否则返回输入错误。
    fn consume_items(&mut self, count: usize) -> Result<(), DubboError> {
        self.collection_items =
            self.collection_items
                .checked_add(count)
                .ok_or(DubboError::InvalidInput(
                    "Dubbo Hessian2 collection item count overflow",
                ))?;
        if self.collection_items > self.limits.max_collection_items {
            return Err(DubboError::InvalidInput(
                "Dubbo Hessian2 arguments exceed max_hessian_collection_items",
            ));
        }
        Ok(())
    }

    /// 业务作用：向有界 frame writer 写入单字节 wire tag，并统一容量错误语义。
    ///
    /// 参数说明：
    /// - `byte`：是 Hessian2 tag 或长度片段。
    ///
    /// 返回：写入成功时返回成功；frame 上限不足时返回输入过大错误。
    fn write_byte(&mut self, byte: u8) -> Result<(), DubboError> {
        self.write_bytes(&[byte])
    }

    /// 业务作用：向有界 frame writer 追加 wire 片段，任何容量错误都在发送前收敛为输入错误。
    ///
    /// 参数说明：
    /// - `bytes`：是已编码的 Hessian2 片段。
    ///
    /// 返回：完整追加时成功；frame 总上限不足时失败且不会产生网络副作用。
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), DubboError> {
        std::io::Write::write_all(&mut self.writer, bytes)
            .map_err(|_| DubboError::InvalidInput("Dubbo request frame is too large"))
    }
}

/// 业务作用：识别 route 明确声明的 Java byte array 类型；只有该类型会把顶层 JSON 字符串
/// 解释为 Base64 binary，其他字符串始终保持文本语义。
///
/// 参数说明：
/// - `parameter_type`：是 route 固定 Java 参数类型名。
///
/// 返回：`byte[]` 或 JVM descriptor `[B` 返回 true，其余返回 false。
fn is_binary_parameter(parameter_type: &str) -> bool {
    matches!(parameter_type, "byte[]" | "[B")
}

#[derive(Clone)]
enum WireValue {
    Null,
    Bool(bool),
    Integer(i64),
    Double(f64),
    String(String),
    Binary(Vec<u8>),
    Date(i64),
    Container(usize),
}

enum WireContainer {
    Pending,
    List(Vec<WireValue>),
    Map(Vec<(WireValue, WireValue)>),
    Object(Vec<(String, WireValue)>),
}

struct ClassDefinition {
    fields: Vec<String>,
}

struct HessianDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: HessianLimits,
    collection_items: usize,
    class_definitions: Vec<ClassDefinition>,
    type_references: Vec<String>,
    value_references: Vec<WireContainer>,
}

impl<'a> HessianDecoder<'a> {
    /// 业务作用：创建只读有界 Hessian2 decoder；远端 bytes 不会被解释为可执行类型或映射到
    /// 本地 class，只进入显式 wire 状态机。
    ///
    /// 参数说明：
    /// - `bytes`：是完整 response frame body
    /// - `limits`：是 route 固定资源预算。
    ///
    /// 返回：返回初始 offset 与引用表为空的 decoder。
    fn new(bytes: &'a [u8], limits: HessianLimits) -> Self {
        Self {
            bytes,
            offset: 0,
            limits,
            collection_items: 0,
            class_definitions: Vec::new(),
            type_references: Vec::new(),
            value_references: Vec::new(),
        }
    }

    /// 业务作用：复验 response body 已被当前 response type 完整消费，拒绝尾随值造成的协议
    /// 歧义或连接复用错位。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：offset 恰好到达 frame 末尾时成功，否则返回协议错误。
    fn finish(&self) -> Result<(), DubboError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DubboError::Protocol(
                "Dubbo Hessian2 response has trailing bytes",
            ))
        }
    }

    /// 业务作用：把 provider exception 正文作为不可信 opaque payload 消费，不尝试重建
    /// `Throwable`、stack trace 或任意 Java class graph；frame 长度已由外层总预算约束。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：response type 后至少存在一个异常值字节时成功并移动到 frame 末尾；空正文返回
    /// 协议错误，避免把截断响应伪装成正常远端异常。
    fn discard_remote_exception(&mut self) -> Result<(), DubboError> {
        if self.offset == self.bytes.len() {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 remote exception body is empty",
            ));
        }
        // 异常内容不会下发给客户端，跳过已受总 frame 门约束的剩余 bytes，可避免解析官方
        // Throwable 的复杂 class/reference graph，也不会影响下一帧边界或连接复用。
        self.offset = self.bytes.len();
        Ok(())
    }

    /// 业务作用：读取 Dubbo response type 等必须为 Hessian2 int 的控制字段，拒绝类型混淆。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法 compact/full int 返回 i32；其他 tag 或截断返回协议错误。
    fn read_required_int(&mut self) -> Result<i32, DubboError> {
        let tag = self.read_byte()?;
        self.read_int_from_tag(tag)
    }

    /// 业务作用：递归解析一个 Hessian2 value 到不可执行的 wire graph，并在进入每层容器前
    /// 执行深度门。
    ///
    /// 参数说明：
    /// - `depth`：是当前 collection/object 的递归深度。
    ///
    /// 返回：受限 wire 值成功返回；未知 tag、截断、越界或非法引用返回协议错误。
    fn read_value(&mut self, depth: usize) -> Result<WireValue, DubboError> {
        if depth > self.limits.max_depth {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 value exceeds max_hessian_depth",
            ));
        }
        let tag = self.read_byte()?;
        match tag {
            0x4e => Ok(WireValue::Null),
            0x46 => Ok(WireValue::Bool(false)),
            0x54 => Ok(WireValue::Bool(true)),
            0x44 => self.read_double64().map(WireValue::Double),
            0x5b => Ok(WireValue::Double(0.0)),
            0x5c => Ok(WireValue::Double(1.0)),
            0x5d => self.read_i8().map(|value| WireValue::Double(value as f64)),
            0x5e => self.read_i16().map(|value| WireValue::Double(value as f64)),
            0x5f => self
                .read_i32()
                .map(|value| WireValue::Double(value as f64 / 1000.0)),
            0x4a => self.read_i64().map(WireValue::Date),
            0x4b => self
                .read_i32()
                .map(|minutes| WireValue::Date(i64::from(minutes) * 60_000)),
            0x00..=0x1f | 0x30..=0x33 | 0x52 | 0x53 => {
                self.read_string_from_tag(tag).map(WireValue::String)
            }
            0x20..=0x2f | 0x34..=0x37 | 0x41 | 0x42 => {
                self.read_binary_from_tag(tag).map(WireValue::Binary)
            }
            0x43 => {
                self.read_class_definition()?;
                self.read_value(depth)
            }
            0x48 => self.read_map(depth, false),
            0x4d => self.read_map(depth, true),
            0x55 => self.read_variable_list(depth, true),
            0x56 => self.read_fixed_list(depth, true),
            0x57 => self.read_variable_list(depth, false),
            0x58 => self.read_fixed_list(depth, false),
            0x60..=0x6f => self.read_object(depth, usize::from(tag - 0x60)),
            0x70..=0x77 => self.read_direct_list(depth, usize::from(tag - 0x70), true),
            0x78..=0x7f => self.read_direct_list(depth, usize::from(tag - 0x78), false),
            0x4f => {
                let class_ref = self.read_required_int()?;
                let class_ref = usize::try_from(class_ref).map_err(|_| {
                    DubboError::Protocol("Dubbo Hessian2 object has negative class reference")
                })?;
                self.read_object(depth, class_ref)
            }
            0x51 => self.read_reference(),
            0x49 | 0x80..=0xd7 => self
                .read_int_from_tag(tag)
                .map(|value| WireValue::Integer(i64::from(value))),
            0x38..=0x3f | 0x4c | 0x59 | 0xd8..=0xff => {
                self.read_long_from_tag(tag).map(WireValue::Integer)
            }
            _ => Err(DubboError::Protocol("unknown Dubbo Hessian2 value tag")),
        }
    }

    /// 业务作用：解析 typed/untyped variable list，并用显式 `Z` 终止门与累计 item 上限阻止
    /// 无界 element 扫描。
    ///
    /// 参数说明：
    /// - `depth`：是当前容器深度
    /// - `typed`：标识是否先消费 Hessian type。
    ///
    /// 返回：完整 list 返回其引用节点；缺少终止符、超限或子值错误返回协议错误。
    fn read_variable_list(&mut self, depth: usize, typed: bool) -> Result<WireValue, DubboError> {
        if typed {
            self.read_type()?;
        }
        let reference = self.reserve_container()?;
        let mut values = Vec::new();
        while self.peek_byte()? != 0x5a {
            self.consume_items(1)?;
            values.push(self.read_value(depth + 1)?);
        }
        self.read_byte()?;
        self.value_references[reference] = WireContainer::List(values);
        Ok(WireValue::Container(reference))
    }

    /// 业务作用：解析 typed/untyped fixed list，先验证声明长度再分配，避免恶意长度触发超量
    /// reservation 或读越 frame。
    ///
    /// 参数说明：
    /// - `depth`：是当前容器深度
    /// - `typed`：标识是否先消费 Hessian type。
    ///
    /// 返回：声明数量的元素全部合法时返回引用节点，否则返回协议错误。
    fn read_fixed_list(&mut self, depth: usize, typed: bool) -> Result<WireValue, DubboError> {
        if typed {
            self.read_type()?;
        }
        let length = self.read_required_int()?;
        let length = usize::try_from(length)
            .map_err(|_| DubboError::Protocol("Dubbo Hessian2 list has negative length"))?;
        self.read_list_values(depth, length)
    }

    /// 业务作用：解析 compact fixed list；即使长度来自 tag 也复用同一累计 collection 门。
    ///
    /// 参数说明：
    /// - `depth`：是当前容器深度
    /// - `length`：来自 direct tag
    /// - `typed`：标识是否消费 type。
    ///
    /// 返回：全部元素合法时返回引用节点，否则返回协议错误。
    fn read_direct_list(
        &mut self,
        depth: usize,
        length: usize,
        typed: bool,
    ) -> Result<WireValue, DubboError> {
        if typed {
            self.read_type()?;
        }
        self.read_list_values(depth, length)
    }

    /// 业务作用：按已验证长度读取 fixed list 内容，并在分配 Vec 前扣减整帧 collection 预算。
    ///
    /// 参数说明：
    /// - `depth`：是当前容器深度
    /// - `length`：是已转换为 usize 的元素数。
    ///
    /// 返回：返回可被后续 ref 使用的 list 节点；任一子值失败则整帧失败。
    fn read_list_values(&mut self, depth: usize, length: usize) -> Result<WireValue, DubboError> {
        self.consume_items(length)?;
        let reference = self.reserve_container()?;
        let mut values = Vec::with_capacity(length.min(4096));
        for _ in 0..length {
            values.push(self.read_value(depth + 1)?);
        }
        self.value_references[reference] = WireContainer::List(values);
        Ok(WireValue::Container(reference))
    }

    /// 业务作用：解析 typed/untyped map，将 key/value 保留为 wire 值而不实例化远端 type，且
    /// 每个 entry 都计入整帧 collection 预算。
    ///
    /// 参数说明：
    /// - `depth`：是当前容器深度
    /// - `typed`：标识是否先消费并记录 Hessian type。
    ///
    /// 返回：遇到 `Z` 且所有 entry 合法时返回 map 节点，否则返回协议错误。
    fn read_map(&mut self, depth: usize, typed: bool) -> Result<WireValue, DubboError> {
        if typed {
            self.read_type()?;
        }
        let reference = self.reserve_container()?;
        let mut entries = Vec::new();
        while self.peek_byte()? != 0x5a {
            self.consume_items(1)?;
            let key = self.read_value(depth + 1)?;
            let value = self.read_value(depth + 1)?;
            entries.push((key, value));
        }
        self.read_byte()?;
        self.value_references[reference] = WireContainer::Map(entries);
        Ok(WireValue::Container(reference))
    }

    /// 业务作用：解析 class definition 的字段布局并限制 definition 数量；type name 只作为
    /// wire 元数据消费，绝不触发本地 class lookup。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：definition 合法并进入有界 class 表时成功，否则返回协议错误。
    fn read_class_definition(&mut self) -> Result<(), DubboError> {
        if self.class_definitions.len() >= MAX_CLASS_DEFINITIONS {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 response has too many class definitions",
            ));
        }
        self.read_string()?;
        let field_count = self.read_required_int()?;
        let field_count = usize::try_from(field_count)
            .map_err(|_| DubboError::Protocol("Dubbo Hessian2 class has negative field count"))?;
        self.consume_items(field_count)?;
        let mut fields = Vec::with_capacity(field_count.min(256));
        for _ in 0..field_count {
            fields.push(self.read_string()?);
        }
        self.class_definitions.push(ClassDefinition {
            fields,
        });
        Ok(())
    }

    /// 业务作用：依据已收录 class definition 解析 object 字段到普通 map 形态，不保留可执行
    /// Java type 行为，并把 object 在读取字段前登记以正确识别循环引用。
    ///
    /// 参数说明：
    /// - `depth`：是当前对象深度
    /// - `class_reference`：是 wire 中零起点 definition id。
    ///
    /// 返回：字段完整时返回 object 引用节点；未知 class、超限或子值错误返回协议错误。
    fn read_object(
        &mut self,
        depth: usize,
        class_reference: usize,
    ) -> Result<WireValue, DubboError> {
        let fields = self
            .class_definitions
            .get(class_reference)
            .ok_or(DubboError::Protocol(
                "Dubbo Hessian2 object references unknown class",
            ))?
            .fields
            .clone();
        self.consume_items(fields.len())?;
        let reference = self.reserve_container()?;
        let mut values = Vec::with_capacity(fields.len());
        for field in fields {
            values.push((field, self.read_value(depth + 1)?));
        }
        self.value_references[reference] = WireContainer::Object(values);
        Ok(WireValue::Container(reference))
    }

    /// 业务作用：解析 Hessian value reference，只允许指向已登记的 map/list/object；循环或
    /// 共享引用在 wire graph 中保留，稍后 JSON 渲染会执行环检测与展开预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：引用 id 有效时返回容器节点，否则返回协议错误。
    fn read_reference(&mut self) -> Result<WireValue, DubboError> {
        let reference = self.read_required_int()?;
        let reference = usize::try_from(reference)
            .map_err(|_| DubboError::Protocol("Dubbo Hessian2 reference is negative"))?;
        if reference >= self.value_references.len() {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 reference is out of range",
            ));
        }
        Ok(WireValue::Container(reference))
    }

    /// 业务作用：为刚遇到的 map/list/object 预留引用槽，既支持识别自引用，又以固定硬上限
    /// 防止引用表独立于 collection 预算增长。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：容量内返回新引用 id；超过硬上限返回协议错误。
    fn reserve_container(&mut self) -> Result<usize, DubboError> {
        if self.value_references.len() >= MAX_VALUE_REFERENCES {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 response has too many value references",
            ));
        }
        let reference = self.value_references.len();
        self.value_references.push(WireContainer::Pending);
        Ok(reference)
    }

    /// 业务作用：读取 list/map type 字符串或 type reference，仅维护有界名称表供后续 wire
    /// 解析使用，不依据名称改变实例化行为。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法 type 返回其文本；负引用、未知引用或错误 tag 返回协议错误。
    fn read_type(&mut self) -> Result<String, DubboError> {
        let tag = self.read_byte()?;
        if is_int_tag(tag) {
            let reference = self.read_int_from_tag(tag)?;
            let reference = usize::try_from(reference)
                .map_err(|_| DubboError::Protocol("Dubbo Hessian2 type reference is negative"))?;
            return self
                .type_references
                .get(reference)
                .cloned()
                .ok_or(DubboError::Protocol(
                    "Dubbo Hessian2 type reference is out of range",
                ));
        }
        let value = self.read_string_from_tag(tag)?;
        if self.type_references.len() >= MAX_CLASS_DEFINITIONS {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 response has too many type references",
            ));
        }
        self.type_references.push(value.clone());
        Ok(value)
    }

    /// 业务作用：读取一个必须为 Hessian string 的字段，复用 UTF-16 unit、surrogate 配对与
    /// 单字符串预算检查。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法字符串返回 owned 文本；其他 tag 或畸形编码返回协议错误。
    fn read_string(&mut self) -> Result<String, DubboError> {
        let tag = self.read_byte()?;
        self.read_string_from_tag(tag)
    }

    /// 业务作用：从已消费首 tag 开始读取完整 chunked Hessian string，按 Java UTF-16
    /// code-unit 计数验证每段，并在转为 Rust UTF-8 后执行单值硬门。
    ///
    /// 参数说明：
    /// - `tag`：是当前字符串首 chunk tag。
    ///
    /// 返回：所有 chunks 合法且以 final chunk 结束时返回字符串，否则返回协议错误。
    fn read_string_from_tag(&mut self, mut tag: u8) -> Result<String, DubboError> {
        let mut utf16 = Vec::new();
        loop {
            let (units, final_chunk) = match tag {
                0x00..=0x1f => (usize::from(tag), true),
                0x30..=0x33 => (
                    (usize::from(tag - 0x30) << 8) | usize::from(self.read_byte()?),
                    true,
                ),
                0x52 => (usize::from(self.read_u16()?), false),
                0x53 => (usize::from(self.read_u16()?), true),
                _ => return Err(DubboError::Protocol("Dubbo Hessian2 value is not a string")),
            };
            self.read_utf16_units(units, &mut utf16)?;
            // 每个合法 UTF-16 unit 转为 UTF-8 后至少占一字节；先用 unit 数门限制临时 Vec，
            // 再在完整 surrogate 配对后按真实 UTF-8 字节数复验。
            if utf16.len() > self.limits.max_string_bytes {
                return Err(DubboError::Protocol(
                    "Dubbo Hessian2 string exceeds max_hessian_string_bytes",
                ));
            }
            if final_chunk {
                break;
            }
            tag = self.read_byte()?;
        }
        let output = String::from_utf16(&utf16).map_err(|_| {
            DubboError::Protocol("Dubbo Hessian2 string has invalid UTF-16 surrogates")
        })?;
        if output.len() > self.limits.max_string_bytes {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 string exceeds max_hessian_string_bytes",
            ));
        }
        Ok(output)
    }

    /// 业务作用：按声明数量读取 Java Hessian2 的单 UTF-16-unit 1/2/3-byte 编码，拒绝
    /// overlong、4-byte scalar、截断或非法 continuation；surrogate 配对由完整字符串统一复验。
    ///
    /// 参数说明：
    /// - `units`：是 chunk 声明长度
    /// - `output`：累积当前完整字符串的 UTF-16 units。
    ///
    /// 返回：恰好读取指定 UTF-16 单元数时成功，否则返回协议错误。
    fn read_utf16_units(&mut self, units: usize, output: &mut Vec<u16>) -> Result<(), DubboError> {
        for _ in 0..units {
            let first = self.read_byte()?;
            let unit = match first {
                0x00..=0x7f => u16::from(first),
                0xc2..=0xdf => {
                    let second = self.read_hessian_utf8_continuation()?;
                    (u16::from(first & 0x1f) << 6) | u16::from(second & 0x3f)
                }
                0xe0..=0xef => {
                    let second = self.read_hessian_utf8_continuation()?;
                    let third = self.read_hessian_utf8_continuation()?;
                    if first == 0xe0 && second < 0xa0 {
                        return Err(DubboError::Protocol(
                            "Dubbo Hessian2 string has overlong UTF-16 encoding",
                        ));
                    }
                    (u16::from(first & 0x0f) << 12)
                        | (u16::from(second & 0x3f) << 6)
                        | u16::from(third & 0x3f)
                }
                _ => {
                    return Err(DubboError::Protocol(
                        "Dubbo Hessian2 string has invalid UTF-16 wire encoding",
                    ))
                }
            };
            output.push(unit);
        }
        Ok(())
    }

    /// 业务作用：读取 Java Hessian2 UTF-16 wire 的 continuation byte，集中拒绝错误前缀，
    /// 避免不同 string 路径接受不一致的畸形编码。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`10xxxxxx` byte 原样返回；截断或其他前缀返回协议错误。
    fn read_hessian_utf8_continuation(&mut self) -> Result<u8, DubboError> {
        let byte = self.read_byte()?;
        if byte & 0xc0 == 0x80 {
            Ok(byte)
        } else {
            Err(DubboError::Protocol(
                "Dubbo Hessian2 string has invalid continuation byte",
            ))
        }
    }

    /// 业务作用：从已消费首 tag 开始读取完整 chunked Hessian binary，并在每次追加前执行
    /// 单 binary 硬上限，防止大对象进入 Base64 渲染。
    ///
    /// 参数说明：
    /// - `tag`：是当前 binary 首 chunk tag。
    ///
    /// 返回：合法 final chunk 结束时返回 bytes；截断、错误 tag 或超限返回协议错误。
    fn read_binary_from_tag(&mut self, mut tag: u8) -> Result<Vec<u8>, DubboError> {
        let mut output = Vec::new();
        loop {
            let (length, final_chunk) = match tag {
                0x20..=0x2f => (usize::from(tag - 0x20), true),
                0x34..=0x37 => (
                    (usize::from(tag - 0x34) << 8) | usize::from(self.read_byte()?),
                    true,
                ),
                0x41 => (usize::from(self.read_u16()?), false),
                0x42 => (usize::from(self.read_u16()?), true),
                _ => return Err(DubboError::Protocol("Dubbo Hessian2 value is not binary")),
            };
            let next_length = output
                .len()
                .checked_add(length)
                .ok_or(DubboError::Protocol(
                    "Dubbo Hessian2 binary length overflow",
                ))?;
            if next_length > self.limits.max_binary_bytes {
                return Err(DubboError::Protocol(
                    "Dubbo Hessian2 binary exceeds max_hessian_binary_bytes",
                ));
            }
            output.extend_from_slice(self.read_slice(length)?);
            if final_chunk {
                break;
            }
            tag = self.read_byte()?;
        }
        Ok(output)
    }

    /// 业务作用：解码 compact/full Hessian int，所有长度与引用控制字段都通过该单一路径避免
    /// 符号扩展差异。
    ///
    /// 参数说明：
    /// - `tag`：是已消费的 int 首 tag。
    ///
    /// 返回：合法 int 返回 i32；非 int tag 或截断返回协议错误。
    fn read_int_from_tag(&mut self, tag: u8) -> Result<i32, DubboError> {
        match tag {
            0x80..=0xbf => Ok(i32::from(tag) - 0x90),
            0xc0..=0xcf => Ok(((i32::from(tag) - 0xc8) << 8) + i32::from(self.read_byte()?)),
            0xd0..=0xd7 => Ok(((i32::from(tag) - 0xd4) << 16)
                + (i32::from(self.read_byte()?) << 8)
                + i32::from(self.read_byte()?)),
            0x49 => self.read_i32(),
            _ => Err(DubboError::Protocol("Dubbo Hessian2 value is not int")),
        }
    }

    /// 业务作用：解码 compact/full Hessian long，并保留有符号范围供 JSON 与业务类型实现使用。
    ///
    /// 参数说明：
    /// - `tag`：是已消费的 long 首 tag。
    ///
    /// 返回：合法 long 返回 i64；非 long tag 或截断返回协议错误。
    fn read_long_from_tag(&mut self, tag: u8) -> Result<i64, DubboError> {
        match tag {
            0xd8..=0xef => Ok(i64::from(tag) - 0xe0),
            0xf0..=0xff => Ok(((i64::from(tag) - 0xf8) << 8) + i64::from(self.read_byte()?)),
            0x38..=0x3f => Ok(((i64::from(tag) - 0x3c) << 16)
                + (i64::from(self.read_byte()?) << 8)
                + i64::from(self.read_byte()?)),
            0x59 => self.read_i32().map(i64::from),
            0x4c => self.read_i64(),
            _ => Err(DubboError::Protocol("Dubbo Hessian2 value is not long")),
        }
    }

    /// 业务作用：把 wire graph 转为 JSON tree，检测循环引用并对共享引用的每次展开重新扣减
    /// item 预算，防止小 frame 通过引用产生指数级输出。
    ///
    /// 参数说明：
    /// - `value`：是已完成 wire 解析的根值。
    ///
    /// 返回：可无歧义表示为 JSON 时返回值；循环、非字符串复杂 map key 或膨胀超限返回协议错误。
    fn render_json(&self, value: &WireValue) -> Result<Value, DubboError> {
        let mut path = Vec::new();
        let mut expanded_items = 0;
        self.render_json_inner(value, 0, &mut path, &mut expanded_items)
    }

    /// 业务作用：执行单个 wire 节点的递归 JSON 渲染，并携带当前引用路径与累计展开预算。
    ///
    /// 参数说明：
    /// - `value`：是当前节点
    /// - `depth`：是渲染深度
    /// - `path`：用于环检测
    /// - `expanded_items`：统计引用展开后的真实 JSON 元素数。
    ///
    /// 返回：节点可安全映射时返回 JSON；环、深度、数值或结构语义不合法时返回协议错误。
    fn render_json_inner(
        &self,
        value: &WireValue,
        depth: usize,
        path: &mut Vec<usize>,
        expanded_items: &mut usize,
    ) -> Result<Value, DubboError> {
        if depth > self.limits.max_depth {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 JSON expansion exceeds max_hessian_depth",
            ));
        }
        match value {
            WireValue::Null => Ok(Value::Null),
            WireValue::Bool(value) => Ok(Value::Bool(*value)),
            WireValue::Integer(value) | WireValue::Date(value) => {
                Ok(Value::Number(Number::from(*value)))
            }
            WireValue::Double(value) => {
                Number::from_f64(*value)
                    .map(Value::Number)
                    .ok_or(DubboError::Protocol(
                        "Dubbo Hessian2 response contains non-finite double",
                    ))
            }
            WireValue::String(value) => Ok(Value::String(value.clone())),
            WireValue::Binary(value) => Ok(Value::String(BASE64_STANDARD.encode(value))),
            WireValue::Container(reference) => {
                if path.contains(reference) {
                    return Err(DubboError::Protocol(
                        "Dubbo Hessian2 cyclic reference cannot be represented as JSON",
                    ));
                }
                let container =
                    self.value_references
                        .get(*reference)
                        .ok_or(DubboError::Protocol(
                            "Dubbo Hessian2 reference is out of range",
                        ))?;
                path.push(*reference);
                let rendered = match container {
                    WireContainer::Pending => Err(DubboError::Protocol(
                        "Dubbo Hessian2 reference targets incomplete value",
                    )),
                    WireContainer::List(values) => {
                        self.consume_rendered_items(expanded_items, values.len())?;
                        let mut output = Vec::with_capacity(values.len());
                        for value in values {
                            output.push(self.render_json_inner(
                                value,
                                depth + 1,
                                path,
                                expanded_items,
                            )?);
                        }
                        Ok(Value::Array(output))
                    }
                    WireContainer::Map(entries) => {
                        self.consume_rendered_items(expanded_items, entries.len())?;
                        let mut output = Map::new();
                        for (key, value) in entries {
                            let key = self.render_map_key(key)?;
                            let value =
                                self.render_json_inner(value, depth + 1, path, expanded_items)?;
                            output.insert(key, value);
                        }
                        Ok(Value::Object(output))
                    }
                    WireContainer::Object(fields) => {
                        self.consume_rendered_items(expanded_items, fields.len())?;
                        let mut output = Map::new();
                        for (name, value) in fields {
                            output.insert(
                                name.clone(),
                                self.render_json_inner(value, depth + 1, path, expanded_items)?,
                            );
                        }
                        Ok(Value::Object(output))
                    }
                };
                path.pop();
                rendered
            }
        }
    }

    /// 业务作用：把 Hessian map primitive key 转为确定的 JSON object key；复杂 key 不做调试
    /// 字符串化，避免碰撞或结构语义丢失。
    ///
    /// 参数说明：
    /// - `key`：是 map 的 wire key。
    ///
    /// 返回：字符串、整数、有限 double、bool、null 或 date 返回稳定文本；其他类型返回协议错误。
    fn render_map_key(&self, key: &WireValue) -> Result<String, DubboError> {
        match key {
            WireValue::String(value) => Ok(value.clone()),
            WireValue::Integer(value) | WireValue::Date(value) => Ok(value.to_string()),
            WireValue::Double(value) if value.is_finite() => Ok(value.to_string()),
            WireValue::Bool(value) => Ok(value.to_string()),
            WireValue::Null => Ok("null".to_owned()),
            _ => Err(DubboError::Protocol(
                "Dubbo Hessian2 map key cannot be represented as JSON",
            )),
        }
    }

    /// 业务作用：累计共享引用展开后的 JSON 元素数，使重复 ref 不能绕过解码阶段 collection
    /// 预算并制造指数级内存消耗。
    ///
    /// 参数说明：
    /// - `expanded_items`：是当前累计值
    /// - `count`：是本容器将新增的元素数。
    ///
    /// 返回：累计不溢出且不超 route 上限时成功，否则返回协议错误。
    fn consume_rendered_items(
        &self,
        expanded_items: &mut usize,
        count: usize,
    ) -> Result<(), DubboError> {
        *expanded_items = expanded_items
            .checked_add(count)
            .ok_or(DubboError::Protocol(
                "Dubbo Hessian2 JSON expansion item count overflow",
            ))?;
        if *expanded_items > self.limits.max_collection_items {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 JSON expansion exceeds max_hessian_collection_items",
            ));
        }
        Ok(())
    }

    /// 业务作用：累计 wire 中 collection/object 字段总数，在任何按声明长度分配之前执行硬门。
    ///
    /// 参数说明：
    /// - `count`：是当前容器新增的元素或字段数。
    ///
    /// 返回：累计值不溢出且不超 route 上限时成功，否则返回协议错误。
    fn consume_items(&mut self, count: usize) -> Result<(), DubboError> {
        self.collection_items =
            self.collection_items
                .checked_add(count)
                .ok_or(DubboError::Protocol(
                    "Dubbo Hessian2 collection item count overflow",
                ))?;
        if self.collection_items > self.limits.max_collection_items {
            return Err(DubboError::Protocol(
                "Dubbo Hessian2 response exceeds max_hessian_collection_items",
            ));
        }
        Ok(())
    }

    /// 业务作用：读取一个 IEEE-754 64-bit double 并拒绝 frame 截断。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回 wire bits 对应的 f64；不足 8 字节时返回协议错误。
    fn read_double64(&mut self) -> Result<f64, DubboError> {
        let bits = u64::from_be_bytes(
            self.read_slice(8)?
                .try_into()
                .expect("fixed Hessian2 double width"),
        );
        Ok(f64::from_bits(bits))
    }

    /// 业务作用：读取有符号单字节 compact 数值并保持二补码符号。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有字节时返回 i8；frame 截断时返回协议错误。
    fn read_i8(&mut self) -> Result<i8, DubboError> {
        Ok(self.read_byte()? as i8)
    }

    /// 业务作用：读取 big-endian i16，用于 Hessian compact double short。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有两个字节时返回 i16；frame 截断时返回协议错误。
    fn read_i16(&mut self) -> Result<i16, DubboError> {
        Ok(i16::from_be_bytes(
            self.read_slice(2)?
                .try_into()
                .expect("fixed Hessian2 i16 width"),
        ))
    }

    /// 业务作用：读取 big-endian i32，用于 full int、compact double mill 与日期分钟。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有四个字节时返回 i32；frame 截断时返回协议错误。
    fn read_i32(&mut self) -> Result<i32, DubboError> {
        Ok(i32::from_be_bytes(
            self.read_slice(4)?
                .try_into()
                .expect("fixed Hessian2 i32 width"),
        ))
    }

    /// 业务作用：读取 big-endian i64，用于 full long 与毫秒日期。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有八个字节时返回 i64；frame 截断时返回协议错误。
    fn read_i64(&mut self) -> Result<i64, DubboError> {
        Ok(i64::from_be_bytes(
            self.read_slice(8)?
                .try_into()
                .expect("fixed Hessian2 i64 width"),
        ))
    }

    /// 业务作用：读取 big-endian u16 chunk 长度，统一字符串与 binary 的边界处理。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有两个字节时返回 u16；frame 截断时返回协议错误。
    fn read_u16(&mut self) -> Result<u16, DubboError> {
        Ok(u16::from_be_bytes(
            self.read_slice(2)?
                .try_into()
                .expect("fixed Hessian2 u16 width"),
        ))
    }

    /// 业务作用：只读查看下一个 tag，用于 variable collection 的 `Z` 终止判断，不提前推进
    /// offset 或绕过后续读取检查。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：frame 尚有字节时返回下一个 tag；到达末尾返回截断错误。
    fn peek_byte(&self) -> Result<u8, DubboError> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or(DubboError::Protocol("truncated Dubbo Hessian2 response"))
    }

    /// 业务作用：读取单个 wire 字节并推进 offset，所有 tag 与小字段读取共用同一截断门。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：frame 尚有字节时返回当前字节；到达末尾返回截断错误。
    fn read_byte(&mut self) -> Result<u8, DubboError> {
        let byte = self.peek_byte()?;
        self.offset += 1;
        Ok(byte)
    }

    /// 业务作用：读取固定长度 wire 片段，并用 checked_add 防止 offset 算术溢出或越过 frame。
    ///
    /// 参数说明：
    /// - `length`：是本字段协议声明的字节数。
    ///
    /// 返回：范围完整时返回借用 slice 并推进 offset；否则返回截断错误。
    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], DubboError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DubboError::Protocol("Dubbo Hessian2 offset overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(DubboError::Protocol("truncated Dubbo Hessian2 response"))?;
        self.offset = end;
        Ok(bytes)
    }
}

/// 业务作用：判断一个 tag 是否属于 Hessian2 compact/full int，用于 type reference 与其他
/// 控制字段在不消费额外字节前选择正确解码分支。
///
/// 参数说明：
/// - `tag`：是已从 frame 读取的首字节。
///
/// 返回：int tag 返回 true，其他 Hessian2 value tag 返回 false。
fn is_int_tag(tag: u8) -> bool {
    matches!(tag, 0x49 | 0x80..=0xd7)
}
