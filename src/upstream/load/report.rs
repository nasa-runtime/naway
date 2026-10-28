//! ORCA 响应元数据与 protobuf 的有界读取；只提取调度需要的数值，不构造通用消息树。

use base64::Engine;
use http::HeaderMap;
use serde::Deserialize;

/// 同一报告的编码及解码上限，限制非业务反馈占用的栈空间与解析时间。
pub const MAX_REPORT_BYTES: usize = 4 * 1024;
pub const BINARY_HEADER: &str = "endpoint-load-metrics-bin";

#[derive(Default, Deserialize)]
struct Utilization {
    #[serde(default, alias = "cpuUtilization")]
    cpu_utilization: Option<f64>,
    #[serde(default, alias = "applicationUtilization")]
    application_utilization: Option<f64>,
    #[serde(default, alias = "memUtilization")]
    mem_utilization: Option<f64>,
}

impl Utilization {
    /// 业务作用：校验报告中的已知利用率并优先采用应用口径，保留超过软容量的负载。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有效数值转换为有界万分比；缺失、负值、非有限值或非法内存比例拒绝。
    fn scaled(&self) -> Option<u32> {
        for value in [self.cpu_utilization, self.application_utilization]
            .into_iter()
            .flatten()
        {
            if !value.is_finite() || value < 0.0 {
                return None;
            }
        }
        if self
            .mem_utilization
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return None;
        }
        let value = self.application_utilization.or(self.cpu_utilization)?;
        Some(
            (value * super::UTILIZATION_SCALE as f64)
                .round()
                .min((super::UTILIZATION_NONE - 1) as f64) as u32,
        )
    }
}

/// 业务作用：读取标准 ORCA HTTP 格式，同时保留既有无前缀 JSON 与冒号文本的兼容入口。
///
/// 参数说明：
/// - `raw`：受信上游返回的完整报告，不能来自下游请求。
///
/// 返回：合法报告的万分比利用率；重复权威字段、坏语法和超长内容整体拒绝。
pub fn parse_orca_utilization(raw: &str) -> Option<u32> {
    if raw.is_empty() || raw.len() > MAX_REPORT_BYTES {
        return None;
    }
    let raw = raw.trim();
    if let Some(encoded) = raw.strip_prefix("BIN ") {
        return parse_binary_header(encoded.as_bytes());
    }
    if let Some(json) = raw
        .strip_prefix("JSON ")
        .or_else(|| raw.starts_with('{').then_some(raw))
    {
        return serde_json::from_str::<Utilization>(json).ok()?.scaled();
    }
    let raw = raw.strip_prefix("TEXT ").unwrap_or(raw);
    let mut report = Utilization::default();
    for field in raw.split(',') {
        let (name, value) = field.split_once('=').or_else(|| field.split_once(':'))?;
        let value = value.trim().parse::<f64>().ok()?;
        if !value.is_finite() {
            return None;
        }
        let slot = match name.trim() {
            "cpu" | "cpu_utilization" => &mut report.cpu_utilization,
            "application_utilization" => &mut report.application_utilization,
            "mem" | "mem_utilization" => &mut report.mem_utilization,
            _ => continue,
        };
        // 同一权威字段重复时不能依赖“先到优先”或“后到覆盖”来决定调度。
        if slot.replace(value).is_some() {
            return None;
        }
    }
    report.scaled()
}

/// 业务作用：从同一响应的头或尾元数据读取唯一 ORCA 报告，拒绝歧义多值。
///
/// 参数说明：
/// - `headers`：真实上游的响应头或 trailers。
/// - `text_header`：构建期冻结的文本报告头名。
///
/// 返回：标准二进制头优先；若同时出现两种头或任一重复则拒绝，不猜测可信来源。
pub fn from_headers(headers: &HeaderMap, text_header: &str) -> Option<u32> {
    let mut binary = headers.get_all(BINARY_HEADER).iter();
    let mut text = headers.get_all(text_header).iter();
    let first_binary = binary.next();
    let first_text = text.next();
    if binary.next().is_some()
        || text.next().is_some()
        || (first_binary.is_some() && first_text.is_some())
    {
        return None;
    }
    if let Some(value) = first_binary {
        parse_binary_header(value.as_bytes())
    } else {
        parse_orca_utilization(first_text?.to_str().ok()?)
    }
}

/// 业务作用：有界解码 gRPC 二进制元数据，避免为小型反馈分配可增长缓冲。
///
/// 参数说明：
/// - `raw`：HTTP/2 元数据中的标准 Base64，允许省略尾部 padding。
///
/// 返回：合法 OrcaLoadReport 的调度数值；坏 Base64、重复拼接和超长报告拒绝。
fn parse_binary_header(raw: &[u8]) -> Option<u32> {
    if raw.len() > MAX_REPORT_BYTES {
        return None;
    }
    let mut decoded = [0u8; MAX_REPORT_BYTES];
    let engine = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let size = engine.decode_slice(raw, &mut decoded).ok()?;
    parse_protobuf(&decoded[..size])
}

/// 业务作用：直接借用 OrcaLoadReport wire bytes 提取利用率，不生成映射表或重新序列化报告。
///
/// 参数说明：
/// - `raw`：不含 gRPC 五字节帧头的单个 protobuf 报告。
///
/// 返回：已校验的万分比；截断、重复标量、错误 wire type、非法数值或资源超限拒绝。
pub fn parse_protobuf(mut raw: &[u8]) -> Option<u32> {
    if raw.len() > MAX_REPORT_BYTES {
        return None;
    }
    let mut report = Utilization::default();
    let mut seen = 0u16;
    while !raw.is_empty() {
        let tag = varint(&mut raw)?;
        let field = tag >> 3;
        let wire = tag & 7;
        if field == 0 || field > 0x1fff_ffff {
            return None;
        }
        match field {
            1 | 2 | 6 | 7 | 9 => {
                if wire != 1 || seen & (1 << field) != 0 {
                    return None;
                }
                seen |= 1 << field;
                let value = f64::from_le_bytes(take(&mut raw, 8)?.try_into().ok()?);
                if !value.is_finite() || value < 0.0 {
                    return None;
                }
                match field {
                    1 => report.cpu_utilization = Some(value),
                    2 => report.mem_utilization = Some(value),
                    9 => report.application_utilization = Some(value),
                    _ => {}
                }
            }
            3 => {
                if wire != 0 || seen & (1 << field) != 0 {
                    return None;
                }
                seen |= 1 << field;
                varint(&mut raw)?;
            }
            4 | 5 | 8 => {
                if wire != 2 {
                    return None;
                }
                let size = usize::try_from(varint(&mut raw)?).ok()?;
                validate_map(take(&mut raw, size)?, field == 5)?;
            }
            _ => skip(&mut raw, wire)?,
        }
    }
    // proto3 的零标量可不编码；存在完整二进制报告本身即为上游证据，空消息按 CPU=0 解释。
    report.cpu_utilization.get_or_insert(0.0);
    report.scaled()
}

/// 业务作用：校验报告中不用于调度的 map entry，避免坏 wire 内容绕过完整报告校验。
///
/// 参数说明：
/// - `raw`：借用的单个 map entry。
/// - `bounded`：资源利用率 map 的值必须位于零到一。
///
/// 返回：结构和数值合法时成功，不保存 key/value 或执行额外分配。
fn validate_map(mut raw: &[u8], bounded: bool) -> Option<()> {
    let mut seen = 0u8;
    while !raw.is_empty() {
        let tag = varint(&mut raw)?;
        if tag >> 3 > 0x1fff_ffff {
            return None;
        }
        match tag {
            10 if seen & 1 == 0 => {
                seen |= 1;
                let size = usize::try_from(varint(&mut raw)?).ok()?;
                std::str::from_utf8(take(&mut raw, size)?).ok()?;
            }
            17 if seen & 2 == 0 => {
                seen |= 2;
                let value = f64::from_le_bytes(take(&mut raw, 8)?.try_into().ok()?);
                if !value.is_finite() || (bounded && !(0.0..=1.0).contains(&value)) {
                    return None;
                }
            }
            value if value >> 3 == 1 || value >> 3 == 2 || value >> 3 == 0 => return None,
            value => skip(&mut raw, value & 7)?,
        }
    }
    Some(())
}

/// 业务作用：读取最多十字节的 protobuf 无符号整数，拒绝溢出和截断。
///
/// 参数说明：
/// - `raw`：尚未读取的 wire bytes，成功时推进至整数之后。
///
/// 返回：完整 u64；失败时调用方必须丢弃整份报告。
pub(super) fn varint(raw: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *raw.first()?;
        *raw = &raw[1..];
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Some(value);
        }
    }
    None
}

/// 业务作用：借用并推进有界 wire 片段，长度由剩余输入决定而非外部字段直接分配。
///
/// 参数说明：
/// - `raw`：剩余输入。
/// - `size`：希望读取的字节数。
///
/// 返回：存在完整片段时返回借用；截断时拒绝。
fn take<'a>(raw: &mut &'a [u8], size: usize) -> Option<&'a [u8]> {
    let value = raw.get(..size)?;
    *raw = &raw[size..];
    Some(value)
}

/// 业务作用：跳过未知的标准 protobuf 标量字段，以有界方式兼容未来报告扩展。
///
/// 参数说明：
/// - `raw`：字段值的剩余输入。
/// - `wire`：已经读取的 protobuf wire type。
///
/// 返回：字段完整时推进；不接受 group、非法类型或超出输入的长度。
fn skip(raw: &mut &[u8], wire: u64) -> Option<()> {
    match wire {
        0 => {
            varint(raw)?;
        }
        1 => {
            take(raw, 8)?;
        }
        2 => {
            let size = usize::try_from(varint(raw)?).ok()?;
            take(raw, size)?;
        }
        5 => {
            take(raw, 4)?;
        }
        _ => return None,
    }
    Some(())
}
