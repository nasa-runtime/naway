//! 原生JSON治理在有限工作席位执行；同链复用一棵有界文档，只有修改后的内容需要重新编码。

use super::Failure;
use anyhow::{ensure, Result};
use bytes::Bytes;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::{fmt, io::Write, sync::Arc};

#[derive(Clone, Debug)]
pub(super) enum Plan {
    Schema(Arc<jsonschema::Validator>),
    Redact(Arc<[String]>),
}

pub(super) struct Document {
    body: Bytes,
    json: Option<Value>,
    dirty: bool,
    maximum: usize,
    resident: Arc<crate::runtime::traffic_limit::resources::Retained>,
    workspace: Option<Arc<crate::extensions::resources::Lease>>,
}

impl Plan {
    /// 业务作用：编译有界Schema并关闭递归引用和回溯正则，校验不能产生远端读取或无界CPU。
    ///
    /// 参数说明：
    /// - `schema`：配置候选中的完整JSON Schema。
    ///
    /// 返回：可共享的不可变校验器；复杂度、引用或正则不符合消息预算时拒绝候选。
    pub(super) fn schema(schema: &Value) -> Result<Self> {
        validate_schema(schema, 0, &mut 0)?;
        let validator = jsonschema::options()
            .with_pattern_options(jsonschema::PatternOptions::regex())
            .build(schema)?;
        Ok(Self::Schema(Arc::new(validator)))
    }

    /// 业务作用：冻结明确的JSON字段修改权限，消息不能临时指定新的脱敏目标。
    ///
    /// 参数说明：
    /// - `pointers`：需要遮蔽的RFC6901指针列表。
    ///
    /// 返回：最多32个非根指针；非法转义、超长或重复指针拒绝候选。
    pub(super) fn redact(pointers: &[String]) -> Result<Self> {
        ensure!(
            !pointers.is_empty() && pointers.len() <= 32,
            "invalid WebSocket redaction field count"
        );
        let mut seen = std::collections::HashSet::new();
        for pointer in pointers {
            ensure!(
                pointer.starts_with('/') && pointer.len() <= 512 && seen.insert(pointer),
                "invalid WebSocket redaction pointer"
            );
            let mut chars = pointer.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' {
                    ensure!(
                        matches!(chars.next(), Some('0' | '1')),
                        "invalid JSON pointer escape"
                    );
                }
            }
        }
        Ok(Self::Redact(Arc::from(pointers)))
    }

    /// 业务作用：在原消息容量凭证与有限工作席位下校验或遮蔽，取消等待不提前归还实际工作集。
    ///
    /// 参数说明：
    /// - `document`：当前链唯一文档，保留原始Bytes及此前已经解析的JSON。
    /// - `budget`：不能超过整条消息期限的插件子预算。
    ///
    /// 返回：同一文档及修改标记；拒绝、超时、资源不足或执行失败均不发布半完成内容。
    pub(super) async fn apply(
        &self,
        mut document: Document,
        budget: &nabudget::RequestBudget,
    ) -> Result<Document, Failure> {
        document.reserve()?;
        let plan = self.clone();
        let wall = budget.clone();
        let work = tokio::task::spawn_blocking(move || {
            let _worker =
                crate::extensions::resources::Worker::acquire().map_err(|_| Failure::Capacity)?;
            wall.check().map_err(|_| Failure::Deadline)?;
            document.parse()?;
            let value = document.json.as_mut().expect("parsed message JSON");
            match plan {
                Self::Schema(validator) => {
                    if !validator.is_valid(value) {
                        return Err(Failure::Denied);
                    }
                }
                Self::Redact(pointers) => {
                    for pointer in pointers.iter() {
                        if let Some(field) = value.pointer_mut(pointer) {
                            if field.as_str() != Some("[REDACTED]") {
                                *field = Value::String("[REDACTED]".to_owned());
                                document.dirty = true;
                            }
                        }
                    }
                }
            }
            wall.check().map_err(|_| Failure::Deadline)?;
            Ok(document)
        });
        budget
            .run(work)
            .await
            .map_err(|_| Failure::Deadline)?
            .map_err(|_| Failure::Dependency)?
    }
}

impl Document {
    /// 业务作用：沿消息链移交原始载荷，不为未声明的内容处理解析JSON。
    ///
    /// 参数说明：
    /// - `body`：已完成协议校验的完整载荷。
    /// - `maximum`：该消息相位的字节上限。
    /// - `resident`：原始载荷的进程容量，阻塞任务必须共同持有至真实退出。
    ///
    /// 返回：尚未分配文档树的唯一处理上下文。
    pub(super) fn new(
        body: Bytes,
        maximum: usize,
        resident: Arc<crate::runtime::traffic_limit::resources::Retained>,
    ) -> Self {
        Self {
            body,
            json: None,
            dirty: false,
            maximum,
            resident,
            workspace: None,
        }
    }

    /// 业务作用：在建立文档树前取得保守运行工作集预算，原始正文大小不能替代解析后的内存占用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：保留原名额或取得有限工作集；不足立即失败，不排入无界执行队列。
    fn reserve(&mut self) -> Result<(), Failure> {
        if self.body.len() > self.maximum {
            return Err(Failure::Capacity);
        }
        if self.workspace.is_none() {
            let bytes = self.body.len().saturating_mul(64).saturating_add(64 * 1024);
            self.workspace = Some(Arc::new(
                crate::extensions::resources::Lease::acquire(bytes)
                    .map_err(|_| Failure::Capacity)?,
            ));
        }
        Ok(())
    }

    /// 业务作用：只解析一次完整JSON，同时拒绝重复键，防止原始载荷在对端产生不同字段解释。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最多4096个值、32层的唯一JSON树；畸形或重复键视为消息策略拒绝。
    fn parse(&mut self) -> Result<(), Failure> {
        if self.json.is_none() {
            let mut decoder = serde_json::Deserializer::from_slice(&self.body);
            let value = Seed {
                depth: 0,
                nodes: &mut 0,
            }
            .deserialize(&mut decoder)
            .map_err(|_| Failure::Denied)?;
            decoder.end().map_err(|_| Failure::Denied)?;
            self.json = Some(value);
        }
        Ok(())
    }

    /// 业务作用：在外部调用或最终发送前一次性编码修改后的文档，未修改载荷保持原始Bytes。
    ///
    /// 参数说明：
    /// - `budget`：当前消息剩余的绝对预算。
    ///
    /// 返回：原始或唯一新编码载荷；超时与输出超界不发布部分JSON。
    pub(super) async fn finish(self, budget: &nabudget::RequestBudget) -> Result<Bytes, Failure> {
        if !self.dirty {
            return Ok(self.body);
        }
        let wall = budget.clone();
        let work = tokio::task::spawn_blocking(move || {
            let _resident = self.resident;
            let _workspace = self.workspace;
            let _worker =
                crate::extensions::resources::Worker::acquire().map_err(|_| Failure::Capacity)?;
            wall.check().map_err(|_| Failure::Deadline)?;
            let mut output = Writer {
                bytes: Vec::new(),
                maximum: self.maximum,
            };
            serde_json::to_writer(&mut output, self.json.as_ref().expect("modified JSON"))
                .map_err(|_| Failure::Capacity)?;
            wall.check().map_err(|_| Failure::Deadline)?;
            Ok(Bytes::from(output.bytes))
        });
        budget
            .run(work)
            .await
            .map_err(|_| Failure::Deadline)?
            .map_err(|_| Failure::Dependency)?
    }
}

/// 业务作用：限制消息Schema的展开复杂度，引用不能将有限配置转成循环执行或外部读取。
///
/// 参数说明：
/// - `value`：当前Schema子树。
/// - `depth`：配置嵌套深度。
/// - `nodes`：本次累计节点预算。
///
/// 返回：16层、1024节点以内的无引用配置成功，否则拒绝候选。
fn validate_schema(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    ensure!(
        depth <= 16 && *nodes <= 1024,
        "WebSocket schema exceeds complexity budget"
    );
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                ensure!(
                    !matches!(key.as_str(), "$ref" | "$dynamicRef" | "$recursiveRef"),
                    "WebSocket schema references are not allowed"
                );
                validate_schema(value, depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_schema(value, depth + 1, nodes)?;
            }
        }
        Value::String(value) => ensure!(
            value.len() <= 4096,
            "WebSocket schema string exceeds budget"
        ),
        _ => {}
    }
    Ok(())
}

struct Seed<'a> {
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    /// 业务作用：在进入下一JSON值前扣除结构预算，不依赖递归完成后再计数。
    ///
    /// 参数说明：
    /// - `decoder`：当前完整载荷的反序列化器。
    ///
    /// 返回：有限结构的下一值；深度或节点超界立即拒绝。
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        *self.nodes += 1;
        if self.depth > 32 || *self.nodes > 4096 {
            return Err(D::Error::custom("message JSON structure exceeds budget"));
        }
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    /// 业务作用：为消息拒绝提供固定错误类型，不在错误中回显原始载荷。
    ///
    /// 参数说明：
    /// - `out`：错误描述输出。
    ///
    /// 返回：固定JSON类型说明。
    fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("bounded message JSON")
    }
    /// 业务作用：保留布尔类型，供Schema按原始语义判断。
    ///
    /// 参数说明：
    /// - `value`：已经解析的布尔值。
    ///
    /// 返回：相同布尔值，不转换为字符串。
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    /// 业务作用：保留有符号整数精度，避免Schema边界因浮点转换改变。
    ///
    /// 参数说明：
    /// - `value`：已经解析的有符号整数。
    ///
    /// 返回：精确整数值。
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }
    /// 业务作用：保留无符号整数精度，避免大数被错误收敛。
    ///
    /// 参数说明：
    /// - `value`：已经解析的无符号整数。
    ///
    /// 返回：精确整数值。
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }
    /// 业务作用：只接收JSON能够表达的有限浮点值，不让无穷数绕过约束。
    ///
    /// 参数说明：
    /// - `value`：已经解析的浮点值。
    ///
    /// 返回：有限数或固定错误。
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }
    /// 业务作用：为跨工作任务持有字符串取得唯一所有权，不保留请求缓冲的悬空借用。
    ///
    /// 参数说明：
    /// - `value`：已解码的JSON字符串。
    ///
    /// 返回：拥有字节的字符串值。
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    /// 业务作用：直接移交反序列化器已经拥有的字符串，避免第二次复制。
    ///
    /// 参数说明：
    /// - `value`：已经拥有字节的JSON字符串。
    ///
    /// 返回：复用同一分配的字符串值。
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    /// 业务作用：保留显式null与缺失字段的区别，供Schema作准确判断。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：显式JSON null。
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    /// 业务作用：在逐项结构预算内接收数组，不按对端声明提前分配巨大集合。
    ///
    /// 参数说明：
    /// - `sequence`：当前数组的顺序读取入口。
    ///
    /// 返回：原顺序数组；任一子值越界使整个消息拒绝。
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed {
            depth: self.depth + 1,
            nodes: self.nodes,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    /// 业务作用：拒绝解码后重复的字段名，原始消息不能在网关和业务端形成首值/末值分歧。
    ///
    /// 参数说明：
    /// - `object`：当前对象的键值读取入口。
    ///
    /// 返回：唯一字段映射；重复、超界或畸形使整个消息拒绝。
    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate message JSON field"));
            }
            let value = object.next_value_seed(Seed {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for Writer {
    /// 业务作用：在脱敏JSON写入前检查最终消息大小，不能先分配超界输出再回头裁剪。
    ///
    /// 参数说明：
    /// - `bytes`：序列化器下一块完整输出。
    ///
    /// 返回：整块写入或固定超界错误，不部分提交输出。
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("message output exceeds limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    /// 业务作用：完成内存编码的Writer合同，发布仍由完整消息发送门负责。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无需额外I/O，不在刷新阶段发送部分消息。
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
