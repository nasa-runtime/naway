//! 来源中立的有界声明；归属和优先级只能由本地配置权威注入。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::control::ownership::Owner;

pub(super) const MAX_SOURCES: usize = 32;
pub(super) const MAX_OBJECTS: usize = 8192;
pub(super) const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Authority {
    pub source: String,
    pub namespace: String,
    pub owner: Owner,
    pub priority: i32,
    pub max_stale: Duration,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Listener,
    Route,
    Service,
    Middleware,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference {
    pub namespace: String,
    pub kind: Kind,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Declaration {
    pub schema_version: u32,
    pub revision: u64,
    pub objects: Vec<Object>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Object {
    pub kind: Kind,
    pub name: String,
    pub generation: u64,
    /// None 是显式 tombstone；不能把删除误译成空对象或缺省策略。
    #[serde(deserialize_with = "required_spec")]
    pub spec: Option<Value>,
}

pub(super) struct Prepared {
    pub revision: u64,
    pub digest: [u8; 32],
    pub bytes: usize,
    pub objects: BTreeMap<(Kind, String), Arc<PreparedObject>>,
}

pub(super) struct PreparedObject {
    pub declaration: Object,
    pub digest: [u8; 32],
}

impl Authority {
    /// 业务作用：限定来源身份、命名空间、固定 owner 和最大陈旧期，不接受远端声明覆盖。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本地权威字段合法时成功；空归属、无限陈旧期或非法标识直接拒绝。
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            identifier(&self.source) && identifier(&self.namespace),
            "invalid provider identity"
        );
        ensure!(
            [
                &self.owner.workspace,
                &self.owner.tenant,
                &self.owner.environment
            ]
            .iter()
            .all(|value| !value.is_empty()
                && value.len() <= 128
                && !value.chars().any(char::is_control)),
            "invalid provider owner"
        );
        ensure!(
            (Duration::from_millis(100)..=Duration::from_secs(3600)).contains(&self.max_stale),
            "invalid provider stale budget"
        );
        Ok(())
    }
}

impl Declaration {
    /// 业务作用：将来源全文规范化为排序声明并验证硬预算，禁止重复身份与无水位对象。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：独立可比较的声明；尚未执行网关语义编译，不能直接发布到数据面。
    pub(super) fn prepare(self) -> Result<Prepared> {
        ensure!(
            self.schema_version == 1 && self.revision > 0,
            "invalid provider document version"
        );
        ensure!(
            self.objects.len() <= 4096,
            "provider object capacity reached"
        );
        let mut objects = BTreeMap::new();
        let mut bytes = 0usize;
        for mut object in self.objects {
            ensure!(
                identifier(&object.name) && object.generation > 0,
                "invalid provider object identity"
            );
            ensure!(
                object.spec.as_ref().is_none_or(Value::is_object),
                "provider object must contain a mapping or tombstone"
            );
            if let Some(spec) = &mut object.spec {
                normalize(spec, 0, &mut 0)?;
            }
            let encoded = serde_json::to_vec(&object)?;
            ensure!(
                encoded.len() <= 65536,
                "provider object byte budget reached"
            );
            bytes = bytes.saturating_add(encoded.len());
            ensure!(
                bytes <= MAX_SOURCE_BYTES,
                "provider document byte budget reached"
            );
            let key = (object.kind, object.name.clone());
            let prepared = Arc::new(PreparedObject {
                digest: Sha256::digest(&encoded).into(),
                declaration: object,
            });
            // 相同身份的多份声明必须在编译前拒绝，不能按输入顺序覆盖安全策略。
            ensure!(
                objects.insert(key, prepared).is_none(),
                "duplicate provider object identity"
            );
        }
        let mut digest = Sha256::new();
        digest.update(self.revision.to_be_bytes());
        for object in objects.values() {
            digest.update(object.digest);
        }
        Ok(Prepared {
            revision: self.revision,
            digest: digest.finalize().into(),
            bytes,
            objects,
        })
    }
}

/// 业务作用：约束来源中立名称，保证命名空间组合无路径穿越、分隔符歧义或显示字符欺骗。
///
/// 参数说明：
/// - `value`：是来源或对象的稳定标识。
///
/// 返回：只接受最多六十四个 ASCII 字母、数字、连字符和下划线。
pub(super) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// 业务作用：要求删除声明显式携带 null，缺失 spec 不能被解释为获授权的删除。
///
/// 参数说明：
/// - `deserializer`：是当前对象的 spec 字段。
///
/// 返回：明确的对象或 tombstone；字段缺失由 serde 拒绝。
fn required_spec<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Option::<Value>::deserialize(deserializer)
}

/// 业务作用：在序列化前限定声明结构并规范化映射顺序，摘要不能受 JSON 容器实现或输入键顺序影响。
///
/// 参数说明：
/// - `value`：是对象 spec
/// - `depth`：是本对象共享结构预算。
/// - `nodes`：是本对象共享结构预算。
///
/// 返回：最多三十二层、四千零九十六个节点；超深、超长或超宽声明拒绝，不递归处理其余输入。
fn normalize(value: &mut Value, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    ensure!(
        depth <= 32 && *nodes <= 4096,
        "provider object structural budget reached"
    );
    match value {
        Value::Object(object) => {
            ensure!(
                object.keys().all(|key| key.len() <= 256),
                "provider field name too long"
            );
            object.sort_keys();
            for value in object.values_mut() {
                normalize(value, depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize(value, depth + 1, nodes)?;
            }
        }
        Value::String(value) => ensure!(value.len() <= 65536, "provider string budget reached"),
        _ => {}
    }
    Ok(())
}
