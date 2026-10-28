//! WebSocket消息处理采用有序原生相位，载荷只有显式声明时才进入内容治理。

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WsMessagePluginCfg {
    /// ACL只读取握手时冻结的认证主体和标准消息类别。
    Acl {
        #[serde(default)]
        consumers: Vec<String>,
        #[serde(default)]
        opcodes: Vec<String>,
    },
    /// 有界JSON Schema不允许引用远端或本地文件，不向插件暴露部分JSON。
    JsonSchema {
        schema: serde_json::Value,
    },
    /// 按RFC6901指针替换明确字段；只有内容实际变化时才重新编码JSON。
    Redact {
        pointers: Vec<String>,
    },
    /// 同一连接同一方向的完整消息计数，不能通过拆分帧重复取得额度。
    RateLimit {
        messages: u64,
        window_ms: u64,
    },
    /// 固定HTTP端点接收原始消息字节，不强制JSON或Base64包装业务正文。
    External {
        endpoint: String,
        #[serde(default)]
        authorization: String,
        #[serde(default)]
        ca_certificate: String,
        #[serde(default)]
        fail_open: bool,
        #[serde(default)]
        allow_rewrite: bool,
        #[serde(default)]
        include_consumer: bool,
    },
}

/// 业务作用：约束显式消息聚合与插件链的总等待时间，防止慢分片永久占用缓冲。
///
/// 参数说明: 无。
///
/// 返回：默认5000毫秒，构建期还需验证硬上限。
pub(super) const fn default_ws_message_timeout_ms() -> u64 {
    5000
}
