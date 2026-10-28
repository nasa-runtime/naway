//! 帧与消息配置在同一候选阶段编译，数据面不解释声明或解析凭据。

use super::{plugins::Chain, FramePolicy, MessageAction};
use anyhow::Result;
use std::path::Path;

impl FramePolicy {
    /// 业务作用：把帧边界、压缩权限与双向消息治理作为一个不可分割的路由计划建立。
    ///
    /// 参数说明：
    /// - `cfg`：当前路由的完整帧治理声明。
    /// - `directory`：插件文件型凭据的相对路径根。
    ///
    /// 返回：全部预算及插件合法时返回计划，任一无效声明拒绝整份候选。
    pub(crate) fn build(cfg: &crate::config::model::WsFrameCfg, directory: &Path) -> Result<Self> {
        let mut plan = Self {
            max_frame_bytes: cfg.max_frame_bytes,
            max_message_bytes: cfg.max_message_bytes,
            max_fragments: cfg.max_fragments,
            max_plugin_payload_bytes: cfg.max_plugin_payload_bytes,
            plugin_timeout_ms: cfg.plugin_timeout_ms,
            max_decompress_ratio: cfg.max_decompress_ratio,
            on_violation: MessageAction::parse(&cfg.on_violation)?,
            permessage_deflate: cfg.permessage_deflate,
            message_timeout_ms: cfg.message_timeout_ms,
            ..Self::default()
        };
        plan.validate()?;
        plan.client_plugins = Chain::build(&cfg.client_plugins, directory)?;
        plan.server_plugins = Chain::build(&cfg.server_plugins, directory)?;
        Ok(plan)
    }

    /// 业务作用：仅在压缩或完整消息决策需要时启用聚合，普通帧治理保持流式转发。
    ///
    /// 参数说明：
    /// - `from_client`：选择握手方向对应的插件链。
    /// - `compressed`：本次握手是否实际接受 permessage-deflate。
    ///
    /// 返回：当前方向需要完整消息时为真。
    pub(crate) fn needs_message(&self, from_client: bool, compressed: bool) -> bool {
        compressed
            || self.on_violation == MessageAction::Drop
            || !if from_client {
                &self.client_plugins
            } else {
                &self.server_plugins
            }
            .is_empty()
    }
}
