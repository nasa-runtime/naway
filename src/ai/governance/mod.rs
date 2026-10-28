//! 同代 prompt、检索来源、引用与外部内容裁决。

pub mod config;
#[cfg(feature = "ai-governance")]
mod runtime;
#[cfg(feature = "ai-governance")]
pub(crate) use runtime::Plan;
#[cfg(not(feature = "ai-governance"))]
pub(crate) struct Plan;

#[cfg(not(feature = "ai-governance"))]
impl Plan {
    /// 业务作用：保持关闭制品时的管理摘要接口一致；关闭时无法构建任何治理实例。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不可执行的空摘要，不声称启用治理能力。
    pub(crate) fn summary(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}

/// 业务作用：执行 AI 治理制品门，未编译能力时禁止配置被静默忽略。
///
/// 参数说明：
/// - `cfg`：是可选策略
/// - `dir`：是候选配置目录。
///
/// 返回：未声明时不创建资源；声明时完整构建同代计划或拒绝候选。
pub(crate) fn build(
    cfg: Option<&config::GovernanceCfg>,
    dir: &std::path::Path,
) -> anyhow::Result<Option<std::sync::Arc<Plan>>> {
    let Some(cfg) = cfg else {
        return Ok(None);
    };
    #[cfg(feature = "ai-governance")]
    {
        runtime::Plan::build(cfg, dir).map(Some)
    }
    #[cfg(not(feature = "ai-governance"))]
    {
        let _ = (cfg, dir);
        anyhow::bail!("LLM governance requires ai-governance feature")
    }
}

/// 业务作用：把模板与独立凭据文件纳入同代 watcher，坏更新保留旧策略。
///
/// 参数说明：
/// - `cfg`：是治理配置
/// - `dir`：是路径基准。
///
/// 返回：精确依赖文件，不暴露内容。
pub(crate) fn dependency_paths(
    cfg: &config::GovernanceCfg,
    dir: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Some(prompt) = &cfg.prompt {
        paths.push(dir.join(&prompt.file));
    }
    if let Some(rag) = &cfg.rag {
        paths.extend(rag.sources.iter().filter_map(|source| {
            crate::security::secret::dependency_path(&source.target.api_key, dir)
        }));
    }
    if let Some(output) = &cfg.output_moderation {
        if let Some(path) = crate::security::secret::dependency_path(&output.service.api_key, dir) {
            paths.push(path);
        }
    }
    paths
}
