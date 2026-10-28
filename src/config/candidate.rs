//! 原文候选的物理读取位置与真实部署依赖根。

use super::*;

#[cfg(feature = "node-actions")]
pub(crate) mod dependencies;

/// 本次构建的实际文档来源；显式规则来源只用于尚未发布的文档集。
#[derive(Clone, Copy)]
pub(crate) struct Documents<'a> {
    pub(crate) gateway: &'a Path,
    pub(crate) sidecars: Option<Sidecars<'a>>,
}

/// 两份规则的候选 base，profile 仍由合并后主配置中的真实声明路径决定。
#[derive(Clone, Copy)]
pub(crate) struct Sidecars<'a> {
    pub(crate) guard: &'a Path,
    pub(crate) sentinel: &'a Path,
}

/// 已完成主配置合并的真实文档目标；隔离工作区路径不得参与文件发布。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Paths {
    pub(crate) gateway: PathBuf,
    pub(crate) guard: PathBuf,
    pub(crate) sentinel: PathBuf,
}

impl Paths {
    /// 业务作用：冻结本次语义构建使用的部署路径，避免发布时借用另一份配置推导规则位置。
    ///
    /// 参数说明：
    /// - `main`：真实主配置路径，决定相对根。
    /// - `config`：已合并profile和环境覆盖的配置。
    ///
    /// 返回：主文档与两份规则的声明目标，不创建文件或解析原文。
    pub(crate) fn new(main: &Path, config: &GatewayConfig) -> Self {
        Self {
            gateway: main.to_path_buf(),
            guard: resolve_relative(main, &config.interface_guard_file),
            sentinel: resolve_relative(main, &config.sentinel_rules_file),
        }
    }

    /// 业务作用：固定依赖先于主文档的提交次序，使所有原文发布共享相同目标排列。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：guard、Sentinel、主配置三个借用路径。
    pub(crate) fn ordered(&self) -> [&Path; 3] {
        [&self.guard, &self.sentinel, &self.gateway]
    }
}

/// 业务作用：从隔离主文档验证候选，并保留真实主配置的 profile 和相对依赖根。
///
/// 参数说明：
/// - `cfg_path`：真实部署主配置路径。
/// - `candidate_path`：有界候选主文档路径。
/// - `version`：用于推演的候选版本。
///
/// 返回：完整候选快照或拒绝原因，不覆盖活动文档或发布快照。
pub fn load_candidate_snapshot(
    cfg_path: &Path,
    candidate_path: &Path,
    version: u64,
) -> Result<GatewaySnapshot> {
    load_documents(
        cfg_path,
        Documents {
            gateway: candidate_path,
            sidecars: None,
        },
        version,
        #[cfg(feature = "config-providers")]
        None,
    )
}

/// 业务作用：把原文候选送入唯一语义构建链，物理 base 替换不能改变部署中的 profile 和依赖根。
///
/// 参数说明：
/// - `cfg_path`：真实主配置路径，决定主 profile 和相对依赖。
/// - `documents`：本次读取的主文档与可选规则 base。
/// - `version`：候选版本。
/// - `previous`：启用动态来源时沿用的当前目录。
///
/// 返回：完整构建但尚未发布的快照；缺失、超限、来源或规则非法时拒绝，不写原始文件。
pub(crate) fn load_documents(
    cfg_path: &Path,
    documents: Documents<'_>,
    version: u64,
    #[cfg(feature = "config-providers")] previous: Option<Arc<crate::control::providers::Snapshot>>,
) -> Result<GatewaySnapshot> {
    let main = super::source_identity::Document::read(documents.gateway)?;
    let loaded: LoadedYml<GatewayConfig> = loader(cfg_path, Some(documents.gateway))
        .preserve_unresolved_placeholders(true)
        .load_tracked()
        .context("load candidate configuration")?;
    let mut cfg = loaded.value;
    expand_config_snippets(&mut cfg, cfg_path, documents.gateway)?;
    let identity =
        super::source_identity::Prepared::new(Paths::new(cfg_path, &cfg), documents, main)?;
    let snapshot = build_snapshot_from_config(
        cfg_path,
        documents,
        version,
        DynamicUpstreamStore::new(),
        cfg,
        loaded.sources,
        #[cfg(feature = "config-providers")]
        crate::control::providers::Input {
            previous,
            observation: None,
        },
    )?;
    identity.finish(snapshot)
}

/// 业务作用：只替换 naml 的本次 base 输入，防止主 profile 把候选规则换回活动文件。
///
/// 参数说明：
/// - `declared`：完成主配置合并后声明的真实规则或主文档路径。
/// - `candidate`：本次隔离 base；为空时读取声明路径。
///
/// 返回：保留真实 profile、环境覆盖及读取预算的加载器，不解析或重编码正文。
pub(super) fn loader(declared: &Path, candidate: Option<&Path>) -> YmlLoader {
    super::loader(declared).base_file(candidate.unwrap_or(declared))
}
