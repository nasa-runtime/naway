//! 配置兼容只在构建阶段执行；来源不能绕过原生路由、安全策略和快照事务。

#[cfg(feature = "scg-compat")]
mod compile;
#[cfg(feature = "scg-compat")]
mod factories;
#[cfg(feature = "scg-compat")]
mod patterns;
#[cfg(feature = "scg-compat")]
mod properties;

#[cfg(feature = "scg-compat")]
use anyhow::{ensure, Context, Result};
#[cfg(feature = "scg-compat")]
use std::{
    collections::HashSet,
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(feature = "scg-compat")]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCfg {
    pub file: String,
    pub format: Format,
    pub proxy: String,
}

#[cfg(feature = "scg-compat")]
#[derive(Debug, serde::Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Yaml,
    Properties,
}

/// 未编译兼容能力的制品只保留拒绝标记，不携带来源格式和工厂解析器。
#[cfg(not(feature = "scg-compat"))]
#[derive(Debug)]
pub struct SourceCfg;

#[cfg(not(feature = "scg-compat"))]
impl<'de> serde::Deserialize<'de> for SourceCfg {
    /// 业务作用：在默认制品读取显式兼容声明时拒绝，不允许来源被悄然忽略。
    ///
    /// 参数说明：
    /// - `_deserializer`：配置声明入口，不解释其内容。
    ///
    /// 返回：始终返回需要 scg-compat 的配置错误。
    fn deserialize<D: serde::Deserializer<'de>>(_deserializer: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom(
            "SCG imports require scg-compat feature; use native proxies/routes",
        ))
    }
}

#[cfg(feature = "scg-compat")]
const MAX_SOURCE_BYTES: usize = 1024 * 1024;

/// 业务作用：将全部显式来源预先翻译为原生路由，再交给唯一快照构建器验证权限和执行能力。
///
/// 参数说明：
/// - `cfg`：本次尚未发布的完整配置，目标 listener 必须已由本地声明且没有原生路由。
/// - `root`：主配置的权威目录，来源文件不得逃出此根。
///
/// 返回：全部来源合法时一次性填充目标；任何失败不发布部分路由，也不修改来源文件。
#[cfg(feature = "scg-compat")]
pub(crate) fn apply(cfg: &mut super::model::GatewayConfig, root: &Path) -> Result<()> {
    if cfg.scg_imports.is_empty() {
        return Ok(());
    }
    ensure!(cfg.scg_imports.len() <= 16, "SCG source count exceeds 16");
    let canonical = root.canonicalize()?;
    let mut targets = HashSet::new();
    let mut prepared = Vec::new();
    let mut count = 0usize;
    let mut program_bytes = 0usize;
    for source in &cfg.scg_imports {
        ensure!(
            targets.insert(&source.proxy),
            "SCG target listener is duplicated"
        );
        let position = cfg
            .proxies
            .iter()
            .position(|p| p.id == source.proxy)
            .context("SCG target must be an existing native proxy")?;
        ensure!(
            cfg.proxies[position].routes.is_empty(),
            "SCG target must have no native routes; keep native routes on a separate proxy"
        );
        let bytes = read(source, &canonical)?;
        let document = match source.format {
            Format::Yaml => super::document::parse(&bytes, MAX_SOURCE_BYTES)?,
            Format::Properties => properties::parse(&bytes)?,
        };
        let routes = compile::translate(document)?;
        for route in &routes {
            for program in route.predicates.iter().chain(&route.filters) {
                program_bytes = program_bytes
                    .checked_add(program.len())
                    .context("SCG program budget exceeded")?;
            }
        }
        // 输入上限不能代替展开上限；百分号路径备选会放大文本，所有来源共用同一候选预算。
        ensure!(
            program_bytes <= 2 * 1024 * 1024,
            "SCG expanded programs exceed 2MiB across all sources"
        );
        count = count
            .checked_add(routes.len())
            .context("SCG route budget exceeded")?;
        ensure!(count <= 1024, "SCG generated route count exceeds 1024");
        prepared.push((position, routes));
    }
    // 翻译完成仍不开放业务；后续 owner、引用图、路由编译及原子发布门保持唯一权威。
    for (position, routes) in prepared {
        cfg.proxies[position].routes = routes;
    }
    Ok(())
}

/// 业务作用：把兼容来源纳入与真实构建同域的内容指纹和文件观察集合。
///
/// 参数说明：
/// - `cfg`：本地权威来源声明。
/// - `root`：主配置相对路径根。
///
/// 返回：声明的精确路径；读取和根目录权限仍由构建阶段验证。
#[cfg(feature = "scg-compat")]
pub(crate) fn dependencies(cfg: &super::model::GatewayConfig, root: &Path) -> Vec<PathBuf> {
    cfg.scg_imports
        .iter()
        .map(|source| root.join(&source.file))
        .collect()
}

/// 业务作用：有界读取根内普通来源文件，阻止 FIFO、最终符号链接或越根读取。
///
/// 参数说明：
/// - `source`：显式路径与格式声明。
/// - `root`：已经 canonicalize 的配置根。
///
/// 返回：最多 1MiB 原文；缺失、越根、非普通文件与超限均拒绝候选。
#[cfg(feature = "scg-compat")]
fn read(source: &SourceCfg, root: &Path) -> Result<Vec<u8>> {
    ensure!(
        !source.file.is_empty() && source.file.len() <= 4096,
        "invalid SCG source path length"
    );
    let path = root
        .join(&source.file)
        .canonicalize()
        .context("SCG source unavailable")?;
    ensure!(
        path.starts_with(root),
        "SCG source must stay inside configuration root"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).context("SCG source unavailable")?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= MAX_SOURCE_BYTES as u64,
        "SCG source must be a regular file up to 1MiB"
    );
    let mut bytes = Vec::new();
    file.take((MAX_SOURCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_SOURCE_BYTES,
        "SCG source exceeds byte budget"
    );
    Ok(bytes)
}
