//! 具名本地业务文档的装配与同代来源验证。

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use naml::strict::{ConfigLoader, FileEvidence, LoadPolicy};
use naml::{ConfigFormat, YmlImport, YmlOverlay};
use serde_json::{Map, Value};

use super::{loader, resolve_relative, MAX_FINGERPRINT_FILE_BYTES};

const MAX_DOCUMENTS: usize = 64;

/// 已装配候选实际采用的文件及本轮必须保持缺席的可选文件。
#[derive(Clone, Debug)]
pub(crate) struct Sources {
    files: Vec<FileEvidence>,
    missing: Vec<PathBuf>,
    watch: Vec<PathBuf>,
}

impl Sources {
    /// 业务作用：补充主入口 watcher，使模块内容及 profile 创建均能触发整代校验。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：所有精确观察目标，不读取磁盘。
    pub(super) fn watch(&self) -> &[PathBuf] {
        &self.watch
    }

    /// 业务作用：把本轮真正读取的各模块内容加入配置指纹，供热更判重。
    ///
    /// 参数说明：
    /// - `hasher`：整代配置指纹的计算器。
    ///
    /// 返回：按声明顺序加入各文件摘要，不记录节点专有绝对路径。
    pub(super) fn hash(&self, hasher: &mut impl Hasher) {
        self.files.len().hash(hasher);
        for file in &self.files {
            file.content_digest().hash(hasher);
        }
    }

    /// 业务作用：在构建完成后复核模块原文及缺席条件，拒绝读取期间混入其它代。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已读文件和缺席条件均相同则成功，出现替换、删除或新建则拒绝候选。
    pub(super) fn revalidate(&self) -> Result<()> {
        let policy = document_policy();
        for file in &self.files {
            file.revalidate(&policy)?;
        }
        for path in &self.missing {
            ensure!(
                naml::strict::read_source(path, true, &policy)?.is_none(),
                "named configuration source appeared during compilation: {}",
                path.display()
            );
        }
        Ok(())
    }
}

/// 业务作用：识别显式声明的业务导入入口，避免启动流程把缺失业务文件自动填为空规则。
///
/// 参数说明：
/// - `path`：真实部署或隔离候选的配置入口。
///
/// 返回：命名入口或包含导入段时返回 true，读取错误时由正常候选加载报告。
pub(super) fn is_manifest(path: &Path) -> bool {
    is_application_filename(path)
        || loader(path)
            .preserve_unresolved_placeholders(true)
            .load_tree()
            .is_ok_and(|tree| tree.pointer("/yml/imports").is_some())
}

/// 业务作用：按 `yml.imports` 装配同一代本地业务文档，并保留精确文件身份。
///
/// 参数说明：
/// - `entry`：真实部署入口及相对路径根。
/// - `physical`：本轮实际读取的入口，决定最终 naml 叠加位置。
/// - `tree`：入口和活动 profile 已经解析出的声明。
///
/// 返回：入口无导入时为空。全部导入有效时返回 naml overlay 和来源计划，否则拒绝整代。
pub(super) fn load(
    entry: &Path,
    physical: &Path,
    tree: &Value,
) -> Result<Option<(YmlOverlay, Arc<Sources>)>> {
    if tree.pointer("/yml/imports").is_none() {
        ensure!(
            !is_application_filename(entry),
            "application.yml requires yml.imports"
        );
        return Ok(None);
    }
    let entry = std::path::absolute(entry)?;
    let physical = std::path::absolute(physical)?;
    let base = entry.parent().unwrap_or_else(|| Path::new("."));
    let imports = naml::strict::parse_imports_checked(tree, base).context("invalid yml.imports")?;
    ensure!(
        (1..=MAX_DOCUMENTS).contains(&imports.len()),
        "yml.imports requires between 1 and {MAX_DOCUMENTS} named documents"
    );
    let mut sources = Sources {
        files: Vec::new(),
        missing: Vec::new(),
        watch: Vec::new(),
    };
    let policy = document_policy();
    let mut names = HashSet::new();
    let mut fields = Map::new();
    let mut total_bytes = 0usize;
    let guard = rule_path(tree, &entry, "interface_guard_file", "interface-guard.yml")?;
    let sentinel = rule_path(tree, &entry, "sentinel_rules_file", "sentinel-rules.yml")?;
    for import in imports {
        // Nacos 与本地文件分别由各自的来源权威读取，避免远端入口被误解为启动时的空配置。
        let YmlImport::File {
            path,
            optional,
        } = import
        else {
            anyhow::bail!("named Nacos imports require a remote configuration authority");
        };
        let name = yaml_name(&path)?;
        ensure!(
            names.insert(name.to_ascii_lowercase()) && path != entry && path != physical,
            "duplicate named configuration document: {name}"
        );
        sources.watch.push(path.clone());
        if optional && !path.try_exists()? {
            sources.missing.push(path);
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .context("invalid YAML filename")?;
        let profile = path.with_file_name(format!("{stem}-{{profile}}"));
        let loaded = ConfigLoader::standard()?
            .base_file(&path)?
            .profile_pattern(profile)?
            .policy(policy.clone())
            .local_imports(false)
            .load()
            .with_context(|| format!("load named configuration document {name}"))?;
        total_bytes += loaded.report().input_bytes;
        ensure!(
            total_bytes <= MAX_FINGERPRINT_FILE_BYTES,
            "named configuration documents exceed the combined size limit"
        );
        for file in &loaded.watch.files {
            ensure!(
                !sources
                    .files
                    .iter()
                    .any(|previous| previous.same_file(file)),
                "named configuration documents must refer to distinct files: {name}"
            );
        }
        sources.files.extend(loaded.watch.files.iter().cloned());
        sources
            .missing
            .extend(loaded.watch.missing_files.iter().cloned());
        sources
            .watch
            .extend(loaded.watch.profile_candidates.iter().cloned());
        let Value::Object(mut module) = loaded.into_tree() else {
            anyhow::bail!("named configuration document must contain a mapping: {name}");
        };
        let is_guard = path == guard;
        let is_sentinel = path == sentinel;
        if is_guard || is_sentinel {
            ensure!(
                !module.contains_key("log"),
                "scoped log requires a log destination for module {name}"
            );
            continue;
        }
        ensure!(
            !module.contains_key("yml") && !module.contains_key("application"),
            "named configuration document cannot change its entry: {name}"
        );
        if let Some(version) = module.remove("schema_version") {
            let number = version
                .as_u64()
                .context("module schema_version must be an integer")?;
            ensure!(
                (1..=u64::from(super::SUPPORTED_GATEWAY_SCHEMA_VERSION)).contains(&number),
                "unsupported named configuration schema version in {name}"
            );
            let floor = fields
                .get("schema_version")
                .or_else(|| tree.get("schema_version"))
                .and_then(Value::as_u64)
                .unwrap_or(1);
            fields.insert("schema_version".to_owned(), Value::from(number.max(floor)));
        }
        ensure!(
            stem == "naway" || !module.contains_key("log"),
            "scoped log requires a log destination for module {name}"
        );
        // 私有日志必须先获得独立输出，否则不能让配置看似生效却把记录写进全局目录。
        let private_http = module
            .get("proxies")
            .and_then(Value::as_array)
            .is_some_and(|proxies| proxies.iter().any(|proxy| proxy.get("log").is_some()));
        let private_stream = module
            .get("stream")
            .and_then(|stream| stream.get("listeners"))
            .and_then(Value::as_array)
            .is_some_and(|listeners| {
                listeners
                    .iter()
                    .any(|listener| listener.get("log").is_some())
            });
        ensure!(
            !private_http
                && !private_stream
                && module
                    .get("server")
                    .and_then(|server| server.get("log"))
                    .is_none()
                && module
                    .get("admin")
                    .and_then(|admin| admin.get("log"))
                    .is_none(),
            "private log output is not supported for a listener in {name}"
        );
        for (key, value) in module {
            // 每个业务字段只有一个文件所有者，冲突时拒绝，避免依赖导入顺序默默覆盖旧配置。
            ensure!(
                !fields.contains_key(&key) && tree.get(&key).is_none(),
                "duplicate gateway configuration field {key} in {name}"
            );
            fields.insert(key, value);
        }
    }
    ensure!(
        guard != sentinel,
        "interface guard and Sentinel require distinct documents"
    );
    ensure!(
        !fields
            .get("config_source")
            .or_else(|| tree.get("config_source"))
            .and_then(|value| value.pointer("/nacos/enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "a local named configuration cannot enable legacy Nacos configuration"
    );
    sources.revalidate()?;
    let overlay = YmlOverlay::required(
        "named gateway modules",
        serde_json::to_string(&fields)?,
        ConfigFormat::Json,
    );
    Ok(Some((overlay, Arc::new(sources))))
}

/// 业务作用：识别需要完整导入清单的默认引导文件名。
///
/// 参数说明：
/// - `path`：部署入口。
///
/// 返回：文件名为 application.yml 或 application.yaml 时为真。
pub(super) fn is_application_filename(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == "application.yml" || name == "application.yaml")
}

/// 业务作用：从入口冻结规则文档的部署路径，使独立规则继续使用各自的 schema。
///
/// 参数说明：
/// - `tree`：解出占位符后的入口声明。
/// - `entry`：相对路径权威根。
/// - `key`：声明规则路径的配置键。
/// - `default`：省略声明时使用的标准文件名。
///
/// 返回：部署声明的路径，空或非字符串声明拒绝。
fn rule_path(tree: &Value, entry: &Path, key: &str, default: &str) -> Result<PathBuf> {
    let Some(raw) = tree.get(key) else {
        return Ok(resolve_relative(entry, default));
    };
    let path = raw
        .as_str()
        .filter(|path| !path.is_empty())
        .with_context(|| format!("{key} must be a nonempty path"))?;
    Ok(resolve_relative(entry, path))
}

/// 业务作用：规定可观察模块必须有确切 YAML 名称，防止模式或非法路径影响文件归属。
///
/// 参数说明：
/// - `path`：已经通过 naml 导入语法检查的本地路径。
///
/// 返回：可作为模块身份的 YAML 文件名，通配符和其它扩展名拒绝。
fn yaml_name(path: &Path) -> Result<&str> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("named import requires a YAML filename")?;
    ensure!(
        matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yml" | "yaml")
        ) && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "named import requires an exact YAML filename"
    );
    Ok(name)
}

/// 业务作用：读取独立模块的原文和 profile，延后环境覆盖及表达式求值到整代装配完成。
///
/// 参数说明: 无。
///
/// 返回：模块读取策略，活动 profile 缺席允许，基础文档使用 Naway 的有界文件预算。
fn document_policy() -> LoadPolicy {
    LoadPolicy {
        limits: naml::strict::LoadLimits {
            source_bytes: MAX_FINGERPRINT_FILE_BYTES,
            ..naml::strict::LoadLimits::default()
        },
        environment_overlay: false,
        placeholders: false,
        strict_profile: false,
        ..LoadPolicy::default()
    }
}
