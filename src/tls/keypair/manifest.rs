//! 不可变材料目录以单一 manifest 激活，回收始终保留当前及恢复指针。

mod bound;
mod prepared;

#[cfg(feature = "node-actions")]
pub(super) use prepared::prepare_decided;
pub(super) use prepared::prepare_keypair_version;

use super::{generation, sync_directory};
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// 业务作用：按保留代数回收 manifest 历史目录，同时永久保护当前指针和崩溃遗留临时指针。
///
/// 参数说明：
/// - `manifest_file`：是唯一激活指针
/// - `retention`：是至少两代的配置硬门。
///
/// 返回：所有可安全判定的过期完整目录已删除时成功；路径、指针或目录事实不可信时停止回收。
pub(super) fn gc_keypair_versions(manifest_file: &Path, retention: usize) -> Result<()> {
    anyhow::ensure!(
        (2..=64).contains(&retention),
        "TLS keypair retention is out of range"
    );
    let parent = manifest_file.parent().unwrap_or_else(|| Path::new("."));
    let root = parent.join(".gateway-keypairs");
    let root_metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("stat TLS keypair versions root"),
    };
    anyhow::ensure!(
        root_metadata.is_dir() && !root_metadata.file_type().is_symlink(),
        "TLS keypair versions root is not a directory"
    );
    let root_canonical =
        fs::canonicalize(&root).context("canonicalize TLS keypair versions root")?;
    let current = crate::io::bounded_io::read_file(
        manifest_file,
        64 * 1024,
        "TLS keypair manifest for cleanup",
    )?;
    let current_version = manifest_version_name(&current)?;
    let mut protected = std::collections::HashSet::new();
    protected.insert(current_version.clone());

    let manifest_name = manifest_file
        .file_name()
        .and_then(|name| name.to_str())
        .context("TLS keypair manifest file name is invalid")?;
    let temporary_prefix = format!(".{manifest_name}.tmp-");
    for entry in fs::read_dir(parent).context("scan TLS keypair manifest directory")? {
        let entry = entry.context("read TLS keypair manifest directory entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&temporary_prefix) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            continue;
        }
        if let Ok(bytes) = crate::io::bounded_io::read_file(
            &entry.path(),
            64 * 1024,
            "temporary TLS keypair manifest",
        ) {
            if let Ok(version) = manifest_version_name(&bytes) {
                protected.insert(version);
            }
        }
    }

    let mut versions = Vec::new();
    let target = generation::manifest_target(manifest_file)?;
    for entry in fs::read_dir(&root).context("scan TLS keypair versions")? {
        let entry = entry.context("read TLS keypair version entry")?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !valid_keypair_version_name(&name) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        // 多个 manifest 可共享同一父目录；没有本目标的完整归属证据时不能回收，尤其不能删除另一监听的当前材料。
        if !matches!(
            generation::read(&entry.path().join(generation::MANIFEST_RECORD), &target),
            Ok(Some(_))
        ) {
            continue;
        }
        let cert = fs::symlink_metadata(entry.path().join("cert.pem"));
        let key = fs::symlink_metadata(entry.path().join("key.pem"));
        if !matches!(cert, Ok(ref value) if value.is_file() && !value.file_type().is_symlink())
            || !matches!(key, Ok(ref value) if value.is_file() && !value.file_type().is_symlink())
        {
            continue;
        }
        versions.push((name, entry.path()));
    }
    versions.sort_by(|left, right| right.0.cmp(&left.0));
    let mut retained = std::collections::HashSet::new();
    retained.insert(current_version);
    for (name, _) in &versions {
        if retained.len() >= retention {
            break;
        }
        retained.insert(name.clone());
    }
    protected.extend(retained);
    for (name, path) in versions {
        if protected.contains(&name) {
            continue;
        }
        let canonical = fs::canonicalize(&path)
            .with_context(|| format!("canonicalize TLS keypair version {}", path.display()))?;
        anyhow::ensure!(
            canonical.parent() == Some(root_canonical.as_path()),
            "TLS keypair cleanup target escaped versions root"
        );
        fs::remove_dir_all(&canonical)
            .with_context(|| format!("remove TLS keypair history {}", canonical.display()))?;
    }
    sync_directory(&root)
}

/// 业务作用：从证书指针清单取得材料代际名称，供加载与清理定位同一版本目录。
fn manifest_version_name(bytes: &[u8]) -> Result<String> {
    let document: serde_json::Value =
        serde_json::from_slice(bytes).context("parse TLS keypair manifest for cleanup")?;
    anyhow::ensure!(
        document
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            == Some(1),
        "TLS keypair cleanup manifest schema is invalid"
    );
    let directory = document
        .get("directory")
        .and_then(serde_json::Value::as_str)
        .context("TLS keypair cleanup manifest directory is missing")?;
    let path = Path::new(directory);
    let mut components = path.components();
    anyhow::ensure!(
        matches!(components.next(), Some(std::path::Component::Normal(root)) if root == ".gateway-keypairs")
            && matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none(),
        "TLS keypair cleanup manifest directory is outside version root"
    );
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("TLS keypair cleanup manifest version name is invalid")?;
    anyhow::ensure!(
        valid_keypair_version_name(name),
        "TLS keypair cleanup manifest version name is invalid"
    );
    Ok(name.to_owned())
}

/// 业务作用：限制证书版本目录名称，禁止指针清单引导读取任意文件路径。
fn valid_keypair_version_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("v-") else {
        return false;
    };
    let Some((timestamp, suffix)) = rest.split_once('-') else {
        return false;
    };
    !timestamp.is_empty()
        && timestamp.bytes().all(|byte| byte.is_ascii_digit())
        && suffix.len() == 16
        && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct KeypairManifest {
    schema_version: u32,
    directory: String,
}

/// 业务作用：一次读取并验证活动 manifest，路径解析与材料代读取共享相同来源规则。
///
/// 参数说明：
/// - `manifest_file`：当前唯一激活指针的位置。
///
/// 返回：合法相对目录或尚未建立的空值；格式、遍历、容量或 I/O 不可信时拒绝候选。
pub(crate) fn current_material_directory(manifest_file: &Path) -> Result<Option<PathBuf>> {
    let bytes = match crate::io::bounded_io::read_optional_file(
        manifest_file,
        64 * 1024,
        "TLS keypair manifest",
    )? {
        Some(bytes) => bytes,
        None => return Ok(None),
    };
    parse_material_directory(manifest_file, &bytes).map(Some)
}

/// 业务作用：只解释调用方已固定的同一份指针原文，句柄捕获不能为取得目录再次打开可变manifest。
///
/// 参数说明：
/// - `manifest_file`：本次原指针所在的确定位置。
/// - `bytes`：一次有界读取取得的完整指针原文。
///
/// 返回：合法相对目录在该父目录下的位置；格式、代际或路径越界拒绝，不再读取文件系统。
pub(super) fn parse_material_directory(manifest_file: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let manifest: KeypairManifest = serde_json::from_slice(bytes)
        .with_context(|| format!("parse TLS keypair manifest {}", manifest_file.display()))?;
    anyhow::ensure!(
        manifest.schema_version == 1,
        "TLS keypair manifest {} uses unsupported schema_version {}",
        manifest_file.display(),
        manifest.schema_version
    );
    let relative = Path::new(&manifest.directory);
    anyhow::ensure!(
        !relative.as_os_str().is_empty()
            && !relative.is_absolute()
            && relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "TLS keypair manifest {} directory must be a non-empty relative path without traversal",
        manifest_file.display()
    );
    let parent = manifest_file.parent().unwrap_or_else(|| Path::new("."));
    let directory = parent.join(relative);
    Ok(directory)
}
