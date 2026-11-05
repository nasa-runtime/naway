//! 不可变材料目录以单一 manifest 激活，回收始终保留当前及恢复指针。

use super::{atomic_write, generation, sync_directory};
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct PreparedKeypairVersion {
    pub(super) directory: PathBuf,
    pub(super) manifest: Vec<u8>,
    pub(super) generation: String,
}

/// 业务作用：把完整 pair 写入不可变版本目录，但不切换当前 manifest。
///
/// 参数说明：
/// - `manifest_file`：固定当前指针及材料归属的文件位置。
/// - `certificate_pem`：已验证的完整证书链。
/// - `private_key_pem`：已验证且与证书匹配的私钥。
/// - `owner`：上层已经为该来源和完整 pair 准备的唯一材料记录。
///
/// 返回：完整材料目录、待激活的指针及唯一材料代；失败不改变当前指针。
/// 指针只有经调用者原子安装后才生效，此前崩溃仅留下未激活目录。
pub(super) fn prepare_keypair_version(
    manifest_file: &Path,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    owner: generation::Record,
) -> Result<PreparedKeypairVersion> {
    // 不可变目录必须携带上层已经固定的同一代，不能在落盘阶段另造无法关联原动作的身份。
    owner.require_material(
        &generation::manifest_target(manifest_file)?,
        certificate_pem,
        private_key_pem,
    )?;
    let parent = manifest_file.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create keypair manifest dir {}", parent.display()))?;
    let versions_root = parent.join(".gateway-keypairs");
    fs::create_dir_all(&versions_root)
        .with_context(|| format!("create keypair versions dir {}", versions_root.display()))?;
    let mut random = [0_u8; 8];
    getrandom::getrandom(&mut random).context("generate keypair version suffix")?;
    let suffix = u64::from_le_bytes(random);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let directory = versions_root.join(format!("v-{timestamp}-{suffix:016x}"));
    fs::create_dir(&directory)
        .with_context(|| format!("create keypair version {}", directory.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod keypair version {}", directory.display()))?;
    }
    let result = (|| -> Result<Vec<u8>> {
        atomic_write(&directory.join("key.pem"), private_key_pem, true)?;
        atomic_write(&directory.join("cert.pem"), certificate_pem, false)?;
        // 当前指针只能指向已经持久化完整 pair 与材料代的目录，不能在激活后补记归属。
        owner.publish(&directory.join(generation::MANIFEST_RECORD))?;
        sync_directory(&directory)?;
        let relative = directory.strip_prefix(parent).with_context(|| {
            format!(
                "keypair version {} is outside manifest dir {}",
                directory.display(),
                parent.display()
            )
        })?;
        let relative = relative
            .to_str()
            .context("keypair version path is not UTF-8")?;
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "directory": relative,
        }))
        .context("serialize keypair manifest")
    })();
    match result {
        Ok(manifest) => Ok(PreparedKeypairVersion {
            directory,
            manifest,
            generation: owner.generation,
        }),
        Err(error) => {
            let _ = fs::remove_dir_all(&directory);
            Err(error)
        }
    }
}

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

#[derive(serde::Deserialize)]
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
    let manifest: KeypairManifest = serde_json::from_slice(&bytes)
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
    Ok(Some(directory))
}
