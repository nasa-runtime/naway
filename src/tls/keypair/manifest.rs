//! 不可变材料目录以单一 manifest 激活，回收始终保留当前及恢复指针。

use super::{atomic_write, sync_directory};
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct PreparedKeypairVersion {
    pub(super) directory: PathBuf,
    pub(super) manifest: Vec<u8>,
}

/// 业务作用：把完整 pair 写入不可变版本目录，但不切换当前 manifest。
///
/// 返回的 manifest 只有在调用者以单次原子 rename 安装后才生效；因此进程在本函数后
/// 崩溃只会留下无引用版本，旧 pair 仍是唯一事实。
pub(super) fn prepare_keypair_version(
    manifest_file: &Path,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<PreparedKeypairVersion> {
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
