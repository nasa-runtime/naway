//! 构建期 SecretSource 解析。
//!
//! 数据面只持有已解析 secret，不在请求路径访问环境变量、磁盘或外部系统。支持明文兼容值以及
//! `env://NAME`、`file://path`、`k8s-file://path`、`vault-agent://path`；后两者对应容器挂载/agent
//! 事实源，不在网关内引入高延迟远程 secret API。

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// 单个文本 secret 的构建期上限，防止错误挂载大文件撑高候选快照内存。
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// 业务作用：解析一个文本 SecretSource。
///
/// 参数说明：
/// - `raw`: literal 或带 scheme 的来源引用。
/// - `config_dir`: 相对 file source 的基准目录。
/// - `field`: 仅用于错误上下文，绝不包含 secret 内容。
///
/// 返回：拥有的 secret 文本。文件只移除一个常见结尾换行；NUL/非 UTF-8/超限均拒绝候选配置。
pub fn resolve_text(raw: &str, config_dir: &Path, field: &str) -> Result<String> {
    if let Some(name) = raw.strip_prefix("env://") {
        anyhow::ensure!(!name.is_empty(), "{field} env SecretSource name is empty");
        let value = std::env::var(name)
            .with_context(|| format!("{field} env SecretSource `{name}` is unavailable"))?;
        return validate(value.into_bytes(), field);
    }
    if let Some(value) = raw.strip_prefix("literal://") {
        return validate(value.as_bytes().to_vec(), field);
    }
    for prefix in ["file://", "k8s-file://", "vault-agent://"] {
        if let Some(path) = raw.strip_prefix(prefix) {
            anyhow::ensure!(!path.is_empty(), "{field} file SecretSource path is empty");
            let path = resolve_path(config_dir, path);
            // 统一有界助手先固定同一文件句柄，再最多读取 MAX+1；既防大文件预分配，也避免
            // metadata 检查与真正打开之间被替换。数据面只持有下面验证后的 String。
            let bytes = crate::io::bounded_io::read_file(
                &path,
                MAX_SECRET_BYTES,
                &format!("{field} SecretSource"),
            )?;
            return validate(bytes, field);
        }
    }
    // 兼容既有配置；新生产配置应使用显式 source，便于 config diff 不直接携带 secret。
    validate(raw.as_bytes().to_vec(), field)
}

/// 业务作用：如果值是文件型 SecretSource，返回其解析后依赖路径；env/literal/旧明文返回 None。
///
/// reload 控制面用该函数建立独立 watcher 与指纹，数据面仍只持有已解析值。
pub(crate) fn dependency_path(raw: &str, config_dir: &Path) -> Option<PathBuf> {
    ["file://", "k8s-file://", "vault-agent://"]
        .iter()
        .find_map(|prefix| raw.strip_prefix(prefix))
        .filter(|path| !path.is_empty())
        .map(|path| resolve_path(config_dir, path))
}

/// 业务作用：从 route filter DSL 里收集文件型 secret 依赖。该 DSL 本身以空白分 token，因此这里
/// 与构建期 parser 保持同样的 `key=value`/单层引号语义，不会把 secret 内容记录到日志。
pub(crate) fn filter_dependency_paths(spec: &str, config_dir: &Path) -> Vec<PathBuf> {
    spec.split_whitespace()
        .filter_map(|token| {
            let value = token
                .split_once('=')
                .map(|(_, value)| value)
                .unwrap_or(token)
                .trim();
            let value = if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                &value[1..value.len() - 1]
            } else {
                value
            };
            dependency_path(value, config_dir)
        })
        .collect()
}

/// 业务作用：按配置目录解析文件型 SecretSource，数据面不接收任意秘密文件路径。
fn resolve_path(config_dir: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    }
}

/// 业务作用：检查解析后的秘密值是否满足非空和文本边界，非法凭据不能进入活动配置。
fn validate(mut bytes: Vec<u8>, field: &str) -> Result<String> {
    anyhow::ensure!(
        bytes.len() <= MAX_SECRET_BYTES,
        "{field} SecretSource exceeds {MAX_SECRET_BYTES} bytes"
    );
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    anyhow::ensure!(
        !bytes.contains(&0),
        "{field} SecretSource contains a NUL byte"
    );
    String::from_utf8(bytes).with_context(|| format!("{field} SecretSource is not UTF-8"))
}
