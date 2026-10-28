//! 管理证书在候选构建期间冻结，运行任务不自行读取尚未发布的文件。

use anyhow::{ensure, Context, Result};
use std::path::Path;

/// 业务作用：在明确配置根内读取有限普通PEM文件，防止管理通道读取越界秘密或阻塞特殊文件。
///
/// 参数说明：
/// - `root`：候选主文档的配置根。
/// - `name`：配置声明的PEM路径。
///
/// 返回：最多256KiB材料；路径越根、类型错误或读入超限拒绝整个候选。
pub(super) fn pem(root: &Path, name: &str) -> Result<Vec<u8>> {
    ensure!(
        !name.is_empty() && name.len() <= 1024,
        "invalid management PEM path"
    );
    let root = root.canonicalize().context("resolve management root")?;
    let path = root
        .join(name)
        .canonicalize()
        .context("resolve management PEM")?;
    ensure!(
        path.starts_with(&root),
        "management PEM escapes configuration root"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    // 已解析路径仍可能被替换；先打开句柄，再检查实际文件，不能按路径检查后重新打开。
    let file = options.open(&path).context("open management PEM")?;
    crate::io::bounded_io::read_open_file(file, &path, 256 * 1024, "management PEM")
}

/// 业务作用：把节点和启动身份限制为无分隔歧义的固定长度标识。
///
/// 参数说明：
/// - `value`：节点声明或协议身份。
///
/// 返回：非空且最多64个安全ASCII字节时为true。
pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
