//! dead properties 使用单个文件扩展属性原子持久化，不维护独立易漂移的路径数据库。

use crate::config::webdav::WebDavCfg;
use dav_server::fs::{DavProp, FsError, FsResult};
use serde::{Deserialize, Serialize};
use std::{fs::File, os::fd::AsRawFd};
use xattr::FileExt;

const ATTRIBUTE: &str = "user.naway.dav.properties";
const MAX_BYTES: usize = 8192;
const MAX_PROPERTIES: usize = 32;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    name: String,
    prefix: Option<String>,
    namespace: Option<String>,
    xml: Option<Vec<u8>>,
}

/// 业务作用：用固定缓冲读取文件属性，外部文件变更不能诱发按声明长度分配内存。
///
/// 参数说明：
/// - `file`：已由目录能力打开且检查类型的文件描述符。
///
/// 返回：最多 8192 字节；属性不存在返回空，超大或系统错误拒绝读取。
pub(super) fn read_raw(file: &File) -> FsResult<Vec<u8>> {
    let mut buffer = vec![0u8; MAX_BYTES];
    let name = c"user.naway.dav.properties";
    #[cfg(target_os = "macos")]
    // SAFETY：文件描述符由 file 保持存活；属性名以 NUL 结束，缓冲地址与长度对应可写内存。
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
            0,
        )
    };
    #[cfg(target_os = "linux")]
    // SAFETY：文件描述符由 file 保持存活；属性名以 NUL 结束，缓冲地址与长度对应可写内存。
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let count: isize = -1;
    if count < 0 {
        let error = std::io::Error::last_os_error();
        #[cfg(target_os = "macos")]
        if error.raw_os_error() == Some(libc::ENOATTR) {
            return Ok(Vec::new());
        }
        #[cfg(target_os = "linux")]
        if error.raw_os_error() == Some(libc::ENODATA) {
            return Ok(Vec::new());
        }
        return Err(if error.raw_os_error() == Some(libc::ERANGE) {
            FsError::TooLarge
        } else {
            FsError::GeneralFailure
        });
    }
    buffer.truncate(count as usize);
    Ok(buffer)
}

/// 业务作用：将持久属性重新经过有界 XML 门，避免磁盘内容绕过网络输入检查。
///
/// 参数说明：
/// - `file`：当前资源的已打开文件描述符。
/// - `cfg`：本代 XML 预算。
///
/// 返回：最多 32 项完整属性；损坏、重名或不合法 XML 拒绝而非忽略。
pub(super) fn read(file: &File, cfg: &WebDavCfg) -> FsResult<Vec<DavProp>> {
    let bytes = read_raw(file)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let stored: Vec<Stored> =
        serde_json::from_slice(&bytes).map_err(|_| FsError::GeneralFailure)?;
    if stored.len() > MAX_PROPERTIES {
        return Err(FsError::TooLarge);
    }
    let mut properties = Vec::with_capacity(stored.len());
    for value in stored {
        if value.name.len() > 256
            || value.namespace.as_ref().is_some_and(|ns| ns.len() > 512)
            || value
                .prefix
                .as_ref()
                .is_some_and(|prefix| prefix.len() > 128)
            || properties
                .iter()
                .any(|p: &DavProp| p.name == value.name && p.namespace == value.namespace)
        {
            return Err(FsError::GeneralFailure);
        }
        if let Some(xml) = &value.xml {
            super::input::validate_xml(xml, cfg, MAX_BYTES).map_err(|_| FsError::GeneralFailure)?;
        }
        properties.push(DavProp {
            name: value.name,
            prefix: value.prefix,
            namespace: value.namespace,
            xml: value.xml,
        });
    }
    Ok(properties)
}

/// 业务作用：对同一资源的完整属性集合做一次原子替换，超限不产生部分 PROPPATCH。
///
/// 参数说明：
/// - `file`：已验证资源的文件描述符。
/// - `properties`：候选完整属性集，不含受保护的 live properties。
///
/// 返回：单次 xattr 更新与 fsync 均成功；容量不足或持久化失败返回明确错误。
pub(super) fn write(file: &File, properties: &[DavProp]) -> FsResult<()> {
    if properties.len() > MAX_PROPERTIES {
        return Err(FsError::InsufficientStorage);
    }
    let stored: Vec<Stored> = properties
        .iter()
        .map(|p| Stored {
            name: p.name.clone(),
            prefix: p.prefix.clone(),
            namespace: p.namespace.clone(),
            xml: p.xml.clone(),
        })
        .collect();
    let bytes = serde_json::to_vec(&stored).map_err(|_| FsError::GeneralFailure)?;
    if bytes.len() > MAX_BYTES {
        return Err(FsError::InsufficientStorage);
    }
    file.set_xattr(ATTRIBUTE, &bytes)
        .map_err(|_| FsError::InsufficientStorage)?;
    file.sync_all().map_err(|_| FsError::GeneralFailure)
}
