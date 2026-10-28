//! 只读索引访问；字节、结构、样本和期限在读取或分配之前核对。
use super::{Error, Result};
use crate::config::media::MediaCfg;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};

pub(super) struct Reader {
    pub file: File,
    pub len: u64,
    pub cfg: Arc<MediaCfg>,
    pub budget: nabudget::RequestBudget,
    bytes: usize,
    boxes: usize,
    samples: usize,
}
impl Reader {
    /// 业务作用：把固定文件描述符与请求预算绑定，后续偏移均以该文件长度为界。
    ///
    /// 参数说明：
    /// - `file`：已打开的只读常规文件。
    /// - `len`：打开后取得的文件长度。
    /// - `cfg`：当前路由解析上限。
    /// - `budget`：取消和单调期限凭证。
    ///
    /// 返回：尚未读取任何媒体实体的解析上下文。
    pub fn new(file: File, len: u64, cfg: Arc<MediaCfg>, budget: nabudget::RequestBudget) -> Self {
        Self {
            file,
            len,
            cfg,
            budget,
            bytes: 0,
            boxes: 0,
            samples: 0,
        }
    }
    /// 业务作用：读取有界索引片段，不能借随机访问绕过总读取预算。
    ///
    /// 参数说明：
    /// - `offset`：原文件中的绝对位置。
    /// - `size`：已经由结构上限约束的读取字节数。
    ///
    /// 返回：精确字节；取消、超限、越界或短读均拒绝，不产生部分索引。
    pub fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        self.check()?;
        if offset
            .checked_add(size as u64)
            .is_none_or(|end| end > self.len)
        {
            return Err(Error::Malformed);
        }
        self.bytes = self.bytes.checked_add(size).ok_or(Error::Limit)?;
        if self.bytes > self.cfg.max_parse_bytes {
            return Err(Error::Limit);
        }
        let mut bytes = vec![0; size];
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| Error::Io)?;
        self.file.read_exact(&mut bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Malformed
            } else {
                Error::Io
            }
        })?;
        self.check()?;
        Ok(bytes)
    }
    /// 业务作用：所有解析循环共享取消和期限，不依赖异步调用者继续等待。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：调用仍有效时成功，失效后停止读取与构造。
    pub fn check(&self) -> Result<()> {
        self.budget.check().map_err(|_| Error::Timeout)
    }
    /// 业务作用：限制容器结构数量和嵌套，未知布局也不能绕过结构预算。
    ///
    /// 参数说明：
    /// - `depth`：当前节点距顶层的深度。
    ///
    /// 返回：累计一个节点；超过硬上限时拒绝。
    pub fn node(&mut self, depth: usize) -> Result<()> {
        self.check()?;
        self.boxes += 1;
        if self.boxes > self.cfg.max_boxes || depth > self.cfg.max_depth {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }
    /// 业务作用：在展开压缩样本表之前累计全部轨道的样本数，避免小表声明巨量内存。
    ///
    /// 参数说明：
    /// - `count`：当前轨道声明的样本或 FLV tag 数。
    ///
    /// 返回：全部轨道的索引仍在配置容量内时成功。
    pub fn samples(&mut self, count: usize) -> Result<()> {
        self.check()?;
        self.samples = self.samples.checked_add(count).ok_or(Error::Limit)?;
        if self.samples > self.cfg.max_samples {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }
}
/// 业务作用：从完整字段边界读取大端无符号数，畸形长度不能触发越界访问。
///
/// 参数说明：
/// - `data`：当前 box 的完整内容。
/// - `offset`：相对内容起点的字段位置。
///
/// 返回：四字节字段；不足四字节则拒绝。
pub(super) fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        data.get(offset..offset.checked_add(4).ok_or(Error::Malformed)?)
            .ok_or(Error::Malformed)?
            .try_into()
            .map_err(|_| Error::Malformed)?,
    ))
}
/// 业务作用：读取扩展长度与时间字段，保留完整 64 位精度。
///
/// 参数说明：
/// - `data`：当前结构内容。
/// - `offset`：八字节字段位置。
///
/// 返回：完整字段或畸形拒绝。
pub(super) fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(
        data.get(offset..offset.checked_add(8).ok_or(Error::Malformed)?)
            .ok_or(Error::Malformed)?
            .try_into()
            .map_err(|_| Error::Malformed)?,
    ))
}
