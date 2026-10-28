//! MP4 元数据树只保留有界索引，不读取 mdat 载荷。
use super::{
    reader::{u32_at, u64_at, Reader},
    Error, Result,
};

pub(super) struct Node {
    pub kind: [u8; 4],
    pub data: Vec<u8>,
    pub children: Vec<Node>,
}
impl Node {
    /// 业务作用：构造已验证的叶节点，序列化统一重新计算长度。
    ///
    /// 参数说明：
    /// - `kind`：标准四字节 box 类型。
    /// - `data`：经过对应字段校验的内容。
    ///
    /// 返回：不带任何原文件绝对偏移的节点外壳。
    pub fn leaf(kind: [u8; 4], data: Vec<u8>) -> Self {
        Self {
            kind,
            data,
            children: Vec::new(),
        }
    }
    /// 业务作用：构造容器节点，使裁剪后的父长度来自完整子树。
    ///
    /// 参数说明：
    /// - `kind`：标准容器类型。
    /// - `children`：已经验证或重写的子节点。
    ///
    /// 返回：没有不透明前缀的容器。
    pub fn container(kind: [u8; 4], children: Vec<Node>) -> Self {
        Self {
            kind,
            data: Vec::new(),
            children,
        }
    }
    /// 业务作用：唯一定位必要结构，重复的时间或样本事实不能择一解释。
    ///
    /// 参数说明：
    /// - `kind`：需要的直接子节点类型。
    ///
    /// 返回：唯一节点；缺失或重复均判为畸形。
    pub fn get(&self, kind: &[u8; 4]) -> Result<&Self> {
        let mut matches = self.children.iter().filter(|node| &node.kind == kind);
        let node = matches.next().ok_or(Error::Malformed)?;
        if matches.next().is_some() {
            return Err(Error::Malformed);
        }
        Ok(node)
    }
    /// 业务作用：在重写阶段唯一定位索引字段，不能同时保留相互冲突的副本。
    ///
    /// 参数说明：
    /// - `kind`：需要修改的直接子节点类型。
    ///
    /// 返回：唯一可变节点；缺失或重复拒绝。
    pub fn get_mut(&mut self, kind: &[u8; 4]) -> Result<&mut Self> {
        if self
            .children
            .iter()
            .filter(|node| &node.kind == kind)
            .count()
            != 1
        {
            return Err(Error::Malformed);
        }
        self.children
            .iter_mut()
            .find(|node| &node.kind == kind)
            .ok_or(Error::Malformed)
    }
    /// 业务作用：区分可选结构缺席与重复结构，缺席不等同于空索引。
    ///
    /// 参数说明：
    /// - `kind`：可选节点类型。
    ///
    /// 返回：缺席为 None，唯一为 Some，重复拒绝。
    pub fn optional(&self, kind: &[u8; 4]) -> Result<Option<&Self>> {
        if self.children.iter().any(|node| &node.kind == kind) {
            self.get(kind).map(Some)
        } else {
            Ok(None)
        }
    }
    /// 业务作用：明确限定可重写的布局，未知定位或时间语义回落原文件而不猜测。
    ///
    /// 参数说明：
    /// - `allowed`：本级可解释的 box 类型。
    ///
    /// 返回：全部在能力范围内时成功，未知结构标为不支持。
    pub fn allow(&self, allowed: &[[u8; 4]]) -> Result<()> {
        if self
            .children
            .iter()
            .all(|node| allowed.contains(&node.kind))
        {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }
    /// 业务作用：在输出分配之前计算重写后元数据长度，溢出或超限不能截断成有效 box。
    ///
    /// 参数说明：
    /// - `limit`：整份元数据的最大字节数。
    ///
    /// 返回：可用 32 位 box 长度表达且未超过预算的大小。
    pub fn size(&self, limit: usize) -> Result<usize> {
        let mut size = 8usize.checked_add(self.data.len()).ok_or(Error::Limit)?;
        for child in &self.children {
            size = size.checked_add(child.size(limit)?).ok_or(Error::Limit)?;
        }
        if size > limit || size > u32::MAX as usize {
            Err(Error::Limit)
        } else {
            Ok(size)
        }
    }
    /// 业务作用：将有界索引树写入响应前缀，长度在写入任何节点之前确认。
    ///
    /// 参数说明：
    /// - `out`：已预留预算的响应前缀。
    /// - `limit`：整个前缀的字节上限。
    ///
    /// 返回：完整标准 box；不会生成超限部分响应。
    pub fn write(&self, out: &mut Vec<u8>, limit: usize) -> Result<()> {
        let size = self.size(limit)?;
        if out.len().checked_add(size).is_none_or(|len| len > limit) {
            return Err(Error::Limit);
        }
        out.extend_from_slice(&(size as u32).to_be_bytes());
        out.extend_from_slice(&self.kind);
        out.extend_from_slice(&self.data);
        for child in &self.children {
            child.write(out, limit)?;
        }
        Ok(())
    }
}
/// 业务作用：解析内存中的有界 moov 子树，所有已知容器都检查递归预算和声明边界。
///
/// 参数说明：
/// - `input`：上层已经按总字节预算读取的元数据。
/// - `reader`：结构数量、深度与期限的唯一计数器。
/// - `depth`：当前层深度。
///
/// 返回：完整子节点列表；截断、非法长度或嵌套超限拒绝。
pub(super) fn parse(input: &[u8], reader: &mut Reader, depth: usize) -> Result<Vec<Node>> {
    let mut offset = 0;
    let mut nodes = Vec::new();
    while offset < input.len() {
        reader.node(depth)?;
        let bytes = &input[offset..];
        let raw = u32_at(bytes, 0)?;
        let kind: [u8; 4] = bytes
            .get(4..8)
            .ok_or(Error::Malformed)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let (len, header) = if raw == 1 {
            (
                usize::try_from(u64_at(bytes, 8)?).map_err(|_| Error::Limit)?,
                16,
            )
        } else if raw == 0 {
            (bytes.len(), 8)
        } else {
            (raw as usize, 8)
        };
        if len < header || len > bytes.len() {
            return Err(Error::Malformed);
        }
        if len > reader.cfg.max_box_bytes {
            return Err(Error::Limit);
        }
        let data = &bytes[header..len];
        let node = if matches!(
            &kind,
            b"moov"
                | b"trak"
                | b"edts"
                | b"mdia"
                | b"minf"
                | b"dinf"
                | b"stbl"
                | b"mvex"
                | b"moof"
                | b"traf"
        ) {
            Node::container(kind, parse(data, reader, depth + 1)?)
        } else {
            Node::leaf(kind, data.to_vec())
        };
        nodes.push(node);
        offset += len;
    }
    Ok(nodes)
}
