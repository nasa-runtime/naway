//! 按 HTTP 引号边界借用来源字段，不复制或解码整段请求头。

pub(super) struct Segments<'a> {
    remaining: Option<&'a str>,
    delimiter: u8,
}

impl<'a> Segments<'a> {
    /// 业务作用：为一个来源字段创建引号感知的借用迭代器。
    ///
    /// 参数说明：
    /// - `value`：已验证可读的字段原文。
    /// - `delimiter`：当前列表层级的 ASCII 分隔符。
    ///
    /// 返回：仅保存切片与分隔符，不分配或改写原文字节。
    pub(super) fn new(value: &'a str, delimiter: u8) -> Self {
        Self {
            remaining: Some(value),
            delimiter,
        }
    }
}

impl<'a> Iterator for Segments<'a> {
    type Item = Result<&'a str, ()>;

    /// 业务作用：读取一个未被引号保护的列表元素，防止扩展参数中的标点伪造代理边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有效元素借用原文；未闭合引号或转义返回错误，耗尽后返回 None。
    fn next(&mut self) -> Option<Self::Item> {
        let value = self.remaining.take()?;
        let mut quoted = false;
        let mut escaped = false;
        for (index, byte) in value.bytes().enumerate() {
            if escaped {
                escaped = false;
            } else if quoted && byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = !quoted;
            } else if byte == self.delimiter && !quoted {
                self.remaining = Some(&value[index + 1..]);
                return Some(Ok(&value[..index]));
            }
        }
        if quoted || escaped {
            return Some(Err(()));
        }
        Some(Ok(value))
    }
}
