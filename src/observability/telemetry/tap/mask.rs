//! JSON 字段存在性采样；词法状态只保存白名单匹配位，不缓存 key 或 value 原文。

use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Clone, Copy)]
enum Frame {
    Object {
        state: u8,
        key: u16,
    },
    Array {
        state: u8,
    },
}
enum Token {
    Idle,
    String {
        key: bool,
        matched: u16,
        length: usize,
        escape: Escape,
        utf8: u8,
        low: u8,
        high: u8,
    },
    Number(u8),
    Literal {
        word: &'static [u8],
        index: usize,
    },
}
#[derive(Clone, Copy)]
enum Escape {
    None,
    Slash,
    Unicode {
        value: u16,
        digits: u8,
        low: bool,
    },
    HighSlash,
    HighU,
}

pub(super) struct JsonMask {
    fields: Arc<[String]>,
    limit: usize,
    bytes: usize,
    stack: Vec<Frame>,
    token: Token,
    present: u16,
    started: bool,
    finished: bool,
    failure: Option<&'static str>,
}

impl JsonMask {
    /// 业务作用：为显式批准的顶层字段建立恒定大小词法状态，所有字段值只能完整遮蔽。
    ///
    /// 参数说明：
    /// - `fields`：是已验证 ASCII 白名单，最多十六项
    /// - `limit`：为检查字节硬门。
    ///
    /// 返回：不持有正文的增量解析器。
    pub(super) fn new(fields: Arc<[String]>, limit: usize) -> Self {
        Self {
            fields,
            limit,
            bytes: 0,
            stack: Vec::with_capacity(16),
            token: Token::Idle,
            present: 0,
            started: false,
            finished: false,
            failure: None,
        }
    }

    /// 业务作用：在原帧交付过程中识别 JSON 结构，不保留任何输入字节。
    ///
    /// 参数说明：
    /// - `bytes`：是当前业务帧的短借用，函数返回后不会继续持有。
    ///
    /// 返回：推进有限状态；超长、畸形或超深时停止检查，业务原帧不受影响。
    pub(super) fn feed(&mut self, bytes: &[u8]) {
        if self.failure.is_some() {
            return;
        }
        self.bytes = self.bytes.saturating_add(bytes.len());
        if self.bytes > self.limit {
            self.failure = Some("too_large");
            self.present = 0;
            return;
        }
        for &byte in bytes {
            if !self.byte(byte) {
                self.failure = Some("malformed");
                self.present = 0;
                return;
            }
        }
    }

    /// 业务作用：只有完整结构通过后才交付固定字段名和遮蔽标记，截断正文不交付部分目录。
    ///
    /// 参数说明：
    /// - `complete`：表示原业务流正常到达结束，而非取消或读取失败。
    ///
    /// 返回：固定状态及白名单字段；任何失败均不包含输入内容。
    pub(super) fn finish(self, complete: bool) -> Value {
        let state = self.failure.unwrap_or(if !complete {
            "incomplete"
        } else if !self.finished || !matches!(self.token, Token::Idle) {
            "malformed"
        } else {
            "complete"
        });
        let fields = if state == "complete" {
            self.fields
                .iter()
                .enumerate()
                .filter(|(index, _)| self.present & (1 << index) != 0)
                .map(|(_, field)| (field.clone(), Value::String("[REDACTED]".into())))
                .collect::<serde_json::Map<_, _>>()
        } else {
            serde_json::Map::new()
        };
        json!({
            "state":state,
            "fields":fields
        })
    }

    /// 业务作用：在父容器中提交一次值起点，只有根对象已批准字段才能进入存在性位图。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法值位置为真；错序或根不是对象时为假。
    fn value(&mut self) -> bool {
        let root = self.stack.len() == 1;
        match self.stack.last_mut() {
            Some(Frame::Object {
                state,
                key,
            }) if *state == 2 => {
                if root {
                    self.present |= *key;
                }
                *state = 3;
                true
            }
            Some(Frame::Array {
                state,
            }) if *state == 0 || *state == 2 => {
                *state = 1;
                true
            }
            _ => false,
        }
    }

    /// 业务作用：按字段位置缩小固定白名单位图，不为未知字段分配字符串。
    ///
    /// 参数说明：
    /// - `matched`：是当前 key 状态
    /// - `length`：是当前 key 状态
    /// - `value`：是已解码字符，仅 ASCII 可能命中。
    ///
    /// 返回：更新匹配位和有界长度，不保存原字符。
    fn key_byte(&self, matched: &mut u16, length: &mut usize, value: u32) {
        for (index, field) in self.fields.iter().enumerate() {
            if value > 127 || field.as_bytes().get(*length).copied().map(u32::from) != Some(value) {
                *matched &= !(1 << index);
            }
        }
        *length = length.saturating_add(1).min(65);
    }

    /// 业务作用：执行单字节 JSON 状态迁移，嵌套、转义和数值语法均有固定空间上限。
    ///
    /// 参数说明：
    /// - `byte`：是原流当前字节。
    ///
    /// 返回：语法仍可完成时为真；拒绝后不再处理后续字节。
    fn byte(&mut self, byte: u8) -> bool {
        let token = std::mem::replace(&mut self.token, Token::Idle);
        match token {
            Token::Number(stage) => {
                let next = match (stage, byte) {
                    (0, b'0') => Some(1),
                    (0, b'1'..=b'9') => Some(2),
                    (2, b'0'..=b'9') => Some(2),
                    (1 | 2, b'.') => Some(3),
                    (1 | 2 | 4, b'e' | b'E') => Some(5),
                    (3 | 4, b'0'..=b'9') => Some(4),
                    (5, b'+' | b'-') => Some(6),
                    (5..=7, b'0'..=b'9') => Some(7),
                    _ => None,
                };
                if let Some(next) = next {
                    self.token = Token::Number(next);
                    return true;
                }
                if !matches!(stage, 1 | 2 | 4 | 7) {
                    return false;
                }
                return self.byte(byte);
            }
            Token::Literal {
                word,
                index,
            } => {
                if word.get(index) != Some(&byte) {
                    return false;
                }
                if index + 1 < word.len() {
                    self.token = Token::Literal {
                        word,
                        index: index + 1,
                    };
                }
                return true;
            }
            Token::String {
                key,
                mut matched,
                mut length,
                mut escape,
                mut utf8,
                mut low,
                mut high,
            } => {
                match escape {
                    Escape::HighSlash => {
                        if byte != b'\\' {
                            return false;
                        }
                        escape = Escape::HighU;
                    }
                    Escape::HighU => {
                        if byte != b'u' {
                            return false;
                        }
                        escape = Escape::Unicode {
                            value: 0,
                            digits: 0,
                            low: true,
                        };
                    }
                    Escape::Unicode {
                        value,
                        digits,
                        low: surrogate,
                    } => {
                        let Some(hex) = (byte as char).to_digit(16) else {
                            return false;
                        };
                        let value = (value << 4) | (hex as u16);
                        if digits < 3 {
                            escape = Escape::Unicode {
                                value,
                                digits: digits + 1,
                                low: surrogate,
                            };
                        } else if surrogate {
                            if !(0xdc00..=0xdfff).contains(&value) {
                                return false;
                            }
                            if key {
                                self.key_byte(&mut matched, &mut length, 0x10000);
                            }
                            escape = Escape::None;
                        } else if (0xd800..=0xdbff).contains(&value) {
                            escape = Escape::HighSlash;
                        } else if (0xdc00..=0xdfff).contains(&value) {
                            return false;
                        } else {
                            if key {
                                self.key_byte(&mut matched, &mut length, u32::from(value));
                            }
                            escape = Escape::None;
                        }
                    }
                    Escape::Slash => {
                        if byte == b'u' {
                            escape = Escape::Unicode {
                                value: 0,
                                digits: 0,
                                low: false,
                            };
                        } else {
                            let value = match byte {
                                b'"' | b'\\' | b'/' => byte,
                                b'b' => 8,
                                b'f' => 12,
                                b'n' => 10,
                                b'r' => 13,
                                b't' => 9,
                                _ => return false,
                            };
                            if key {
                                self.key_byte(&mut matched, &mut length, u32::from(value));
                            }
                            escape = Escape::None;
                        }
                    }
                    Escape::None => {
                        if utf8 > 0 {
                            if !(low..=high).contains(&byte) {
                                return false;
                            }
                            utf8 -= 1;
                            low = 0x80;
                            high = 0xbf;
                        } else if byte == b'"' {
                            if key {
                                for (index, field) in self.fields.iter().enumerate() {
                                    if field.len() != length {
                                        matched &= !(1 << index);
                                    }
                                }
                                let Some(Frame::Object {
                                    state,
                                    key,
                                }) = self.stack.last_mut()
                                else {
                                    return false;
                                };
                                *state = 1;
                                *key = matched;
                            }
                            return true;
                        } else if byte == b'\\' {
                            escape = Escape::Slash;
                        } else if byte < 0x20 {
                            return false;
                        } else if byte < 0x80 {
                            if key {
                                self.key_byte(&mut matched, &mut length, u32::from(byte));
                            }
                        } else {
                            let span = match byte {
                                0xc2..=0xdf => (1, 0x80, 0xbf),
                                0xe0 => (2, 0xa0, 0xbf),
                                0xe1..=0xec | 0xee..=0xef => (2, 0x80, 0xbf),
                                0xed => (2, 0x80, 0x9f),
                                0xf0 => (3, 0x90, 0xbf),
                                0xf1..=0xf3 => (3, 0x80, 0xbf),
                                0xf4 => (3, 0x80, 0x8f),
                                _ => return false,
                            };
                            (utf8, low, high) = span;
                            if key {
                                matched = 0;
                            }
                        }
                    }
                }
                self.token = Token::String {
                    key,
                    matched,
                    length,
                    escape,
                    utf8,
                    low,
                    high,
                };
                return true;
            }
            Token::Idle => {}
        }
        if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
            return true;
        }
        if self.finished {
            return false;
        }
        if !self.started {
            if byte != b'{' {
                return false;
            }
            self.started = true;
            self.stack.push(Frame::Object {
                state: 0,
                key: 0,
            });
            return true;
        }
        match byte {
            b'"' => {
                let key = matches!(
                    self.stack.last(),
                    Some(Frame::Object {
                        state: 0 | 4,
                        ..
                    })
                );
                if !key && !self.value() {
                    return false;
                }
                self.token = Token::String {
                    key,
                    matched: ((1u32 << self.fields.len()) - 1) as u16,
                    length: 0,
                    escape: Escape::None,
                    utf8: 0,
                    low: 0x80,
                    high: 0xbf,
                };
                true
            }
            b'{' | b'[' => {
                if self.stack.len() >= 16 || !self.value() {
                    return false;
                }
                self.stack.push(if byte == b'{' {
                    Frame::Object {
                        state: 0,
                        key: 0,
                    }
                } else {
                    Frame::Array {
                        state: 0,
                    }
                });
                true
            }
            b'}' | b']' => {
                let valid = matches!(
                    (byte, self.stack.last()),
                    (
                        b'}',
                        Some(Frame::Object {
                            state: 0 | 3,
                            ..
                        })
                    ) | (
                        b']',
                        Some(Frame::Array {
                            state: 0 | 1
                        })
                    )
                );
                if !valid {
                    return false;
                }
                self.stack.pop();
                self.finished = self.stack.is_empty();
                true
            }
            b':' => match self.stack.last_mut() {
                Some(Frame::Object {
                    state,
                    ..
                }) if *state == 1 => {
                    *state = 2;
                    true
                }
                _ => false,
            },
            b',' => match self.stack.last_mut() {
                Some(Frame::Object {
                    state,
                    ..
                }) if *state == 3 => {
                    *state = 4;
                    true
                }
                Some(Frame::Array {
                    state,
                }) if *state == 1 => {
                    *state = 2;
                    true
                }
                _ => false,
            },
            b'-' | b'0'..=b'9' => {
                if !self.value() {
                    return false;
                }
                self.token = Token::Number(match byte {
                    b'-' => 0,
                    b'0' => 1,
                    _ => 2,
                });
                true
            }
            b't' | b'f' | b'n' => {
                if !self.value() {
                    return false;
                }
                self.token = Token::Literal {
                    word: match byte {
                        b't' => b"true",
                        b'f' => b"false",
                        _ => b"null",
                    },
                    index: 1,
                };
                true
            }
            _ => false,
        }
    }
}
