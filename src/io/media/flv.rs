//! FLV 字节起播只选完整视频关键帧，并补齐 AVC/AAC 初始化 tag。
use super::{
    reader::{u32_at, Reader},
    Error, Result, Segment,
};

/// 业务作用：验证完整 FLV tag 链并选择指定字节之前的关键帧，避免把任意实体偏移解释成帧头。
///
/// 参数说明：
/// - `reader`：固定文件及解析资源预算。
/// - `start`：请求的原文件字节位置。
///
/// 返回：标准 FLV 头、必要编码初始化 tag 和原文件连续尾段；未知编码回落静态服务。
pub(super) fn prepare(reader: &mut Reader, start: u64) -> Result<Segment> {
    let header = reader.read(0, 13)?;
    if &header[..3] != b"FLV"
        || header[3] != 1
        || header[4] & !5 != 0
        || u32_at(&header, 5)? != 9
        || u32_at(&header, 9)? != 0
    {
        return Err(Error::Malformed);
    }
    if header[4] & 1 == 0 {
        return Err(Error::Unsupported);
    }
    if start >= reader.len {
        return Err(Error::Position);
    }
    let mut offset = 13u64;
    let mut selected = None;
    let mut first = None;
    let mut video_config = None;
    let mut audio_config = None;
    let mut previous_video = 0;
    let mut previous_audio = 0;
    let mut unsupported = false;
    let mut seen_media = false;
    let mut avc = false;
    let mut aac = false;
    let mut video_codec = None;
    let mut audio_codec = None;
    while offset < reader.len {
        reader.samples(1)?;
        let tag = reader.read(offset, 11)?;
        let size = be24(&tag[1..4]) as usize;
        let end = offset
            .checked_add(15 + size as u64)
            .ok_or(Error::Malformed)?;
        if end > reader.len || tag[8..11] != [0, 0, 0] {
            return Err(Error::Malformed);
        }
        if size > reader.cfg.max_box_bytes {
            return Err(Error::Limit);
        }
        if u32_at(&reader.read(end - 4, 4)?, 0)? != 11 + size as u32 {
            return Err(Error::Malformed);
        }
        let time = be24(&tag[4..7]) | ((tag[7] as u32) << 24);
        let head = reader.read(offset + 11, size.min(5))?;
        match tag[0] {
            9 => {
                if time < previous_video {
                    return Err(Error::Unsupported);
                }
                previous_video = time;
                let control = *head.first().ok_or(Error::Malformed)?;
                let codec = control & 15;
                if video_codec
                    .replace(codec)
                    .is_some_and(|previous| previous != codec)
                {
                    unsupported = true;
                }
                let frame = control >> 4;
                if !(1..=5).contains(&frame) {
                    return Err(Error::Malformed);
                }
                let key = match codec {
                    7 => {
                        avc = true;
                        if head.len() < 5 {
                            return Err(Error::Malformed);
                        }
                        match head[1] {
                            0 => {
                                let init = initialization(reader, offset, size)?;
                                if video_config.replace(init).is_some() {
                                    unsupported = true;
                                }
                                false
                            }
                            1 => {
                                if video_config.is_none() {
                                    return Err(Error::Malformed);
                                }
                                frame == 1
                            }
                            2 => false,
                            _ => return Err(Error::Malformed),
                        }
                    }
                    2 => frame == 1,
                    _ => {
                        unsupported = true;
                        false
                    }
                };
                if key {
                    first.get_or_insert(offset);
                    if start == 0 && selected.is_none() || offset <= start {
                        selected = Some(offset);
                    }
                }
                if codec != 7 || head.get(1) == Some(&1) {
                    seen_media = true;
                }
            }
            8 => {
                if time < previous_audio {
                    return Err(Error::Unsupported);
                }
                previous_audio = time;
                let codec = *head.first().ok_or(Error::Malformed)? >> 4;
                if header[4] & 4 == 0 {
                    return Err(Error::Malformed);
                }
                if audio_codec
                    .replace(codec)
                    .is_some_and(|previous| previous != codec)
                {
                    unsupported = true;
                }
                match codec {
                    10 => {
                        aac = true;
                        match head.get(1) {
                            Some(0) => {
                                let init = initialization(reader, offset, size)?;
                                if audio_config.replace(init).is_some() {
                                    unsupported = true;
                                }
                            }
                            Some(1) => {
                                if audio_config.is_none() {
                                    return Err(Error::Malformed);
                                }
                                seen_media = true;
                            }
                            _ => return Err(Error::Malformed),
                        }
                    }
                    2 => seen_media = true,
                    _ => unsupported = true,
                }
            }
            18 => {
                if seen_media {
                    unsupported = true;
                }
            }
            _ => unsupported = true,
        }
        offset = end;
    }
    if unsupported || avc && video_config.is_none() || aac && audio_config.is_none() {
        return Err(Error::Unsupported);
    }
    let offset = selected.or(first).ok_or(Error::Unsupported)?;
    let mut prefix = header;
    for config in [video_config, audio_config].into_iter().flatten() {
        if prefix
            .len()
            .checked_add(config.len())
            .is_none_or(|size| size > reader.cfg.max_metadata_bytes)
        {
            return Err(Error::Limit);
        }
        prefix.extend_from_slice(&config);
    }
    Ok(Segment {
        prefix,
        offset,
        len: reader.len - offset,
    })
}
/// 业务作用：保留解码初始化信息但重置其时间戳，陈旧脚本元数据不会被放入新片段前缀。
///
/// 参数说明：
/// - `reader`：有界读取上下文。
/// - `offset`：已验证的初始化 tag 位置。
/// - `size`：tag 的载荷长度。
///
/// 返回：包含前后 framing 的完整初始化 tag；超预算拒绝。
fn initialization(reader: &mut Reader, offset: u64, size: usize) -> Result<Vec<u8>> {
    if size + 15 > reader.cfg.max_metadata_bytes / 2 {
        return Err(Error::Limit);
    }
    let mut bytes = reader.read(offset, size + 15)?;
    bytes[4..8].fill(0);
    Ok(bytes)
}
/// 业务作用：解码固定三字节字段，避免把 FLV 长度误当作主机字节序。
///
/// 参数说明：
/// - `bytes`：经过 framing 校验的三字节字段。
///
/// 返回：无符号长度或时间戳低位。
fn be24(bytes: &[u8]) -> u32 {
    (bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32
}
