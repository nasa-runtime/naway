//! 非分片 MP4 的样本索引裁剪；保留编码载荷，仅重写时间表与 chunk 偏移。
use super::{
    boxes::{self, Node},
    reader::{u32_at, u64_at, Reader},
    Error, Result, Segment,
};

struct Sample {
    offset: u64,
    dts: u64,
    duration: u32,
    size: u32,
    cts: u32,
    sync: bool,
}
struct Track {
    node: Node,
    samples: Vec<Sample>,
    scale: u32,
    edit: u64,
    duration: u64,
    video: bool,
}

/// 业务作用：从固定文件构造时间裁剪计划，未知布局交回原静态响应，不输出猜测索引。
///
/// 参数说明：
/// - `reader`：带文件、取消和全部解析预算的上下文。
/// - `start_us`：以微秒表达的非负起播时间。
///
/// 返回：前置 moov 与原 mdat 的连续尾段；不重编码、不读入媒体载荷。
pub(super) fn prepare(reader: &mut Reader, start_us: u64) -> Result<Segment> {
    let mut offset = 0u64;
    let mut moov = None;
    let mut ftyp = None;
    let mut mdat = None;
    let mut unsupported = false;
    while offset < reader.len {
        reader.node(1)?;
        let head = reader.read(offset, 8)?;
        let raw = u32_at(&head, 0)?;
        let kind: [u8; 4] = head[4..8].try_into().map_err(|_| Error::Malformed)?;
        let (size, header) = if raw == 1 {
            (u64_at(&reader.read(offset + 8, 8)?, 0)?, 16)
        } else if raw == 0 {
            (reader.len - offset, 8)
        } else {
            (raw as u64, 8)
        };
        let end = offset.checked_add(size).ok_or(Error::Malformed)?;
        if size < header || end > reader.len {
            return Err(Error::Malformed);
        }
        if &kind != b"mdat" && size > reader.cfg.max_box_bytes as u64 {
            return Err(Error::Limit);
        }
        match &kind {
            b"ftyp" => {
                if ftyp.is_some() {
                    return Err(Error::Malformed);
                }
                let data = reader.read(offset + header, (size - header) as usize)?;
                if data.len() < 8 || data.len() % 4 != 0 {
                    return Err(Error::Malformed);
                }
                ftyp = Some(Node::leaf(kind, data));
            }
            b"moov" => {
                if moov.is_some() {
                    return Err(Error::Malformed);
                }
                if size > reader.cfg.max_metadata_bytes as u64 {
                    return Err(Error::Limit);
                }
                let data = reader.read(offset + header, (size - header) as usize)?;
                moov = Some(Node::container(kind, boxes::parse(&data, reader, 2)?));
            }
            b"mdat" => {
                if mdat.replace((offset + header, end)).is_some() {
                    unsupported = true;
                }
            }
            b"free" | b"skip" | b"wide" => {}
            _ => unsupported = true,
        }
        offset = end;
    }
    if unsupported {
        return Err(Error::Unsupported);
    }
    let mut moov = moov.ok_or(Error::Malformed)?;
    let ftyp = ftyp.ok_or(Error::Unsupported)?;
    let mdat = mdat.ok_or(Error::Malformed)?;
    moov.allow(&[*b"mvhd", *b"trak", *b"udta", *b"meta", *b"iods"])?;
    let (movie_scale, movie_duration) = clock(&moov.get(b"mvhd")?.data, false)?;
    if movie_scale == 0 || movie_duration == 0 {
        return Err(Error::Malformed);
    }
    let start_movie = ticks(start_us, movie_scale)?;
    if start_movie >= movie_duration {
        return Err(Error::Position);
    }
    let mut tracks = Vec::new();
    let mut kept = Vec::new();
    for node in std::mem::take(&mut moov.children) {
        if &node.kind == b"trak" {
            if tracks.len() >= 2 {
                return Err(Error::Unsupported);
            }
            tracks.push(track(node, reader, mdat)?);
        } else {
            kept.push(node);
        }
    }
    if tracks.is_empty()
        || tracks.iter().filter(|track| track.video).count() > 1
        || tracks.iter().filter(|track| !track.video).count() > 1
    {
        return Err(Error::Unsupported);
    }
    let mut selected = Vec::new();
    let mut first = mdat.1;
    let mut duration = 0;
    for mut track in tracks {
        reader.check()?;
        if start_movie >= track.duration {
            continue;
        }
        let desired = ticks(start_us, track.scale)?
            .checked_add(track.edit)
            .ok_or(Error::Malformed)?;
        let candidate = track
            .samples
            .iter()
            .rposition(|sample| {
                sample.dts.saturating_add(sample.cts as u64) <= desired
                    && (!track.video || sample.sync)
            })
            .ok_or(Error::Unsupported)?;
        // 视频从前一个同步样本开始解码；音频保留一个预卷样本，真正展示时间由 edit list 限定。
        let cut = if track.video {
            candidate
        } else {
            candidate.saturating_sub(1)
        };
        let base = track.samples[cut].dts;
        let media_time = desired.checked_sub(base).ok_or(Error::Unsupported)?;
        track.samples.drain(..cut);
        first = first.min(
            track
                .samples
                .iter()
                .map(|sample| sample.offset)
                .min()
                .ok_or(Error::Malformed)?,
        );
        let display = track.duration - start_movie;
        duration = duration.max(display);
        rewrite(&mut track, media_time, display)?;
        selected.push(track);
    }
    if selected.is_empty() || first >= mdat.1 {
        return Err(Error::Position);
    }
    moov.children = kept;
    set_duration(&mut moov.get_mut(b"mvhd")?.data, false, duration)?;
    for track in selected {
        moov.children.push(track.node);
    }
    let limit = reader.cfg.max_metadata_bytes;
    let header_size = ftyp
        .size(limit)?
        .checked_add(moov.size(limit)?)
        .and_then(|n| n.checked_add(16))
        .ok_or(Error::Limit)?;
    if header_size > limit {
        return Err(Error::Limit);
    }
    for trak in moov
        .children
        .iter_mut()
        .filter(|node| &node.kind == b"trak")
    {
        let offsets = &mut trak
            .get_mut(b"mdia")?
            .get_mut(b"minf")?
            .get_mut(b"stbl")?
            .get_mut(b"co64")?
            .data;
        for chunk in offsets[8..].chunks_exact_mut(8) {
            reader.check()?;
            let old = u64::from_be_bytes(chunk.try_into().map_err(|_| Error::Malformed)?);
            let new = old
                .checked_sub(first)
                .and_then(|n| n.checked_add(header_size as u64))
                .ok_or(Error::Malformed)?;
            chunk.copy_from_slice(&new.to_be_bytes());
        }
    }
    let mut prefix = Vec::with_capacity(header_size);
    ftyp.write(&mut prefix, limit)?;
    moov.write(&mut prefix, limit)?;
    let payload = mdat.1 - first;
    prefix.extend_from_slice(&1u32.to_be_bytes());
    prefix.extend_from_slice(b"mdat");
    prefix.extend_from_slice(&(payload + 16).to_be_bytes());
    Ok(Segment {
        prefix,
        offset: first,
        len: payload,
    })
}

/// 业务作用：验证单轨道的时间、数据来源及全部样本位置，不能引用 mdat 之外的文件内容。
///
/// 参数说明：
/// - `node`：唯一轨道树。
/// - `reader`：跨轨道共享的样本及期限预算。
/// - `mdat`：唯一媒体数据区的起止位置。
///
/// 返回：可安全裁剪的视频或音频轨道；外部引用、加密或其它布局回落原文件。
fn track(node: Node, reader: &mut Reader, mdat: (u64, u64)) -> Result<Track> {
    node.allow(&[*b"tkhd", *b"edts", *b"mdia", *b"udta"])?;
    let (_, duration) = clock(&node.get(b"tkhd")?.data, true)?;
    let edit = if let Some(edts) = node.optional(b"edts")? {
        edit_time(edts, duration)?
    } else {
        0
    };
    let mdia = node.get(b"mdia")?;
    mdia.allow(&[*b"mdhd", *b"hdlr", *b"minf"])?;
    let (scale, declared) = clock(&mdia.get(b"mdhd")?.data, false)?;
    if scale == 0 || duration == 0 {
        return Err(Error::Malformed);
    }
    let handler = mdia.get(b"hdlr")?.data.get(8..12).ok_or(Error::Malformed)?;
    let video = match handler {
        b"vide" => true,
        b"soun" => false,
        _ => return Err(Error::Unsupported),
    };
    let minf = mdia.get(b"minf")?;
    minf.allow(&[*b"vmhd", *b"smhd", *b"dinf", *b"stbl"])?;
    let dinf = minf.get(b"dinf")?;
    dinf.allow(&[*b"dref"])?;
    let dref = &dinf.get(b"dref")?.data;
    if dref.len() != 20
        || u32_at(dref, 0)? != 0
        || u32_at(dref, 4)? != 1
        || u32_at(dref, 8)? != 12
        || dref.get(12..16) != Some(b"url ")
        || u32_at(dref, 16)? != 1
    {
        return Err(Error::Unsupported);
    }
    let stbl = minf.get(b"stbl")?;
    stbl.allow(&[
        *b"stsd", *b"stts", *b"ctts", *b"stsc", *b"stsz", *b"stco", *b"co64", *b"stss", *b"sgpd",
        *b"sbgp",
    ])?;
    sample_description(stbl.get(b"stsd")?, video, reader)?;
    let sizes = &stbl.get(b"stsz")?.data;
    if u32_at(sizes, 0)? != 0 {
        return Err(Error::Unsupported);
    }
    let fixed = u32_at(sizes, 4)?;
    let count = u32_at(sizes, 8)? as usize;
    reader.samples(count)?;
    if count == 0
        || sizes.len()
            != 12
                + if fixed == 0 {
                    count * 4
                } else {
                    0
                }
    {
        return Err(Error::Malformed);
    }
    let durations = expand(stbl.get(b"stts")?, count, false)?;
    let composition = stbl
        .optional(b"ctts")?
        .map(|node| expand(node, count, true))
        .transpose()?;
    let mut samples = Vec::with_capacity(count);
    let mut dts = 0u64;
    for (index, duration) in durations.into_iter().enumerate() {
        reader.check()?;
        let size = if fixed == 0 {
            u32_at(sizes, 12 + index * 4)?
        } else {
            fixed
        };
        if duration == 0 || size == 0 {
            return Err(Error::Malformed);
        }
        samples.push(Sample {
            offset: 0,
            dts,
            duration,
            size,
            cts: composition.as_ref().map_or(0, |values| values[index]),
            sync: !video,
        });
        dts = dts.checked_add(duration as u64).ok_or(Error::Malformed)?;
    }
    if dts != declared {
        return Err(Error::Malformed);
    }
    if let Some(stss) = stbl.optional(b"stss")? {
        let data = &stss.data;
        let entries = u32_at(data, 4)? as usize;
        if u32_at(data, 0)? != 0 || entries > count || data.len() != 8 + entries * 4 {
            return Err(Error::Malformed);
        }
        let mut previous = 0;
        for index in 0..entries {
            let sample = u32_at(data, 8 + index * 4)? as usize;
            if sample <= previous || sample > count {
                return Err(Error::Malformed);
            }
            samples[sample - 1].sync = true;
            previous = sample;
        }
    } else {
        for sample in &mut samples {
            sample.sync = true;
        }
    }
    offsets(stbl, &mut samples, mdat, reader)?;
    roll_groups(stbl, count, video)?;
    Ok(Track {
        node,
        samples,
        scale,
        edit,
        duration,
        video,
    })
}

/// 业务作用：展开受样本总量约束的游程表，表长与声明数量必须完全一致。
///
/// 参数说明：
/// - `node`：stts 或 ctts 表。
/// - `count`：已准入的轨道样本数。
/// - `composition`：是否读取非负合成偏移。
///
/// 返回：恰好覆盖全部样本的值；负 CTS 布局保持原文件处理。
fn expand(node: &Node, count: usize, composition: bool) -> Result<Vec<u32>> {
    let data = &node.data;
    if u32_at(data, 0)? != 0 {
        return Err(if composition {
            Error::Unsupported
        } else {
            Error::Malformed
        });
    }
    let entries = u32_at(data, 4)? as usize;
    if entries > count || data.len() != 8 + entries * 8 {
        return Err(Error::Malformed);
    }
    let mut result = Vec::with_capacity(count);
    for index in 0..entries {
        let n = u32_at(data, 8 + index * 8)? as usize;
        let value = u32_at(data, 12 + index * 8)?;
        if n == 0 || n > count - result.len() {
            return Err(Error::Malformed);
        }
        result.resize(result.len() + n, value);
    }
    if result.len() != count {
        return Err(Error::Malformed);
    }
    Ok(result)
}

/// 业务作用：验证唯一内置编码描述及其子结构，外部数据或保护封装不参与裁剪。
///
/// 参数说明：
/// - `node`：唯一 stsd 描述。
/// - `video`：轨道类型是否为视频。
/// - `reader`：结构计数和深度预算。
///
/// 返回：avc1 视频或 mp4a 音频的单一自包含描述。
fn sample_description(node: &Node, video: bool, reader: &mut Reader) -> Result<()> {
    let data = &node.data;
    if u32_at(data, 0)? != 0 || u32_at(data, 4)? != 1 {
        return Err(Error::Unsupported);
    }
    let size = u32_at(data, 8)? as usize;
    if size != data.len() - 8 {
        return Err(Error::Malformed);
    }
    let entry = &data[8..];
    let base = if video {
        86
    } else {
        36
    };
    if entry.len() < base || entry.get(14..16) != Some(&[0, 1]) {
        return Err(Error::Unsupported);
    }
    if entry.get(4..8)
        != Some(if video {
            b"avc1"
        } else {
            b"mp4a"
        })
    {
        return Err(Error::Unsupported);
    }
    if !video && entry.get(16..18) != Some(&[0, 0]) {
        return Err(Error::Unsupported);
    }
    let children = boxes::parse(&entry[base..], reader, 8)?;
    let container = Node::container(*b"stsd", children);
    container.allow(&[*b"avcC", *b"esds", *b"btrt", *b"pasp", *b"colr", *b"fiel"])?;
    container.get(if video {
        b"avcC"
    } else {
        b"esds"
    })?;
    Ok(())
}

/// 业务作用：将 chunk 表映射到每个样本并核对长度，任何索引均不得越出唯一媒体区。
///
/// 参数说明：
/// - `stbl`：完整样本表容器。
/// - `samples`：已验证长度和时序的样本列表。
/// - `mdat`：允许访问的媒体载荷范围。
/// - `reader`：期限和取消上下文。
///
/// 返回：每个样本得到唯一原文件偏移；重复、倒序或越界拒绝。
fn offsets(stbl: &Node, samples: &mut [Sample], mdat: (u64, u64), reader: &Reader) -> Result<()> {
    let short = stbl.optional(b"stco")?;
    let long = stbl.optional(b"co64")?;
    if short.is_some() == long.is_some() {
        return Err(Error::Malformed);
    }
    let data = &short.or(long).ok_or(Error::Malformed)?.data;
    let width = if short.is_some() {
        4
    } else {
        8
    };
    let chunks = u32_at(data, 4)? as usize;
    if u32_at(data, 0)? != 0
        || chunks == 0
        || chunks > samples.len()
        || data.len() != 8 + chunks * width
    {
        return Err(Error::Malformed);
    }
    let map = &stbl.get(b"stsc")?.data;
    let entries = u32_at(map, 4)? as usize;
    if u32_at(map, 0)? != 0 || entries == 0 || entries > chunks || map.len() != 8 + entries * 12 {
        return Err(Error::Malformed);
    }
    let mut rules = Vec::with_capacity(entries);
    let mut previous = 0;
    for index in 0..entries {
        let first = u32_at(map, 8 + index * 12)? as usize;
        let n = u32_at(map, 12 + index * 12)? as usize;
        if first <= previous
            || first > chunks
            || n == 0
            || n > samples.len()
            || u32_at(map, 16 + index * 12)? != 1
        {
            return Err(Error::Malformed);
        }
        rules.push((first, n));
        previous = first;
    }
    if rules[0].0 != 1 {
        return Err(Error::Malformed);
    }
    let mut rule = 0;
    let mut sample = 0;
    let mut end = mdat.0;
    for chunk in 1..=chunks {
        reader.check()?;
        if rule + 1 < rules.len() && rules[rule + 1].0 == chunk {
            rule += 1;
        }
        let mut offset = if width == 4 {
            u32_at(data, 8 + (chunk - 1) * 4)? as u64
        } else {
            u64_at(data, 8 + (chunk - 1) * 8)?
        };
        if offset < end {
            return Err(Error::Unsupported);
        }
        for _ in 0..rules[rule].1 {
            let value = samples.get_mut(sample).ok_or(Error::Malformed)?;
            value.offset = offset;
            offset = offset
                .checked_add(value.size as u64)
                .ok_or(Error::Malformed)?;
            if offset > mdat.1 {
                return Err(Error::Malformed);
            }
            sample += 1;
        }
        end = offset;
    }
    if sample != samples.len() {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// 业务作用：只接受可由一个音频预卷样本覆盖的 AAC roll 描述，未知分组保留原布局。
///
/// 参数说明：
/// - `stbl`：音视频样本表。
/// - `count`：已验证样本总数。
/// - `video`：视频不接受音频预卷分组。
///
/// 返回：无分组或单一有限 roll 描述时成功。
fn roll_groups(stbl: &Node, count: usize, video: bool) -> Result<()> {
    let group = stbl.optional(b"sgpd")?;
    let map = stbl.optional(b"sbgp")?;
    if group.is_none() && map.is_none() {
        return Ok(());
    }
    if video {
        return Err(Error::Unsupported);
    }
    let group = &group.ok_or(Error::Unsupported)?.data;
    let map = &map.ok_or(Error::Unsupported)?.data;
    if group.len() != 18
        || u32_at(group, 0)? != 0x01000000
        || group.get(4..8) != Some(b"roll")
        || u32_at(group, 8)? != 2
        || u32_at(group, 12)? != 1
        || !matches!(group.get(16..18), Some([0, 0]) | Some([255, 255]))
    {
        return Err(Error::Unsupported);
    }
    let entries = u32_at(map, 8)? as usize;
    if u32_at(map, 0)? != 0
        || map.get(4..8) != Some(b"roll")
        || entries > count
        || map.len() != 12 + entries * 8
    {
        return Err(Error::Unsupported);
    }
    let mut total = 0u64;
    for index in 0..entries {
        total += u32_at(map, 12 + index * 8)? as u64;
        if u32_at(map, 16 + index * 8)? > 1 {
            return Err(Error::Unsupported);
        }
    }
    if total != count as u64 {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// 业务作用：读取单段正常速率 edit list，复杂拼接与空白编辑不猜测映射。
///
/// 参数说明：
/// - `node`：轨道 edts 容器。
/// - `duration`：tkhd 声明的可见时长，必须与唯一编辑段一致。
///
/// 返回：原始媒体起点；复杂布局返回不支持。
fn edit_time(node: &Node, duration: u64) -> Result<u64> {
    node.allow(&[*b"elst"])?;
    let data = &node.get(b"elst")?.data;
    if u32_at(data, 4)? != 1 {
        return Err(Error::Unsupported);
    }
    match u32_at(data, 0)? {
        0 if data.len() == 20 && u32_at(data, 16)? == 65536 => {
            if u32_at(data, 8)? as u64 != duration {
                return Err(Error::Unsupported);
            }
            let value = u32_at(data, 12)?;
            if value > i32::MAX as u32 {
                Err(Error::Unsupported)
            } else {
                Ok(value as u64)
            }
        }
        0x01000000 if data.len() == 28 && u32_at(data, 24)? == 65536 => {
            if u64_at(data, 8)? != duration {
                return Err(Error::Unsupported);
            }
            let value = u64_at(data, 16)?;
            if value > i64::MAX as u64 {
                Err(Error::Unsupported)
            } else {
                Ok(value)
            }
        }
        _ => Err(Error::Unsupported),
    }
}
/// 业务作用：读取标准时基和时长，保持版本字段的真实宽度。
///
/// 参数说明：
/// - `data`：mvhd、mdhd 或 tkhd 内容。
/// - `track_header`：tkhd 的时长使用 movie 时基，不含自身 scale。
///
/// 返回：时基及持续时长；未知版本回落，字段截断拒绝。
fn clock(data: &[u8], track_header: bool) -> Result<(u32, u64)> {
    let version = *data.first().ok_or(Error::Malformed)?;
    let offset = match (version, track_header) {
        (0, false) => 16,
        (1, false) => 24,
        (0, true) => 20,
        (1, true) => 28,
        _ => return Err(Error::Unsupported),
    };
    let duration = if version == 0 {
        u32_at(data, offset)? as u64
    } else {
        u64_at(data, offset)?
    };
    let scale = if track_header {
        0
    } else {
        u32_at(data, offset - 4)?
    };
    Ok((scale, duration))
}
/// 业务作用：在原头版本内更新持续时间，不能截断 64 位时长或改变其它显示属性。
///
/// 参数说明：
/// - `data`：已经验证的时间头。
/// - `track_header`：是否为 tkhd。
/// - `duration`：对应时基中的新时长。
///
/// 返回：完整更新时间字段，不能表示时回落原文件。
fn set_duration(data: &mut [u8], track_header: bool, duration: u64) -> Result<()> {
    clock(data, track_header)?;
    let version = data[0];
    let offset = match (version, track_header) {
        (0, false) => 16,
        (1, false) => 24,
        (0, true) => 20,
        (1, true) => 28,
        _ => return Err(Error::Unsupported),
    };
    if version == 0 {
        data[offset..offset + 4].copy_from_slice(
            &u32::try_from(duration)
                .map_err(|_| Error::Unsupported)?
                .to_be_bytes(),
        );
    } else {
        data[offset..offset + 8].copy_from_slice(&duration.to_be_bytes());
    }
    Ok(())
}
/// 业务作用：把公开微秒参数精确换算到轨道时基，不使用浮点舍入决定样本边界。
///
/// 参数说明：
/// - `us`：非负微秒。
/// - `scale`：已验证的每秒 tick 数。
///
/// 返回：向下取整的 tick；无法表示时拒绝起播位置。
fn ticks(us: u64, scale: u32) -> Result<u64> {
    u64::try_from(us as u128 * scale as u128 / 1_000_000).map_err(|_| Error::Position)
}

/// 业务作用：用剩余样本重新构造时间、大小及定位表，edit list 隐藏解码前卷而保留请求时间。
///
/// 参数说明：
/// - `track`：已经裁剪到所需同步样本的轨道。
/// - `media_time`：裁剪后解码时间线上可见起点。
/// - `display_duration`：movie 时基下的可见时长。
///
/// 返回：轨道保持原编码描述，样本索引只指向保留的媒体实体。
fn rewrite(track: &mut Track, media_time: u64, display_duration: u64) -> Result<()> {
    let duration = track
        .samples
        .iter()
        .map(|sample| sample.duration as u64)
        .sum();
    let mdia = track.node.get_mut(b"mdia")?;
    set_duration(&mut mdia.get_mut(b"mdhd")?.data, false, duration)?;
    let stbl = mdia.get_mut(b"minf")?.get_mut(b"stbl")?;
    let stsd = stbl
        .children
        .iter()
        .position(|node| &node.kind == b"stsd")
        .ok_or(Error::Malformed)?;
    let description = stbl.children.remove(stsd);
    stbl.children = vec![description];
    stbl.children.push(runs(
        *b"stts",
        track.samples.iter().map(|sample| sample.duration),
    ));
    if track.samples.iter().any(|sample| sample.cts != 0) {
        stbl.children.push(runs(
            *b"ctts",
            track.samples.iter().map(|sample| sample.cts),
        ));
    }
    let mut sizes = vec![0; 8];
    sizes.extend_from_slice(&(track.samples.len() as u32).to_be_bytes());
    let mut offsets = vec![0; 4];
    offsets.extend_from_slice(&(track.samples.len() as u32).to_be_bytes());
    let mut sync = vec![0; 8];
    let mut sync_count = 0u32;
    for (index, sample) in track.samples.iter().enumerate() {
        sizes.extend_from_slice(&sample.size.to_be_bytes());
        offsets.extend_from_slice(&sample.offset.to_be_bytes());
        if sample.sync {
            sync.extend_from_slice(&((index + 1) as u32).to_be_bytes());
            sync_count += 1;
        }
    }
    sync[4..8].copy_from_slice(&sync_count.to_be_bytes());
    stbl.children.push(Node::leaf(*b"stsz", sizes));
    stbl.children.push(Node::leaf(*b"co64", offsets));
    stbl.children.push(Node::leaf(
        *b"stsc",
        [0u32, 1, 1, 1, 1]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect(),
    ));
    if track.video {
        stbl.children.push(Node::leaf(*b"stss", sync));
    }
    set_duration(
        &mut track.node.get_mut(b"tkhd")?.data,
        true,
        display_duration,
    )?;
    if media_time > i64::MAX as u64 {
        return Err(Error::Unsupported);
    }
    let mut edit = vec![1, 0, 0, 0];
    edit.extend_from_slice(&1u32.to_be_bytes());
    edit.extend_from_slice(&display_duration.to_be_bytes());
    edit.extend_from_slice(&media_time.to_be_bytes());
    edit.extend_from_slice(&65536u32.to_be_bytes());
    track.node.children.retain(|node| &node.kind != b"edts");
    track
        .node
        .children
        .push(Node::container(*b"edts", vec![Node::leaf(*b"elst", edit)]));
    Ok(())
}
/// 业务作用：把逐样本时序重新压成标准游程，不复制媒体实体。
///
/// 参数说明：
/// - `kind`：stts 或 ctts 类型。
/// - `values`：有界样本的持续时间或合成偏移。
///
/// 返回：覆盖全部保留样本的规范游程表。
fn runs(kind: [u8; 4], values: impl Iterator<Item = u32>) -> Node {
    let mut data = vec![0; 8];
    let mut entries = 0u32;
    let mut previous = None;
    let mut count = 0u32;
    for value in values {
        if previous == Some(value) {
            count += 1;
            continue;
        }
        if let Some(value) = previous {
            data.extend_from_slice(&count.to_be_bytes());
            data.extend_from_slice(&value.to_be_bytes());
            entries += 1;
        }
        previous = Some(value);
        count = 1;
    }
    if let Some(value) = previous {
        data.extend_from_slice(&count.to_be_bytes());
        data.extend_from_slice(&value.to_be_bytes());
        entries += 1;
    }
    data[4..8].copy_from_slice(&entries.to_be_bytes());
    Node::leaf(kind, data)
}
