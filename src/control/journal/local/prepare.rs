//! 在持久决定之前捕获完整基线和候选，不触碰活动文件或暂存路径。

use super::model::{
    mode, stage_name, Body, Destination, Direction, Document, FileState, Location, Plan, LIMIT,
};
use crate::control::documents::{Fingerprint, Target};
use anyhow::{ensure, Result};
use cap_std::fs::File;
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub(crate) struct Input<'a> {
    pub(crate) current: [&'a Path; 3],
    pub(crate) targets: [&'a Path; 3],
    pub(crate) baseline: Option<[&'a [u8]; 3]>,
    pub(crate) desired: [Option<&'a [u8]>; 3],
    pub(crate) candidate: Option<&'a crate::config::GatewaySnapshot>,
}

pub(super) enum Source<'a> {
    File(File),
    Bytes(&'a [u8]),
}

pub(in crate::control::journal) struct Prepared<'a> {
    pub(in crate::control::journal) plan: Plan,
    pub(super) sources: Vec<(Body, Source<'a>)>,
}

impl<'a> Prepared<'a> {
    /// 业务作用：冻结三份基线、候选和目标原存在状态，正文只保留借用或文件句柄。
    ///
    /// 参数说明：
    /// - `input`：当前与候选明确路径，以及可选的已验证原文借用。
    ///
    /// 返回：完整计划及流式来源；基线或新目标冲突返回空，文件边界异常拒绝。
    pub(in crate::control::journal) fn new(input: Input<'a>) -> Result<Option<Self>> {
        let mut sources = Vec::with_capacity(6);
        let mut baseline = Vec::with_capacity(3);
        for (index, path) in input.current.iter().enumerate() {
            let target = Target::open(path)?;
            let Some((source, fingerprint, mode)) = capture(&target)? else {
                return Ok(None);
            };
            if input
                .baseline
                .as_ref()
                .is_some_and(|expected| Fingerprint::of(expected[index]) != fingerprint)
            {
                return Ok(None);
            }
            let body = retain(&mut sources, index as u8, fingerprint, source);
            baseline.push(Document {
                location: Location::capture(&target)?,
                state: FileState {
                    body,
                    mode,
                },
            });
        }
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| anyhow::anyhow!("local publication randomness unavailable"))?;
        let operation = hex(&random);
        let mut targets = Vec::with_capacity(3);
        for (index, path) in input.targets.iter().enumerate() {
            let target = Target::open(path)?;
            let location = Location::capture(&target)?;
            let existing = capture(&target)?;
            let (source, fingerprint) = match input.desired[index] {
                Some(bytes) => {
                    ensure!(bytes.len() <= LIMIT, "configuration document exceeds limit");
                    (Source::Bytes(bytes), Fingerprint::of(bytes))
                }
                None => {
                    let Some((source, fingerprint, _)) = capture(&target)? else {
                        return Ok(None);
                    };
                    (source, fingerprint)
                }
            };
            let body = retain(&mut sources, (index + 3) as u8, fingerprint, source);
            let candidate = FileState {
                body,
                mode: existing.as_ref().map_or(0o600, |entry| entry.2),
            };
            let original = if location.path == baseline[index].location.path {
                if existing.as_ref().is_none_or(|entry| {
                    entry.1 != baseline[index].state.body.fingerprint
                        || entry.2 != baseline[index].state.mode
                }) {
                    return Ok(None);
                }
                Some(baseline[index].state)
            } else {
                // 新引用文件只有内容恰好等于候选才纳入事务，其原存在状态不能在补偿时被删除。
                match existing {
                    Some((_, actual, _)) if actual != fingerprint => return Ok(None),
                    Some(_) => Some(candidate),
                    None => None,
                }
            };
            targets.push(Destination {
                location,
                original,
                candidate,
                forward_stage: stage_name(&operation, index, Direction::Forward),
                backward_stage: stage_name(&operation, index, Direction::Backward),
            });
        }
        let plan = Plan {
            operation,
            direction: Direction::Preparing,
            baseline: baseline
                .try_into()
                .map_err(|_| anyhow::anyhow!("local publication baseline count differs"))?,
            targets: targets
                .try_into()
                .map_err(|_| anyhow::anyhow!("local publication target count differs"))?,
        };
        plan.validate()?;
        if let Some(candidate) = input.candidate {
            let mut decided = plan.clone();
            decided.direction = Direction::Forward;
            super::require_snapshot(&decided, candidate)?;
        }
        if !baseline_matches(&plan)? {
            return Ok(None);
        }
        Ok(Some(Self {
            plan,
            sources,
        }))
    }
}

/// 业务作用：在决定提交之前复验完整旧集合，已退出引用的文件同样不能在规划期间悄然变化。
///
/// 参数说明：
/// - `plan`：尚未修改目标的已冻结计划。
///
/// 返回：所有基线和目标原存在状态均相同为真；任何边界异常拒绝。
pub(in crate::control::journal) fn baseline_matches(plan: &Plan) -> Result<bool> {
    for old in &plan.baseline {
        if !matches(&old.location.open()?, Some(old.state))? {
            return Ok(false);
        }
    }
    for target in &plan.targets {
        if !matches(&target.location.open()?, target.original)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// 业务作用：以完整摘要、权限与存在状态比较实际目标，缺失不等于空正文。
///
/// 参数说明：
/// - `target`：已经复验父目录的目标。
/// - `expected`：期望的文件身份，空表示必须缺失。
///
/// 返回：目标准确匹配时为真，特殊类型或读取失败拒绝。
pub(super) fn matches(target: &Target, expected: Option<FileState>) -> Result<bool> {
    let permissions = expected
        .map(|state| super::model::permissions(state.mode))
        .transpose()?;
    target.matches(
        expected
            .zip(permissions.as_ref())
            .map(|(state, permissions)| (state.body.fingerprint, permissions)),
    )
}

/// 业务作用：捕获有界实际文件的原文身份和流式来源，不为恢复再保留全文副本。
///
/// 参数说明：
/// - `target`：明确的单个配置位置。
///
/// 返回：缺失为空，成功返回已回到起点的句柄、摘要和权限，读取不稳定时拒绝。
fn capture(target: &Target) -> Result<Option<(Source<'static>, Fingerprint, u32)>> {
    let Some((mut file, metadata)) = target.file()? else {
        return Ok(None);
    };
    let fingerprint = Fingerprint::read(&mut file)?;
    ensure!(
        fingerprint.length == metadata.len() && file.metadata()?.len() == metadata.len(),
        "local publication source changed while reading"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(Some((
        Source::File(file),
        fingerprint,
        mode(&metadata.permissions())?,
    )))
}

/// 业务作用：完全相同的原文共享固定正文引用，权限仍由各自文件状态独立保存。
///
/// 参数说明：
/// - `sources`：本次计划已保留的有界来源集合。
/// - `slot`：该角色首选的固定正文槽。
/// - `fingerprint`：完整原文身份。
/// - `source`：借用原文或已打开的来源句柄。
///
/// 返回：已有相同摘要的引用或新保留引用，不额外复制正文。
fn retain<'a>(
    sources: &mut Vec<(Body, Source<'a>)>,
    slot: u8,
    fingerprint: Fingerprint,
    source: Source<'a>,
) -> Body {
    if let Some((body, _)) = sources
        .iter()
        .find(|(body, _)| body.fingerprint == fingerprint)
    {
        return *body;
    }
    let body = Body {
        slot,
        fingerprint,
    };
    sources.push((body, source));
    body
}

/// 业务作用：将固定长度随机身份编码为安全的协议名字，不引入可解释的外部路径字符。
///
/// 参数说明：
/// - `bytes`：本次操作的随机字节。
///
/// 返回：小写十六进制操作身份。
fn hex(bytes: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(32);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("writing to a string cannot fail");
    }
    value
}

impl Read for Source<'_> {
    /// 业务作用：统一借用原文与文件来源的流式接口，正文存储无需区分或重新编码输入。
    ///
    /// 参数说明：
    /// - `buffer`：调用方提供的固定容量接收缓冲。
    ///
    /// 返回：本次读取的字节数或原来源错误，推进来源位置。
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.read(buffer),
            Self::Bytes(bytes) => bytes.read(buffer),
        }
    }
}
