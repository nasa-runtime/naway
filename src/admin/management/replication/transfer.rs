//! 有界 gRPC 配置原文传输，只接受完整且摘要一致的记录。

use anyhow::{ensure, Context, Result};
use futures::Stream;
use nasa::grpc::{Status, Streaming};
use std::collections::BTreeMap;
use std::sync::Arc;

use super::super::protocol::{self, named_config_frame::Value};
use super::ledger::{self, Hash, Revision};
use crate::config::replication::{
    Document, Generation, Name, MAX_TRANSFER_BYTES, MAX_TRANSFER_DOCUMENTS,
};

const PART_BYTES: usize = 24 * 1024;

pub(super) struct Incoming {
    pub(super) history: Vec<Revision>,
    files: Vec<File>,
}

struct File {
    name: Name,
    bytes: usize,
    digest: Hash,
}

struct Cursor {
    offer: Option<protocol::NamedConfigOffer>,
    files: Vec<Arc<[u8]>>,
    index: usize,
    offset: usize,
}

impl Incoming {
    /// 业务作用：允许接收端在分配原文空间前验证文档名、大小和历史身份。
    /// 参数说明：
    /// - `offer`：已和 mTLS 会话核对的传输头。
    /// 返回：经过完整有界校验的接收计划。重复或乱序文档不得进入正文接收。
    pub(super) fn accept(offer: protocol::NamedConfigOffer) -> Result<Self> {
        ensure!(
            (2..=MAX_TRANSFER_DOCUMENTS).contains(&offer.documents.len()),
            "invalid document count"
        );
        ensure!(
            (1..=ledger::LIMIT).contains(&offer.lineage.len()),
            "invalid revision count"
        );
        let mut history = Vec::with_capacity(offer.lineage.len());
        for revision in offer.lineage {
            history.push(Revision {
                id: hash(&revision.id)?,
                parent: hash(&revision.parent)?,
                content: hash(&revision.content_sha256)?,
            });
        }
        ledger::validate(&history)?;
        let mut total = 0usize;
        let mut files: Vec<File> = Vec::with_capacity(offer.documents.len());
        for document in offer.documents {
            let name = Name::new(document.entry, document.name)?;
            ensure!(
                files.last().is_none_or(|file| file.name < name),
                "document order differs"
            );
            let bytes = document.bytes as usize;
            total = total.checked_add(bytes).context("document size overflow")?;
            ensure!(
                bytes <= crate::config::document::MAX_DOCUMENT_BYTES && total <= MAX_TRANSFER_BYTES,
                "document transfer exceeds size budget"
            );
            files.push(File {
                name,
                bytes,
                digest: hash(&document.content_sha256)?,
            });
        }
        ensure!(files[0].name == Name::Entry, "configuration entry missing");
        Ok(Self {
            history,
            files,
        })
    }

    /// 业务作用：逐正文段校验索引、偏移、摘要及整组身份，仅完整内容可以提交。
    /// 参数说明：
    /// - `stream`：完成身份和基线验证的当前网络流。
    /// 返回：网络流结束且所有文档和目标代匹配时返回候选。
    pub(super) async fn receive(
        &self,
        mut stream: Streaming<protocol::NamedConfigFrame>,
    ) -> Result<Generation, Status> {
        let mut documents = BTreeMap::new();
        for (index, file) in self.files.iter().enumerate() {
            let mut body = Vec::with_capacity(file.bytes);
            while body.len() < file.bytes {
                let part = match stream.message().await?.and_then(|frame| frame.value) {
                    Some(Value::Part(part)) => part,
                    _ => {
                        return Err(Status::invalid_argument(
                            "named configuration body incomplete",
                        ))
                    }
                };
                if part.document as usize != index
                    || part.offset as usize != body.len()
                    || part.body.is_empty()
                    || part.body.len() > PART_BYTES.min(file.bytes - body.len())
                {
                    return Err(Status::invalid_argument(
                        "named configuration body boundary differs",
                    ));
                }
                body.extend_from_slice(&part.body);
            }
            let document = Document::from_bytes(body.into(), Some(file.digest)).map_err(|_| {
                Status::invalid_argument("named configuration document identity differs")
            })?;
            documents.insert(file.name.clone(), document);
        }
        if stream.message().await?.is_some() {
            return Err(Status::invalid_argument(
                "unexpected named configuration body",
            ));
        }
        let generation = Generation::build(documents)
            .map_err(|_| Status::invalid_argument("invalid named configuration generation"))?;
        if self
            .history
            .last()
            .is_none_or(|target| target.content != generation.digest)
        {
            return Err(Status::invalid_argument(
                "named configuration generation identity differs",
            ));
        }
        Ok(generation)
    }
}

/// 业务作用：以固定大小和次序产生逐段原文，避免按节点预先复制整个配置集合。
/// 参数说明：
/// - `sender`：已通过固定管理通道建立并认证的启动会话。
/// - `lineage`：与原文在同一持久记录中取得的复制历史。
/// - `generation`：本机当前已完整应用的不可变原文集合。
/// 返回：一个传输头及每份文档的非空有界正文段。
pub(super) fn outgoing(
    sender: protocol::NamedConfigSession,
    lineage: &[Revision],
    generation: &Generation,
) -> impl Stream<Item = protocol::NamedConfigFrame> + Send + 'static {
    let documents = generation
        .documents
        .iter()
        .map(|(name, document)| protocol::NamedConfigDocument {
            entry: *name == Name::Entry,
            name: name.as_str().to_owned(),
            bytes: document.body.len() as u32,
            content_sha256: document.digest.to_vec(),
        })
        .collect();
    let cursor = Cursor {
        offer: Some(protocol::NamedConfigOffer {
            sender: Some(sender),
            lineage: lineage
                .iter()
                .map(|entry| protocol::NamedConfigRevision {
                    id: entry.id.to_vec(),
                    parent: entry.parent.to_vec(),
                    content_sha256: entry.content.to_vec(),
                })
                .collect(),
            documents,
        }),
        files: generation
            .documents
            .values()
            .map(|document| document.body.clone())
            .collect(),
        index: 0,
        offset: 0,
    };
    futures::stream::unfold(cursor, |mut state| async move {
        if let Some(offer) = state.offer.take() {
            return Some((
                protocol::NamedConfigFrame {
                    value: Some(Value::Offer(offer)),
                },
                state,
            ));
        }
        let body = loop {
            let bytes = state.files.get(state.index)?;
            if state.offset < bytes.len() {
                break &bytes[state.offset..(state.offset + PART_BYTES).min(bytes.len())];
            }
            state.index += 1;
            state.offset = 0;
        };
        let part = protocol::NamedConfigPart {
            document: state.index as u32,
            offset: state.offset as u32,
            body: body.to_vec(),
        };
        state.offset += body.len();
        Some((
            protocol::NamedConfigFrame {
                value: Some(Value::Part(part)),
            },
            state,
        ))
    })
}

/// 业务作用：限制传输身份的固定 SHA-256 宽度。
/// 参数说明：
/// - `bytes`：网络传输的摘要字节。
/// 返回：精确的摘要值，长度不符时拒绝。
pub(super) fn hash(bytes: &[u8]) -> Result<Hash> {
    bytes
        .try_into()
        .context("invalid named configuration digest length")
}
