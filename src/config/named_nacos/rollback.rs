//! 具名 Nacos 的整代原文回滚及提交条件。

use super::*;

impl NamedNacos {
    /// 业务作用：绑定有效提交标记与整代目标，预读所有将写入 Data ID 的条件。
    /// 参数说明：
    /// - `active`：已完成整代构建和授权时的配置基线。
    /// - `target`：匹配当前清单且完整验证过的归档模块。
    /// 返回：可安全提交或续办时给出所有比较条件，远端漂移或其它未完成意图时为空。
    pub(crate) async fn prepare_rollback(
        &self,
        active: &GatewaySnapshot,
        mut target: BTreeMap<String, String>,
    ) -> Result<Option<Rollback>> {
        let plan = self.plan.current(&self.entry)?;
        let id = plan
            .revision
            .as_ref()
            .context("named Nacos rollback requires a revision marker")?;
        let group = &plan.connection.group;
        let client = connect(&plan).await?;
        let mut remote = fetch_bundle(&client, &plan.refs).await?;
        let (mut head, expected_md5) = read_revision(&client, id, group).await?;
        let documents = target
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    format!("{:x}", Sha256::digest(value.as_bytes())),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if !documents.keys().eq(head.documents.keys()) {
            return Ok(None);
        }
        let changed = documents
            .iter()
            .filter(|(name, digest)| head.documents.get(*name) != Some(*digest))
            .map(|(name, digest)| (name.clone(), digest.clone()))
            .collect::<BTreeMap<_, _>>();
        if changed.is_empty() {
            return Ok(None);
        }
        let current = bundle_digests(&remote);
        let claimed = match &head.pending {
            None if current == head.documents => {
                head.pending = Some(PendingRevision::Batch(PendingBatch {
                    id: revision_intent_id()?,
                    replacements: changed.clone(),
                }));
                false
            }
            Some(PendingRevision::Batch(batch))
                if batch.replacements == changed && current == documents =>
            {
                // 已持久化的完整候选可续办标记。只从活动原文重建校验基线，不再次写业务 Data ID。
                for doc in &mut remote.documents {
                    let name = &doc.source.data_id;
                    if changed.contains_key(name) {
                        let prior = active
                            .named_documents
                            .iter()
                            .find(|module| &module.name == name)
                            .and_then(|module| module.content.as_deref())
                            .context("rollback baseline document unavailable")?;
                        doc.content = prior.to_owned();
                    }
                }
                if bundle_digests(&remote) != head.documents {
                    return Ok(None);
                }
                true
            }
            _ => return Ok(None),
        };
        // 标记与远端集合的相等不能代替本机活动代复验，节点间传播尚在进行时拒绝旧授权。
        if self.storage.active_directory_for(active).as_ref()
            != Some(&self.storage.generation(&plan, &remote))
        {
            return Ok(None);
        }
        let writes = tokio::time::timeout(READ_TIMEOUT, async {
            let mut writes = Vec::with_capacity(changed.len());
            for doc in &mut remote.documents {
                let name = &doc.source.data_id;
                if !changed.contains_key(name) {
                    continue;
                }
                let body = target
                    .remove(name)
                    .context("missing rollback candidate document")?;
                if !claimed {
                    let document_group = doc
                        .source
                        .group
                        .as_deref()
                        .context("Nacos module is missing a group")?;
                    let Some((raw, md5)) =
                        client.fetch_optional_with_md5(name, document_group).await?
                    else {
                        return Ok(None);
                    };
                    if raw != doc.content {
                        return Ok(None);
                    }
                    writes.push(RollbackWrite {
                        name: name.clone(),
                        group: document_group.to_owned(),
                        md5,
                        body: body.clone(),
                    });
                }
                doc.content = body;
            }
            Ok::<_, anyhow::Error>(Some(writes))
        })
        .await??;
        let Some(writes) = writes else {
            return Ok(None);
        };
        let generation = self
            .storage
            .generation(&plan, &remote)
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid Nacos configuration generation")?
            .to_owned();
        Ok(Some(Rollback {
            client,
            generation,
            writes,
            revision: RevisionEdit {
                id: id.clone(),
                group: group.clone(),
                refs: plan.refs,
                expected_md5,
                claimed,
                head,
                next: Revision {
                    schema_version: 1,
                    documents,
                    pending: None,
                },
            },
        }))
    }
}

impl Rollback {
    /// 业务作用：在同一提交标记的写入权下恢复所有相关原文，并在全量摘要确认后提交。
    /// 参数说明: 无。
    /// 返回：确认提交的配置代；抢占冲突返回空，部分写入或响应未知时保留待确认标记。
    pub(crate) async fn commit(self) -> Result<Option<String>> {
        let Some(md5) = self.revision.claim(&self.client).await? else {
            return Ok(None);
        };
        for write in self.writes {
            // 每个 Data ID 只发出一次条件写入，失去单项写权即终止后续写入，原代继续服务。
            ensure!(
                publish_cas(
                    &self.client,
                    &write.name,
                    &write.group,
                    &write.body,
                    &write.md5
                )
                .await?,
                "Nacos rollback document condition changed"
            );
        }
        self.revision.finish(&self.client, &md5).await?;
        Ok(Some(self.generation))
    }
}
