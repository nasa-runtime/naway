//! 从 Nacos 读取一整代具名业务 YAML 后提交给唯一重载任务。

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use arc_swap::ArcSwap;
use naml::YmlImport;
use nasa::config::nacos::{ConfigBundle, ConfigRef, NacosConfigClient};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::config::{bootstrap::module_template, document, loader, GatewaySnapshot};
use crate::control::history::ConfigHistory;
use crate::control::reload::{nacos_config_props, ReloadHandle};

const READ_TIMEOUT: Duration = Duration::from_secs(12);
const RECHECK: Duration = Duration::from_secs(2);
const MISSING_CAS: &str = "naway-create-only";

/// Nacos 引导连接和已校验的业务文档清单。
struct Plan {
    connection: crate::config::model::NacosConfigSourceCfg,
    refs: Vec<ConfigRef>,
    guard: String,
    sentinel: String,
    application: String,
    revision: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    schema_version: u32,
    documents: BTreeMap<String, String>,
}

/// 持有启动时已取到的 Nacos 配置和该进程的独占物化目录。
pub struct NamedNacos {
    entry: PathBuf,
    plan: Plan,
    storage: Arc<Storage>,
}

/// 最近读取并复验的远端单文档比较交换条件。
pub(crate) struct Edit {
    client: NacosConfigClient,
    group: String,
    name: String,
    md5: String,
    generation: String,
}

/// 用于关闭后台 Nacos 订阅及其运行线程。
pub struct Subscription {
    stop: oneshot::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

struct Storage {
    home: PathBuf,
    selector: PathBuf,
}

impl NamedNacos {
    /// 业务作用：在打开业务监听前读取、补齐并物化完整具名 Nacos 配置。
    ///
    /// 参数说明：
    /// - `entry`：由 CLI 选定的本地引导入口。
    ///
    /// 返回：具名 Nacos 模式返回路径权威，普通入口返回空。远端读取或完整性检查失败时不启动业务。
    pub async fn prepare(entry: &Path) -> Result<Option<Self>> {
        let entry = entry.canonicalize()?;
        let Some(plan) = Plan::load(&entry)? else {
            return Ok(None);
        };
        ensure!(
            cfg!(feature = "nacos-sdk"),
            "named Nacos imports require the nacos-sdk feature"
        );
        let client = connect(&plan).await?;
        tokio::time::timeout(READ_TIMEOUT, seed(&client, &plan))
            .await
            .context("Nacos module initialization deadline exceeded")??;
        let bundle = fetch(&client, &plan).await?;
        let storage = Arc::new(Storage::create(&entry)?);
        storage.stage(&plan, &bundle)?;
        Ok(Some(Self {
            entry,
            plan,
            storage,
        }))
    }

    /// 业务作用：提供已完整物化的入口，令全体业务共享原来的语义构建与发布门禁。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：进程专属的合成入口路径。真实引导与运维 YAML 不是写回目标。
    pub fn candidate_path(&self) -> &Path {
        &self.storage.selector
    }

    /// 业务作用：为单个模块绑定同一 Nacos 权威和完整活动代，再取得 Data ID 的 CAS 条件。
    /// 参数说明：
    /// - `active`：完成本地校验和权限判断时的活动快照。
    /// - `name`：活动清单中的具名模块，不能选额外的远端对象。
    /// - `content`：已经完整构建验证的候选原文。
    /// 返回：当前远端状态与校验基线一致时返回待提交条件，配置已变化时为空。
    pub(crate) async fn prepare_edit(
        &self,
        active: &GatewaySnapshot,
        name: &str,
        content: &str,
    ) -> Result<Option<Edit>> {
        let plan = self.plan.current(&self.entry)?;
        // 带提交标记的配置需要整代提交条件，不能用单文档写入制造未经提交的集群代。
        ensure!(
            plan.revision.is_none(),
            "Nacos revision requires a coordinated publication"
        );
        let client = connect(&plan).await?;
        let mut current = fetch(&client, &plan).await?;
        if self.storage.active_directory_for(active).as_ref()
            != Some(&self.storage.generation(&plan, &current))
        {
            return Ok(None);
        }
        let document = current
            .documents
            .iter_mut()
            .find(|doc| doc.source.data_id == name)
            .context("named source is no longer declared")?;
        let group = document
            .source
            .group
            .clone()
            .context("Nacos module is missing a group")?;
        let latest =
            tokio::time::timeout(READ_TIMEOUT, client.fetch_optional_with_md5(name, &group))
                .await??;
        let Some((baseline, md5)) = latest else {
            return Ok(None);
        };
        if baseline != document.content {
            return Ok(None);
        }
        document.content = content.to_owned();
        let generation = self
            .storage
            .generation(&plan, &current)
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid Nacos configuration generation")?
            .to_owned();
        Ok(Some(Edit {
            client,
            group,
            name: name.to_owned(),
            md5,
            generation,
        }))
    }

    /// 业务作用：按初始引导权限开启 Nacos 订阅、记录完整候选并通知发布任务。
    ///
    /// 参数说明：
    /// - `reload`：唯一配置发布任务的受限通知句柄。
    /// - `history`：保护候选文件与编译事务的共享锁。
    /// - `snapshot`：只读活动快照，用于保留仍在使用的原文代。
    ///
    /// 返回：拥有停止权的观察句柄，线程初始化失败返回错误。
    pub fn subscribe(
        self: Arc<Self>,
        reload: ReloadHandle,
        history: ConfigHistory,
        snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    ) -> Result<Subscription> {
        let (stop, stopped) = oneshot::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let thread = std::thread::Builder::new()
            .name("named-nacos-config".to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    tokio::select! {
                        _ = stopped => {}
                        _ = self.observe(reload, history, snapshot) => {}
                    }
                })
            })?;
        Ok(Subscription {
            stop,
            thread,
        })
    }

    /// 业务作用：失联后重连并保持本地已发布代，禁止引导身份变化隐式获取远端权限。
    ///
    /// 参数说明：
    /// - `reload`：受限修改通知。
    /// - `history`：共享物化和构建文件锁。
    /// - `snapshot`：当前活动配置。
    ///
    /// 返回：持续观察，只有上层撤销观察任务才退出。
    async fn observe(
        &self,
        reload: ReloadHandle,
        history: ConfigHistory,
        snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    ) {
        loop {
            if let Err(error) = self.watch(&reload, &history, &snapshot).await {
                tracing::warn!(error = %error, "named Nacos watch will reconnect");
            }
            tokio::time::sleep(RECHECK).await;
        }
    }

    /// 业务作用：重读订阅事件和定期对账的完整集合，安全切换模块清单及源文档。
    ///
    /// 参数说明：
    /// - `reload`：目标发布队列。
    /// - `history`：物化发布使用的共享文件锁。
    /// - `snapshot`：为已发布文档提供精确回读身份。
    ///
    /// 返回：依赖或清单读取失败时回到重连，同一规则下持续消费变更。
    async fn watch(
        &self,
        reload: &ReloadHandle,
        history: &ConfigHistory,
        snapshot: &ArcSwap<GatewaySnapshot>,
    ) -> Result<()> {
        let reader = connect(&self.plan).await?;
        let watcher = connect(&self.plan).await?;
        let mut plan = self.plan.current(&self.entry)?;
        let (mut subscription, mut changes) = tokio::time::timeout(
            READ_TIMEOUT,
            watcher.watch_many_channel(plan.subscriptions()),
        )
        .await??;
        let mut interval = tokio::time::interval(RECHECK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut staged = self.storage.active_directory(snapshot);
        loop {
            tokio::select! {
                changed = changes.changed() => { changed?; }
                _ = interval.tick() => {}
            }
            let next = self.plan.current(&self.entry)?;
            if plan.refs != next.refs || plan.revision != next.revision {
                // 先订阅新目录再释放原订阅，随后读回全量，避免切换窗口遗漏变化。
                let watched = tokio::time::timeout(
                    READ_TIMEOUT,
                    watcher.watch_many_channel(next.subscriptions()),
                )
                .await??;
                (subscription, changes) = watched;
            }
            plan = next;
            let bundle = fetch(&reader, &plan).await?;
            let desired = self.storage.generation(&plan, &bundle);
            if staged.as_ref() != Some(&desired) {
                // 目录内所有 YAML 完整落盘后才切换选择器。任一写入失败时，旧选择器和活跃代仍可用。
                history.with_exclusive_local_files(|| {
                    self.storage.stage(&plan, &bundle)?;
                    let active = self.storage.active_directory(snapshot);
                    self.storage.reap(&desired, active.as_deref());
                    Ok(())
                })?;
                staged = Some(desired.clone());
            }
            if self.storage.active_directory(snapshot).as_ref() != Some(&desired) {
                ensure!(
                    reload.trigger_named_nacos(&self.storage.selector).await,
                    "reload worker stopped"
                );
            }
            let _ = &subscription;
        }
    }
}

impl Edit {
    /// 业务作用：只写已经复验的 Data ID，并用服务端 CAS 防止覆盖后来者。
    /// 参数说明：
    /// - `content`：构建时冻结的模块 YAML。
    /// 返回：服务端确认后返回预期生效代，冲突返回空，超时不能判定远端是否已提交。
    pub(crate) async fn commit(self, content: &str) -> Result<Option<String>> {
        let committed = tokio::time::timeout(
            Duration::from_secs(3),
            self.client
                .publish_cas(&self.name, &self.group, content, &self.md5),
        )
        .await??;
        Ok(committed.then_some(self.generation))
    }
}

impl Subscription {
    /// 业务作用：停止订阅并等线程放弃物化目录，避免关停后继续写入。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：工作线程退出后返回。
    pub async fn close(self) {
        let _ = self.stop.send(());
        let _ = tokio::task::spawn_blocking(move || self.thread.join()).await;
    }
}

impl Plan {
    /// 业务作用：观察业务文档及提交标记，使提交元数据更新也能唤醒重读。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：按配置权威分组的完整远端订阅集合。
    fn subscriptions(&self) -> Vec<ConfigRef> {
        let mut refs = self.refs.clone();
        if let Some(id) = &self.revision {
            refs.push(
                ConfigRef::required(id.clone())
                    .with_group(self.connection.group.clone())
                    .with_file_extension("yaml"),
            );
        }
        refs
    }

    /// 业务作用：严格解释本地引导连接、业务 Data ID 和完整性提交标记。
    ///
    /// 参数说明：
    /// - `entry`：真实引导入口。
    ///
    /// 返回：全量 Nacos 清单或普通本地入口。冲突、非法名称或错误的分组绑定会拒绝。
    fn load(entry: &Path) -> Result<Option<Self>> {
        let tree = loader(entry)
            .preserve_unresolved_placeholders(true)
            .load_tree()?;
        let base = entry
            .parent()
            .context("Nacos bootstrap entry needs a directory")?;
        let imports = naml::strict::parse_imports_checked(&tree, base)?;
        if !imports
            .iter()
            .any(|import| matches!(import, YmlImport::Nacos(_)))
        {
            return Ok(None);
        }
        ensure!(imports.len() <= 64, "too many named Nacos documents");
        let mut config = tree
            .get("nacos")
            .cloned()
            .context("named Nacos imports require a nacos bootstrap mapping")?;
        let root = config
            .as_object_mut()
            .context("invalid nacos bootstrap mapping")?;
        let revision = root
            .remove("revision_data_id")
            .map(serde_json::from_value::<String>)
            .transpose()?;
        let connection: crate::config::model::NacosConfigSourceCfg =
            serde_json::from_value(config)?;
        ensure!(
            !connection.server_addr.trim().is_empty() && !connection.group.trim().is_empty(),
            "named Nacos imports require server_addr and group"
        );
        let application = tree
            .pointer("/application/name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("naway")
            .to_owned();
        let guard = document_id(tree.get("interface_guard_file"), "interface-guard.yml")?;
        let sentinel = document_id(tree.get("sentinel_rules_file"), "sentinel-rules.yml")?;
        let mut names = BTreeSet::new();
        let mut refs = Vec::new();
        for import in imports {
            let YmlImport::Nacos(import) = import else {
                anyhow::bail!("file and Nacos module imports cannot share an entry");
            };
            let id = import.data_id;
            ensure!(
                valid_file_name(&id),
                "Nacos dataId must be an exact YAML filename"
            );
            ensure!(
                id != "application.yml" && names.insert(id.to_ascii_lowercase()),
                "duplicate or reserved Nacos dataId"
            );
            ensure!(
                import
                    .file_extension
                    .as_deref()
                    .is_none_or(|ext| matches!(ext, "yml" | "yaml")),
                "named Nacos modules must use YAML"
            );
            refs.push(ConfigRef {
                group: Some(import.group.unwrap_or_else(|| connection.group.clone())),
                data_id: id,
                optional: import.optional,
                file_extension: Some("yaml".to_owned()),
            });
        }
        ensure!(
            guard != sentinel
                && [&guard, &sentinel].into_iter().all(|role| refs
                    .iter()
                    .any(|source| &source.data_id == role && !source.optional)),
            "required Nacos guard and Sentinel documents must be declared"
        );
        if let Some(id) = revision.as_deref() {
            ensure!(
                valid_id(id) && !names.contains(&id.to_ascii_lowercase()),
                "invalid or conflicting Nacos revision_data_id"
            );
        }
        Ok(Some(Self {
            connection,
            refs,
            guard,
            sentinel,
            application,
            revision,
        }))
    }

    /// 业务作用：重新读取共享清单，同时固定本次启动已验证的远端身份。
    ///
    /// 参数说明：
    /// - `entry`：原始引导入口。
    ///
    /// 返回：连接、空间和凭据一致时接受清单，变更远端 authority 时要求重新启动。
    fn current(&self, entry: &Path) -> Result<Self> {
        let next = Self::load(entry)?
            .context("named Nacos source cannot change to local files during reload")?;
        ensure!(
            crate::config::centers::same_nacos_config_bootstrap(&self.connection, &next.connection),
            "Nacos connection authority changed and requires restart"
        );
        Ok(next)
    }
}

/// 业务作用：解析守卫或 Sentinel 对应的确切 Data ID。
///
/// 参数说明：
/// - `value`：引导入口中可选的角色文件名。
/// - `fallback`：角色的默认 Data ID。
///
/// 返回：映射到单一文件名的合法 YAML Data ID。
fn document_id(value: Option<&serde_json::Value>, fallback: &str) -> Result<String> {
    let name = match value {
        Some(value) => value
            .as_str()
            .context("named Nacos role must be a string")?,
        None => fallback,
    };
    ensure!(valid_file_name(name), "invalid named Nacos role Data ID");
    Ok(name.to_owned())
}

/// 业务作用：约束映射到私有目录的标识，避免穿越和跨文件身份重叠。
///
/// 参数说明：
/// - `name`：外部提供的配置标识。
///
/// 返回：仅允许有限长度的 ASCII 名称。
fn valid_id(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// 业务作用：限制 Nacos 业务原文只能使用明确的 YAML 名称。
///
/// 参数说明：
/// - `name`：Data ID。
///
/// 返回：单一合法 YAML 文件名时为真。
fn valid_file_name(name: &str) -> bool {
    valid_id(name) && (name.ends_with(".yml") || name.ends_with(".yaml"))
}

/// 业务作用：连接同一启动权威下固定 namespace 的 Nacos 客户端。
///
/// 参数说明：
/// - `plan`：已验证的引导配置。
///
/// 返回：成功建立连接或返回带截止时间的错误。
async fn connect(plan: &Plan) -> Result<NacosConfigClient> {
    tokio::time::timeout(
        READ_TIMEOUT,
        NacosConfigClient::connect(&nacos_config_props(&plan.connection)),
    )
    .await
    .context("Nacos connection deadline exceeded")?
}

/// 业务作用：启动前仅补齐确认为缺失的标准 Data ID，既有正文和并发运维写入保持原样。
///
/// 参数说明：
/// - `client`：同一 namespace 的远端客户端。
/// - `plan`：已验证的模块声明。
///
/// 返回：标准必需文档可读或已安装缺省值；非缺失读取错误、无模板或写入不可确认时拒绝启动。
async fn seed(client: &NacosConfigClient, plan: &Plan) -> Result<()> {
    for source in &plan.refs {
        let group = source
            .group
            .as_deref()
            .expect("named import has resolved group");
        if source.optional
            || client
                .fetch_optional_with_md5(&source.data_id, group)
                .await?
                .is_some()
        {
            continue;
        }
        let initial = module_template(&source.data_id)
            .with_context(|| format!("missing required Nacos configuration {}", source.data_id))?;
        // 服务端 CAS 在现存记录上比较真实 md5。该值不能匹配任何 md5，并发插入只允许一个胜者。
        let result = client
            .publish_cas(&source.data_id, group, initial, MISSING_CAS)
            .await;
        let mut visible = false;
        for _ in 0..20 {
            if client
                .fetch_optional_with_md5(&source.data_id, group)
                .await?
                .is_some()
            {
                visible = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !visible {
            result?;
            anyhow::bail!("could not confirm Nacos default {}", source.data_id);
        }
    }
    Ok(())
}

/// 业务作用：读回稳定完整的配置集合，并在开启提交标记时严格绑定每个文档的 SHA-256。
///
/// 参数说明：
/// - `client`：专用远端事实读取客户端。
/// - `plan`：完整文档清单与可选提交标记。
///
/// 返回：全部必需文档完整且两个观测一致的集合。失联、并发漂移或未提交的批次拒绝。
async fn fetch(client: &NacosConfigClient, plan: &Plan) -> Result<ConfigBundle> {
    tokio::time::timeout(READ_TIMEOUT, async {
        let first = client.fetch_many(&plan.refs).await?;
        let mut bytes = 0usize;
        for doc in &first.documents {
            bytes = bytes
                .checked_add(doc.content.len())
                .context("Nacos configuration byte count overflow")?;
            ensure!(
                bytes <= document::MAX_DOCUMENT_BYTES,
                "named Nacos configuration exceeds total byte limit"
            );
        }
        if let Some(id) = &plan.revision {
            let head = client
                .fetch_optional_with_md5(id, &plan.connection.group)
                .await?
                .context("Nacos revision is missing")?;
            let head = document::decode::<Revision>(head.0.as_bytes(), 64 * 1024)?;
            let actual = first
                .documents
                .iter()
                .map(|doc| {
                    (
                        doc.source.data_id.clone(),
                        format!("{:x}", Sha256::digest(doc.content.as_bytes())),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            ensure!(
                head.schema_version == 1 && head.documents == actual,
                "Nacos configuration does not match its committed revision"
            );
        }
        let second = client.fetch_many(&plan.refs).await?;
        ensure!(
            first == second,
            "Nacos configuration changed during the complete read"
        );
        Ok(first)
    })
    .await
    .context("Nacos configuration read deadline exceeded")?
}

/// 业务作用：从本机物化入口和已验证规则路径恢复远端配置代摘要，供集群读回。
///
/// 参数说明：
/// - `entry`：已参与候选构建的内部选择器。
/// - `guard`：本轮实际校验的规则文件。
///
/// 返回：两个路径确属同一份私有物化布局时返回共享内容摘要。
pub(super) fn materialized_revision(entry: &Path, guard: &Path) -> Option<String> {
    let owner = entry.file_stem()?.to_str()?;
    let nonce = owner.strip_prefix(".naway-center-")?;
    if nonce.len() != 32 || !nonce.bytes().all(|value| value.is_ascii_hexdigit()) {
        return None;
    }
    let directory = guard.parent()?;
    let deploy = entry.parent()?;
    let home = deploy.join(owner);
    if directory.parent()? != home {
        return None;
    }
    let digest = directory.file_name()?.to_str()?;
    (digest.len() == 64 && digest.bytes().all(|value| value.is_ascii_hexdigit()))
        .then(|| digest.to_owned())
}

impl Storage {
    /// 业务作用：建立单进程专用目录和同部署根下的内部入口，不与运维原文共享写目标。
    ///
    /// 参数说明：
    /// - `entry`：真实引导入口。
    ///
    /// 返回：本进程独占物化权，名称冲突或创建失败时拒绝。
    fn create(entry: &Path) -> Result<Self> {
        let parent = entry
            .parent()
            .context("Nacos bootstrap entry needs a directory")?;
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|error| anyhow::anyhow!("{error}"))?;
        let label = format!(".naway-center-{:032x}", u128::from_be_bytes(random));
        let home = parent.join(&label);
        let selector = parent.join(format!("{label}.yml"));
        DirBuilder::new().mode(0o700).create(&home)?;
        Ok(Self {
            home,
            selector,
        })
    }

    /// 业务作用：从模块声明和实际正文计算物化身份，避免重复拉取造成无效文件换代。
    ///
    /// 参数说明：
    /// - `plan`：本轮已验证的清单。
    /// - `bundle`：Nacos 完整读取结果。
    ///
    /// 返回：本进程私有代目录的精确路径。
    fn generation(&self, plan: &Plan, bundle: &ConfigBundle) -> PathBuf {
        let mut digest = Sha256::new();
        for field in [&plan.application, &plan.guard, &plan.sentinel]
            .into_iter()
            .map(String::as_str)
            .chain(bundle.documents.iter().flat_map(|doc| {
                [
                    doc.source.data_id.as_str(),
                    doc.source.group.as_deref().unwrap_or_default(),
                    doc.content.as_str(),
                ]
            }))
        {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        self.home.join(format!("{:x}", digest.finalize()))
    }

    /// 业务作用：完整持久化一代模块后一次切换入口，拒绝任何部分写入的候选。
    ///
    /// 参数说明：
    /// - `plan`：已验证的模块清单与规则角色。
    /// - `bundle`：本轮完整的原文。
    ///
    /// 返回：选择器已原子指向完整目录时成功，失败保留原选择器。
    fn stage(&self, plan: &Plan, bundle: &ConfigBundle) -> Result<()> {
        let current = self.generation(plan, bundle);
        if !current.exists() {
            DirBuilder::new().mode(0o700).create(&current)?;
            for doc in &bundle.documents {
                let result = private_write(&current.join(&doc.source.data_id), &doc.content);
                if let Err(error) = result {
                    // 未发布的目录完全属于本进程，移除半写内容后不能成为下轮有效缓存。
                    let _ = fs::remove_dir_all(&current);
                    return Err(error);
                }
            }
        }
        let imports = bundle
            .documents
            .iter()
            .map(|doc| {
                serde_json::json!({
                    "file": current.join(&doc.source.data_id),
                    "optional": false,
                })
            })
            .collect::<Vec<_>>();
        let yaml = document::encode(
            &serde_json::json!({
                "application": {"name": plan.application},
                "interface_guard_file": current.join(&plan.guard),
                "sentinel_rules_file": current.join(&plan.sentinel),
                "yml": {"imports": imports},
            }),
            64 * 1024,
        )?;
        let temporary = self.home.join("selector.next");
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        private_write(&temporary, &yaml)?;
        fs::rename(temporary, &self.selector)?;
        Ok(())
    }

    /// 业务作用：从真实发布时间点读取活动远端原文目录，禁止回收正在服务的配置代。
    ///
    /// 参数说明：
    /// - `snapshot`：唯一快照指针。
    ///
    /// 返回：活动配置来自本进程的物化目录时返回该目录。
    fn active_directory(&self, snapshot: &ArcSwap<GatewaySnapshot>) -> Option<PathBuf> {
        let active = snapshot.load();
        self.active_directory_for(&active)
    }

    /// 业务作用：用冻结活动配置验证远端写入所基于的完整内容代。
    /// 参数说明：
    /// - `active`：只读活动配置。
    /// 返回：快照确属此进程物化权威时为其完整代路径。
    fn active_directory_for(&self, active: &GatewaySnapshot) -> Option<PathBuf> {
        let parent = active.document_paths.guard.parent()?;
        (parent.parent() == Some(self.home.as_path())).then(|| parent.to_path_buf())
    }

    /// 业务作用：清理已经脱离选择器和活动代的独占模块原文，控制长期存储空间。
    ///
    /// 参数说明：
    /// - `desired`：当前选择器的完整代。
    /// - `active`：当前仍在提供服务的代。
    ///
    /// 返回：不移除这两代；回收失败记录并留待下轮处理。
    fn reap(&self, desired: &Path, active: Option<&Path>) {
        let Ok(entries) = fs::read_dir(&self.home) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path == desired
                || Some(path.as_path()) == active
                || !entry.file_type().is_ok_and(|kind| kind.is_dir())
            {
                continue;
            }
            if let Err(error) = fs::remove_dir_all(path) {
                tracing::warn!(%error, "retired Nacos configuration directory could not be reclaimed");
            }
        }
    }
}

impl Drop for Storage {
    /// 业务作用：停止远端配置消费后回收本进程生成的目录和合成入口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只回收独占文件，保留真实部署入口和原始配置。
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.selector);
        let _ = fs::remove_dir_all(&self.home);
    }
}

/// 业务作用：严格写入本进程的私有配置原文，禁止复用已有文件、硬链接或符号链接。
///
/// 参数说明：
/// - `path`：锁定在本进程私有工作区的目标。
/// - `content`：Nacos 原文或完整选择器文本。
///
/// 返回：文件完整写入并刷盘时返回成功；路径已经存在或 I/O 失败时返回错误。
fn private_write(path: &Path, content: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
