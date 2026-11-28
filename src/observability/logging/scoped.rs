//! 已发布业务范围与日志输出绑定。数据面只能从真实监听身份选择目的地。

use anyhow::{ensure, Context, Result};
use http_body_util::BodyExt as _;
use hyper::body::{Body, Frame, SizeHint};
use nasa::log::{FileLogConfig, LogConfig, LogContext};
use parking_lot::Mutex;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context as TaskContext, Poll};
use tracing::instrument::WithSubscriber;
use tracing::Dispatch;
use tracing_subscriber::EnvFilter;

use super::{
    scoped_files::Files,
    scoped_writer::{Destination, Worker},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Module {
    Http,
    Stream,
    Admin,
    Upstream,
    InterfaceGuard,
    Sentinel,
    AccessLog,
    Telemetry,
    Providers,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    Module(Module),
    Instance(Module, String),
}

#[derive(Clone, Debug)]
struct DestinationPlan {
    format_level: String,
    file: Arc<FileLogConfig>,
    signature: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Plan(BTreeMap<Scope, DestinationPlan>);

#[derive(Default)]
pub(crate) struct Declarations(BTreeMap<Scope, Value>);

#[derive(Default)]
pub(super) struct Directories(BTreeMap<PathBuf, DirectoryOwners>);

type DirectoryOwners = Vec<(Scope, Weak<Mutex<Files>>)>;

#[derive(Clone, Default)]
pub struct Active(Arc<BTreeMap<Module, ModuleOutput>>);

#[derive(Default)]
struct ModuleOutput {
    default: Option<Arc<Output>>,
    instances: BTreeMap<String, Arc<Output>>,
}

pub struct Output {
    dispatch: Dispatch,
    destination: Destination,
    instance: bool,
}

/// 让已运行的模块后台任务在发出每条记录时取得当前目的地。
#[derive(Clone, Default)]
pub(crate) struct ModuleLog(Arc<arc_swap::ArcSwapOption<Output>>);

impl ModuleLog {
    /// 业务作用：业务后端配置未变时更新现有任务的模块日志，避免只改日志触发重连。
    ///
    /// 参数说明：
    /// - `active`：已经提交的业务快照中的日志资源。
    /// - `module`：该后台任务真正所属的业务模块。
    ///
    /// 返回：之后产生的记录采用新目的地，已入队记录保持之前归属。
    pub(crate) fn update(&self, active: &Active, module: Module) {
        self.0.store(active.output(module, None));
    }

    /// 业务作用：在运行中的模块任务为所产生的记录选择当时的实际文件。
    ///
    /// 参数说明：
    /// - `record`：已经确定业务归属的 tracing 调用。
    ///
    /// 返回：原动作的值；未配置时沿用全局兜底。
    pub(crate) fn record<T>(&self, record: impl FnOnce() -> T) -> T {
        if let Some(output) = self.0.load().as_ref() {
            output.write(record)
        } else {
            record()
        }
    }
}

impl Output {
    /// 业务作用：让后台 tracing sink 执行原结构化格式，并使用业务产生时确定的独立文件。
    ///
    /// 参数说明：
    /// - `record`：已经完成访问日志条件与采样检查的写入动作。
    ///
    /// 返回：原动作的值；输出失败由范围文件队列计数。
    pub fn write<T>(&self, record: impl FnOnce() -> T) -> T {
        tracing::dispatcher::with_default(&self.dispatch, record)
    }
}

tokio::task_local! {
    static REQUEST_OUTPUT: Option<Arc<Output>>;
}

static FALLBACK: OnceLock<Dispatch> = OnceLock::new();

/// 业务作用：记住所属进程的正式 tracing 兜底，避免复用旧连接时继承已撤销的私有输出。
///
/// 参数说明: 无。
///
/// 返回：保留进程订阅器的引用，不修改其它作用域。
pub(super) fn initialize_fallback() {
    let _ = FALLBACK.set(tracing::dispatcher::get_default(Clone::clone));
}

impl Declarations {
    /// 业务作用：按具名 YAML 的真实业务字段解析模块与实例日志声明，同时从路由配置剥离该字段。
    ///
    /// 参数说明：
    /// - `module`：按 naml 完成解析的同一业务文档，包括实际模块和已求值的日志路径。
    /// - `global_scope`：只有全局 YAML 能把最外层的日志交给进程兜底。
    /// - `rule_module`：已绑定独立接口守卫或 Sentinel 文件时提供实际规则域。
    ///
    /// 返回：已登记合法的日志范围和构建计划。声明没有业务归属、重复或无效时拒绝整代。
    pub(crate) fn collect(
        &mut self,
        module: &mut Map<String, Value>,
        global_scope: bool,
        rule_module: Option<Module>,
    ) -> Result<()> {
        let mut owners = BTreeSet::new();
        if let Some(role) = rule_module {
            owners.insert(role);
        } else {
            for (keys, role) in [
                (&["proxies", "server", "routes"][..], Module::Http),
                (&["stream"], Module::Stream),
                (&["admin"], Module::Admin),
                (&["upstreams", "discovery"], Module::Upstream),
                (&["access_log"], Module::AccessLog),
                (&["telemetry"], Module::Telemetry),
                (&["providers"], Module::Providers),
            ] {
                if keys.iter().any(|key| module.contains_key(*key)) {
                    owners.insert(role);
                }
            }
        }
        if !global_scope {
            if let Some(value) = module.remove("log") {
                ensure!(
                    owners.len() == 1,
                    "module log requires an unambiguous business scope"
                );
                self.insert(Scope::Module(owners.pop_first().expect("one owner")), value)?;
            }
        }
        if let Some(proxies) = module.get_mut("proxies").and_then(Value::as_array_mut) {
            for proxy in proxies.iter_mut().filter_map(Value::as_object_mut) {
                self.collect_instance(proxy, Module::Http)?;
            }
        }
        if let Some(listeners) = module
            .get_mut("stream")
            .and_then(|stream| stream.get_mut("listeners"))
            .and_then(Value::as_array_mut)
        {
            for listener in listeners.iter_mut().filter_map(Value::as_object_mut) {
                self.collect_instance(listener, Module::Stream)?;
            }
        }
        for (field, role, id) in [
            ("server", Module::Http, "default"),
            ("admin", Module::Admin, "admin"),
        ] {
            if let Some(value) = module
                .get_mut(field)
                .and_then(Value::as_object_mut)
                .and_then(|instance| instance.remove("log"))
            {
                self.insert(Scope::Instance(role, id.to_owned()), value)?;
            }
        }
        Ok(())
    }

    /// 业务作用：把单个监听日志和实际配置的稳定身份一起登记。
    ///
    /// 参数说明：
    /// - `instance`：一个代理或 stream listener 的 naml 配置。
    /// - `module`：包含该实例的业务域。
    ///
    /// 返回：未配置时保留模块继承；显式配置但无实际实例 ID 时拒绝。
    fn collect_instance(
        &mut self,
        instance: &mut Map<String, Value>,
        module: Module,
    ) -> Result<()> {
        if let Some(value) = instance.remove("log") {
            let id = instance
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .context("instance log requires a listener id")?;
            self.insert(Scope::Instance(module, id.to_owned()), value)?;
        }
        Ok(())
    }

    /// 业务作用：冻结每个范围的原始日志声明，以便使用完成装配后的同一 naml 上下文解析。
    ///
    /// 参数说明：
    /// - `scope`：实际模块或监听实例身份。
    /// - `value`：由该范围提供的原始日志 mapping。
    ///
    /// 返回：声明唯一时加入候选；其它配置文件已声明相同范围时拒绝。
    fn insert(&mut self, scope: Scope, value: Value) -> Result<()> {
        ensure!(
            self.0.insert(scope.clone(), value).is_none(),
            "duplicate configuration for scoped log {scope:?}"
        );
        Ok(())
    }

    /// 业务作用：在装配完成后用 naml 求值范围日志，统一环境和跨模块引用的含义。
    ///
    /// 参数说明：
    /// - `entry`：已经解析的引导根，包含根级元数据及其活动 profile。
    /// - `fields`：其余已装配并确认没有字段覆盖冲突的业务输入。
    ///
    /// 返回：所有范围均得到有界合法的日志声明；未解析目录、循环引用或非法字段拒绝候选。
    pub(crate) fn resolve(self, entry: &Value, fields: &Map<String, Value>) -> Result<Plan> {
        let mut plan = Plan::default();
        if self.0.is_empty() {
            return Ok(plan);
        }
        let (scopes, raw): (Vec<_>, Vec<_>) = self.0.into_iter().unzip();
        let mut context = entry
            .as_object()
            .context("scoped logging requires a configuration mapping")?
            .clone();
        context.extend(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        // 解析副本保留真实配置引用；这些中间项从不进入业务配置和活动原文。
        const SCOPE_RECORDS: &str = "__naway_scoped_logging";
        context.insert(SCOPE_RECORDS.to_owned(), Value::Array(raw));
        let mut resolved = Value::Object(context);
        naml::resolve_placeholders_preserving_unresolved(&mut resolved)
            .context("resolve scoped log configuration")?;
        let Value::Array(values) = resolved
            .get_mut(SCOPE_RECORDS)
            .context("scoped log inputs missing")?
            .take()
        else {
            anyhow::bail!("resolved scoped log inputs must be a list");
        };
        ensure!(
            values.len() == scopes.len(),
            "scoped log declaration count changed"
        );
        for (scope, value) in scopes.into_iter().zip(values) {
            plan.insert(scope, value)?;
        }
        Ok(plan)
    }
}

impl Plan {
    /// 业务作用：在候选语义构建阶段严格核对日志字段、级别和 NASA 文件配置。
    ///
    /// 参数说明：
    /// - `scope`：声明实际归属的模块或稳定监听 ID。
    /// - `value`：naml 已解析的日志 mapping。
    ///
    /// 返回：成功加入已验证计划。解析阶段不创建目录或接管活动输出。
    fn insert(&mut self, scope: Scope, value: Value) -> Result<()> {
        let fields = value.as_object().context("scoped log must be a mapping")?;
        for key in fields.keys() {
            ensure!(
                matches!(
                    key.as_str(),
                    "path"
                        | "level"
                        | "max_file_size_mb"
                        | "max_file_size"
                        | "maxFileSize"
                        | "total_size_cap_mb"
                        | "total_size_cap"
                        | "totalSizeCap"
                        | "max_history_days"
                        | "maxHistory"
                        | "clean_history_on_start"
                        | "cleanHistoryOnStart"
                        | "split_error_file"
                        | "color"
                ),
                "unsupported scoped log field {key}"
            );
        }
        let config: LogConfig = serde_json::from_value(value).context("decode scoped log")?;
        let path = config
            .path
            .as_deref()
            .filter(|path| !path.trim().is_empty())
            .context("scoped log requires a file path")?;
        ensure!(
            !path.contains("${"),
            "scoped log.path contains an unresolved placeholder"
        );
        // 路径解析规则与全局日志一致。Nacos 的短期物化路径不能影响相对输出目录。
        match std::fs::metadata(path.trim()) {
            Ok(metadata) => ensure!(
                metadata.is_dir(),
                "scoped log destination is not a directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect scoped log directory"),
        }
        let resolved = config.resolve(&LogContext::console_only())?;
        EnvFilter::try_new(&resolved.level).context("invalid scoped log.level")?;
        let signature = format!("{resolved:?}");
        let file = resolved.file.context("scoped log directory missing")?;
        self.0.insert(
            scope,
            DestinationPlan {
                format_level: resolved.level,
                file: Arc::new(file),
                signature,
            },
        );
        Ok(())
    }

    /// 业务作用：判断候选是否需要分配范围文件日志资源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有私有声明时为真，调用方继续沿用进程兜底。
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 业务作用：在无日志语义变化时复用同代的范围输出，不重开文件或重复整理历史。
    ///
    /// 参数说明：
    /// - `other`：参与比较的范围日志计划。
    ///
    /// 返回：范围与已解析配置逐项相同时为真。
    pub(crate) fn same_as(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(&other.0)
                .all(|((a, left), (b, right))| a == b && left.signature == right.signature)
    }

    /// 业务作用：在开放该代业务之前打开完整的私有文件目的地。
    ///
    /// 参数说明：
    /// - `worker`：唯一有界文件写入任务。
    /// - `global`：全局文件输出目录，可以不启用。
    ///
    /// 返回：可随配置快照发布的全部输出。任何目录冲突、不安全或不可写都拒绝候选。
    pub(super) fn prepare(
        &self,
        worker: &Worker,
        global: Option<&Path>,
        current_global: Option<&Path>,
        retained: &mut Directories,
    ) -> Result<Active> {
        let mut directories = BTreeSet::<PathBuf>::new();
        let mut result = BTreeMap::<Module, ModuleOutput>::new();
        for (scope, plan) in &self.0 {
            std::fs::create_dir_all(&plan.file.dir)
                .with_context(|| format!("prepare log directory for {scope:?}"))?;
            let path = std::fs::canonicalize(&plan.file.dir)?;
            retained.check_global(global)?;
            ensure!(
                current_global != Some(path.as_path())
                    && global.and_then(|path| path.canonicalize().ok()).as_deref()
                        != Some(path.as_path()),
                "scoped log directory aliases the global destination"
            );
            ensure!(
                directories.insert(path.clone()),
                "scoped logs require independent directories"
            );
            let owners = retained.0.entry(path.clone()).or_default();
            // 私有目录直到旧业务与队列都排空才可转移给其它业务范围。
            ensure!(
                owners.iter().all(|(owner, _)| owner == scope),
                "scoped log directory is still owned by another scope"
            );
            let file = Arc::new(Mutex::new(Files::open(&path, &plan.file)?));
            owners.push((scope.clone(), Arc::downgrade(&file)));
            let output = worker.destination(file, plan.file.clone());
            let dispatch = Dispatch::new(
                tracing_subscriber::fmt()
                    .with_env_filter(EnvFilter::try_new(&plan.format_level)?)
                    .with_ansi(plan.file.color)
                    .with_writer(output.clone())
                    .finish(),
            );
            let output = Arc::new(Output {
                dispatch,
                destination: output,
                instance: matches!(scope, Scope::Instance(..)),
            });
            match scope {
                Scope::Module(module) => {
                    result.entry(*module).or_default().default = Some(output);
                }
                Scope::Instance(module, id) => {
                    result
                        .entry(*module)
                        .or_default()
                        .instances
                        .insert(id.clone(), output);
                }
            }
        }
        Ok(Active(Arc::new(result)))
    }
}

impl Directories {
    /// 业务作用：在任何全局输出换代前检查旧范围是否仍拥有同一物理目录。
    ///
    /// 参数说明：
    /// - `global`：新全局兜底声明的实际路径。
    ///
    /// 返回：清除已排空的范围引用，目标仍有私有记录在途时拒绝候选。
    pub(super) fn check_global(&mut self, global: Option<&Path>) -> Result<()> {
        self.0.retain(|_, owners| {
            owners.retain(|(_, files)| files.strong_count() > 0);
            !owners.is_empty()
        });
        if let Some(global) = global.and_then(|path| path.canonicalize().ok()) {
            ensure!(
                !self.0.contains_key(&global),
                "global log directory is still owned by a private scope"
            );
        }
        Ok(())
    }
}

impl Active {
    /// 业务作用：为已确定的实例或模块选择唯一文件输出，不接受任何客户端提供的日志目录。
    ///
    /// 参数说明：
    /// - `module`：正在运行的真实业务模块。
    /// - `instance`：由监听和快照选定的稳定实例 ID。
    ///
    /// 返回：优先实例，其次模块。两者均未配置时交给全局兜底。
    pub fn output(&self, module: Module, instance: Option<&str>) -> Option<Arc<Output>> {
        let module = self.0.get(&module)?;
        instance
            .and_then(|id| module.instances.get(id))
            .or(module.default.as_ref())
            .cloned()
    }

    /// 业务作用：记录由具体业务模块产生的事实，有私有实例时仍归属所接受业务的实例。
    ///
    /// 参数说明：
    /// - `module`：实际生成该记录的业务子模块。
    /// - `record`：执行真正 tracing 调用的动作。
    ///
    /// 返回：原动作的值；实例、模块或当前上层兜底只执行一次。
    pub fn record_module<T>(&self, module: Module, record: impl FnOnce() -> T) -> T {
        if current().is_some_and(|output| output.instance) {
            return record();
        }
        if let Some(output) = self.output(module, None) {
            output.write(record)
        } else {
            record()
        }
    }

    /// 业务作用：为送入后台队列的子模块记录冻结真实目的地，保留监听实例的优先级。
    /// 参数说明：
    /// - `module`：产生该记录的子模块。
    /// 返回：原请求的实例、子模块、原请求的模块输出依次匹配。均缺席时采用全局兜底。
    pub(crate) fn queued_output(&self, module: Module) -> Option<Arc<Output>> {
        let request = current();
        if request.as_ref().is_some_and(|output| output.instance) {
            return request;
        }
        self.output(module, None).or(request)
    }

    /// 业务作用：记录监听器接入、错误和排空等同步事实，按实际实例选择正式输出。
    ///
    /// 参数说明：
    /// - `module`：绑定端口的业务域。
    /// - `instance`：真实监听器的稳定配置身份。
    /// - `record`：执行实际日志动作的闭包。
    ///
    /// 返回：执行一次原动作，作为本实例记录写入唯一目的地。
    pub fn record_instance<T>(
        &self,
        module: Module,
        instance: &str,
        record: impl FnOnce() -> T,
    ) -> T {
        if let Some(output) = self.output(module, Some(instance)) {
            output.write(record)
        } else {
            record()
        }
    }

    /// 业务作用：在日志输出随业务配置成为活动后执行保留维护。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：每个实际日志目的地按配置加入一次清理任务，不阻塞快照发布。
    pub fn activate(&self) {
        for module in self.0.values() {
            for writer in module.default.iter().chain(module.instances.values()) {
                writer.destination.activate();
            }
        }
    }
}

/// 业务作用：将一次连接、请求或后台任务绑定同一份活动日志输出，跨执行器线程也保留归属。
///
/// 参数说明：
/// - `output`：已按可信实例或模块确定的目标，空时沿用当前执行器默认输出。
/// - `work`：执行日志所属业务的异步过程。
///
/// 返回：原过程的值，业务错误语义不受日志的分配影响。
pub async fn route<F: Future>(output: Option<Arc<Output>>, work: F) -> F::Output {
    if let Some(output) = output {
        let dispatch = output.dispatch.clone();
        REQUEST_OUTPUT
            .scope(Some(output), work.with_subscriber(dispatch))
            .await
    } else if let Some(fallback) = FALLBACK.get().filter(|_| current().is_some()) {
        REQUEST_OUTPUT
            .scope(None, work.with_subscriber(fallback.clone()))
            .await
    } else {
        work.await
    }
}

/// 业务作用：将已选定的日志范围携带到结构化访问日志队列，不用新快照重新选择。
///
/// 参数说明: 无。
///
/// 返回：绑定的私有输出，或表示进程兜底的空值。
pub(crate) fn current() -> Option<Arc<Output>> {
    REQUEST_OUTPUT.try_with(Clone::clone).ok().flatten()
}

/// 业务作用：将从业务请求派生的隧道、后台对照和资源收尾纳入原请求的文件归属。
///
/// 参数说明：
/// - `work`：继承当前请求责任、在独立 Tokio 任务中继续执行的过程。
///
/// 返回：可取消的任务句柄，与原先的生命周期和业务值一致。
pub(crate) fn spawn<F>(work: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(route(current(), work))
}

struct ScopedBody {
    inner: Option<crate::BoxBody>,
    output: Option<Arc<Output>>,
}

/// 业务作用：响应实体在请求 future 结束后仍采用本次请求原有的范围文件。
///
/// 参数说明：
/// - `output`：请求实际选定的实例、模块或进程兜底。
/// - `body`：必须保持零拷贝流式传输及既有 EOF 语义的响应体。
///
/// 返回：需要隔离时绑定后续帧及取消操作。普通未启用私有输出的请求保留原 body。
pub(crate) fn bind_body(output: Option<Arc<Output>>, body: crate::BoxBody) -> crate::BoxBody {
    if output.is_none() && current().is_none() {
        return body;
    }
    ScopedBody {
        inner: Some(body),
        output,
    }
    .boxed()
}

/// 业务作用：对一次同步 body 操作临时安装其原请求的输出身份。
///
/// 参数说明：
/// - `output`：原请求的独立输出，空值为进程兜底。
/// - `work`：实际读取帧或销毁实体的操作。
///
/// 返回：透明传递业务返回值，原父任务的日志归属在操作退出时恢复。
fn with_output<T>(output: &Option<Arc<Output>>, work: impl FnOnce() -> T) -> T {
    if let Some(output) = output {
        REQUEST_OUTPUT.sync_scope(Some(output.clone()), || output.write(work))
    } else if let Some(fallback) = FALLBACK.get() {
        REQUEST_OUTPUT.sync_scope(None, || tracing::dispatcher::with_default(fallback, work))
    } else {
        work()
    }
}

impl Body for ScopedBody {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;

    /// 业务作用：转发原帧并让响应中途错误仍属于已接收请求的实例。
    ///
    /// 参数说明：
    /// - `ctx`：下游用于背压唤醒的轮询上下文。
    ///
    /// 返回：原始响应帧、等待状态或错误。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        ctx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let Self {
            inner,
            output,
        } = &mut *self;
        with_output(output, || {
            inner
                .as_mut()
                .map_or(Poll::Ready(None), |body| Pin::new(body).poll_frame(ctx))
        })
    }

    /// 业务作用：保留下游能够安全识别的真实结束状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有实体或真实实体已终止时为真。
    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    /// 业务作用：保留 HTTP 实体长度边界，不因日志发生聚合。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：透传下游发送端原先可见的大小提示。
    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), Body::size_hint)
    }
}

impl Drop for ScopedBody {
    /// 业务作用：使响应取消期间产生的清理记录仍归属该请求。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：销毁原实体并归还其资源，保留原日志归属直到这一操作结束。
    fn drop(&mut self) {
        with_output(&self.output, || drop(self.inner.take()));
    }
}
