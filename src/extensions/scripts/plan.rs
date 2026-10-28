//! 候选编译冻结源码与权限，调用不读取文件，旧请求继续使用自己的不可变计划。
mod semantic;

use super::{
    circuit::Circuit,
    contract::{self, Input, Output},
    vm::Vm,
    Context, Failure,
};
use crate::{
    config::scripts::{FailureMode, Phase, ScriptCfg},
    extensions::resources,
};
use anyhow::{ensure, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderName};
use std::{collections::HashSet, io::Read, path::Path, sync::Arc, time::Duration};

#[derive(PartialEq, Eq)]
pub(crate) struct Chain {
    phases: [Vec<Arc<Plugin>>; 6],
}
struct Plugin {
    cfg: ScriptCfg,
    source: Arc<str>,
    fingerprint: String,
    include: Vec<HeaderName>,
    mutation: Vec<HeaderName>,
    circuit_key: String,
    circuit: parking_lot::Mutex<Option<(String, Arc<Circuit>)>>,
}
pub(crate) struct Execution {
    pub body: Option<Bytes>,
    pub reject: Option<u16>,
}
/// 业务作用：为已知相位选取固定数组槽，不在请求路径重新筛选配置列表。
///
/// 参数说明：
/// - `phase`：明确的调用相位。
///
/// 返回：六个已知阶段中的索引。
fn index(phase: Phase) -> usize {
    match phase {
        Phase::RequestHeaders => 0,
        Phase::RequestBody => 1,
        Phase::RequestBodyStream => 2,
        Phase::ResponseHeaders => 3,
        Phase::ResponseBody => 4,
        Phase::ResponseBodyStream => 5,
    }
}
impl Chain {
    /// 业务作用：候选期读取并验证全部源与预算，任一失败阻止整个路由快照发布。
    ///
    /// 参数说明：
    /// - `cfgs`：有序脚本声明。
    /// - `root`：配置根，用于约束本地源码能力。
    /// - `route`：稳定路由标识，用于隔离熔断域。
    /// - `identity`：宿主管理的动态身份头名称。
    ///
    /// 返回：按相位分组的不可变脚本链；坏源、预算、权限或组合拒绝。
    pub fn build(
        cfgs: &[ScriptCfg],
        root: &Path,
        route: &str,
        identity: &HashSet<HeaderName>,
    ) -> Result<Self> {
        ensure!(cfgs.len() <= 16, "script plugin count exceeds 16");
        let root = root.canonicalize()?;
        let mut phases: [Vec<Arc<Plugin>>; 6] = Default::default();
        let mut ids = HashSet::new();
        for cfg in cfgs {
            cfg.validate()?;
            ensure!(ids.insert(cfg.id.as_str()), "duplicate script id");
            ensure!(
                !cfg.phase.body() || cfg.mutation_headers.is_empty(),
                "body scripts cannot mutate headers"
            );
            let include = compile_headers(&cfg.include_headers, identity)?;
            let mutation = compile_headers(&cfg.mutation_headers, identity)?;
            let path = root
                .join(&cfg.source_file)
                .canonicalize()
                .map_err(|_| anyhow::anyhow!("script source unavailable"))?;
            ensure!(
                path.starts_with(&root),
                "script source must stay inside configuration root"
            );
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
            }
            let file = options
                .open(&path)
                .map_err(|_| anyhow::anyhow!("script source unavailable"))?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() <= 65536,
                "script source must be a regular file up to 64KiB"
            );
            let mut source = String::new();
            file.take(65537).read_to_string(&mut source)?;
            ensure!(
                !source.is_empty() && source.len() <= 65536,
                "invalid script source length"
            );
            let fingerprint = nasa::crypto::sha256(&serde_json::to_string(&(cfg, &source))?);
            let circuit_key = nasa::crypto::sha256(&format!(
                "{}\0{route}\0{}\0{}",
                root.to_string_lossy(),
                cfg.id,
                nasa::crypto::sha256(&source)
            ));
            // 构建工厂也执行用户代码，必须先取得与数据面相同的资源凭证和时间预算。
            let _lease = resources::Lease::acquire(cfg.working_set())?;
            let _worker = resources::Worker::acquire()?;
            let vm = Vm::new(
                cfg,
                nabudget::RequestBudget::from_now(Duration::from_millis(cfg.timeout_ms)),
            )?;
            vm.compile(&source)?;
            phases[index(cfg.phase)].push(Arc::new(Plugin {
                cfg: cfg.clone(),
                source: source.into(),
                fingerprint,
                include,
                mutation,
                circuit_key,
                circuit: Default::default(),
            }));
        }
        ensure!(
            phases[1].is_empty() || phases[2].is_empty(),
            "request whole-body and stream scripts cannot coexist"
        );
        ensure!(
            phases[4].is_empty() || phases[5].is_empty(),
            "response whole-body and stream scripts cannot coexist"
        );
        Ok(Self {
            phases,
        })
    }
    /// 业务作用：仅为显式相位安装管线适配，普通路由不创建解释器或输入副本。
    ///
    /// 参数说明：
    /// - `phase`：待查询阶段。
    ///
    /// 返回：该阶段有至少一个脚本时为 true。
    pub fn has(&self, phase: Phase) -> bool {
        !self.phases[index(phase)].is_empty()
    }
    /// 业务作用：在实体读取之前取得链中最严格的输入与输出上限。
    ///
    /// 参数说明：
    /// - `phase`：实体阶段。
    ///
    /// 返回：最小显式实体预算；无实体脚本为零。
    pub fn body_limit(&self, phase: Phase) -> usize {
        self.phases[index(phase)]
            .iter()
            .filter_map(|p| p.cfg.max_body_bytes)
            .min()
            .unwrap_or(0)
    }
    /// 业务作用：为等待实体或保留流上下文预留跨语言工作集，慢客户端不能建立无界扩展任务。
    ///
    /// 参数说明：
    /// - `phase`：当前实体阶段。
    ///
    /// 返回：覆盖最大调用工作集的资源凭证；满额失败关闭。
    pub fn reserve(&self, phase: Phase) -> Result<resources::Lease, Failure> {
        resources::Lease::acquire(
            self.phases[index(phase)]
                .iter()
                .map(|p| p.cfg.working_set())
                .max()
                .unwrap_or(0),
        )
        .map_err(|_| Failure::Capacity)
    }
    /// 业务作用：只为流式包装保留字段白名单并集，避免慢连接持有全部请求头。
    ///
    /// 参数说明：
    /// - `phase`：流式方向。
    /// - `headers`：已完成 head 阶段的字段。
    ///
    /// 返回：最多 128 个值、64KiB 的只读字段集；越界立即拒绝安装包装。
    pub fn stream_headers(&self, phase: Phase, headers: &HeaderMap) -> Result<HeaderMap, Failure> {
        let mut selected = HeaderMap::new();
        let mut bytes = 0usize;
        for name in self.phases[index(phase)].iter().flat_map(|p| &p.include) {
            if selected.contains_key(name) {
                continue;
            }
            for value in headers.get_all(name) {
                bytes = bytes
                    .saturating_add(name.as_str().len())
                    .saturating_add(value.len());
                if selected.len() >= 128 || bytes > 65536 {
                    return Err(Failure::Input);
                }
                selected.append(name.clone(), value.clone());
            }
        }
        Ok(selected)
    }
    /// 业务作用：输出不含源码、文件路径和请求内容的管理语义摘要。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：声明的阶段、预算、失败模式和不可逆源码指纹。
    pub fn semantic(&self) -> serde_json::Value {
        serde_json::json!(self
            .phases
            .iter()
            .flatten()
            .map(|p| serde_json::json!({
                "id":p.cfg.id,
                "phase":p.cfg.phase,
                "fingerprint":p.fingerprint,
                "failure_mode":p.cfg.failure_mode,
                "circuit":p.cfg.circuit,
                "max_memory_bytes":p.cfg.max_memory_bytes,
                "max_instructions":p.cfg.max_instructions,
                "max_allocations":p.cfg.max_allocations,
                "max_cpu_ms":p.cfg.max_cpu_ms,
                "timeout_ms":p.cfg.timeout_ms,
                "max_body_bytes":p.cfg.max_body_bytes
            }))
            .collect::<Vec<_>>())
    }
    /// 业务作用：依配置顺序执行同相位脚本，只发布成功且通过权限验证的完整输出。
    ///
    /// 参数说明：
    /// - `phase`：当前阶段。
    /// - `headers`：原子修改的头部目标；实体阶段只读。
    /// - `context`：冻结请求上下文与当前响应状态。
    /// - `body`：实体或单帧；head 阶段必须为 None。
    ///
    /// 返回：通过的实体或明确拒绝；错误时不提交当前脚本的任何半完成变更。
    pub async fn execute(
        &self,
        phase: Phase,
        headers: &mut HeaderMap,
        context: &Context,
        mut body: Option<Bytes>,
    ) -> Result<Execution, Failure> {
        for plugin in &self.phases[index(phase)] {
            let mut metric = super::metrics::Operation::begin(phase);
            let result = plugin.invoke(headers, context, body.clone()).await;
            let output = match result {
                Ok(output) => output,
                // 只有解释器依赖不可用可按声明跳过，本地预算、客体错误和主动拒绝均不得放行。
                Err(Failure::Dependency) if plugin.cfg.failure_mode == FailureMode::Open => {
                    metric.finish("fail_open");
                    continue;
                }
                Err(error) => {
                    metric.finish(error.outcome());
                    return Err(error);
                }
            };
            if output.reject.is_some() {
                metric.finish("reject");
                return Ok(Execution {
                    body: None,
                    reject: output.reject,
                });
            }
            if let Err(error) = output.validate_head(headers) {
                metric.finish(error.outcome());
                return Err(error);
            }
            for name in output.remove {
                headers.remove(name);
            }
            for (name, value) in output.set {
                if let Some(name) = name {
                    headers.insert(name, value);
                }
            }
            if output.body.is_some() {
                body = output.body;
            }
            metric.finish("continue");
        }
        Ok(Execution {
            body,
            reject: None,
        })
    }
}
impl Plugin {
    /// 业务作用：在有界阻塞任务中执行独立 VM，取消等待后任务仍持有资源直到真正结束。
    ///
    /// 参数说明：
    /// - `headers`：仅白名单字段可见。
    /// - `context`：冻结请求元数据。
    /// - `body`：显式阶段的有限字节。
    ///
    /// 返回：完整验证的输出或低敏失败；任何 Lua 句柄不会离开任务线程。
    async fn invoke(
        self: &Arc<Self>,
        headers: &HeaderMap,
        context: &Context,
        body: Option<Bytes>,
    ) -> Result<Output, Failure> {
        let circuit = self.bind(context)?;
        let epoch = circuit.enter()?;
        let lease =
            resources::Lease::acquire(self.cfg.working_set()).map_err(|_| Failure::Capacity)?;
        let input = Input::capture(&self.cfg, &self.include, headers, context, body)?;
        let budget = nabudget::RequestBudget::from_now(Duration::from_millis(self.cfg.timeout_ms));
        let _cancel = budget.cancel_on_drop();
        let worker_budget = budget.clone();
        let plugin = self.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let _worker = resources::Worker::acquire().map_err(|_| Failure::Capacity)?;
            let vm = Vm::new(&plugin.cfg, worker_budget)?;
            let function = vm.compile(&plugin.source)?;
            let table = input
                .table(&vm.lua)
                .map_err(|error| vm.guard.classify(error))?;
            let result = function
                .call::<mlua::Value>(table)
                .map_err(|error| vm.guard.classify(error))?;
            Output::parse(&vm, result, &plugin.cfg, &plugin.mutation)
        });
        let result = match budget.run(worker).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Failure::Dependency),
            Err(nabudget::BudgetError::Cancelled) => Err(Failure::Cancelled),
            Err(nabudget::BudgetError::DeadlineExceeded) => Err(Failure::Deadline),
        };
        circuit.complete(epoch, result.as_ref().err().copied(), &self.cfg.circuit);
        result
    }
    /// 业务作用：首次请求将熔断状态绑定可信路由归属，后续相位和旧流不能换用其它工作区额度。
    ///
    /// 参数说明：
    /// - `context`：由主管线冻结的资源域与状态预算，客体不可见。
    ///
    /// 返回：同域共享状态；归属不一致或常驻额度不足时失败关闭。
    fn bind(&self, context: &Context) -> Result<Arc<Circuit>, Failure> {
        let mut binding = self.circuit.lock();
        if let Some((scope, circuit)) = binding.as_ref() {
            if scope != &context.scope {
                return Err(Failure::Input);
            }
            return Ok(circuit.clone());
        }
        let key = nasa::crypto::sha256(&format!("{}\0{}", self.circuit_key, context.scope));
        let circuit = Circuit::shared(key, context.state_budget.as_ref())?;
        *binding = Some((context.scope.clone(), circuit.clone()));
        Ok(circuit)
    }
}
/// 业务作用：编译严格头部权限，拒绝静态安全字段和宿主声明的身份字段。
///
/// 参数说明：
/// - `names`：配置白名单。
/// - `identity`：当前路由宿主身份字段。
///
/// 返回：无重复的规范名称；任何敏感字段使候选失败。
fn compile_headers(names: &[String], identity: &HashSet<HeaderName>) -> Result<Vec<HeaderName>> {
    let mut compiled = Vec::new();
    for name in names {
        ensure!(name.len() <= 128, "script header name limit");
        let name = HeaderName::from_bytes(name.as_bytes())?;
        ensure!(
            !contract::forbidden(&name) && !identity.contains(&name),
            "script header is host-owned or sensitive"
        );
        ensure!(!compiled.contains(&name), "duplicate script header");
        compiled.push(name);
    }
    Ok(compiled)
}
