# Naway

**Naway** 是资源有界的 Rust **流量网关 + 业务网关**。同一进程提供 HTTP、gRPC、WebSocket 与 L4 转发，独立管理端口提供 YAML 编辑、CAS 发布、集群收敛和配置回滚。gRPC 边缘能力按订阅兴趣散出不透明业务消息；可选 AI 能力把模型、MCP 工具和 A2A 任务接入同一认证、固定目标、预算与撤权边界。all-in-one 可在不连接外部运行态服务的情况下启动。

- 数据面：基于 `hyper`/`tokio` 的流式反向代理，支持 h1/h2c、WebSocket/WSS、TLS/ALPN、SSE/gRPC、证书热换和慢连接 deadline。
- 本地配置直接使用 `naml` 的分层加载、来源追踪和精确 watcher；Nacos、Redis、axum 等运行组件复用 nasa-runtime-rust 的 `nasa` 门面。
- 可选工作区把配置归属、委派权限、双人审批与资源预算绑定到同一权威快照；不同团队可管理各自对象，共享上游必须显式授权。
- 内置管理监控提供本机与集群当前流量、保护、资源和节点状态，不保存监控历史；Prometheus 与外部历史监控可独立配置。

行为边界以配置 schema、公开协议契约和下述能力说明为准。

## 配置目录（固定 `/data/naway`，便于 Docker 挂载）

外部 yml **统一放一个固定目录**（默认 `/data/naway/`），做容器时整目录挂进去即可：

```
/data/naway/
├── naway.yml              # 监听 + SCG 风格路由(Path=/Method= 断言、StripPrefix= 过滤器)
└── interface-guard.yml   # 接口级拦截(独立文件):某接口对外关闭 → 直接返回配置的 response
```

配置路径优先级：`--config <路径>` > `NAWAY_CONFIG=<路径>` > `GW_CONFIG=<路径>` > `${NAWAY_CONFIG_DIR:-/data/naway}/naway.yml`。
`interface-guard.yml` 相对主配置目录解析，因此与 `naway.yml` 同目录、一起挂载和热更。

设置非空 `APP_PROFILE` 时，主配置、接口守卫和 Sentinel 规则分别加载同 stem 的
`-{profile}` 文件；profile 不存在时保持可选，但其全部格式候选仍会被精确观察。每个本地 YAML、
JSON 或 TOML 配置文件都有 32 MiB 单文件读取硬门，超限候选不会进入构建事务。

管理端的单文档与完整文档集校验直接读取候选原文，不为临时路径重编码 YAML。主配置与规则的
profile 仍以真实部署路径派生，相对 SecretSource 与其它依赖保持真实配置根；主 profile 和
环境覆盖不能把规则候选换回活动 base。候选工作区目录使用 `0700`、文件使用 `0600`，排他创建，
由构建任务在完成或拒绝后清理；请求取消不会取消该清理职责。单文档候选只覆盖主文档输入，
规则仍按真实路径加载。构建结果只用于验证，不直接发布活动快照。

每个 Admin 共享两个候选构建槽，涵盖原文发布、dry-run、完整文档集、工作区、语义比较与归档回滚。
任务排队、构建和清理期间持续占槽；HTTP 等待者取消不释放仍在执行的任务容量，超量立即返回 `503`。
单文档使用共享 `Bytes`，三文档在取得许可后才复制任务所需原文；两个任务的原文输入最多 192 MiB，
这不是全进程内存上限，不包括请求正文、调用方持有的原文和解析结果。非法候选返回 `400`，配置版本
耗尽返回 `409`，工作任务或临时存储失败返回 `500`；这些拒绝均不表示配置已经发布。工作区清理
无法确认时关闭该 Admin 的后续候选受理，新请求返回 `503`；需核对残留后重启，不自动删除未知文件
或重新开放容量。活动配置的 GET dry-run 也使用这两个槽，并继续读取实际活动来源。

构建同时冻结主配置、guard 与 Sentinel 三份 base 的原文字节数及 SHA-256；主配置解析前和完整编译后
复验原文，发生变化则拒绝候选。摘要按固定角色与长度分隔，通过固定缓冲计算，不保存插值后的秘密
或为哈希复制完整正文。三份 base 相同不表示 profile、环境、其它依赖或当前权限相同，这些条件仍由
同一配置构建及发布门分别验证。Nacos bundle 保持原有原文字节摘要与 UTF-8 约束。

本地管理发布使用已验证快照中的真实主配置、guard 和 Sentinel 路径。改变规则路径时，退出引用的
旧文件保留；新目标的父目录须已存在，已有文件须属于当前文档集或与候选内容完全相同。三个目标
必须各异，管理写入拒绝符号链接、特殊文件和共享硬链接。每份原文先进入排他创建的随机临时文件，
全部准备并同步后才逐文件替换；保留原文件的 Unix 权限位，新文件使用 `0600`。这些写入使用 Unix 目录与同步语义。

单文档发布、完整文档集与归档回滚共用文件事务，提交前复验当前基线。条件补偿使用本次精确文件收据，
恢复原内容或原缺失状态；后来出现的其它内容或 Unix 权限位变化会阻止补偿。
管理发布补偿在文件写锁内复验活动快照仍为发布前版本；文件观察者已发布候选时，信号发送失败也不会
撤回新快照对应的文件。该写锁与最终快照发布的读锁互斥。补偿未确认会返回失败，不能视为基线已恢复。
进程内锁和逐文件同步不提供整个文档集的断电原子性。需要跨进程恢复时，须显式启用下述节点持久
存储；未启用或仅初始化永久身份时，文件收据只在当前进程内有效。

naml watcher 只观察主配置、活动 profile 候选和已构建快照声明的 Secret、schema、策略及扩展文件，
同目录日志和临时文件不会触发 reload。候选必须先完成运行态资源 prepare 和 watcher 对账，随后才
原子发布快照；读取、校验、资源准备或新增目录观察失败时继续使用上一份有效配置。

## 节点持久身份

启用可选 `node-journal` 制品特性后，可用固定启动参数 `--node-journal <目录>` 持有节点持久身份。
目录必须预先创建为仅当前用户可访问；通过 `--node-journal-init --node-journal <目录>
--node-journal-node <节点> --node-journal-cluster <集群>` 显式初始化，随后普通启动保留同一目录参数。
`--node-journal-status --node-journal <目录>` 只读查看永久身份与独占 owner 是否占用。
初始化和检查直接退出，不创建默认配置或开放监听；普通启动先验证目录，再执行配置自举。

节点目录仅支持 Unix 的私有权限、目录句柄和持久同步语义。`data`、`sidecar` 与 `all-in-one`
可以持有目录，纯 `admin` 只可检查。永久 node 必须等于 `admin.management.node_id`，管理上报目标
均须开启发行者证明且属于永久 cluster；关闭管理或跨节点/集群的候选会被拒绝，同集群密钥可轮换。
同一目录只能有一个进程 owner，不依赖 PostgreSQL。损坏、未完成初始化或未知记录会在配置自举前
拒绝启动，不能通过重复初始化清空或换绑。部署移除目录参数属于改变启动权威，不能继续宣称受到
该目录保护。身份目录不隐式启用持久存储；仅初始化身份不提供配置文件事务恢复。

可在节点停止后，通过 `--node-journal-storage-init --node-journal <目录>` 显式安装持久受理代际。
初始受理代际为 `1`，已关闭水位为 `0`。两个有界状态槽由一个原子 head 决定当前提交；未提交槽即使
序号更大也不获得权威。状态记录最多 128 KiB，head、永久标记与固定暂存记录各最多 4 KiB，配置正文
另存于有界私有槽。只有完整且属于原身份的初始安装残留可以继续安装；永久存储标记存在后，缺失或损坏记录不能由
重复初始化重建。

只读状态的 `storage` 对象提供 `revision`、`admission_epoch`、`closed_epoch` 和 `compare_token`；
尚未安装时为 `null`。读取过程中复验 head，持续换代则返回忙碌，不返回混合状态。停止节点后可使用
`--node-journal-close-epoch <revision:sha256> --node-journal <目录>`，按原比较令牌关闭当前代际并开启
下一代；存在待完成文件决定时拒绝关闭代际。旧令牌和其它目录的令牌均拒绝，在线 owner 存在时禁止维护。I/O 错误可能发生在提交之后，
须先只读查看当前令牌与水位，不能盲目取得新令牌重复推进。

普通启动固定已提交的存储事实，仅本 owner 确认同步成功的提交可以推进内存期望。运行期间外部
改变代际、安装或移除存储都会阻止后续配置写入及热更。存储维护不创建默认配置或监听，普通数据
节点不依赖 PostgreSQL。节点命令接收与集群执行分别使用独立开关；共享提案经双人审阅后仍须显式执行。

### 节点命令接收

`node-actions` 在节点持久存储之上提供类型化动作接收，`admin.management.reporter.actions` 默认
为 `false`。开启要求已初始化的 journal、可信命令发行者、当前认证、RBAC 与审计，并且配置来源为
本地文件。开启 Nacos 配置来源的节点不能同时使用这条文件动作链；配置中心继续使用其 bundle/CAS 发布。
纯 Data 无需数据库；all-in-one 与 Data 使用相同的节点动作权限和持久事实。

只构建 `node-actions` 时保留接收、验签、原文下载、节点持久执行及结果上报，不编译管理动作发行
适配器，也不引入 PostgreSQL 或 MySQL driver。管理发行、本机执行入口与目标投递槽要求同时启用
`admin-operations-workflow-pgsql`；仅节点接收能力的制品不会经管理 Report 发行命令，管理端的
`ActionData`、`ActionResult` 与 `ReleaseResult` 返回发行能力未启用。已有发行身份握手独立保留，
握手证明本身不产生动作资格。

命令通过现有主动 mTLS 管理连接接收，原始候选单独按最多 16 KiB 分片读取，总量最多 1 MiB，
完整 SHA-256 核对后才进入预检。同一节点最多一个真实动作工作单元，取消网络等待不会释放仍在执行
磁盘工作的容量。当前会话、发行计划、权限、节点基线、单调期限和持久 fence 均须持续成立。

准备成功只表示原文与候选通过预检；文件方向先持久提交，实际快照发布后才确认应用效果。正向与补偿
保存独立收据，Resolve 必须按签名方向查询，未知和断连不生成成功或拒绝事实。对于明确未受理的正向
效果，节点可在独占工作许可内先持久提交更高 fence 和永久拒绝证明，再报告 `node_effect_not_admitted`；
迟到 Execute 不能重新生效，原流程据此补偿，已有受理和文件方向保留原恢复责任。证明不伪造业务 attempt，
需要管理端和目标端共同支持；旧制品遇到无法解释的持久字段或原因码会拒绝继续。关闭接收不会删除未决方向
或材料，重启仍按持久决定恢复。管理制品同时启用 `admin-operations-workflow-pgsql` 与 `node-actions`
后提供共享执行入口和完整目标进度；`execution_supported` 表示编译能力，独立执行开关和当前权威
决定是否可以受理。接收开关本身不授权提案执行。

### 经审阅的集群执行

多个 Admin 共享同一 PostgreSQL 执行事实；同一提案只创建一次执行，断连后按原身份回查。
候选只保存一份原文，按所有原目标先准备再应用；真实快照发布后才确认效果。未知结果保留原身份，
失败按条件补偿，不能把补偿完成显示为发布成功。节点永久关闭原代际后才释放占位，完整进度不会
因为目标离线而缩小分母。all-in-one 可同时承担 Admin 和 Data，并通过本机动作入口参与集群执行。

管理页 `/operations` 提供显式摘要确认、当前执行收据及全部目标释放进度；这些是持久操作事实，
不构成实时监控的历史存储。执行要求强制同步审计、命令信任、当前双人权限和节点持久存储。
初始化、独立开关、API、重放和基线边界见[持久管理提案](docs/admin-operations.md)。

### 本地配置文件恢复

已显式初始化存储的业务节点，为本地管理发布的主文档、完整文档集及归档回滚保存恢复决定。
同一时刻最多一个决定：先提交 `Preparing` 并完整保存原文，再提交 `Forward`，随后按 guard、
Sentinel、主配置的顺序替换和同步目录。三次文件替换不是一个文件系统原子事务；恢复以 head
选中的方向为准。状态中的可选 `local_publication` 只公开操作标识与方向，不包含路径或正文。

原文使用六个固定私有槽，每份最多 32 MiB、总量最多 192 MiB，相同正文共享引用。原始占位符保持
不变，不保存插值后的秘密；校验和恢复使用固定缓冲，避免重新聚合全部原文。记录绑定明确的旧/新
路径、父目录身份、权限、原存在状态、完整长度及 SHA-256。实际目标必须等于记录的完整旧内容或
候选内容，出现第三种内容、权限改变、非法链接或父目录替换时保护退出，不先改其它目标。退出引用
的旧文件保留；恢复旧指针之前还须确认其重新引用的文件仍为原基线。

普通启动先取得独占 owner，在配置自举和开放业务监听之前核对实际 `--config` 路径并恢复文件。
`Preparing` 未授权活动文件修改，重启只清理已登记的正文；`Forward` 完成候选集合，`Backward`
恢复原集合。启动先重新确认选中状态的持久同步，再执行文件副作用。候选仍须完成正常构建、永久
身份验证和资源准备；全部依赖指纹与原文再次一致后才结束记录并开放初始监听。运行中的最终 reload
同样在唯一文件事务内结束记录，再发布活动快照。完整无变化的发布不创建决定或改动存储 revision。

待完成决定期间拒绝其它配置写入，节点不再上报可选发布基线；此前活动快照可继续处理业务。
文件 rename 后同步报错属于提交结果未知，当前 owner 不猜测已经成功，也不继续文件副作用。
客户端取消或超时不改变已提交方向。需要主动反向恢复时，在节点停止后使用
`--config <原主配置> --node-journal <目录> --node-journal-rollback-local <revision:sha256>`；
命令复验当前令牌、全部原文和目标后才提交 `Backward`，恢复文件后仍保留决定，直到正常启动确认。
旧令牌、在线 owner、`Preparing` 或外来内容均拒绝。条件补偿也须先持久提交反向决定；已发布的
候选快照不能由迟到的失败撤回。

此协议保护合作写者与已记录文件，不能消除同一 OS 权限的不合作写者在最终复验与 rename 之间
制造的任意竞争。它不把 Nacos 的远端 CAS 或物化缓存变成本地管理事实，也不承担跨节点工作流的
终态裁决和补偿基线释放。

### 集群中的当前恢复状态

`/cluster` 的节点页通过同一次节点报告展示本地文件决定，独立于实时指标采样开关。
业务就绪与文件恢复分别显示：旧配置仍可转发时，节点可能正在准备文件或等待恢复决定完成。
各 Admin 使用自己当前授权的成员目录；节点失联、身份冲突或报告失效时撤下旧操作和存储序号，
不把缺席节点显示为恢复成功，也不保存恢复状态历史。

| 状态 | 含义 |
|---|---|
| `unsupported` | 节点未提供对应协议、未编译相关能力或为纯 Admin |
| `disabled` | 业务节点未持有节点目录 |
| `uninitialized` | 已有永久身份，尚未初始化文件恢复存储 |
| `unavailable` | 本轮无法取得有效观察，不保留上一轮提交信息 |
| `protected` | 目录身份、所选状态或当前管理绑定无法确认，配置写入受保护 |
| `idle` | 当前存储没有待完成文件决定 |
| `preparing` | 正在准备原文，尚未授权替换配置文件 |
| `forward` | 已决定完成候选，尚未确认结束 |
| `backward` | 已决定恢复基线，尚未确认结束 |

集群概览的 `nodes[].action_baseline.local_publication` 包含协议 `schema`、`state` 和可选 `storage`。
只有后四种状态携带存储集群、身份、受理代际和提交序号；待完成状态另有操作标识。代际和序号在
JSON 中使用十进制字符串，避免大整数精度损失。观察与发布基线共用一次有界磁盘读取，未知时同时
撤下对应证据；旧报告缺少字段时按 `unsupported` 处理。

该观察只说明当前元数据决定，不证明全部正文已重新校验、文件替换或活动快照发布成功。
`idle` 也不代替当前业务就绪、完整原文基线和执行前授权。接口不返回路径、正文或离线比较令牌，
页面不提供强制恢复按钮；远程工作流执行仍未开放。

## 进程日志

进程日志复用 NASA 的格式化、非阻塞文件输出与滚动保留策略。省略 `log` 时只写控制台并使用
`RUST_LOG`；显式声明 `log` 后使用该段级别与输出设置。日志文件打不开时启动失败，不开放业务监听。

```yaml
application:
  name: naway
log:
  path: "${NAWAY_LOG_PATH:/usr/local/logs/${application.name}}"
  level: info
  max_file_size: 500MB
  total_size_cap: 2GB
  max_history_days: 7
  split_error_file: true
  color: false
```

naml 先解析环境变量，再使用默认目录中的 `application.name`；可通过 `NAWAY_LOG_PATH` 指定部署目录。
文件名为 `info.log` 与 `error.log`。`log` 属于启动配置，改动需要重启；配置热更和管理发布会拒绝
不同的日志声明并保留当前路由。访问日志继续由独立的 `access_log` 控制。

## 集群节点管理

管理端口的 `/cluster` 展示整个已声明集群的当前节点清单，支持角色、节点身份与管理地址筛选。
每个节点独立显示实际就绪、进程启动身份、配置版本与指纹、注册／配置中心开关以及配置中的
监听计划、路由和上游数量。纯 Admin 与 Data、Sidecar、all-in-one 分开计数；多地址访问同一
启动实例只计一次。同一显式节点身份对应不同进程时，保留冲突明细，不推断可安全执行写操作。

节点事实可以通过独立管理 gRPC 主动上报，也可从 `admin.monitor.peers` 静态声明和实际启用的
网关自注册目录查询。后两者与实时监控使用相同的成员解析规则。`monitor.enabled: false` 关闭
指标采样后仍可查询节点事实。页面要求 `cluster/read` 权限；HTTP 跨节点读取另需显式配置认证
与 `admin.auth.allow_cluster_metrics_scrape`，内部固定入口为 `/admin/cluster/facts`，Data 与
Sidecar 也可提供。启用管理上报时，节点身份使用 `admin.management.node_id`；否则优先使用
`GW_NODE_ID`，其次使用自注册 metadata 的 `gateway.node_id`。未声明时显示未知。

自注册成员查询在每个 Admin 中共用惰性执行者，最多一个在途查询和十六个排队请求。
普通查询的五秒期限包含排队、连接与查询，监控目录使用一秒期限；容量不足或发现不可用明确
返回失败，不能把失败解释为节点退休。最多四个命名客户端按完整连接域和凭据复用，成员事实
逐次读取；凭据不同不会共享客户端。该预算约束 Naway 的查询执行者和客户端缓存，底层 SDK
的后台连接维护由 SDK 管理。

`/api/cluster/overview` 只返回当前清单，不接受历史或任意目标参数。每个 Admin 共享两秒一次的
按需查询，最多 128 个成员、8 个并发请求、单节点 1 秒和 32 KiB 实体，整轮期限 2 秒；无观察者
12 秒后释放当前结果。页面明确显示失联、拒绝、超时、目录陈旧、身份冲突和容量不足。
各节点配置版本与完整指纹按实际值展示；包含节点专属配置的指纹不同，不直接等同于集群发布失败。
HTTP 读面应置于可信管理网络；读取目标不会隐式获得远端写权限。显式 gRPC 成员优先使用上报
槽，失联或身份冲突时不回退 HTTP 掩盖故障；授权成员尚未上报时仍保留在覆盖分母中。

集群概览的节点 `action_baseline` 单独描述持久动作基线的可用性。启用节点 journal 且已安装
受理代际存储时，Data、Sidecar 和 all-in-one 可通过同次管理报告提供永久 `store_id`、发行集群、
`node_admission_epoch` 和三份 base 原文的 `documents_sha256`；JSON 中代际使用十进制字符串。
本机和上报前的文件观察共用一个读取许可，完整等待期限为一秒，取消等待不会提前释放仍在
执行的磁盘工作。目录保护、过期、身份冲突或撤权后不提供可消费基线。旧节点和 HTTP 事实来源
显示 `unsupported`；支持协议但当前没有完整证据时显示 `unavailable`。

提案目标可选填 `node_baseline`，缺省保持原意图格式；填写后存储身份、代际和原文摘要都进入
幂等比较，且发行集群必须与提案相同。共享同一提案库的 Admin 均支持此扩展后才应填写它；
旧 Admin 的严格目标解码器不能读取新增字段，已有旧目标记录仍可由新 Admin 原样读取与回放。
这仍是提交者声明的冻结意图，保存与批准不代表已核对
目标当前状态或取得执行权限。原文摘要只覆盖三份 base，不代替 profile、外部依赖和当前授权；
远程动作执行仍未开放。

提案页的平台范围可在拥有 `Cluster/Read` 时显式读取集群目录，逐个冻结同集群业务节点的完整基线。
过期、不完整、冲突或缺少基线的成员不可选；已选声明不会随刷新或节点重启改变，须明确移除后重新选取。
工作区范围不读取平台目录，仍可手工声明目标。页面与详情持续区分冻结意图和实际执行资格。

### 节点主动管理通信

启用编译特性 `admin-grpc` 后，`admin.management` 提供独立的节点当前事实上报通道，默认关闭。
它与注册中心、配置中心、监控采样和 HTTP 抓取开关独立；静态集群无需启用中心服务。
同一 Naway 项目支持 `all-in-one` 同时承担管理和业务转发，也支持 `admin`、`data`、`sidecar`
分离部署。`receiver` 可用于 `admin` 与 `all-in-one`，`reporter` 可用于全部角色，两者可同时配置。

以下为接收端配置片段；`certificate_sha256` 必须填写节点客户端叶证书 DER 的 64 位小写十六进制
SHA-256，不能使用示例中的占位值。浏览器登录仍需另外配置管理认证主体和权限。

```yaml
admin:
  auth:
    enabled: true
  management:
    enabled: true
    node_id: admin-a
    receiver:
      listen: 192.0.2.10:19090
      tls:
        ca_file: management/ca.pem
        cert_file: management/admin-a.pem
        key_file: management/admin-a.key
      nodes:
        data-a:
          certificate_sha256: "<data-a 客户端叶证书 SHA-256>"
```

节点可同时向多个 Admin 报告；每个管理入口应声明相同的预期集群成员，并排除自身。
以下为 `data-a` 的对应片段；端点必须为显式 IP:port，`authority` 用于验证服务端证书名称。

```yaml
admin:
  management:
    enabled: true
    node_id: data-a
    reporter:
      tls:
        ca_file: management/ca.pem
        cert_file: management/data-a.pem
        key_file: management/data-a.key
      targets:
        - address: 192.0.2.10:19090
          authority: admin-a.example.internal
        - address: 192.0.2.11:19090
          authority: admin-b.example.internal
```

连接强制双向 TLS，根证书和身份材料必须位于配置根目录内。服务端每次调用都校验节点与实际
客户端叶证书绑定；同一证书不能绑定多个节点。接收端最多声明 127 个远端成员，另保留本机，
上报端最多连接 8 个 Admin。关闭总开关时不读取证书、不绑定接收监听，也不建立上报连接。

协议 `naway.management.v1.NodeManagement` 通过 Open 建立 node/boot 会话，通过 Report
提交递增序号和类型化当前事实。默认每两秒复用连接上报，启用一秒采样且存在上传需求时改为每秒；
建立会话、可选发行者证明与报告共用一秒总期限，失败退避
最多十秒，不排队重放旧样本。接收端按单调时钟判定六秒新鲜期；重复序号或重复 Open 不延长
有效期。同名活跃 boot 冲突会明确展示；过期后新 boot 可建立会话，旧令牌立即失效。

单条消息上限 32 KiB，进程最多受理 128 条管理连接，每连接两个 HTTP/2 流，最多 32 个在途 RPC；
另有 2 MiB 在途消息预算和 64 MiB 受管资源预算。系统监听队列中的待受理 TCP 连接不计为已受理
管理连接。未完成握手的已受理连接两秒到期。单个 Admin 不可达不阻塞其它端点或业务转发。

本地受信配置热更可调整节点成员、上报目标和证书。候选材料及新监听在发布前准备，验证或绑定
失败保留当前配置。发布后才激活新监听；激活异常会报告接收端不可用，不恢复已撤销的监听权限。
证书节点授权在每次调用复验；TLS 材料轮换用于新握手，既有连接保留原握手信任，最长连接年龄
为 300 秒。Nacos 业务配置不能改变管理身份、信任材料和目标，只能沿用当前本地权威。

此通道提供当前节点事实、低敏配置对象目录及显式启用的实时指标上传，不保存历史，也不传输业务正文或日志。
节点事实接收不授予远程配置写权限，也不构成多个 Admin 之间的持久操作协调权威。

需要把接收服务进一步绑定到指定 Admin 发行身份时，可显式启用 Ed25519 证明。接收端配置
`receiver.issuer`，上报端在对应 `reporter.targets[].issuer` 中声明固定集群、节点和公钥：

```yaml
# 接收端的 admin.management.receiver 内
issuer:
  enabled: true
  cluster_id: production
  private_key: file://management/issuer-private.b64
  public_key: file://management/issuer-public.b64
```

```yaml
# 上报端的 admin.management.reporter.targets 内
- address: 192.0.2.10:19090
  authority: admin-a.example.internal
  issuer:
    enabled: true
    cluster_id: production
    node_id: admin-a
    public_key: file://management/admin-a-public.b64
```

这两个开关默认关闭。材料使用 SecretSource，私钥为 Base64 PKCS#8，公钥为 Base64 SPKI，
单份最多 2048 字节；只在候选构建时读取，文件变更参与热更。私钥与公钥不匹配、弱公钥或材料
无效时保留当前配置。接收端签名身份使用自己的 `management.node_id`。

启用验证后，节点在接受会话前调用 `AuthenticateIssuer`，使用 NASA Ed25519 校验固定集群、
Admin 节点以及本次随机挑战、node/boot/session 的绑定；不支持、未开启、签名不符或超时都拒绝
该目标的本轮握手。证明不刷新心跳，信任材料换代撤销旧会话。身份校验不授予节点动作权限，
也不能作为后续配置命令的授权票据；其它 Admin 和数据转发保持独立。

实时指标上传分别由 `admin.management.reporter.metrics` 与
`admin.management.receiver.metrics` 控制，两者默认关闭，还需要各节点的
`admin.monitor.enabled=true`。它们与 `admin.auth.allow_cluster_metrics_scrape` 独立：HTTP 抓取
关闭时，已声明的管理成员仍可通过 gRPC 上传当前指标。Admin、Data、Sidecar 与 all-in-one
共用同一采样器；纯 Admin 的控制指标与业务节点汇总分开，页面逐节点标注实际来源。

只有通过授权的集群观察请求才产生最多十二秒的上传兴趣，Report 确认仅传递剩余需求；心跳本身
不续期兴趣。多个 Admin 的需求取并集，节点只保留当前样本，不为慢端点积压历史。采样在进程内
共享 `Arc`，HTTP JSON 在对应读面首次访问时才编码，类型化上传不经过 JSON 或 Prometheus 文本。
有有效上传需求时，上报周期取本机采样周期与两秒的较小值；需求结束后恢复两秒心跳。样本仍按
原始采集年龄失效，不能用新的聚合响应或持续心跳延长旧指标寿命。

`Sample` 方法使用客户端流提交一份当前样本，固定指标每片最多 64 系列，随后路由事实每片最多
32 行；每片不超过 32 KiB，完整流最多 49 片。样本分别限制为 1024 个固定系列和 1024 个路由，
另有 32 个直方图边界及 64 项能力状态的上限。接收端在完整摘要与流结束校验通过后，
再次核对当前证书、会话、配置及递增样本身份，最后原子替换可读结果；半份、超时或取消不发布。
相同内容可重复确认，但缓存释放后也不能靠重传刷新年龄。心跳与指标分别判断新鲜度；持续上报
节点事实不会让停止更新的指标继续显示为有效。目录和样本在心跳后的同一秒剩余预算内有界并发。

样本候选预留 4 MiB，候选与当前接收槽共享 64 MiB 许可池；完整校验后按保守实体容量保留许可。
集群当前及相邻基线另受 8 MiB 限制，超限保留明确覆盖缺口，不保证最大成员数与最大单样本容量
可以同时驻留。推送成员出现失联、撤权、陈旧或不支持时保留在分母中，不以 HTTP 回退掩盖故障；
其它显式授权的 HTTP 成员仍可混合读取。关闭监控、撤权及兴趣到期后释放采样状态，无历史查询。

### 集群配置对象目录

管理端口的 `/catalog` 展示路由、HTTP 入口与逻辑上游在集群中的分布。对象按种类、所属入口和
稳定身份合并；每个对象分别列出存在节点、已确认缺少的节点、尚无法确认的节点及不同摘要。
节点明细保留角色、启动身份、配置版本和指纹。入口表示配置计划，逻辑上游表示声明存在；目录
不证明监听已绑定或上游实例健康，公开字段一致也不代表完整配置相同。

平台目录读取同时要求 `cluster/read` 与领域权限：路由需要 `routes/read`，HTTP 入口需要
`config/read`，逻辑上游需要 `upstreams/read`。工作区专用主体不会因此获得平台目录权限。
`GET /api/cluster/catalog` 支持 `domain=routes|listeners|upstreams`、`search`、`offset` 和 `limit`；
每页最多 100 项，后续页必须携带前页的 `ETag` 作为 `If-Match`。分页身份由整个节点配置向量
决定；节点配置或覆盖变化返回 412，需要重新读取第一页，不能把跨代页面拼成一致清单。

节点在同一快照内共享目录，通过管理 `Catalog` 方法提交类型化消息。首片最多一个对象，
并携带完整工作区读取证明；后续每片最多 32 个对象。证明与对象共同计入目录容量并原子发布。
心跳先行，每轮最多八片且与 Open/Report 共用一秒期限；ACK 丢失时重复内容只确认，不重复追加。
接收端验证会话、配置身份、偏移、对象唯一性和完整 SHA-256 后发布。目录接收不刷新节点心跳；
新配置撤下旧目录，未完成分片保持等待状态。目录不包含原始 URI、匹配值、header、密钥或证书。

每节点最多 2048 个对象、512 KiB 目录内存，接收槽合计最多 64 MiB；超过观测预算仍继续运行
业务配置，但明确显示目录容量不足。领域汇聚最多 4096 个匹配对象，进程最多八个并发读取，响应
上限 4 MiB；超限需缩小搜索或页容量。只通过 HTTP 提供节点事实的成员保留为“未提供对象目录”，
不能因此从成员分母删除，也不能将其对象判断为缺失。页面显示的是当前目录，不提供历史查询或
远程修改按钮；对象详细配置和远程发布不属于此目录接口。工作区集群读取使用独立授权入口。

## 持久管理提案

配置编辑前可使用[配置候选差异](docs/admin-configuration-diff.md)核对固定活动基线；
Sentinel 比较覆盖实际生效配置的全部规则字段，集群发布仍由原目标的持久执行确认。

可选 `admin-operations-pgsql` 制品与 `admin.operations.enabled` 开关提供跨 Admin 的共享候选、
幂等提交和双人审阅记录。数据库不可用时拒绝依赖它的新管理请求，已有数据转发继续工作；
注册中心、配置中心和实时监控分别配置。可选保留策略以持久受理代际封闭过期请求，有限批次回收
从未执行的过期提案与匹配收据；各 Admin 共用数据库裁决。管理端口 `/operations` 提供授权工作区和
三个领域的共享列表、目标录入、原文审阅与按原请求查找；未知提交保持原身份，支持从另一 Admin 核查。
共享容量可通过显式维护命令按原修订调整，缩容必须容纳全部保留事实，新旧写入均受数据库预算约束。
执行存储可显式永久绑定一个集群；数据库同时约束新旧进程的注册，已有其它集群时拒绝绑定。
绑定只确定存储所属范围，不初始化工作流或开放节点执行。
可选 `admin-operations-workflow-pgsql` 复用 NASA 工作流引擎，显式事务初始化 Saga、Inbox、Outbox，
普通启动只读校验实际结构与在途定义。工作流存储就绪与节点执行资格分别报告，当前提案入口仍不下发动作。
使用方式与容量、权限、未知提交语义见
[持久管理提案](docs/admin-operations.md)。提案批准只表示审阅记录已保存，当前接口不下发配置、
不执行节点动作，也不表示目标已经通过预检或配置已经生效。

## 内置实时监控

管理端口的 `/monitor` 默认展示集群实时页面，也可查看接入节点，使用当前管理主体的 Bearer 或 Basic 凭据；监控读取要求
`cluster/read` 权限。原管理首页继续提供配置编辑和治理入口。浏览器凭据仅保留在当前页面内存中，
退出、撤权或关闭页面后释放。浏览器应通过 HTTPS 访问管理面；本机回环地址允许 HTTP。

监控只展示最新区间和当前状态，不提供时间范围查询、趋势回放或历史数据存储。它与 Grafana 等
历史分析系统用途不同，也不依赖 `admin.expose_metrics`。请求速率、已生成响应头的错误比例、响应头
时延分布、活动连接、进程 CPU/RSS、限流与熔断拒绝，以及已编译功能的固定指标来自现有运行事实。
没有独立事实源的指标不生成估算值；响应头时延不表示流式响应结束耗时。

HTTP 正文另有入站/出站字节、响应在途量、EOF/正文错误/提前丢弃/协议升级终态和正文结束耗时。
`gw_http_body_bytes_total` 的 `request` 是管线实际消费的原始编码 DATA，`response` 是最终编码后
交给 HTTP adapter 的 DATA；它们不含头、trailers、协议或加密开销，也不代表对端确认接收。
未读取的上传不按 Content-Length 补算，重试与镜像不重复统计下游输入；计数过程移动原始帧，
不复制或聚合正文。`gw_http_response_inflight` 覆盖等待响应头到正文 EOF 的整个本地生命周期。

`gw_http_response_events_total` 区分 `eof`、`body_error`、`dropped` 和 `upgraded`；`dropped`
也包括提前拒绝及头前取消，不能据此推断客户端责任。完整 HTTP 错误响应仍可正常 EOF，gRPC
trailers 中的业务状态不等同于正文传输错误。101 和成功 CONNECT 不进入普通 HTTP 完成分布；
SSE 与 native gRPC 保持流式观察。HEAD、204、304 和空正文在响应头就绪时结束。
`gw_http_response_duration_microseconds_total`、`gw_http_response_duration_count` 和
`gw_http_response_duration_bucket_total{upper_bound_ms}` 共同描述入口到本地正文 EOF 的时间；
桶互不累计，上界包含该值，`+Inf` 为溢出桶。集群先按各节点实际区间归一化，再合并桶，
只在完整指标组覆盖和计数一致时计算均值及 P95；样本不足或分位落入溢出桶时显示未知。
这些固定事实同时供 Prometheus、OTLP 和内置实时监控使用，不保存历史。

`/traffic` 提供集群与工作区的路由实时流量。平台读取要求同时具备 `cluster/read` 和
`routes/read`；工作区读取使用本域角色及显式 `cluster_nodes`，并逐节点核对同代目录与权限证明。
工作区响应不提供其它域对象、节点地址或全局配置指纹。纯 Admin 不进入业务流量分母；失联、
权限不一致、旧协议或容量不足的节点保留为未知，不能冒充零流量。

每条路由显示首个公开入口命中的请求速率、当前在途量、最终响应类别、输出实体字节、四种流结束
结局，以及完整响应均值和 P50/P95/P99。内部转路由、分层叶子、镜像及重试不重复累计入口请求；
匹配前拒绝与未命中请求只进入全局指标。路由输入字节不提供估算，升级后的隧道流量不属于这组
HTTP 事实。观察复用同一正文适配器，不复制正文；配置热更建立新所有者，旧在途完成不会更新
同名新路由或改变后的工作区归属。

路由事实通过本机采样或显式授权的管理 gRPC 提供。原始 HTTP 指标抓取不携带对象身份，
HTTP-only 成员在路由流量中显示未提供能力。每节点和聚合目录最多 1024 路由，超限撤下整个
路由观测域，业务路由仍按原配置运行；固定低基数指标和已有采样内存预算保持独立约束。
`GET /api/monitor/routes` 与 `GET /api/workspaces/{workspace}/monitor/routes` 接受
`search`（最多64字节）、`offset` 和 `limit`（1–100）。后续页要求当前响应的 `ETag` 作为
`If-Match`；采样变化返回412，缺少条件返回428。搜索不改变节点覆盖分母。页面详情属于同一次
采样，暂停、隐藏、切换范围或退出立即清空旧值，不保存历史页面。

熔断状态直接来自执行状态机：`gw_circuit_state_instances{state}` 的 `closed`、`open`、
`half_open` 表示当前保留的节点本地状态实例；保护时间届满仍为 `open`，取得实际探测权后才进入
`half_open`。`gw_circuit_active_calls` 统计尚未归还的执行许可，
`gw_circuit_transitions_total{from,to}` 只统计真实状态迁移；取消探测归还半开权并回到 `open`。
旧策略仍有活动许可或等待安全回收时继续计入，因此实例数量不等于当前配置规则数量。
集群相加的是节点本地实例与许可；Redis 共享滑动窗口统计不提供全局唯一半开执行权。
页面分别展示保护、探测、关闭态与许可，并保留组覆盖；缺失节点不补零。采样读取固定计数，
不遍历热状态表，也不触发探测或改变业务保护。

响应内容编码提供 `gw_response_codec_bytes_total{operation,algorithm,side}`：`encode` 或 `decode`、
`gzip` 或 `br`、实际消费的 `input` 或产出的 `output`。透传响应不计入变换，字节不包含协议开销。
`gw_response_codec_inflight` 表示尚未结束的变换；`gw_response_codec_events_total` 以 `outcome`
区分 `eof`、`body_error` 和 `dropped`，codec EOF 不等于下游 HTTP 完成或对端确认。

`gw_response_codec_completed_input_bytes_total` 和 `gw_response_codec_completed_output_bytes_total`
只对成功 codec EOF 成对结算，并与成功次数一致采样。页面的成功编码节省率按本区间完成的
gzip/br 编码集合计算 `(输入-输出)/输入`，压缩膨胀时为负；解码、错误、取消和透传不混入该比率。
此集合可能包含此前区间处理的字节，因此不是本区间网络带宽节省。集群使用有效区间的成对字节
之和计算，不平均节点百分比；覆盖缺失、输入为零或无有效完成区间时保持未知。普通输入/输出
卡片另行展示本区间实际处理速率。观察复用原有trailer共享分配，输出块跨Pending保留，
只有实际交付DATA后才获取新块，不增加正文复制或聚合。

启用 `admin-grpc` 的制品还提供当前管理接收监听状态、实际受理连接、方法在途、拒绝原因和最终
RPC 结局，直接读取 NASA 受管观察器。集群指标列表区分业务节点与纯管理节点，可按角色筛选；
管理监听状态、连续接收失败和停滞时长在节点明细中独立展示，不按节点相加。未配置接收监听
显示未启用，当前观察句柄缺失显示不可观测；没有凭据、节点身份或动态错误文本指标标签。

```yaml
admin:
  monitor:
    enabled: true
    sample_interval_ms: 2000
    use_discovery: true
    peers: []
```

`sample_interval_ms` 支持 `1000`、`2000`、`5000`、`10000`。本机与集群采样分别由进程内共享
协调器按需执行，多个页面读取相同编码结果；没有观察者后释放当前样本和差值基线。监控配置可热更，
关闭监控会停止采样和监控外连，业务转发继续运行。

通过 HTTP 抓取的集群监控需要 `admin.auth.enabled=true`、`admin.auth.allow_cluster_metrics_scrape=true`，以及
本机配置中拥有 `cluster/read` 权限的认证主体。各成员必须识别该节点派生的凭据；不会转发页面
调用方的凭据。自动成员仅来自实际启用的 Nacos 网关自注册目录。关闭注册中心时，可以在 `peers`
声明静态成员，例如 `{id: node-b, address: "10.0.0.12:18080"}`；目标只能是明确的 IP 与管理端口，
不接受浏览器传入的 URL。HTTP 抓取使用管理 HTTP 端口，应置于可信管理网络；启用管理 gRPC 指标
接收时，接收成员通过 mTLS 主动上传，不要求打开此 HTTP 抓取开关，两种来源可按显式成员声明混合使用。

同一个 Naway 项目支持 `all-in-one`（缺省）、`admin`、`data` 和 `sidecar`。`all-in-one` 同时
承载业务与管理功能；也可部署独立 Admin 进程观察多个数据节点。纯 Admin 的资源汇总独立显示，
业务流量与时延仅聚合数据节点；同一进程的多个管理地址按启动身份去重。多个 Admin 的实时采样
各自执行，监控读面不代表集群写操作已具备协调接管能力。

未配置远端成员且关闭发现时，页面明确显示仅声明了接入节点；纯 Admin 没有已知数据节点时显示
无数据节点。发现失败时保留当前配置代内最后完整的成员目录，标记陈旧并继续观察已知成员；
身份冲突、截断和失联均明确显示，不能把缺失成员当作零流量或正常退休。

每轮最多覆盖含本机在内的 128 个节点，最多 8 条并发抓取；单节点完整期限 1 秒，响应上限 1 MiB，
基线总预算 8 MiB。整轮抓取受采样周期预算约束，超时后轮转节点顺序，避免故障成员长期阻塞其它成员。
超过目录或内存容量会明确显示容量状态和缺失覆盖，不把部分成功显示为全集群正常。

首轮、计数重置、配置代改变或失联恢复时，速率显示未知。集群先按每节点实际区间计算速率，再合并
直方图桶速率求分位，不平均节点 P99。P50/P95/P99 分别至少需要 5/20/100 个实际样本，落入溢出桶
时不生成有限估值。页面显示节点覆盖、区间范围和当前节点明细；暂停、切换范围、页面隐藏后清空显示。

## 快速开始

```bash
# 本地开发:用仓库示例配置目录 zcf/
NAWAY_CONFIG_DIR=zcf cargo run
# 或显式指定主配置
cargo run -- --config zcf/naway.yml

# 生产：把 yml 放宿主 /data/naway，直接运行（默认读 /data/naway/naway.yml）
naway

# 热更(nginx 风格,向运行进程发 SIGHUP);或直接改 yml,naml 自动热加载(无感、零抖动)
naway -s reload
```

```bash
# 例:export 接口已在 interface-guard.yml 里下线 → 直接 403,不走上游
curl -i http://127.0.0.1:8080/api/export/orders     # → 403 {"code":40301,"msg":"export 接口已下线"}
curl -i http://127.0.0.1:8080/api/hello             # → 命中路由 demo,转发上游
```

## 当前能力

Naway 已提供统一的 gRPC 边缘发布、订阅、群播与定向单播契约。Naway 不解析业务
protobuf 内容，业务消息按不透明字节传递，只依据 gRPC metadata/header 与订阅兴趣执行规则散出。
集群传输可在原生 gRPC Relay、Redis Pub/Sub 与 Redis Stream 之间显式选择；单个部署只启用
一种集群通信方式，Redis Stream 的历史消息裁剪由业务生产侧负责。

支持流式 h1/h2c/TLS/gRPC/WS/WSS 反代、Nacos 发现与网关自注册、Redis/Nacos 共享运行态、Sentinel 防护、配置 build-then-swap、管理面/RBAC/审计、HTTP L1/L2 缓存、OTel、压缩、OpenAPI 请求/响应契约、声明式 JSON/XML/SOAP 转换、OpenAI/Anthropic/Google LLM 网关，以及 WASM/外部插件、OPA/Casbin、GraphQL、Dubbo/MQTT/Kafka、TCP/UDP/TLS stream、K8s/Consul/Eureka/DNS 发现和开发者门户。

route 可显式启用内置 API WAF。未配置时不扫描请求 head，也不读取 body；`inspect_body: true`
只对 JSON/XML 进入有界聚合慢路径。规则命中日志只包含 route、固定规则 id 与 target，不记录
原始 URI、header 值或 body。body 超过显式上限时返回 413，解析失败或规则命中不会继续访问上游。

```yaml
routes:
  - id: protected-api
    uri: "http://127.0.0.1:3000"
    predicates: ["Path=/api/"]
    waf:
      mode: enforce              # enforce | monitor
      inspect_body: true         # 默认 false
      max_body_bytes: 1048576
      max_value_bytes: 65536
      enabled_rules: []          # 空数组启用全部内置规则
      exclusions:                # 只支持精确 rule + target，不支持通配符
        - rule: sql_injection
          target: header:x-known-query
      max_json_depth: 64
      max_json_nodes: 100000
      max_xml_depth: 64
      max_xml_nodes: 100000
      max_xml_attributes: 10000
      rule_pack:                 # 可选：签名 JSON literal 规则包
        source: waf-rules.json
        sha256: "<64 个十六进制字符>"
        signature: file://secrets/waf-rules.sig
        public_key: file://secrets/waf-rules.pub
        max_pack_bytes: 4194304
        max_rules: 1024
        max_patterns: 16384
        max_compile_ms: 2000
```

外部规则包固定使用 `schema_version: 1` 的 JSON，只接受可打印 ASCII literal，不接受正则或脚本。
每条规则声明稳定 `id`、作用位置和一个或多个大小写不敏感 literal；位置可为 `path`、`query`、
`body`、全部 `header` 或精确 `header:<lowercase-name>`。网关对原始文件同时复验 SHA-256 和
detached Ed25519 signature，再检查文件字节、规则数、literal 数量、单 literal 长度和构建时间。
来源、签名或公钥变化进入同一配置 watcher；坏更新拒绝候选，当前规则继续生效。外部规则也可用
route 的 `exclusions` 做精确 `rule + target` 豁免。

```json
{
  "schema_version": 1,
  "id": "api-security",
  "rules": [
    {
      "id": "blocked_internal_marker",
      "targets": ["query", "header:x-client-marker", "body"],
      "patterns": ["internal-only-marker"]
    }
  ]
}
```

route 也可使用本地 MaxMind MMDB 对权威客户端地址执行国家、ASN 与匿名网络门禁。数据库只在
候选构建阶段有界读取，请求热路径不访问文件或网络；文件变更必须完整解析、核对数据库类型与
build epoch 后才原子发布，失败继续使用上一份有效快照。未命中、解码失败和陈旧数据的动作均需
显式配置，默认分别为 `deny`、`deny` 和拒绝候选，日志与指标不包含 IP、国家或 ASN 原值。

```yaml
routes:
  - id: regional-api
    uri: "http://127.0.0.1:3000"
    predicates: ["Path=/regional/"]
    geoip:
      country_database_file: GeoIP2-Country.mmdb
      asn_database_file: GeoIP2-ASN.mmdb
      anonymous_database_file: GeoIP2-Anonymous-IP.mmdb
      allowed_countries: [VN, SG]
      denied_countries: []
      allowed_asns: []
      denied_asns: [64512]
      denied_anonymous_traits: [anonymous_vpn, public_proxy, tor_exit_node]
      on_not_found: deny          # allow | deny
      on_lookup_error: deny       # allow | deny
      on_stale: reject            # reject | allow | deny
      max_database_age_secs: 3888000
```

Bot 策略可组合大小写不敏感的 User-Agent glob、必需 header、自动化信号、稳定 SHA-256 指纹和
共享 RateLimiter。命中可选择 `enforce` 或 `monitor`；enforce 返回带固定
`WWW-Authenticate: NawayBot` 的挑战响应，速率拒绝返回 429 与 `Retry-After`。可信搜索机器人
不会仅凭 User-Agent 获得豁免：每个请求都必须用构建期 SecretSource 对时间戳、权威客户端 IP、
方法、authority、path/query 和 User-Agent 做 HMAC-SHA256 签名复验。原始输入与指纹不进入日志、
指标或限流 key。

```yaml
routes:
  - id: bot-protected
    uri: "http://127.0.0.1:3000"
    predicates: ["Path=/public/"]
    bot:
      mode: enforce
      allowed_user_agents: []
      denied_user_agents: ["*sqlmap*", "*HeadlessChrome*"]
      required_headers: []
      automation_headers: [x-playwright, x-puppeteer, webdriver]
      fingerprint_headers: [accept, accept-language, sec-ch-ua, sec-ch-ua-platform]
      denied_fingerprints: []
      score_threshold: 4
      trusted_search_bots:
        - name: signed-search
          user_agents: ["TrustedCrawler/*"]
          signature_secret: file://secrets/search-bot-hmac
          signature_header: x-naway-bot-signature
          timestamp_header: x-naway-bot-timestamp
          max_clock_skew_secs: 60
      rate:
        limit: 120
        window_ms: 60000
        burst: 20
        max_active_keys: 100000
        active_keys_fail_open: false
      challenge_status: 403
      challenge_realm: verification-required
```

浏览器 API 可显式启用 CSRF 门禁。默认只保护 POST/PUT/PATCH/DELETE，先按 listener 确定的
scheme、请求 authority 与严格单值 Origin 复验同源；Origin 缺失时可回退 Referer，但不会把完整
Referer 写入状态或日志。随后验证 `__Host-` host-only cookie 与单值 header 的 token。默认
`double_submit` 使用固定 256-bit Base64URL token；`signed` 使用构建期 SecretSource 对
timestamp、nonce 和 route 作用域做 HMAC-SHA256。安全方法的成功响应可签发新 token，同时添加
`Secure; HttpOnly; SameSite=Strict` cookie 和 `Cache-Control: private, no-store`，避免每客户端 token
进入共享缓存。策略只读取 head，不聚合请求 body。

```yaml
routes:
  - id: browser-api
    uri: "http://127.0.0.1:3000"
    predicates: ["Path=/browser-api/"]
    csrf:
      mode: enforce
      methods: [POST, PUT, PATCH, DELETE]
      allowed_origins: [same-origin, "https://console.example.com"]
      allow_referer_fallback: true
      allow_missing_origin: false
      token_mode: signed
      cookie_name: __Host-naway-csrf
      header_name: x-csrf-token
      token_secret: file://secrets/csrf-hmac
      token_ttl_secs: 7200
      issue_on_safe_methods: true
```

route 还可显式启用敏感数据防护。策略可检查选定的请求/响应 header、query、access-log path，
以及有界 JSON、URL encoded form 或文本 body；支持 `block`、`redact` 和 `monitor`。内置规则覆盖
email、带分隔符的电话号码、通过 Luhn 校验的银行卡号、常见身份号码、JWT、API key、private-key
marker 与密码/token/Authorization 等 secret 语义。例外必须同时指定固定规则和精确 target，日志和
指标只记录固定结果，不记录命中原值。body 检查拒绝压缩实体、超限、非法结构和 partial response；
遮蔽后会移除旧的摘要、validator、range header 并重建 Content-Length，避免发送与实体不一致的元数据。

```yaml
routes:
  - id: data-protected
    uri: "http://127.0.0.1:3000"
    predicates: ["Path=/data/"]
    dlp:
      action: redact             # block | redact | monitor
      enabled_rules: []          # 空数组启用全部内置规则
      request_headers: [authorization, x-customer-email]
      response_headers: [x-export-token]
      inspect_query: true
      protect_log_path: true
      inspect_request_body: true
      inspect_response_body: true
      body_media_types:
        - application/json
        - application/*+json
        - application/x-www-form-urlencoded
      max_body_bytes: 1048576
      replacement: "[REDACTED]"
      exclusions:
        - rule: email
          target: query:public_contact
```

命名上游凭据把 secret 与 route/service 分离。每个对象必须声明允许接收凭据的 HTTP(S) origin 或
`lb://service`；引用与 backend 不匹配会拒绝候选。header/query 注入发生在普通 route mutation
之后，客户端同名值始终先删除，因此重复 header 的 first/last-wins 差异不能覆盖网关凭据。
`overwrite` 必须显式声明；为 false 时同名 route header mutation 会在构建期被拒绝。文件型
SecretSource 进入统一 watcher，成功换版后新请求使用新值，坏 secret 保留当前快照。TLS client
identity 只能绑定逻辑 service，使证书身份进入该 service 的连接池与 TLS profile，而不能按请求漂移。

```yaml
upstream_credentials:
  - name: payments-bearer
    kind: bearer               # api_key | bearer | basic | header | query
    value: file://secrets/payments-token
    overwrite: true
    allowed_backends: ["lb://payments"]
  - name: payments-client
    kind: tls_client_identity
    client_certificate: file://secrets/payments-client.crt
    client_private_key: file://secrets/payments-client.key
    allowed_backends: ["lb://payments"]

upstreams:
  services:
    payments:
      instances: [{ uri: "https://payments.internal:8443" }]
      upstream_credentials: [payments-client]

routes:
  - id: payments
    uri: "lb://payments"
    predicates: ["Path=/payments/"]
    upstream_credentials: [payments-bearer]
```

远程值使用 `remote://<provider>/<secret-path>`。provider endpoint 必须是固定 HTTPS URL，secret path
仅能追加为受限且逐段编码的相对路径，不能改变 scheme、authority、query 或 fragment。认证 token、CA
和可选 mTLS client identity 本身使用本地 SecretSource，可直接读取 Kubernetes projected token、Vault
Agent 文件或其它工作负载身份挂载；重定向、超限响应、非 JSON、版本回退和同版异值都会拒绝候选。

provider 响应通过 JSON Pointer 映射到字符串值、单调 `u64` 版本和可选 lease 秒数。后台只触发统一
prepare→publish reload，不直接改活动 route；临时故障仅能在 `max_stale_ms` 和 lease 的较早截止点前
复用 last-known-good。截止后 header/query 凭据返回上游错误，远程 mTLS 身份也不能创建新请求；
请求路径不会访问 provider、文件或环境变量。

`adapter.kind` 可选择 `aws_secrets_manager`、`azure_key_vault` 或 `gcp_secret_manager`，并复用上述
TLS、刷新、退避、版本单调和失效规则。AWS 适配器调用 `GetSecretValue`，用本地 SecretSource 中的
标准容器凭据 JSON（`AccessKeyId`、`SecretAccessKey`、`Token`、`Expiration`）执行 SigV4，版本取
`CreatedDate`；Azure 适配器调用 Key Vault Secret API，以 `attributes.updated` 为版本；Google
适配器只允许完整的 `projects/.../secrets/.../versions/<number|latest>` 资源并调用 `:access`，版本取
响应中的数字 version。Azure 和 Google 的 OAuth Bearer token 使用本地 SecretSource。所有 adapter
都要求显式 HTTPS endpoint，不探测 metadata service，不接受 redirect，也不把云凭据带入数据面。

`crypto_providers` 可选择固定 HTTPS keyless/KMS 或 PKCS#11/HSM。HTTPS 后端提供 `encrypt`、
`decrypt` 与 `sign` 操作契约；认证、custom CA 和 mTLS 身份使用本地 SecretSource，
请求采用有界 JSON/Base64，禁重定向，并受 deadline、并发、队列、算法 allowlist 和熔断约束。
远程 Secret 的 `envelope` 仅可引用 HTTPS provider；ciphertext 解密后才进入候选快照，AAD
强制绑定 Secret provider、路径、单调版本和可选业务上下文，避免密文跨位置或跨版本重放。

PKCS#11 后端由 `pkcs11` feature 显式编译，只执行 TLS `sign`，不用于 envelope 加解密。
`module_path` 解析为绝对真实路径，slot id 与 token label 恰好选择一项，User PIN 必须来自
本地 SecretSource，不允许递归访问远程 provider。`max_concurrency` 同时是固定 HSM session
数，每个 session 只能被一个签名 worker 独占。`key_id` 精确匹配唯一可签名 private-key
label；其 `CKA_ID` 必须唯一关联 public-key object，且 RSA modulus/exponent 或 EC curve/point
必须与叶证书 SPKI 完全一致后才发布 TLS 身份。网关不读取 HSM 私钥值，provider
故障、队列满、deadline、算法/曲线错配和证书错位都拒绝新握手，绝不回退本地私钥。

```yaml
secret_providers:
  - name: vault
    endpoint: "https://vault.internal/v1/gateway-secrets"
    authorization: k8s-file:///var/run/secrets/tokens/vault
    authorization_prefix: "Bearer "
    ca_certificate: file://secrets/provider-ca.pem
    client_certificate: file://secrets/provider-client.pem
    client_private_key: file://secrets/provider-client-key.pem
    envelope:
      crypto_provider: workload-kms
      key_id: payments-secret-kek
      aad_context: payments-production
    value_pointer: /data/value
    version_pointer: /data/version
    lease_seconds_pointer: /lease_duration
    refresh_interval_ms: 30000
    max_stale_ms: 300000
    connect_timeout_ms: 3000
    request_timeout_ms: 5000
    max_response_bytes: 65536
    retry_base_ms: 1000
    retry_max_ms: 30000

  - name: aws-production
    endpoint: "https://secretsmanager.us-east-1.amazonaws.com/"
    adapter:
      kind: aws_secrets_manager
      region: us-east-1
      credentials: file:///var/run/secrets/aws/container-credentials.json
    refresh_interval_ms: 30000
    max_stale_ms: 300000

  - name: azure-production
    endpoint: "https://payments.vault.azure.net/"
    adapter:
      kind: azure_key_vault
      api_version: "7.5"
    authorization: file:///var/run/secrets/azure/access-token
    authorization_prefix: "Bearer "
    refresh_interval_ms: 30000
    max_stale_ms: 300000

  - name: gcp-production
    endpoint: "https://secretmanager.googleapis.com/v1/"
    adapter:
      kind: gcp_secret_manager
    authorization: file:///var/run/secrets/gcp/access-token
    authorization_prefix: "Bearer "
    refresh_interval_ms: 30000
    max_stale_ms: 300000

crypto_providers:
  - name: workload-kms
    endpoint: "https://kms-agent.internal/v1/operations"
    authorization: k8s-file:///var/run/secrets/tokens/kms
    authorization_prefix: "Bearer "
    ca_certificate: file://secrets/kms-ca.pem
    allowed_algorithms: [rsa_pss_sha256]
    timeout_ms: 3000
    max_concurrency: 8
    queue_capacity: 64

  - name: gateway-hsm
    pkcs11:
      module_path: "/usr/lib/vendor-pkcs11.so"
      token_label: naway-production
      user_pin: file:///var/run/secrets/hsm/user-pin
    allowed_algorithms: [rsa_pss_sha256]
    timeout_ms: 2000
    max_concurrency: 4
    queue_capacity: 64

upstream_credentials:
  - name: payments-bearer
    kind: bearer
    value: remote://vault/payments/bearer
    overwrite: true
    allowed_backends: ["lb://payments"]
  - name: cloud-payment-key
    kind: bearer
    value: remote://gcp-production/projects/example/secrets/payment-key/versions/latest
    overwrite: true
    allowed_backends: ["lb://payments"]
```

下游 TLS 可为默认身份和每个 SNI 身份分别绑定 OCSP response。加载时会验证 responder 签名、issuer、
CertID、good 状态、`thisUpdate`/`nextUpdate` 与 must-staple；握手选证时还会复验截止时刻，响应陈旧后
不会继续发送。`fetch_from_aia` 可在后台预刷新，所有 AIA 地址先解析为固定 IP 集，禁用 redirect 并
限制响应类型、字节和 deadline；私网 responder 只有命中显式 CIDR allowlist 才可访问。新响应只有
完整验证后才通过同目录 rename 原子替换，坏更新保留活动 ServerConfig。

mTLS 客户端认证可同时使用 CRL 与在线 OCSP。CRL 的 hard/soft fail 只改变“无法判定”处理，明确
revoked 始终拒绝。在线 OCSP 在证书链验证成功后、读取任何 HTTP 或 stream 业务字节前执行，并使用
有界并发和证书摘要缓存；`soft_fail` 同样不能放过 revoked、unknown、坏签名或错 CertID。配置 SPIFFE
allowlist 后，客户端叶证书必须只有一个合法 URI SAN，并命中精确 SPIFFE ID 或 trust domain。

共享 session ticket key 使用 Base64 编码的 32-byte SecretSource。首项签发、后续项只解密，允许
跨节点先发布 `[new, old]` 再删除 `old`；删除旧 key 会立即停止恢复对应 ticket，但不终止已建立连接。

TLS 身份可以用 `private_key_provider` 代替 `key_file`。网关只从证书取得公开 SPKI；rustls 选定的
握手算法与待签名消息经固定大小 worker pool 发送给外部 signer，provider 不可用、超时、队列满、
算法不在 allowlist 或返回格式无效都会拒绝新握手，绝不回退到本地私钥。外部 signer 不能与 ACME
或 keypair manifest 混用；默认身份与每个 SNI 身份分别声明自己的 key 引用。

`spire-workload` feature 提供 SPIRE Workload API 的原生 X.509-SVID 流式订阅，可用于下游服务端
身份和上游 mTLS 客户端身份。`socket_path` 必须是已存在的绝对 Unix socket；SPIRE Agent 依据
socket 调用方的本地进程身份与 workload selectors 决定授权集合，Naway 不接受客户端自报 selector。
每条完整响应只按精确 `spiffe_id` 与可选 `hint` 选择一个 SVID，并复验证书 URI SAN、有效期、
PKCS#8 私钥匹配和同响应 local bundle 签发链。候选启动前必须取得首个完整有效响应。

`federation_trust_domains` 是 foreign bundle 的显式 allowlist。启用下游 `client_auth` 时，网关先从
客户端唯一 SPIFFE URI SAN 取得 trust domain，再只用该域对应的 bundle 验证证书链，避免不同域的
CA 混入同一信任池。完整响应删除 SVID、必需 federation bundle 或 Agent 返回
`PermissionDenied` 时，新握手立即停止；普通断流只可沿用到证书 `notAfter`，后台按有界退避重连。
服务端 SPIRE 身份禁止 session ticket，上游 SPIRE 客户端身份关闭 TLS resumption，确保恢复会话
不能绕过身份轮换、bundle 换代或 selector 撤权。已建立连接按正常连接生命周期继续 drain。

```yaml
server:
  tls:
    listen: "0.0.0.0:443"
    cert_file: secrets/server-chain.pem
    private_key_provider:
      provider: workload-kms
      key_id: gateway-server-key
      algorithms: [rsa_pss_sha256]
    ocsp_stapling:
      response_file: secrets/server.ocsp.der
      mode: required
      fetch_from_aia: true
      refresh_interval_seconds: 3600
      request_timeout_ms: 5000
      allowed_responder_cidrs: ["10.20.0.0/16"]
    client_auth:
      mode: require
      ca_file: secrets/workload-ca.pem
      crl_files: [secrets/workload.crl.pem]
      revocation_mode: hard_fail
      enforce_crl_expiration: true
      allowed_spiffe_trust_domains: [prod.example.org]
      ocsp:
        mode: hard_fail
        timeout_ms: 3000
        max_stale_seconds: 0
        max_cache_entries: 4096
        max_concurrency: 8
        allowed_responder_cidrs: ["10.20.0.0/16"]
    session_tickets:
      lifetime_seconds: 43200
      keys:
        - file://secrets/ticket-current.b64
        - file://secrets/ticket-previous.b64
```

SPIRE 服务端身份不配置 `cert_file`、`key_file`、SNI 证书、ACME、外部 signer、OCSP staple 或
session ticket。若同时启用 mTLS，`client_auth.ca_file` 留空，并通过精确 SPIFFE ID 或 trust domain
声明授权边界；Agent 返回的 CRL 会随同当前完整响应进入对应域验证器。

```yaml
server:
  tls:
    listen: "0.0.0.0:443"
    spire:
      socket_path: /run/spire/sockets/agent.sock
      spiffe_id: spiffe://prod.example.org/naway/ingress
      hint: ingress
      federation_trust_domains: [partner.example.org]
      timeout_ms: 3000
      reconnect_min_ms: 100
      reconnect_max_ms: 5000
      max_response_bytes: 8388608
      min_validity_seconds: 30
      clock_skew_seconds: 30
    client_auth:
      mode: require
      allowed_spiffe_ids:
        - spiffe://partner.example.org/payments/client
      allowed_spiffe_trust_domains:
        - prod.example.org

upstreams:
  services:
    payments:
      protocol: h2
      tls:
        server_name: payments.internal
        ca_file: secrets/payments-server-ca.pem
        spire:
          socket_path: /run/spire/sockets/agent.sock
          spiffe_id: spiffe://prod.example.org/naway/egress
          hint: egress
      instances:
        - uri: https://10.20.0.8:8443
```

Proxy-Wasm 模块可继续使用本地 `module_file`，也可在候选快照构建阶段从固定 HTTPS URL 或 OCI
Distribution registry 获取。远程来源必须固定最终 wasm 的 SHA-256，并至少提供 detached Ed25519
signature 或签名的 in-toto Statement；两者同时声明时全部验证。OCI tag 还必须固定 manifest SHA-256，
且 registry 返回的 `Docker-Content-Digest` 必须一致，因而 tag 不能把已发布候选指向另一份内容。
`authorization` 和附加 CA 使用 SecretSource。`cache_dir` 只保存按模块摘要命名的已验证内容，离线读取
仍会重新验证当前字节上限、来源凭据格式、附加 CA、摘要及全部供应链证明。缓存摘要匹配但当前
证明失效时直接拒绝候选；重新下载相同内容不能恢复失去的信任。获取、验签、编译或实例化失败时，
当前路由快照保持不变。

```yaml
routes:
  - id: verified-wasm
    uri: "http://orders.internal:8080"
    predicates: ["Path=/orders/"]
    wasm_plugins:
      - id: request-policy
        module_source:
          reference: "oci://registry.example.com/gateway/request-policy:stable"
          sha256: "<Wasm layer 的 64 位十六进制 SHA-256>"
          manifest_sha256: "<OCI manifest 的 64 位十六进制 SHA-256>"
          authorization: file://secrets/registry-authorization
          ca_certificate: file://secrets/registry-ca.pem
          cache_dir: state/wasm-cache
          signature: file://secrets/request-policy.wasm.sig.b64
          public_key: file://secrets/wasm-signer.pub.b64
          attestation:
            statement: file://attestations/request-policy.intoto.json
            signature: file://attestations/request-policy.intoto.sig.b64
            public_key: file://secrets/provenance-signer.pub.b64
            predicate_type: https://slsa.dev/provenance/v1
            builder_id: https://builder.example.com/gateway-wasm
            subject_name: request-policy.wasm
        phase: request_headers
        fail_open: false
        max_module_bytes: 16777216
        max_memory_bytes: 8388608
        max_fuel: 10000000
        timeout_ms: 10
```

route 可按 OpenAPI operation、HTTP status 与 media type 校验最终响应。`observe` 是默认模式，只在
响应流结束后记录结论，不延迟或替换实体；`block` 和 `replace_error` 会在显式字节上限内先聚合再
决定是否发送。schema 引用只允许主 OpenAPI、显式本地 catalog，或配置中逐项登记的 HTTPS 文档。
HTTPS 文档必须固定 SHA-256，并通过 detached Ed25519 signature 复验；redirect、未登记引用、引用
循环、资源超限或候选编译失败都不会替换当前 route 快照。

`request_transform` 与 `response_transform` 提供有界 JSON Pointer 操作，以及 namespace-aware 的
XML/SOAP 固定字段提取和输出。支持 rename、add、remove、default 与 type check，不执行脚本、通配
遍历或动态元素名；冲突写、父子覆盖和 rename 循环在候选构建阶段拒绝。XML 禁用 DTD、自定义实体
与 processing instruction，并限制深度、节点、属性、文本和输出字节。转换会重建 Content-Type 与
Content-Length，删除失效的编码、摘要、validator 和 range 元数据；partial entity 与 trailers 不参与
转换。SOAP 可固定 `SOAPAction`，并把声明路径上的 Fault 映射为指定 HTTP status。
响应转换和响应契约作用于最终响应，包含路由内产生的本地拒绝；例如请求校验返回的文本错误若
不符合已配置的 JSON 响应转换，会以 `502` 结束。需要直接保留请求校验 `400`/`413` 的路由应避免
组合这种不兼容的响应转换或阻断契约。

```yaml
routes:
  - id: customer-json
    uri: "http://customer.internal:8080"
    predicates: ["PathExact=/customers/current"]
    response_contract:
      openapi_file: schemas/customer-openapi.yml
      operation_id: getCurrentCustomer
      catalog_files: [schemas/customer-models.yml]
      mode: block                 # observe | block | replace_error
      max_body_bytes: 1048576
    request_transform:
      input: json
      output: json
      max_body_bytes: 1048576
      max_output_bytes: 1048576
      operations:
        - action: rename
          from: /customerId
          to: /customer_id
        - action: default
          path: /source
          value: gateway

  - id: signed-schema
    uri: "http://orders.internal:8080"
    predicates: ["Path=/orders/"]
    response_contract:
      openapi_file: schemas/orders-openapi.yml
      operation_id: getOrder
      registry_documents:
        - url: "https://schemas.example.com/order.yml"
          sha256: "<64 个十六进制字符>"
          signature: file://secrets/order-schema.sig
          public_key: file://secrets/order-schema.pub
          ca_file: secrets/schema-registry-ca.pem
          max_bytes: 1048576
          timeout_ms: 3000
          cache_ttl_ms: 60000

  - id: legacy-soap
    uri: "http://legacy.internal:8080"
    predicates: ["PathExact=/legacy/customer", "Method=POST"]
    request_transform:
      input: soap
      output: json
      max_body_bytes: 1048576
      max_output_bytes: 1048576
      namespaces:
        soap: http://www.w3.org/2003/05/soap-envelope
        customer: urn:example:customer
      xml_extract:
        - from: /soap:Envelope/soap:Body/customer:Get/customer:id
          to: /id
          required: true
          value_type: integer
      soap_action: urn:example:get-customer
```

### Kubernetes Gateway API

`kubernetes_routes` 固定兼容 Gateway API v1.5.1 experimental contract。当前声明
`GATEWAY-HTTP`、`GATEWAY-GRPC` 与 TLS passthrough 的 Core 能力；HTTP 还支持 query/method
匹配、response header 修改、host/path rewrite、path/scheme/port 与 303/307/308 redirect、
RequestMirror、百分比 RequestMirror、CORS 和 named rule。GRPCRoute named rule 已按 provisional
contract 支持。

TLS listener 支持 `Passthrough` 与 `Terminate`：透传按 exact SNI 优先、再按最长 wildcard suffix
选择 TLSRoute；终止模式从受授权 Secret 构建同代证书配置。`parentRef.sectionName`/`port`、多个有界
RequestMirror，以及带 System/ConfigMap CA 和显式 DNS/URI SAN 的 BackendTLSPolicy 均在候选发布前
裁决。未知 kind、ExtensionRef、TLS mode、跨 namespace 引用或冲突 policy 会通过 status 报告并失败
闭合；无效 L4 backend 仍保留拒绝型 listener，避免其它进程接管本应保护的端口。

HTTP/HTTPS listener 使用 `gateway_bind_address`。TLS/TCP/UDP listener 默认使用
`gateway_stream_bind_address`；配置非空 `gateway_stream_bind_addresses` 后，控制器按稳定 Gateway
对象顺序为每个包含 stream listener 的 Gateway 分配一个独立地址。同一 Gateway 的 stream listener
共享该地址，地址池耗尽的 Gateway 不进入数据面并通过 status 报告未编程，避免同端口 listener 互相
抢占 socket。

```yaml
kubernetes_routes:
  enabled: true
  gateway_api_enabled: true
  gateway_api_version: "v1.5.1"
  gateway_api_experimental: true
  gateway_mesh_interception_ready: true
  gateway_mesh_bind_address: "127.0.0.1"
  gateway_mesh_port: 15001
  gateway_bind_address: "0.0.0.0"
  gateway_stream_bind_address: "127.0.0.2"
  gateway_stream_bind_addresses:
    - "127.0.0.2"
    - "127.0.0.3"
```

Experimental Channel 能力只在使用 `gateway-api-experimental` feature 构建且配置显式开启时生效：

```bash
cargo build --release --features gateway-api-experimental
```

Gateway API Inference Extension 通过独立 `inference-gateway` feature 提供，并固定兼容
`inference.networking.k8s.io/v1`、Inference Extension v1.5.0。控制器把 InferencePool 的
`selector.matchLabels`、一到八个 `targetPorts`、`http|kubernetes.io/h2c` `appProtocol` 与 Ready Pod
编译为同代静态 endpoint 目录；EPP 只允许引用同 namespace 的 core Service、数字 TCP port，
`ExternalName` 明确拒绝。HTTPRoute backendRef 上的 `port` 按该合同不参与池端口选择，最终目标仍必须
命中池的 Pod IP 与声明端口。

```bash
cargo build --release --features inference-gateway
```

```yaml
kubernetes_routes:
  enabled: true
  gateway_api_enabled: true
  inference_gateway_enabled: true
  inference_extension_version: "v1.5.0"
```

每条 InferencePool Route 使用标准 Envoy External Processing 双向 gRPC 流调用 EPP。客户端携带的
`x-gateway-destination-endpoint` 会在进入 EPP 前删除；处理器返回的 IP 或 IP:port 子集经过数量、
语法、当前池成员、Ready 状态和端口复验后才交给 LB，重试与健康降级也不能越出该子集。正常 EPP
协议流缺少、冲突或返回池外目标时响应 5xx；只有 `failureMode: FailOpen` 且发生连接、超时、容量或
服务不可用等依赖故障时，网关才从当前池目录自行选择。响应阶段会把实际取得 reservation 的
endpoint 写入 `envoy.lb/x-gateway-destination-endpoint-served`，供 EPP 核对真实承载者。

InferencePool 的 parent status 随已接纳 HTTPRoute 到 Gateway 的引用重建，并分别发布 `Accepted` 与
`ResolvedRefs`；EPP Service 缺失、端口无效或类型不受支持时，该 rule 保留本地 5xx 匹配面，合法池
继续发布。控制器 watch InferencePool、Pod 和 Service；Pod 进入非 Ready 或删除态后不会留在下一代
候选中。EPP 会收到有界的完整 request headers/body，可据此使用模型、KV/prefix-cache、queue、LoRA、
请求成本、accelerator/topology 和 SLO 信号选址；这些信号只影响当前池内候选，不能扩大地址授权面。

MCS 支持 `multicluster.x-k8s.io/v1alpha1` 的 `ClusterSetIP` `ServiceImport` 作为 HTTP、gRPC、
TLS、TCP 与 UDP Route 后端，可与 core Service 组成带权 backendRefs。跨 namespace 引用仍须由目标
namespace 的 `ReferenceGrant` 精确授权；端点从带
`multicluster.kubernetes.io/service-name` label 的 EndpointSlice 获取，并把 source cluster 与 zone
保留为调度 metadata。未知 ServiceImport 类型、版本、kind、端口或 appProtocol 会在候选发布前拒绝。

Mesh Profile 接受 HTTPRoute/GRPCRoute 的 Service 或 ServiceImport parent。producer Route 与 parent
同 namespace；consumer Route 必须由受信透明流量捕获组件注入内部
`x-naway-mesh-source-namespace` header，Naway
在完成 parent/Route 选择后立即删除该 header，不能把客户端自报值转发给后端。Mesh listener 只允许
绑定 loopback，且 `gateway_mesh_interception_ready` 是部署方对透明捕获链已就绪的明确声明；未声明时
controller 只发布未接纳状态，不开放该 listener。Service 使用 `*.svc.cluster.local` authority，
ServiceImport 使用 `*.svc.clusterset.local` authority。

`gateway.networking.x-k8s.io/v1alpha1` 的 `XBackendTrafficPolicy` 支持 Service/ServiceImport
`targetRefs`、确定性冲突裁决、逐目标 status、RetryConstraint 和 SessionPersistence。重试百分比、
窗口及 `minRetryRate` 编译到原生共享 retry budget；Cookie/Header 会话支持 absolute/idle timeout，
Permanent cookie 的 `Max-Age` 随剩余绝对期限递减。HTTPRoute/GRPCRoute rule 级
`sessionPersistence` 覆盖后端策略并生成隔离逻辑服务；为避免把多后端粘滞近似成普通权重散列，
带多个 backendRefs 的 inline session policy 会在构建期明确拒绝。

控制器对依赖 collection 使用 LIST 后携带 `resourceVersion` 建立 watch，接受 bookmark，并在连接结束、
超时或 compaction 后完整 relist。ReferenceGrant 撤销和对象删除先通过同一候选移除路由，再由 reload
worker 原子发布；旧 EndpointSlice 不会作为被撤权 Route 的旁路入口。兼容声明仅覆盖以上明确列出的
Gateway/Mesh 能力，未支持的 Experimental 字段不会被静默忽略。

每条 AI route 通过 `llm.api_type` 固定独立 wire 契约，可选择 Chat Completions、Responses、embeddings、
rerank、image、audio、video、batch、file 或 WebSocket Realtime。每种 API 分别执行允许的 content-type、
请求体、响应累计字节、流帧、持续时间和估算费用门；非 Chat API 不进入 Chat adapter，provider 原生
request/response 字段与 media type 保持不变。Realtime 在升级后继续执行单帧、单消息和连接寿命门。

provider 计划支持 OpenAI、Anthropic、Google Gemini Developer API、Azure OpenAI、AWS Bedrock、
Vertex AI、Cohere、Mistral、Hugging Face、xAI、DashScope、DeepSeek、Ollama 和 vLLM。Azure API 版本、
Bedrock region/SigV4、Vertex project/region 与所有 endpoint 都在候选快照中冻结；API key、AWS access
key、secret key 和 session token 可使用同一 Secret provider，在请求热路径只读取已物化快照。

Chat 的 text-only Anthropic/Google 转换只接受可证明等价的字段；tool call、structured output、JSON
schema 和多模态请求会先与模型 capability catalog 求交，不能无损表达时在 provider I/O 前拒绝。
原生透传不会伪造或丢弃 usage、finish、tool 与 provider 扩展字段。模型选择支持 ordered、cost、
latency、weighted 与 joint；joint 联合冻结能力、声明/观测 SLO 和价格，可配置 shadow evaluation 与
失败后回落正常模型顺序的 rollout。客户端不能改写 provider、模型、价格、能力或云身份 scope。

可选 external moderation 使用 OpenAI-compatible `/v1/moderations`，明确 `flagged=true` 永远拒绝，
依赖故障则按 route 的 `closed|open` 策略处理。token quota 在 cache miss 后预留，依据 provider 最终
usage 幂等多退少补；非 2xx/transport 失败退款，成功但 usage 缺失或流中断保留保守预留。

token quota 与缓存的 `api_key`、`consumer` 维度只读取本地认证后冻结的身份；外部授权或后续插件
改写请求头不会转移额度或缓存归属。子路由可继承父层 API-Key 认证，但完整父链必须具有真实
认证来源；仅外部授权成功不能创建 API-Key 计费身份，缺少该事实返回 401。

`runtime_state.store.backend` 支持 `file|redis|nacos`。Nacos 后端需要 `nacos-sdk` feature，每个
collection 使用独立 dataId 和带 schema/revision 的有界 JSON 文档，二进制 value 以 Base64 保存；
写入、删除和容量 admission 使用 md5 CAS，watch 把完整快照差异转换成本地增量事件。坏文档或超限
推送不会覆盖 last-known-good。`admin.listen`、普通/TLS/QUIC listener、xDS/edge 集群传输、日志与
审计 sink、HTTP cache、telemetry exporter 和 ACME worker 使用 prepare→publish→drain 换代：候选
bind、连接、权限、provider 或锁初始化失败时，旧快照与旧 generation 保持在线。

ACME DNS-01 可直接使用 Cloudflare、RFC2136 HMAC-SHA256 TSIG、Vault action endpoint，或兼容的
无 shell command provider；所有内建凭据只从 SecretSource 解析。manifest 证书模式保护当前与恢复
指针后按保留代数回收，旧双文件模式通过持久 journal 在任何读取前恢复完整 pair。

OPA route 默认通过外部 Data API 执行 head-only 授权，也可用 `opa-embedded` feature 从 detached
Ed25519 签名的标准 tar.gz bundle 构建本地 Rego 引擎。bundle 的压缩/解压字节、文件数、路径、
manifest、module/data 与 query 都在候选 snapshot 发布前验证，失败保留 last-known-good；revision
自动取 manifest 或 bundle SHA-256。decision cache 支持 allow/deny 分离 TTL、节点内 single-flight
与显式 DynamicStore 跨节点复用，key 覆盖 revision、可信身份、query/header、可选完整 JWT claims
和 request body。body/claims 均默认关闭；开启 body 后只接受配置 media type、按硬上限聚合并把同一
字节重放给后续管线。OPA 返回的 request/response header mutation 与 audit metadata 必须整组通过
route allowlist、凭据/hop-by-hop/framing 禁区及条目/单值/总字节门，任一非法项都不会部分执行。

显式启用 `grpc-descriptor` feature 后，route 可通过受信 `FileDescriptorSet` 提供 unary/streaming Connect JSON 与 `google.api.http` 转码；descriptor 和每条 JSON/protobuf/stream 均有资源上限，坏热换保留 last-known-good。上游主动检查支持标准 `grpc.health.v1.Health/Check`，可按 service 设置 deadline、连续成功/失败阈值与间隔抖动，并直接驱动 LB 摘除和恢复；该探针不依赖 descriptor feature。

Dubbo2 route 支持既有 JSON serialization id=6，以及显式 `dubbo-hessian2` feature 提供的
Hessian2 id=2 泛化调用。公网 body 只能提交 `{"arguments":[...]}`，interface、method、Java
参数类型和 attachments 均由可信 route 固定；Hessian2 对深度、collection 项、字符串、binary、
请求/响应 frame 和最终 JSON 分别设硬门，`byte[]` 使用标准 Base64。class definition 只作为数据
解析，不加载 Java class 或执行 constructor/reflection；provider exception 映射为 502，非法下游
类型在选择 upstream 前返回 400。真实 Apache Dubbo 3.3.5 provider 已覆盖 POJO、非 BMP 字符、
`byte[]` 和异常互操作；关闭 feature 时 Hessian2 route 在快照构建阶段拒绝，JSON 路径不受影响。

```bash
cargo build --release --features dubbo-hessian2
```

```yaml
dubbo:
  interface: org.example.Greeter
  method: greet
  parameter_types: [java.lang.String]
  version: 1.0.0
  serialization: hessian2
  max_request_body_bytes: 1048576
  max_request_frame_bytes: 4194304
  max_response_body_bytes: 4194304
  max_hessian_string_bytes: 1048576
  max_hessian_binary_bytes: 1048576
  max_hessian_collection_items: 65536
  max_hessian_depth: 32
```

MQTT stream listener 可通过独立 `mqtt-governance` feature 启用 MQTT 3.1.1/5.0 协议治理；
关闭时仍是原有透明 TCP 转发，可选地只 preread CONNECT client id 做路由。治理 profile 在拨号
broker 前校验 client id，并对 PUBLISH topic、SUBSCRIBE/UNSUBSCRIBE filter、QoS1/2 packet-id
状态及连接、单包、聚合 buffer、topic、订阅、在途消息设置硬门。packet deadline 从 fixed-header
首字节开始，纯 idle 长连接不计时；坏 reload 继续保留 last-known-good snapshot。

治理 profile 只接受 Clean Session/Start，broker 的 CONNACK 也必须返回 `Session Present=0`，因为
跨连接 persistent session 的订阅/QoS2 状态无法由单连接网关安全重建。需要 persistent session、
shared subscription (`$share/...`) 或 MQTT 5 topic-alias-only 空 topic 时应使用透明 profile。MQTT 5
property block 只做长度有界的 opaque 转发；Naway 不充当 broker、不合成 ACK，也不宣称校验每种
property 的业务语义。

```bash
cargo build --release --features mqtt-governance
```

```yaml
stream:
  listeners:
    - id: mqtt-public
      protocol: tcp
      listen: "0.0.0.0:1883"
      preread:
        mqtt_connect: true
        timeout_ms: 3000
        max_bytes: 4096
      mqtt:
        enabled: true
        max_connections: 256
        max_packet_bytes: 1048576
        packet_timeout_ms: 10000
        max_buffered_bytes: 536870912
        max_topic_bytes: 1024
        max_subscriptions: 1024
        max_inflight_messages: 128
        client_id_allow: [device-a, device-b]
        publish_topic_allow: [sensors/+/temperature]
        subscribe_topic_allow: [sensors/#]
      routes:
        - id: broker
          default: true
          upstream: "10.0.0.20:1883"
```

Kafka client data-plane 可通过独立 `kafka-governance` feature 启用有界协议治理；关闭 profile 时仍是
完全透明 TCP，不读取 Kafka header。治理面支持 ApiVersions v0..4、Metadata v0..8、Produce v0..8、
Fetch v4..11、ListOffsets v1..5、常用 consumer-group API、非事务 InitProducerId、
OffsetForLeaderEpoch v3，以及 framed SaslHandshake v1/SaslAuthenticate v0..1。ApiVersions response
只发布治理 parser 与 broker 同时支持的版本，未知 API、未支持版本、broker replica request、事务 API
和全 topic 枚举均失败闭合。

`broker_rewrite` 必须为 Metadata/FindCoordinator 中每个成功 endpoint 提供显式一一映射；缺项会断开
会话，不把内部 broker 地址泄露给 client。多 broker 集群应为每个 broker 暴露不同的可达代理 endpoint，
并把各 endpoint 路由回对应 broker；Naway 不充当 broker、group/transaction coordinator，也不合并
多个 broker 到同一个不可区分入口。SASL token 只做 frame 有界 opaque 转发，不记录或解释凭据。

```bash
cargo build --release --features kafka-governance
```

```yaml
stream:
  listeners:
    - id: kafka-broker-1
      protocol: tcp
      listen: "0.0.0.0:19092"
      kafka:
        enabled: true
        max_connections: 256
        max_frame_bytes: 1048576
        frame_timeout_ms: 10000
        max_buffered_bytes: 536870912
        max_inflight_requests: 128
        max_client_id_bytes: 256
        max_topic_bytes: 249
        max_group_bytes: 255
        max_array_items: 4096
        client_id_allow: [orders-client]
        topic_allow: [orders]
        group_allow: [orders-consumers]
        sasl_mechanism_allow: [PLAIN, SCRAM-SHA-256]
        broker_rewrite:
          - from_host: kafka-1.internal
            from_port: 9092
            to_host: kafka.example.com
            to_port: 19092
      routes:
        - id: broker-1
          default: true
          upstream: "10.0.0.31:9092"
```

HTTP/3 / QUIC 通过独立 `http3` feature 提供下游与上游双向代理，同一 TLS listener 端口承载
TCP h1/h2 与 UDP h3；DATA/trailers、取消、GOAWAY、Retry、连接迁移、证书热换和资源预算均
复用现有数据面语义。HTTP/3 默认关闭，扩展能力还需在 listener 上逐项声明：

- `connect_udp + datagram` 提供经过 route 认证、授权、SSRF/DNS rebinding 复验与会话预算的
  CONNECT-UDP；目标只能是当前请求刚解析且全部通过 allowlist 的 IP。
- `webtransport + datagram` 把下游 session 的双向/单向 stream 与 DATAGRAM 转发到固定 HTTPS
  上游；Origin、TLS trust、队列、并发、字节、idle 和最长寿命都在 route 快照中冻结。
- `early_data` 与 `zero_rtt: true` 共同开放安全 0-RTT。只有显式 GET/HEAD/OPTIONS/TRACE、固定
  HTTP 上游、关闭请求体转发且没有认证、凭据注入或外部副作用的 route 才能构建成功。每个早期
  请求必须携带 `Early-Data: 1` 与一个 base64url 编码的 32 字节
  `x-naway-early-data-nonce`；nonce 在本地或 Redis 账本中一次性占位，重复、敏感凭据、DATA、
  trailers 或未授权 route 返回不可缓存的 425。客户端应在握手确认后重试 425 请求。

0-RTT 使用 rustls 有状态、单次消费的 TLS 1.3 session，不能与 `tls.session_tickets` 的无状态
共享 key 或 TLS client authentication 同时启用。多节点部署必须设置 `multi_node: true`、使用
`runtime_state.replay_guard.backend: redis` 和 `fail_mode: closed`，并声明
`early_data_shared_replay_cache: true`；配置与实际后端不一致时 listener 不会发布。证书或 listener
generation 切换会使旧的本地恢复状态失效，客户端自动回到 1-RTT。

```yaml
runtime_state:
  replay_guard:
    backend: local              # 多节点改为 redis，并设置 fail_mode: closed
proxies:
  - id: public
    listen: "0.0.0.0:8080"
    tls:
      listen: "0.0.0.0:8443"
      cert_file: "tls/server.crt"
      key_file: "tls/server.key"
    http3:
      enabled: true
      capabilities: [early_data]
      zero_rtt: true
      early_data_session_rotation_seconds: 3600
      retry: auto
    routes:
      - id: public-catalog
        uri: "http://catalog.internal:8080"
        predicates: ["Method=GET", "Path=/catalog/"]
        filters: ["proxy_pass_request_body off"]
        early_data:
          enabled: true
          replay_window_ms: 10000
```

## Agent 协议与 AI 内容治理

`agent-protocols` 启用 MCP/A2A，并包含 `ai-governance`；只需要模板、RAG 与外部输出裁决时可单独
启用 `ai-governance`。结构化本地内容规则不需要额外 feature。未编入的能力若出现在配置中，候选
构建失败，不会退回普通代理。Agent 与治理路由必须先通过本地 API-Key、Basic 或已验证 JWT 等
身份认证；自报 consumer、group、scope 或 tenant header 不构成授权证据。

```bash
cargo build --release --features agent-protocols
```

### MCP 固定工具目录

Streamable HTTP 显式支持 `2025-11-25`：initialize、initialized、ping、tools/list、tools/call、
cancelled、GET 通知和 DELETE 会话关闭。请求 POST 同时接受 JSON 与 SSE；后续请求携带
`MCP-Protocol-Version` 和网关签发的 `Mcp-Session-Id`。上游 MCP 也必须协商同一版本和 tools 能力。
这是受控工具入口，不是任意 MCP 扩展的透明隧道：不支持 batch、roots、sampling、elicitation、
resources/prompts 方法、tasks 扩展或基于 Last-Event-ID 的回放；未知方法与能力失败闭合。

```yaml
routes:
  - id: inventory-tools
    predicates: ["PathExact=/mcp"]
    filters: ["api_key header=X-Api-Key value=file://secrets/client.key consumer=inventory-reader"]
    agent:
      protocol: mcp
      protocol_version: "2025-11-25"
      security:
        tenant: inventory
        allowed_origins: ["https://console.example.com"]
        consumer_groups: {inventory-reader: [readers]}
      limits:
        max_sessions: 128
        max_sessions_per_identity: 8
        session_ttl_ms: 300000
        max_inflight: 64
        deadline_ms: 5000
        max_request_bytes: 65536
        max_response_bytes: 262144
        max_frame_bytes: 65536
        max_calls_per_session: 100
        max_bytes_per_session: 16777216
      tools:
        - name: stock
          description: Read inventory
          discovery: {groups: [readers]}
          invocation: {consumers: [inventory-reader]}
          input_schema: {type: object, additionalProperties: false}
          output_schema: {type: object, required: [stock], properties: {stock: {type: integer}}}
          side_effect: read_only
          deadline_ms: 2000
          max_calls_per_session: 20
          max_request_bytes: 4096
          max_response_bytes: 4096
          backend:
            type: rest
            method: GET
            target: {uri: "lb://inventory", path: /stock, api_key: "file://secrets/inventory.key"}
```

每个工具的 discovery 和 invocation 独立裁决。配置了多个维度时消费者、组、scope 之间取交集，
同一消费者或组列表内可匹配任一项，scope 必须全部满足；没有维度的 ACL 只有显式
`allow_authenticated: true` 才允许访问。`groups_claim`、`scopes_claim`、`tenant_claim` 只读取
验证后的 claims。Origin 存在时必须匹配 `allowed_origins`，无 Origin 的服务端客户端不受此项限制。

`servers: [{id: inventory, target: {...}}]` 可接入多个固定 MCP 后端；工具使用
`backend: {type: mcp, server: inventory, tool: remote-stock}`。客户端会话与各后端会话分别管理，
客户端认证、Cookie 和会话头不会照搬给后端。REST 工具参数由 `path`、`query`、`body` 承载；
目标 origin、方法与路径模板只来自配置，路径参数不允许注入分隔符或父目录。

`openapi` 接受本地 OpenAPI 3.0/3.1 文档，并只转换 `operations` 中显式声明的 `operation_id`。
每项还需声明 `name`、discovery、invocation、side_effect 和工具预算。`file`、固定 `target`
与上述字段组成一份目录；忽略文档内的 servers，拒绝外部引用、循环引用、header/cookie 参数和
未支持的编码。输入支持有界标量 path/query 及 JSON body。手工工具可额外声明 `output_schema`。

side_effect 为 `read_only`、`idempotent` 或 `destructive`，用于公开工具描述与审计，不代表远端
事务保证。调用前保守扣除调用次数和最大响应字节预算，不因超时、断连或结果未知返还；工具不自动
重试。取消先停止本地交付，再尽力通知 MCP 后端；REST 请求已产生的副作用无法撤销。会话有总量、
每身份数量和 TTL 硬门，每会话只允许一条通知 GET；通知队列拥塞关闭会话，不无限缓存。

### A2A 任务与发现

A2A 显式支持 `0.3.0` 的 JSON-RPC 或 HTTP+JSON REST binding；每条路由选择一种 binding，
上下游相同。REST 使用 Protobuf JSON 的 content、角色/状态枚举和消息封装，内部先归一化再授权。
支持 message/send、message/stream、tasks/get、tasks/cancel、tasks/resubscribe；REST 对应
`/v1/message:send`、`:stream`、`/v1/tasks/{id}`、`:cancel`、`:subscribe`。

```yaml
routes:
  - id: inventory-agent
    predicates: ["Path=/agents/inventory"]
    filters: ["api_key header=X-Api-Key value=file://secrets/client.key consumer=inventory-reader"]
    agent:
      protocol: a2a
      protocol_version: "0.3.0"
      binding: jsonrpc
      target: {uri: "lb://inventory-agent", path: /agent, api_key: "file://secrets/agent.key"}
      card_path: /.well-known/agent-card.json
      public_url: "https://gateway.example.com/agents/inventory"
      security: {tenant: inventory}
      discovery: {allow_authenticated: true}
      invocation: {consumers: [inventory-reader]}
      card_security_schemes:
        gateway: {type: apiKey, in: header, name: X-Api-Key}
      card_security: [{gateway: []}]
```

网关在 `public_url` 路径下提供 `/.well-known/agent-card.json`。URL 和认证说明来自网关配置，
不信任客户端 Host，也不复制上游认证地址、签名或其它私有入口。路由断言必须覆盖 public_url
路径本身以及其子路径；仅使用以 `/**` 结尾的匹配可能遗漏 JSON-RPC 根入口。

任务、上下文、调用预算和终态绑定已验证身份与当前配置快照。跨主体、未知或过期 ID 不提供可枚举
差异；同一任务只允许一个活动动作，cancel 可先撤销旧动作再申请远端取消。终态不重新开放。
SSE 先发布 owner 与状态再交付内容；断连保留有 TTL 的任务索引，允许 owner 重新订阅，但不保存
消息正文，也不提供事件 ID 回放。此入口不支持 push notification URL、远程 file URI、非空 metadata、
协议扩展、authenticated extended card 或 gRPC binding；文件仅允许有界内联 Base64。

### 内容规则、模板与检索证据

Chat 路由的 `llm.guardrails.rules` 支持 `prompt_injection`、`jailbreak`、`pii`、`secret`、`content`
分类；每条规则选择 contains、有限长度 regex 或内置 detector 之一，命中即阻断，不自动改写正文。
detector 可选 email、phone、national_id、api_key、private_key、bearer。它们检测文本形态，不能
保证识别所有自然语言攻击或真实个人身份；语义判定需配置外部内容服务。

```yaml
llm:
  guardrails:
    stream_window_bytes: 4096
    rules:
      - {id: no-override, category: prompt_injection, directions: [request], contains: "ignore all previous instructions"}
      - {id: no-email, category: pii, directions: [request, response], detector: email}
      - {id: no-private-key, category: secret, directions: [response], detector: private_key}
  governance:
    security: {tenant: inventory}
    retention: request_only
    prompt:
      name: stock-assistant
      revision: inventory-approved
      file: prompts/stock.txt
      variables: {team: inventory}
    rag:
      citations: required
      max_context_bytes: 32768
      sources:
        - id: stock-docs
          target: {uri: "lb://retrieval", path: /retrieve, api_key: "file://secrets/retrieval.key"}
          invocation: {consumers: [inventory-reader]}
          timeout_ms: 1000
          max_documents: 8
          max_response_bytes: 65536
          allowed_sources: [inventory]
          allowed_citation_origins: ["https://docs.example.com"]
          fail_mode: closed
    output_moderation:
      stream_window_bytes: 1024
      max_calls: 128
      service:
        uri: "lb://content-policy"
        path: /v1/moderations
        api_key: "file://secrets/moderation.key"
        model: output-policy
        timeout_ms: 1000
        max_request_bytes: 262144
        max_response_bytes: 16384
        fail_mode: closed
  models:
    - {id: chat, provider: openai, uri: "lb://model", model: inventory-assistant}
```

模板只展开配置固定的 `{{name}}`，不执行表达式或请求变量；文件、修订标识、变量、来源和凭据
一起编入快照。模板缺失、未声明或未使用变量、超限均拒绝配置。检索查询取最后一条纯文本 user
消息；发送 `{query, tenant, subject, sources, limit}`，其中 subject 为身份摘要，不发送客户端凭据。
检索服务返回 `{tenant, subject, documents}`；每个文档包含 id、source、revision、sha256、text、uri。
网关核对身份、来源白名单、文本摘要和 HTTPS 引用 origin；摘要用于证明传输内容一致，不保证文档
本身真实。文档作为低信任数据注入，不能成为系统模板或控制目标。

回答引用格式为 `[cite:stock-docs:document-id@revision]`，必须来自本次已批准文档；required 要求
回答正文至少包含一个有效引用，工具参数或元数据中的标签不算引用。响应附加 `gateway_citations`
提供实际引用的 provenance。当前 RAG 仅接受完整缓冲回答，所有 stream 请求在模型调用前拒绝；
去掉 rag 后，模板与输出 moderation 可以用于流式 Chat。引用检查验证来源绑定，不判断自然语言
论断是否真正由文档支持。

本地响应规则必须证明最大匹配长度小于窗口；无限或空匹配正则拒绝配置。流式实现按 choice/tool
独立拼接文本，持有完整 SSE 事件，先裁决再释放；遇到坏 JSON、未知 delta、压缩、trailer、超限、
缺失 DONE 或撤权则结束流，不继续交付待审数据。外部 moderation 按有限前瞻窗口判定，窗口之外
的跨段语义不属于保证范围；已批准的早期窗口不能撤回。配置窗口越大，首 token 延迟与内存占用越高。

RAG/输出服务的 closed 拒绝依赖故障；open 仅允许网络不可用、服务端错误或依赖时限耗尽的降级。
明确 flagged/拒绝、非法响应、坏 provenance、来源不符和网关总预算耗尽不会因 open 放行。required
引用在没有批准文档时仍拒绝。`request_only` 不持久化 prompt、检索文档或治理结果，并禁止语义/响应
缓存及 shadow 复制；不限制已批准模型或依赖服务自身的数据保留，部署方需单独约定其存储政策。

### 撤权、观测与组合边界

Agent 和治理请求的身份、固定目标、schema、模板及策略来自同一不可变快照。成功 reload 后旧会话、
任务与在途结果失去交付权限；坏候选保留当前有效状态。回滚重新构建新代，不恢复已撤销 session/task
索引。重启同样不恢复索引。管理长连接关闭可终止活动调用/流，但不是永久封禁，新请求仍由当前策略
决定。配置改变不能撤销已在远端发生的副作用；调用者必须按结果未知处理超时和取消。

为保证裁决后的内容不被再次改写或复制，这些路由不能组合通用正文转换、响应契约、缓存、镜像、
hedge、内部重定向、ext_proc、外部插件或头部/上游凭据改写等冲突路径；冲突在构建期拒绝。
取消/关闭使用独立有界控制槽，不与长业务流争抢最后一个槽。

管理状态提供脱敏能力/配额摘要；`gw_ai_operations_total` 按 route、protocol、method、固定工具/模型/
来源与 outcome 记录操作，`method="task.state"` 记录 A2A 状态。`gw_ai_duration_seconds_sum`、
`gw_ai_ttft_seconds_sum/count` 记录生命周期和通过输出策略后实际交付首帧的时间；指标序列有硬上限。
响应级 `completed` 表示正文交付结束，不表示 JSON-RPC result 或工具业务执行成功；调用方仍需检查
协议 error、工具 isError 和任务终态。
`gw_ai_guardrail_blocked_total` 使用固定 direction/category。LLM token、费用、缓存和 moderation 指标
继续分别提供计量；未知 usage 不虚构精确 token 或费用。task/context 日志只记录摘要，prompt、工具
参数、检索正文与模型响应不写入这些日志，也没有默认内容采样入口。

## WebSocket 帧与消息治理

省略路由的 `ws_frame` 时保持透明双向字节转发，不解析或聚合业务消息。显式开启后校验帧头、
掩码、opcode、RSV、控制帧、分片数、消息字节和 UTF-8；没有压缩、消息插件或 `drop` 策略的方向
仍按帧流式转发。需要完整消息决策时，先取得进程容量，再聚合、校验和执行策略，批准后才发送
该消息的第一字节。控制帧不进入消息插件或消息额度。

```yaml
routes:
  - id: notifications
    uri: http://notification-service:8080
    predicates: ["PathPrefix=/events"]
    ws_frame:
      permessage_deflate: true
      max_frame_bytes: 65536
      max_message_bytes: 1048576
      max_fragments: 256
      max_decompress_ratio: 100
      max_plugin_payload_bytes: 65536
      message_timeout_ms: 5000
      plugin_timeout_ms: 100
      on_violation: policy_close
      client_plugins:
        - type: acl
          opcodes: [text]
        - type: rate_limit
          messages: 100
          window_ms: 1000
        - type: json_schema
          schema:
            type: object
            required: [event]
            properties:
              event:
                type: string
                maxLength: 128
      server_plugins:
        - type: redact
          pointers: [/credentials/token]
```

`client_plugins` 和 `server_plugins` 各自按声明顺序执行，最多 16 步。`acl.consumers` 使用握手认证
冻结的主体，后续外部授权修改请求头不能改变它；未配置的主体或 opcode 维度不限制。`rate_limit`
是每连接、每方向的完整消息固定窗口计数，重连取得新窗口，不代表跨节点主体额度。已执行的计数
不会因后续插件拒绝而退还。Schema 与脱敏只解析完整 JSON，拒绝重复键、超过 32 层或 4096 个值的
文档；Schema 禁止引用并约束声明复杂度，正则使用非回溯实现。脱敏按 RFC6901 指针替换为
`[REDACTED]`，缺少目标字段不修改。连续内容步骤复用已解析文档，未修改正文保留原始字节，修改后
在发送或外部调用边界编码一次。

可选 `external` 插件向固定 HTTP/HTTPS 端点发送原始消息字节，无 JSON 或 Base64 包装：

```yaml
client_plugins:
  - type: external
    endpoint: https://policy.internal/message
    authorization: file://secrets/ws-plugin-token
    ca_certificate: file://secrets/ws-plugin-ca.pem
    include_consumer: true
    allow_rewrite: false
    fail_open: false
```

请求使用 `POST`、`Content-Type: application/octet-stream`，固定头 `x-naway-ws-direction` 为
`client|server`，`x-naway-ws-opcode` 为 `text|binary`；只有显式开启才发送冻结主体头
`x-naway-ws-consumer`。`authorization` 文件内容是完整 Authorization 值。禁止重定向和环境代理。
成功响应必须为 200，且只有一个 `x-naway-ws-action`：`allow`、`drop`、`close` 或 `replace`。
前三者必须没有响应正文；`replace` 必须事先开启 `allow_rewrite`，正文是完整替换载荷且不能超限。
不接受压缩的插件响应。`fail_open` 只允许网络、服务端 5xx 或插件子期限失败后继续使用原消息，
非法动作、替换内容、资源不足和整条消息期限耗尽仍拒绝。

`permessage_deflate` 仅协商双方禁止跨消息字典的压缩；上游没有接受 `server_no_context_takeover`
时拒绝升级。压缩输入受消息总字节、解压比例与共享内存门约束；解压后转发合法的未压缩帧，不为
转发重新压缩。`max_plugin_payload_bytes` 默认 64 KiB、最高 1 MiB，超限关闭连接，不把截断前缀交给
插件授权。完整消息模式的 `message_timeout_ms` 从首字节起覆盖分片、插件和背压发送，默认 5000 ms、
最高 60000 ms；每个插件的子期限不能延长它。消息保留量共享进程 4096 个名额和 64 MiB 字节预算；
内容与外部调用另外受扩展工作集预算约束，阻塞内容任务取消后仍持有容量直到真实退出。

`on_violation: drop` 只丢弃完整且通过协议门的策略拒绝消息；外部显式 `drop` 同样丢弃整条消息。
协议错误、超限、非法插件结果和期限耗尽必须关闭。默认 `policy_close` 使用对应标准关闭码：
协议错误 1002、非法 UTF-8 为 1007、策略或期限拒绝 1008、消息/解压超界 1009、插件失败 1011、
本地容量不足 1013；`upstream_close` 结束隧道并向下游返回 1011。

消息策略、插件凭据和 CA 随候选完整构建后原子发布，无效候选保留旧快照。既有连接继续使用握手
快照；需要使旧权限失效时可按 route、IP、consumer 撤权，或启用 `long_connections.drain_on_config_change`。
撤权、空闲超时、生命周期和停机共用连接治理：能确认完整帧边界时发送 Close，取消发生在半帧写入
时直接断流；透明模式无法证明帧边界，强制关闭同样直接断流。关闭等待有上限，不让背压无限阻塞退出。

## 双向共享带宽与有界等待

`traffic_limit` 的请求与响应方向各用一个共享桶，同一作用域和维度的并发流竞争同一份速率。
实体逐帧通过，不聚合正文、不复制 `Bytes`；每帧的完整成本先进入发送时刻，再等待交付，
因此大首帧不能绕过突发额度。以下示例每方向共享 1 MiB/s，允许 64 KiB 突发：

```yaml
routes:
  - id: bounded-transfer
    uri: http://127.0.0.1:9000
    predicates: ["Path=/transfer/**"]
    traffic_limit:
      key: ip
      fail_mode: fail_closed
      request_bandwidth:
        bytes_per_second: 1048576
        burst_bytes: 65536
        after_bytes: 0
        max_wait_ms: 5000
      response_bandwidth:
        bytes_per_second: 1048576
        burst_bytes: 65536
        max_wait_ms: 5000
```

`after_bytes` 是每条流独立的免整形前缀；随后字节参与共享速率。`max_wait_ms` 范围 1–60000，
默认 60000；无法在期限内发送时不追加债务，而是终止该方向。响应头已发送时表现为流错误，
不是完整的成功响应；请求方向失败不会把未获发送额度的正文送给上游。已保留后取消的额度
不返还，避免并发流重复消费；债务随时间到期。
本地流量保护拒绝不作为上游健康、熔断或重试依据，不因客户端超额摘除健康后端。
请求确实经历本地整形等待后，混合 TTFB 不参与 EWMA、慢响应或自适应并发学习；
此时响应头/路由期限耗尽保守归入本地拒绝，不推测后端耗时。真实上游失败状态与 ORCA
利用率报告仍按原规则观察，普通未整形请求的超时归因不变。

多窗口 `overflow: delay` 的 `max_queue` 范围 1–4096，`max_wait_ms` 范围 1–60000。
所有延迟准入和待发送帧共同受进程级 4096 个等待者、64 MiB 保留实体字节预算约束，
热更不重置占用，取消和交付归还名额。延迟准入只接受有已知实体上界的正文；
额度不足且正文上界未知时返回 429，不为等待预读整条流。该字节预算统计所保留的逻辑实体，
不等同于整个进程 RSS 或网络栈缓冲上限。

状态容量耗尽时，`fail_closed` 返回 503；`fail_open` 只跳过不可用的计数项，不跳过仍可用的
另一方向带宽。资源预算或等待期限耗尽不能被 `fail_open` 绕过。配置省略失败模式时兼容
`fail_open`，需强制保护的路由应显式选择。`gw_traffic_wait_events_total{outcome=...}` 记录固定
失败类别；`gw_traffic_wait_resources{resource="waiters|retained_bytes"}` 提供等待占用。
Prometheus、OTLP 和管理读面使用同一份样本。
旧路由的过期额度和带宽状态可被同工作区其它状态使用者回收；在途请求借用的账本、
仍有窗口效力的消费和未到期带宽债务不会因为热更或容量压力被清空。

### HTTP 请求解压

普通公开 HTTP 转发路由可显式解码客户端的单层 gzip（包括 `x-gzip`）或 Brotli 实体：

```yaml
filters:
  - request_decompression algorithms=gzip,br max_encoded_bytes=16m max_decoded_bytes=64m max_ratio=100 timeout_ms=30000 chunk_bytes=16k
```

缺省关闭，`request_decompression off` 显式关闭。无编码或 identity 正文直通。认证先检查客户端原始字节，
HMAC 正文签名也覆盖压缩字节；认证完成后安装流式解码器，OPA、WAF、DLP、Schema 和后续正文变换读取
解码实体。解码移除原 Content-Encoding、Content-Length 与 Content-MD5/Digest/Content-Digest/Repr-Digest，
合规业务 trailers 在完整输入结束后保留，身份、路由与逐跳控制字段不得通过 trailers 注入。

编码、解码预算各允许 1 字节至 1GiB，倍数允许 1–1000，chunk 允许 1–64KiB，总期限允许 1–300000ms。
每个输出帧交付前验证解码总量和 `decoded <= max(consumed_encoded, 1024) × max_ratio`；proxy 总正文上限
仍然生效。输入借用 Bytes，输出每次最多一个 chunk，不聚合完整实体；需要完整正文检查的策略另按其聚合预算执行。
全进程最多同时保留 64 个 gzip 与 8 个 Brotli 解码器、64MiB 输入帧，无等待队列，热更共用容量。
Brotli 只接受标准窗口，最大字典窗口 16MiB，拒绝 large-window 扩展；这不是整个编码库的精确 RSS 上限。
结束、失败与取消释放资源，已开始请求继续使用冻结策略和原截止时间。

未知、多层、重复或空 Content-Encoding 返回 415，并用 Accept-Encoding 告知支持的编码。压缩的
gRPC/Connect、Upgrade、CONNECT、Content-Range 和 no-transform 请求拒绝转换。内部/层级路由、CGI、
静态资源、媒体、WebDAV、专用 RPC/AI/聚合终端、隧道或关闭正文/请求头透传的配置不能组合该策略。
声明式请求头操作不能覆盖解码相关实体字段。gzip 校验全部 member；截断、错误校验和或尾随无效字节为 400，
字节或倍率超限为 413，期限为 408，本机容量不足为 503。这些本地失败不参与后端重试或熔断。

纯流式转发可能在最终校验失败前已向上游交付部分正文，不提供上游业务副作用回滚。响应头提交前已知的
解码失败返回对应拒绝；提交后只能中断响应流。上游提前结束响应时不会无限读取剩余上传，也不声称整篇输入已验证。
需要整篇验证后再执行的业务应配置独立的有界完整正文检查。

`gw_request_decompression_events_total`、`gw_request_decompression_bytes_total`、
`gw_request_decompression_active` 和 `gw_request_decompression_retained_bytes` 提供固定结果、结束请求字节
及当前占用。Prometheus、OTLP 和集群实时管理使用相同口径，不保留单请求历史。

### HTTP Digest 认证

路由 filter `auth_digest` 提供原生 SHA-256、SHA-256-sess 与 `qop=auth` 认证。验证客户端原始
请求目标和方法后，再原子消费一次性计数；成功后移除下游 Authorization，冻结 consumer 并进入
工作区归属、授权和限流管线。正文保持流式，不为认证聚合或重新序列化。

```yaml
filters:
  - auth_digest user=alice realm=orders password=file://secrets/alice-password nonce_secret=file://secrets/digest-nonce-key consumer=alice ttl_secs=60 algorithm=SHA-256
```

`password` 与 `ha1` 必须二选一；`ha1` 是 SHA-256(username:realm:password) 的64位十六进制值，
两者都支持 SecretSource。运行态只保存 HA1。`nonce_secret` 必填，长度32–4096字节，应该使用
随机秘密；用户名、consumer 和 realm 限可打印 ASCII、最多128字节。`ttl_secs` 为1–300秒。
密钥文件参与配置指纹和精确监听；密码、HA1、nonce密钥或认证范围变化后旧挑战不能继续授权。

单机默认使用本地重放账本：挑战绑定该账本实例，重启或更换本地账本后失效。集群配置
`runtime_state.replay_guard.backend: redis`，并通过 `runtime_state.rate_limiter.redis` 提供
一致的连接声明和 namespace；共享同一策略、nonce密钥和Redis账本的节点可以互认挑战。
注册中心与配置中心均可关闭。严格登记始终故障关闭，不受既有 `replay_guard.fail_mode: open`
影响；Redis不可达、容量不足和未知ACK均拒绝，不回退本地。平台共享账本最多65536个有效凭证，
工作区另受其状态预算约束。Redis必须保留消费记录；丢失账本后应轮换nonce密钥再接入。

凭据头最多8192字节，cnonce最多128字节；重复字段、非唯一Authorization、错误URI/签名/算法、
重复计数均返回401和新挑战。只有密码响应正确且nonce过期才带 `stale=true`。允许不同计数并发
乱序到达，同nonce/cnonce/用户/计数只接受一次。节点以单调时间推进挑战有效期，Redis另以自身
时钟核对截止时间；起始时钟偏差过大时拒绝。远端登记最长等待1秒。

支持明文或 `userhash=true` 用户名、origin-form目标。当前不协商MD5、无qop、auth-int、username*
或完整国际化凭据。`qop=auth` 不认证正文内容，传输保密性由TLS提供。策略只用于公开非层级路由，
不允许satisfy=any、内部跳转、公开共享缓存、early-data或竞争同一Authorization的认证方案；独立
头部凭据和ext_authz可在satisfy=all下叠加。

### 共享作用域与认证主体

`scope` 决定哪些路由共用账本，`key` 决定同一账本中的调用方维度。默认 `scope: route`，
同名路由位于不同入口时也各自独立。`scope: service` 要求固定 `lb://service` 目标，
同一逻辑服务的多个路由、入口共用额度；不接受动态目标或直接 HTTP URL。
`scope: global` 跨当前归属域内所有声明该作用域的路由共享；`scope: shared:public-api`
只合并显式使用同一名字的路由。共享名称限 1–256 个 ASCII 字母、数字、点、下划线或连字符。
所有作用域都受工作区、租户和环境隔离；关闭归属功能时使用平台域，不会从客户端头推导归属。

同一共享域的 `traffic_limit` 声明必须完全一致，包括维度、限额、成本、带宽和失败模式。
候选中存在冲突时整份配置拒绝并保留上一份有效配置，不为冲突路由暗中创建额外额度。
未声明流控的路由不自动加入任何共享域。`key: global` 表示域内只有一个总桶，
与 `scope: global` 是不同概念；`key: route` 则在共享域内再次按路由名分桶。

`key: consumer` 使用本地认证成功并经过工作区归属解析的主体；`key: api_key` 使用本地
API-Key 策略匹配后的 SHA-256 前128位指纹。身份在外部授权与插件改写之前冻结，父层认证
可以向子层移交同一事实；重新认证会撤下旧凭据。指纹在配置构建期计算，请求只共享引用，
不把原始密钥写入账本键。缺少所需认证事实返回 401，即使 `fail_mode: fail_open` 也不例外。
仅有外部鉴权注入的 consumer/API-Key 头不授予该身份；普通 `header:<name>` 和 `query:<name>`
仍是调用方可控维度，不具有认证含义。

## GraphQL 查询成本准入

`traffic_limit.quota.cost_source: graphql_cost` 使用 `graphql_guard` 已解析的查询成本，
在上游分派前对同一作用域、同一维度的所有窗口原子扣账。成本是选定操作展开 fragment 后的字段出现次数，
不是查询深度、数据库执行时间或 schema resolver 费用；alias 和重复 fragment 分别计数，
条件指令不减少静态成本，batch 累加全部操作。例如 `{ a { b } }` 成本为 2，
`{ a { b c d } }` 成本为 4，两者深度相同但额度消耗不同。

```yaml
routes:
  - id: graphql
    uri: http://127.0.0.1:9000
    predicates: ["PathExact=/graphql"]
    graphql_guard:
      max_body_bytes: 1048576
      max_depth: 16
      max_complexity: 1000
    traffic_limit:
      key: ip
      fail_mode: fail_closed
      quota:
        algorithm: sliding_window
        cost_source: graphql_cost
        overflow: reject
        windows:
          - limit: 1000
            window_ms: 1000
          - limit: 10000
            window_ms: 60000
```

GET、JSON / `application/graphql` POST、multipart operations 使用同一解析预算。
POST 仅在显式上限内聚合，检查后原字节与 trailers 重放；`degraphql` 使用构建期冻结的模板成本，
不在每次请求重新解析固定模板。缺少 guard、允许 WebSocket subscriptions、解析后请求正文变换、
关闭请求体转发或内部重定向的组合拒绝构建。CORS 预检没有查询成本，不占用查询额度。
缺失、非法或不完整查询在上游前拒绝，`fail_open` 不能绕过成本证据门，
任何客户端 cost/usage header 都不参与计算。

查询成本在准入时已经确定，`reserve` 不代替实际成本；响应失败或取消不返还已提交操作的成本。
同配置热更继续使用原账本；修改限额策略隔离新账本，回到原策略时复用仍未过期的原账本。
`reject` 立即返回 429，`delay` 使用有限队列与等待期限，取消归还排队名额。
`RateLimit-*` / `X-RateLimit-*` 表示网关准入时最紧窗口的余额，拒绝时附带 `Retry-After`，
这些头在响应变换后写入，不信任上游的同名余额。

`traffic_limit.backend` 默认为 `local`，按显式作用域在进程内共享。
选择 `redis` 后，同一 namespace、归属、作用域、策略和维度的多个节点共享全部窗口、两个方向的带宽
以及 `delay` 队列名额。需要 `redis-runtime` feature、`runtime_state.rate_limiter.backend: redis`
和 Redis 7 及以上的脚本 ACL 预检能力；复用 NASA Redis 连接，支持该连接配置的部署方式。
注册中心和配置中心可以保持关闭，共享流控仍独立工作。

```yaml
runtime_state:
  rate_limiter:
    backend: redis
    redis:
      url: redis://127.0.0.1:6379
      namespace: gateway-production
# 在需要集群共享的路由上设置 traffic_limit.backend: redis。
```

Redis 多窗口在一次同 slot 操作中预检并扣账，使用服务端时钟；只有明确的 NOSCRIPT 才重新发送脚本。
每次 RPC 最长 500ms；丢失响应时保留未知提交，不重复扣账或猜测退款。
带宽按原始帧调度，每流冻结后端与方向键，每帧仅传递整数成本；取消释放保留帧，已提交时间债务继续有效。
发送等待期限包含 Redis 调用时间，整帧无法在期限内交付时关闭实体。`after_bytes` 仍按每条流计算。
共享队列令牌在准入提交内再次验证并消费，取消后的清理继续占用原进程名额，远端名额最长在等待期限加
1000ms 后失效。队列容量按共享维度计算，进程级 4096 等待者和 64 MiB 保留字节限制仍同时生效。

Redis 窗口为 1ms 至 31天，最多16个；额度加 burst 不超过 `2^32`，与窗口毫秒数的乘积不超过 `2^52`。
漏桶每额度至少对应1微秒；带宽速率与 burst 不超过 `2^32` 字节，burst 不超过60秒的配置速率。
类型错误、损坏账本、权限不足和过期排队权威均拒绝继续；只有连接不可用或状态容量不足可按显式
`fail_open` 降级。Redis 数据丢失或切换时丢失未复制的写入会使相应额度回退，部署持久化与切换策略
决定共享账本的数据保留保障。

Redis 支持 `per_request`、`graphql_cost`、`response_bytes`、`grpc_messages` 和 `trusted_usage`。
响应成本准入时同时创建同 slot 回执并预留额度，实际成本超过预留时先提交累计补扣，再交付原始帧；
补扣可以形成超过准入额度的债务，后续请求据此拒绝。结束或取消按已交付事实返还未使用预留，
已经关闭的回执不能被迟到补扣重新打开。丢失准入响应不授予退款权威；结算结果未知时保留远端已有状态，
不猜测退款或隐式改用本地共享账本。

共享响应的 `quota.max_actual` 默认为 1000000，范围 1–`2^32`，且 `reserve` 不得超过它；
它是累计事实成本的硬交付上限，超过时关闭响应流，不静默截断计费。
`quota.settlement_idle_ms` 默认为 60000，范围 1000–600000；回执在响应帧进展时续期，
无进展或客户端背压持续超过期限后不能重建权威。每个在途回执占用一个进程等待槽和一个共享状态名额，
终态回执最多再保留1000ms用于幂等识别。取消清理复用原名额，仍受500ms RPC限制。
固定/滑动窗口补扣后的整数乘积仍受 `2^52` 约束，漏桶未来债务最多31天；超界帧不交付。
依赖 `fail_open` 只放弃该次共享结算保证，本地成本、闲置及物理资源硬上限继续生效。

响应字节按实际交付的帧计量。gRPC 消息退款要求原生 `application/grpc`、`+proto` 或 `+json`
正文、无 HTTP 内容编码，以及完整合法的消息 envelope；畸形、截断或协议不匹配时保留至少准入预留。
漏桶补扣形成的未到期债务持续占用状态名额，过期预留或其它退款已经移走的时间不能再次抵消新请求。
`trusted_usage` 在本地和 Redis 多窗口中使用明确声明的上游来源：

```yaml
traffic_limit:
  backend: redis
  key: consumer
  fail_mode: fail_closed
  quota:
    cost_source: trusted_usage
    reserve: 100
    max_actual: 1000000
    usage:
      source: response_header
      header: x-service-cost
    windows:
      - limit: 10000
        window_ms: 60000
```

`response_header` 只接受最终选中真实上游响应中唯一的十进制无符号整数头。
同名请求头在发送前移除，响应插件、缓存中的旧头和重试／hedge 落选响应不能改变当前计费事实。
`provider_tokens` 用于已有解析器的 Chat Completions 模型，此时不配置 `header`；
原生不透明模型、其它模型 API、内部改投、HTTP 镜像或多个终端来源不能混用该来源。
provider 计数复用已解析 JSON／SSE；Anthropic 输入包含普通输入、缓存创建和读取，
Google 输入包含工具提示，输出包含 thinking token。OpenAI 与 Google 的总数存在时必须和分项一致。
模型额度对应最终选中的生成调用，不汇总 moderation、embedding、shadow 或失败 fallback 的未知费用。
这些是处理额度单位；供应商缓存单价、工具调用等额外收费不由 token 总数推导。

未知用量与零用量分开处理。中途累计值只提高已知消耗下界，最终完整事实才能返还预留；
OpenAI SSE 使用空 `choices` 的最终 usage，Google 使用结束标记同时或之后的完整 metadata，
Anthropic 使用 `message_stop` 前已经报告的输入与累计输出。缺失事实保留预留与已知下界中的较大值。
重复相同值幂等，倒退、矛盾、畸形或超过 `max_actual` 的事实关闭响应，不能由 `fail_open` 绕过。
HTTP 或模型缓存命中不重复计入旧响应的上游成本。

已知响应头或非流式 provider 成本在响应头发布前结算；流式补扣保持原始帧与背压。
provider 已报告的消耗独立于客户端交付进度，取消或丢失 Redis 补扣响应不能退掉这部分消耗。
响应头尚未发布时结算失败返回错误状态，发布后失败会终止实体；共享依赖降级不授予未知回执退款权威。
产品用量启用外部 meter 时记录同一份已验证 GraphQL／AI 事实；
普通流量可独立启用持久成本事件。LLM token quota、流量事件和产品 usage 计量各有明确归属，
不会自动合并为一份商业收费账单。

### 持久流量成本事件

```yaml
runtime_state:
  traffic_meter:
    endpoint: https://meter.example/traffic/
    authorization: env://TRAFFIC_METER_AUTHORIZATION
    ca_certificate: file://meter-ca.pem
    max_pending: 1024
    timeout_ms: 2000
    retry_ms: 500

routes:
  - id: metered-api
    uri: http://127.0.0.1:8081
    predicates: ["Path=/api/**"]
    filters:
      - "api_key header=x-api-key value=env://API_KEY consumer=example-consumer"
    traffic_limit:
      events: true
      key: consumer
      quota:
        cost_source: per_request
        windows:
          - limit: 1000
            window_ms: 60000
```

`events` 默认关闭；声明时必须同时有 quota 和 `runtime_state.traffic_meter`。未配置传输时没有
worker、队列或外部依赖。该入口独立于产品绑定，关闭注册中心和配置中心也可使用。传输端点、凭据、
CA、容量与超时在进程启动时冻结，变更需要重启；路由事件开关可热更，切换不重置既有额度债务。

到达该额度策略且身份、成本证据有效的请求，先取得有界事件容量并持久确认 `request_started`，
再执行配额扣账和终端上游调用。容量耗尽、依赖不可用或收据不匹配返回 503，不能由 quota 的
`fail_open` 绕过；开始确认期间配置代际变化返回 409。更早被认证或其它策略拒绝的请求不产生该事件。

使用下文外部 meter 的 HTTPS、固定事件身份、SHA-256 收据和幂等重投协议，`aggregate_type` 为
`GatewayTraffic`。`tenant` 为受信工作区命名空间，无工作区时为 `platform`；`payload.attribution`
包含 owner、listener、route、scope、dimension_sha256、policy、config_generation、gateway_request_id
和 source。维度使用同一次认证冻结的主体，仅发送摘要；不记录凭据、原始头、正文或 prompt。
`aggregate_id` 关联开始和结束，gateway_request_id 可与访问日志关联。不得按重投次数累计成本。

`request_finished` 的 `cost` 包含 reserved_cost、observed_cost、settlement_cost、admission、settlement。
`observed_cost: null` 表示证据不足；settlement_cost 是提交所依据的有效成本，可能仍为保守预留。
必须结合 admission 的 `not_attempted|accepted|rejected|unknown` 和 settlement 的
`not_attempted|confirmed|unknown` 解释，不能把未知确认记作扣款成功。字节和消息成本以实际交付事实为准，
可信 provider 用量独立于下游读取进度。取消时等待原账本的有限清理，最长 1500ms，仍在途则记录未知。
帧路径只维护固定计数和原始载荷，不逐帧生成事件或序列化正文。

status 是 HTTP 响应状态，outcome 区分 `complete|failed|cancelled|cancelled_before_response|not_dispatched`。
complete 仅表示 HTTP 实体结束，不证明对端应用消费或业务成功；升级后的 WebSocket/CONNECT 流量不计入
HTTP 实体成本。开始确认丢失时可能产生孤立结束事件，不能单独据此收费。结束队列使用有界内存重投，
进程崩溃或停机 flush 超时可能只保留持久开始事件；接收端必须展示 incomplete/待核对，不能推断零成本。

`gw_traffic_meter_admitted_total`、`gw_traffic_meter_rejected_total`、`gw_traffic_meter_retry_total` 与
`gw_traffic_meter_pending` 表示独立传输健康。流量事件不进入产品门户的应用用量查询，额度后端仍是准入权威。

## API 产品、团队门户与持久用量

`/developer` 展示产品合同、团队应用、凭据状态、套餐和低敏用量。产品身份是
`product / version / operation`，不是 route id；`management.bindings` 把已发布操作绑定到具体入口。
OpenAPI 自动生成的旧 catalog 仍可使用，与产品目录共用公开文档投影边界。

### 合同与生命周期

```yaml
developer_portal:
  enabled: true
  public_catalog: true
  max_document_bytes: 1048576
  products:
    - id: inventory
      title: 库存 API
      versions:
        - id: stable
          lifecycle: active
          visibility: public
          subscription_teams: [warehouse]
          documents:
            - id: http
              format: openapi
              file: inventory.openapi.yml
              operations: [read_inventory]
            - id: guide
              format: markdown
              file: inventory-guide.md
```

`lifecycle` 为 `draft / active / deprecated / retired`；草稿只对管理读面可见，只有 active/deprecated
允许绑定和订阅。`deprecated_at` 是可选 RFC 3339 弃用时间；`compare_to` 指定同产品比较基线。
兼容 diff 按已投影操作合同比较：删除或任何变化都保守标为不兼容，不宣称完整语义兼容证明。
隐藏版本不会因 diff 泄露。private 版本只对其 `subscription_teams` 中的当前登录团队公开。

支持 OpenAPI 3.0/3.1、AsyncAPI 3.0 send/receive 和纯文本 Markdown。API 文档必须显式选择 operation；
AsyncAPI 的 channel/message 引用必须在本文件，operation 的 messages 只允许其 channel 下的子集；
共享 channel 只合并已发布操作需要的消息。reply channel、转义 channel/message id、带 sibling 的
`$ref` 和远程引用需要先整理为支持的独立操作/内联合同，不会静默展开为另一业务语义。
引用深度最多 32，展开节点最多 65536；单文档、总投影、产品/版本/文档/操作数都在候选构建期限制。

公开投影移除 servers、security/securitySchemes、外部文档地址、callback、link、example/default、
bindings/traits 和扩展元数据；业务 schema 的同名属性不被误删。SecretSource 标记和私钥标记拒绝。
**公开资料必须由配置作者明确整理为对外合同**，网关不推测自由文本中的业务保密等级。
Markdown 不转为 HTML，页面只用文本节点渲染；文档带 nosniff、no-store 和禁止执行的 CSP。
不抓取远程 logo、spec 或 Markdown 资源。匿名 `/api/developer/products` 永不返回应用/团队统计；
完整管理目录使用独立 `/api/products` 和 RoutesRead 权限。

### 企业身份与应用审批

`developer_portal.management` 需要开启 admin 认证、RBAC、持久审计和 `consumers` maker-checker。
门户会话不是 admin Bearer 的别名。以下片段与上述产品和既有 admin 配置合并：

```yaml
developer_portal:
  management:
    identity_domain: corporate
    sso:
      type: oidc
      groups_claim: groups
      filter: >-
        oidc_rp issuer=https://id.example
        discovery_url=https://id.example/.well-known/openid-configuration
        authorization_endpoint=https://id.example/authorize
        token_endpoint=https://id.example/token
        client_id=naway-portal client_secret=env://PORTAL_OIDC_SECRET
        redirect_uri=https://portal.example/api/developer/account/callback
        callback_path=/api/developer/account/callback
        logout_path=/api/developer/account/logout cookie_name=naway_portal_oidc
    allowed_origins: [https://portal.example]
    max_sessions: 1024
    session_ttl_seconds: 1800
    teams:
      - id: warehouse
        title: 仓储团队
        group_roles: {warehouse-owners: owner, warehouse-developers: developer, warehouse-readers: viewer}
        max_applications: 64
    applications: []
    bindings:
      - {product: inventory, version: stable, operation: read_inventory, proxy: default, route: inventory-read}
```

OIDC 使用固定 issuer/JWKS/端点、PKCE、state 和 nonce；discovery 的其它标准元数据不授予动态端点权威。
回调、注销路径、专用 Cookie、HTTPS origin 和会话预算必须一致。`/api/developer/account/login` 完成登录
后只返回固定门户，不能指定任意 return URL。门户应置于可信 HTTPS 前置层之后；Secure/HttpOnly/SameSite
Cookie 不向明文公网客户端提供会话。每次配置换代使门户旧会话失效。

SAML 需编译 `enterprise-saml`：`sso.type: saml`，`filter` 使用既有 `saml_auth` DSL，提供已签名 metadata、
固定 metadata_signing_cert、idp_entity_id、sp_entity_id、HTTPS acs 和 `identity_headers`；另配置
`groups_header` 为签名属性映射输出头、`acs_path: /api/developer/account/callback`。
支持 IdP-initiated HTTP-POST，表单只接受一个 SAMLResponse，不接受 RelayState；不实现门户 SP-initiated
登录跳转或 SAML Single Logout。Response/Assertion 双签名、audience、时间和重放门全部适用。
门户重放域在进程中常驻且有容量/TTL，reload 不清空；不是跨节点或跨进程持久重放服务。
一个签名 group 属性值映射一个组，不把任意分隔符字符串拆成多个权限。也可用 `subject_roles` 显式映射主体。

viewer 可读所属团队资料；developer 可注册/更新应用和管理凭据；owner 还可撤销应用、转移 owner 和导出明细。
转移必须同时拥有旧、新团队的 owner 权限。所有写请求需要唯一可信 Origin、当前 If-Match 和严格有界 JSON。
没有其它团队权限时应用操作统一返回 404。以下动作通过既有完整候选验证、CAS、双人审批和审计生效：

- `POST /api/developer/account/applications`：`action: register`，声明 id/team/title/plan、redirect_uris 和 subscriptions。
- `POST /api/developer/account/applications/{id}/actions`：update、transfer、revoke、create_credential、rotate_credential、revoke_credential。
- create_credential 使用 id；rotate_credential 使用 id 和 replacement；update 显式提供 title/plan/redirect_uris/subscriptions。

返回 202 表示待审批，不是已生效。创建/轮换的高熵 API key 只在该次 no-store 响应出现，配置只存 SHA-256 摘要；
审批前不能调用产品，轮换审批原子替换旧 key。每应用最多 16 条凭据记录，撤销记录仍占容量；达到上限需由管理者
审核整理配置，不自动丢弃凭据历史。无有效凭据的产品入口关闭，不退化为匿名。应用计划不允许被 route 自行覆盖，
其它认证 authority 和内部重路由不能绕过订阅凭据。redirect URI 只接受有限、固定 HTTPS 地址，无 wildcard、
userinfo 或 fragment；登记 URI 本身不触发外呼。

### Consumer Group 与策略顺序

```yaml
usage_plans:
  plans:
    standard: {requests: 1000, window_ms: 60000, burst: 20}
    shared: {requests: 5000, window_ms: 60000}
  groups:
    partners: {consumers: [partner-a, partner-b], plan: standard}
  policies:
    - id: partners-budget
      scope: {type: group, group: partners}
      require_authentication: true
      quota_plan: shared
      quota_per_consumer: false
      products: [inventory]
      request_headers: {x-naway-context-tier: partner}
```

固定顺序是 global → product → route → group → consumer。consumer 显式套餐绑定优先于 group 套餐；
多个 group 的不同套餐必须由 consumer 显式选择。deny 永远优先；产品允许集合取交集，显式空集拒绝全部；
配额全部满足才允许。scope 的 product 还需 version，route 还需 proxy/route，consumer 需 consumer。
group/consumer 只匹配认证链已验证主体，不信任客户端身份头。

`authentication` 只能在 global/product/route 入口作用域编译进原认证链，group/consumer 声明认证会拒绝候选；
可以在身份层要求 require_authentication，但不能在该层重新认证。产品托管的应用凭据 authority 不与另一认证源叠加。
同入口重复认证类型或重叠同层的不同头变换拒绝，结果不依赖配置 map 遍历顺序。
上下文变换只允许 `x-naway-context-*`，先清除客户端同名值，再按层级覆盖，null 表示删除；不允许改变认证或 framing。
quota_per_consumer=false 是作用域共享预算，true 按已认证 consumer 分隔；逐门裁决已消耗的请求额度不因后续拒绝退还。
所有作用域限制复用既有 local/Redis 限额后端，外呼跨过配置代际时拒绝继续业务。

### 外部 meter 协议与失败语义

```yaml
usage_plans:
  meter:
    endpoint: https://meter.example/gateway/
    authorization: env://METER_AUTHORIZATION
    ca_certificate: file://meter-ca.pem
    max_pending: 1024
    timeout_ms: 2000
    retry_ms: 500
```

`usage_plans.meter` 只作用于有托管产品/应用绑定的 HTTP 请求，非产品路由不自动归因。关闭时没有 worker 或队列。
端点、凭据、CA、容量和传输预算是进程启动合同，变更需重启；reload/审批候选不能重置旧结束队列。
endpoint 是固定 HTTPS 基址且以 `/` 结尾，不接受 userinfo/query/fragment，不跟随重定向。
计量前拒绝 WebSocket/CONNECT 升级，不能把握手冒充完整隧道用量。

发送 `POST {endpoint}events`，带 Authorization、Content-Type: application/json、Idempotency-Key。
事件字段为 event_id、aggregate_type=GatewayUsage、aggregate_id、event_type、tenant、payload。
使用 NASA `naoutbox-core` 的事件身份模型；每个请求有独立随机关联，开始和结束使用固定不同的 event_id。
payload.attribution 是同代验证出的 team/product/version/operation/application/consumer/plan/config_generation，
不含 header、正文、prompt、key、subject claim 或客户端给出的产品身份。

sink 必须先持久提交并以 event_id 去重，再返回 HTTP 2xx 和如下 JSON；sha256 是收到的原始事件字节的
小写 SHA-256，同身份不同摘要必须拒绝：

```json
{"event_id":"request-id:request_finished","sha256":"received-event-body-digest","outcome":"committed"}
```

重复同摘要返回 outcome=duplicate。单独的 HTTP 成功码、错身份或错摘要不算确认。
先为结束事实预留容量并确认 request_started，再允许业务副作用；开始事件没有可信收据时返回 503，不执行上游。
结束事件按实际正文 EOF/error/cancel 产生一次并重投到确认；在途、排队和投递中事件共享 max_pending 硬门。
结束 sink 长期故障会耗尽准入容量，不能静默丢失再继续无限接流量。停机有界 flush，超时仍保留远端开始证据。

request_finished 包含最终 HTTP status、outcome、latency_us、请求/响应实际观测帧字节和 extended。
completed 表示 HTTP body 已交付，不代表业务成功；failed/cancelled/not_dispatched 区分正文错误、取消与未分派。
响应字节是最终变换/压缩后经网关 body 交付的字节，不证明对端应用已消费；请求字节不从 Content-Length 推算。
GraphQL cost 来自验证后的字段复杂度/batch 累计；Chat token 来自解析通过的 provider usage，配置模型单价计算
微美元费用。没有 usage、原生透传无法解析或价格未知时为 null，不把预留额度/估算 token 当成实际结算。

**结束队列是有界内存重投，不是本地 WAL。** 进程崩溃可能只留下开始事件，sink 必须以 incomplete/待核对展示，
不能据此伪造成功、完整字节、零费用或 exactly-once 业务执行。开始确认丢失时网关不分派，结束可能是
not_dispatched；没有对应开始的孤立结束事实不得单独作为收费请求。sink 按关联身份合并事件并按业务需要核对，
request/error/latency/bytes 和扩展成本可按全部归因维度聚合，不以重投次数累计用量。

门户 `GET /api/developer/account/usage` 与 `/usage/export?cursor=...` 调用固定
`POST {endpoint}query`：`{"applications":["authorized-id"],"kind":"summary","limit":512,"cursor":null}`，
明细 kind=events。sink 返回 `{"rows":[...],"next_cursor":null}`；每行必须有授权 application，数值字段仅无符号数或
null。允许字段包括 requests/errors/latency_us/request_bytes/response_bytes/graphql_cost/ai_input_tokens/
ai_output_tokens/ai_cost_microusd/incomplete；明细另含 event_id/product/version/operation/consumer/plan/outcome。
网关最多并发 8 次查询、2MiB 响应、512 行，未知字段不向门户透出；越权 application 使整次响应失败。
游标最多 1024 个 ASCII 字母、数字、`-_.`，不允许任意 filter 或 tenant 查询参数。viewer/developer 仅汇总，owner 可导出；
空授权集不外呼，不解释为全局检索。查询返回后复验配置代际，撤权不能由在途查询绕过。

`gw_meter_admitted_total/rejected_total/retry_total` 和 `gw_meter_pending` 只描述当前进程传输健康，不是持久账本，
不把应用/consumer/token 做指标标签。页面展示配置套餐，不伪造实时剩余额度；限额后端仍是准入权威。
网关不内置税务、支付、发票、汇率或地区商业规则。

## 工作区、委派管理与公平容量

`ownership.enabled` 默认关闭。启用后，归属由完整配置确定，客户端的 workspace、tenant、environment
header 不能选择归属；这些内部头进入业务管线前会被清除。完整 owner 是 workspace、tenant、environment
三元组，同名工作区更换租户后不能复用旧身份、缓存、审批或审计读面。

对象身份使用 `种类:稳定标识`，例如 `proxy:edge`、`route:edge/orders`、`service:orders`、
`consumer:mobile`。`name` 仅是工作区内名称，不改变稳定引用；同名 consumer 别名按路由归属解析。
路由继承入口、证书和扩展继承所属配置对象、应用继承团队、应用生成的 consumer 和凭据继承应用。
未分配的根对象属于 `platform`。跨域引用需要 `grants` 中的精确目标，不接受通配授权。
平台引用租户对象也必须有 grant。候选在外部构建前及动态物化后均验证引用图、对象配额和归属；
删除、转移或撤销 grant 使任何引用失效时，整份候选拒绝，继续提供上一份有效配置。

启用必须同时开启管理认证、RBAC 和持久审计。以下是单工作区配置示例；凭据从部署环境读取，
浏览器管理需把实际管理站点的完整 Origin 加入白名单，远程访问使用 HTTPS：

```yaml
schema_version: 1
server:
  listen: 127.0.0.1:8080
admin:
  listen: 127.0.0.1:9000
  auth:
    enabled: true
    allowed_origins: ["http://127.0.0.1:9000"]
  rbac:
    enabled: true
    principals:
      - {id: alice, bearer_token: "env://NAWAY_ALICE_TOKEN", roles: [workspace]}
      - {id: reviewer, bearer_token: "env://NAWAY_REVIEWER_TOKEN", roles: [workspace]}
  approval:
    enabled: true
    max_pending: 32
    resources: []
  audit:
    enabled: true
    file: audit.jsonl
    signing_key: "env://NAWAY_AUDIT_KEY"
    allow_local_only: true
ownership:
  enabled: true
  workspaces:
    orders:
      tenant: commerce
      environment: production
      labels: {department: sales}
      members: {alice: administrator, reviewer: administrator}
      quota:
        max_objects: 256
        max_inflight: 256
        max_pending_changes: 8
        max_state_entries: 4096
  objects:
    "proxy:default": {workspace: orders, labels: {exposure: private}}
  grants:
    - {source_workspace: orders, target: "service:shared-api"}
upstreams:
  services:
    shared-api:
      instances: [{uri: "http://127.0.0.1:3000"}]
routes:
  - id: orders
    uri: lb://shared-api
    predicates: ["Path=/orders/"]
```

管理主体的 `roles: [workspace]` 只获得工作区入口，不能同时带平台角色或 grant。成员角色中，
viewer 只读，operator 可提交，administrator 可复核、回滚和委派已存在的认证主体。启用审批时每域
至少两名管理员。平台管理员也必须成为目标工作区成员，才能使用该域入口。

管理端口的 `/workspaces` 提供独立 Console；Bearer 凭据仅保留在当前页面内存中，退出或切换身份
清空旧视图与草稿。`GET /api/workspaces` 只列当前主体的域；各域的 `/objects`、`/changes`、`/rollouts`、
`/audit`、`/export`、`/watch` 均位于 `/api/workspaces/{workspace}` 下。列表和导出用 `offset`/`limit`
分页，单页最多 128 条；同一次分页可用 `If-Match` 固定 ETag。每域最多两个管理操作和一个 10 秒
观察请求，watch 返回前复验权限。跨域读取返回 404，返回值标记 private/no-store；平台指标与全局
审计不向工作区凭据开放。

`/workspaces` 的对象视图默认读取集群范围，支持路由、HTTP入口、逻辑上游的搜索、分页和逐节点
分布。平台在 `ownership.workspaces.<id>.cluster_nodes` 声明最多128个唯一稳定节点身份，例如
`cluster_nodes: [gateway-a, gateway-b]`；节点身份应与管理通道配置一致。空列表表示尚未配置集群
读取范围，不会自动使用本机数据代替集群。此列表不能通过工作区委派操作扩大，节点地址也不能由
浏览器指定。节点需要在管理通道报告完整对象目录，未知或未部署成员仍保留在本工作区覆盖分母中。

`GET /api/workspaces/{workspace}/cluster/catalog` 使用工作区成员权限，支持
`domain=routes|listeners|upstreams`、`search`、`offset`、`limit`；每页最多100项，后续页要求
`If-Match`。它只返回本工作区对象、授权节点身份和可读状态，不返回全平台配置指纹、管理地址或
其他工作区对象。读取证明绑定工作区、租户、环境、成员角色及节点范围，与对象目录同时发布。
对象在不同节点上合法缺失不会改变读取证明；权限不一致、旧协议、目录未完成、容量不足和失联均
计为未知，只有完整且权限相符的节点才能计为对象缺失。旧发送端仍能提供平台目录，但不被视为支持
工作区集群目录。远端权限变更受上报新鲜期约束；本机撤权在响应交付前复验。

集群目录每两秒刷新，不保存历史；页面隐藏、退出或切换工作区时取消读取并清空旧对象。集群分页
ETag与配置写入基线分开维护，前者不可用于提交候选。配置导出、审批及审计仍保留各自接口合同，
对象目录不会将多个管理进程的本地操作记录解释为持久共享协调状态。

`POST /api/workspaces/{workspace}/changes` 接受不超过 64 KiB 的声明式动作：patch、delete、
create_route、delegate、rollback。字段按对象类型白名单校验，不接受任意 JSON Pointer、文件路径、
环境变量展开或平台 bootstrap 变更。必须带当前目录 ETag；提交后的 `candidate_etag` 绑定完整 owner
和候选摘要，复核使用 `/changes/{change_id}/approve` 或 `/reject`。示例：

```json
{"action":"patch","object":"route:default/orders","fields":{"request_timeout_ms":5000}}
```

申请者不能自批，旧平台审批入口不能消费工作区记录。成员、引用授权或基线变化会使旧候选失效。
回滚只恢复指定历史版本中同归属对象的可委派字段，不恢复旧成员、跨域授权、凭据或其它域配置。
门户应用申请共用这条审批链，不能通过团队 transfer 实现跨工作区所有权迁移。
Nacos 灰度、晋级与拒绝回滚保留相同 owner/摘要，工作区读面不输出节点地址、dataId 和外部错误正文。
每域独立保留四条发布记录，活动灰度不被驱逐，终态释放完整候选正文。
节点注册 `gateway.bundle_sha256` 证明已应用的原始三文档；只有健康节点的版本、依赖指纹和目标摘要
均满足发布判据才算收敛。灰度撤回用 CAS 将覆盖层改为带 rollout 身份的释放标记，节点据此读取
全局 bundle；不使用读取后无条件删除。释放标记可被下一次灰度 CAS 复用，外部换主时拒绝清理。
启用灰度前，运维必须在没有在线发布者时为每个节点预建 `<bundle_data_id>.canary.<node_id>`，内容为
`{"schema_version":1,"state":"released","rollout_id":"initial"}`。Nacos 没有原子 create-only 创建接口，
因此在线控制器拒绝缺席槽，不用先读后写冒充初始化互斥。后续发布和撤回均使用已有槽的 MD5 CAS。

`usage_plans.policies` 按 platform → workspace → product/service → route → consumer group → consumer
固定顺序组合。认证只在静态入口物化；产品允许集取交集，deny 优先，额度逐项同时成立。
下层同名上下文头覆盖上层；`inherit_headers: false` 只重建上下文头，不能关闭认证、deny 或额度。
同层相交主体产生冲突覆盖时拒绝构建，不依赖 map 遍历顺序。

`max_inflight` 覆盖认证外呼、完整 HTTP 正文、升级隧道以及 TCP/UDP 会话，跨 reload 不重置。
TCP 在派生任务与握手前预留，UDP 在创建会话和上游之前预留；结束、取消或空闲到期才归还。
`max_state_entries` 约束按请求生成的驻留条目，包括限额桶、重放事实、缓存及 flight、外部鉴权、
熔断窗口、托管会话和插件共享表。缓存满时跳过新缓存，鉴权和重放不能借 fail-open 无界建表；
本地缓存到期可被同域其它状态申请触发回收，借给在途请求的值仍占原名额。
本地熔断每资源最多 17 个聚合桶，不逐请求保存事件；窗口边界最多保守多计一个桶宽。

本地池跨快照复用，进程最多 400 万个已预留工作区状态；每个 Redis namespace/backend 独立计数，
同一 Redis 域内限额、重放、HTTP/LLM/OPA 缓存与熔断共享原子容量索引和 TTL。
这不是跨全部后端的单一分布式计数，也不是物理字节预算：正文、向量、协议队列和单条编码另受各功能
上限约束。LLM 的有界候选目录计为一个条目。File/Nacos 上的 OPA 集合采用同域容量和按值到期拒绝，
过期记录惰性删除，不承诺文档后端自动 TTL 清理。

共享 service 的连接池、实例健康、被动摘除和负载反馈仍属于该 service；授权共享 service 也共享其
基础设施状态。需要独立健康策略或物理资源故障域时应配置独立 service 或部署，工作区不是进程沙箱。
进程级发现、审计出口、遥测出口、门户身份入口等保留平台归属，不能通过委派 API 修改。
平台指标只输出低基数聚合，不携带租户请求身份。每个完整 owner 独立保留最多
`min(admin.audit.history_limit, 128)` 条审计查询记录，完整历史以已验证的持久链或外部 sink 为准。
单域高频写入不能挤掉另一域当前的尾窗；新建归属目录最多保留 256 个域，超过后退休最久未写入的旧域。

## 三信号遥测出口

`telemetry-otlp` 制品可把 traces、metrics、请求收尾 logs 通过 OTLP/HTTP protobuf 或 OTLP/gRPC
送到 Collector。三个信号独占队列、批次、连接、重试和熔断；数据面只做有限编码与非阻塞投递。
Collector 失联、超时或队列满不会等待业务请求，丢弃原因可从 `gw_telemetry_export_total` 观察。
出口不是持久消息队列，不保证零丢失；网络重试可能产生重复，部分接收响应不重试。

```yaml
telemetry:
  enabled: true
  endpoint: http://127.0.0.1:4318
  service_name: naway
  sample_ratio: 0.1
  multi_signal:
    protocol: http_protobuf  # gRPC 使用 grpc 和对应的根地址，例如 http://127.0.0.1:4317
    metrics_interval_ms: 10000
    traces:
      enabled: true
      queue_size: 1024
      batch_size: 128
      max_record_bytes: 16384
      max_batch_bytes: 1048576
      batch_delay_ms: 1000
      deadline_ms: 5000
      retry_limit: 2
      retry_base_ms: 100
      circuit_failures: 5
      circuit_open_ms: 10000
    metrics: {}  # 各自采用同样的默认预算，不与 traces 借用容量
    logs: {}
```

每个信号可用 `endpoint` 覆盖顶层地址。HTTP 根地址自动加 `/v1/traces`、`/v1/metrics`、`/v1/logs`；
显式路径直接使用。gRPC 只接受根地址。地址不接受用户信息、query 或 fragment；HTTPS 执行证书校验，
HTTP 不跟随重定向。配置不会被 `OTEL_*` 环境变量替换。

每信号最多 16,384 条排队记录、64 MiB 最坏记录载荷，单条最多 256 KiB、批次最多 4 MiB。
同一批的首发和所有重试共享不超过 60 秒的绝对期限；指数退避带抖动，并尊重服务端等待提示。
只有协议允许的瞬时错误重试；gRPC `ResourceExhausted` 需要有效 `RetryInfo`。
每个信号熔断后只由其唯一 worker 探测恢复，不影响另两个出口。

热更先准备新代，发布后停止旧代指标采集；在途请求的 trace/log 保留原代并有界排空。进程同时最多
保留四个准备、活动或排空代；超过容量会拒绝候选，当前配置继续运行。停机先关闭生产入口，再尽力
排空，超过期限的记录丢弃。`gw_telemetry_export_total{signal,outcome}` 的进程累计值不因热换重置，
其中 metrics 数量按 data point 计，`retry` 按额外导出尝试计；`collector_warning` 表示部分接收响应
带有非空警告，警告正文不进入日志。拒收数即使为零，也不因此忽略警告或重试整批。

结构化指标目录复用 `nametrics-core`。核心请求/响应、上游尝试与重试、限额/熔断拒绝、L4 字节、
请求时延、WAF、配置代、上游服务数和出口诊断读取原有原子事实，不通过反解析 Prometheus 文本生成。
指标只使用固定标签；trace id、用户和 URL 原值不是标签。请求时延从进入 HTTP 处理到最终响应头，
不包含随后实体流传输；其 OTLP histogram 可携带固定十三槽的 sampled trace exemplar。

治理目录还包含 `gw_admission_events_total{policy,outcome}`（retry budget 许可/拒绝、自适应并发的
许可/忙/排队和上限变化）、`gw_ext_proc_exchange_total{direction,outcome}`（相位发送/接收，包括取消）、
`gw_rollout_transitions_total{phase}`（本节点已提交的发布状态迁移）和
`gw_ai_operations_summary_total{protocol,outcome}`（从已有 AI/MCP/A2A 操作事实汇总）。这些计数不包含
服务名、消费者或操作内容；准入忙表示一次尝试未取得名额，不等于最终 HTTP 拒绝。控制台只消费
`/api/dashboard` 的 `telemetry.schema_version: 1` 固定目录，关闭新模式后隐藏该面板。

三信号模式的 trace 只导出固定名称和明确的 method、scheme、route、status、attempts 等属性，不导出
原始 URL、请求头、任意 span event/link 或错误正文。logs 是请求完成的固定结构记录，包含标准
trace/span 关联和 route/status/attempts，不是任意进程日志镜像，也不读取 body。
`telemetry.enabled` 与 `multi_signal.traces.enabled` 共同决定 trace 记录，metrics/logs 有独立开关。
未配置 `multi_signal` 时保留原有 OTLP/HTTP traces、W3C/B3 传播及 Prometheus 输出，不创建新出口。

### 分层采样

`multi_signal.sampling` 以顶层 `sample_ratio` 为 head 默认值，按 platform → listener → workspace →
product → route 的固定顺序覆盖。规则数组顺序不影响结果；同一 scope 重复、未知对象或非法概率拒绝
整个候选。listener 的 `proxy` 是物理入口 ID；workspace 取已验证的路由 owner，product/version 取
门户管理的静态 operation binding，不接受客户端头或自报 tenant 改变采样策略。

```yaml
sampling:
  remote_parent: inherit
  error_ratio: 0.1
  slow_ms: 1000
  slow_ratio: 0.5
  rules:
    - scope: { type: listener, proxy: default }
      head_ratio: 0.1
    - scope: { type: workspace, workspace: blue }
      head_ratio: 0.2
    - scope: { type: product, product: catalog, version: stable }
      head_ratio: 0.5
    - scope: { type: route, proxy: default, route: orders }
      head_ratio: 1.0
```

规则只覆盖显式字段；`slow_ms: 0` 禁用慢请求提升。`inherit` 尊重可信远端父的 sampled 位，未采样父
也禁止错误/慢请求提升。显式 `resample` 保留 trace lineage，但由本地策略重新决定采样。无可信父时
按 trace ID 确定性 head 采样。trace/span ID 在选路前冻结，选路后不会改变。

未 head 采样的请求只有在 5xx 或响应头耗时达到门槛时，才按对应概率补一条 server 摘要并标注
`gateway.sampling.promotion`；不会补造之前未记录的子 span，也不会缓存完整 trace。取消请求不冒充
5xx；完整 tail sampling 应由 Collector 实施。未命中路由使用入口策略，路由覆盖只在实际匹配后生效。

### 审批式限时诊断

`telemetry.multi_signal.traffic_tap: true` 开放本机诊断 API，不向 Collector 发送样本。要求完整管理
平面、管理认证、RBAC、持久审计同时启用，且至少两个主体拥有 `diagnostics: write`。`admin` 自动获权，
`viewer`、`operator` 和 `security-sre` 不自动获得诊断读写权限；可使用显式 grant 委派 `read` 或 `write`。
`read` 包括列表与下载，`write` 包括申请、复核与停止；复核者必须不同于申请者。

先向 `POST /api/diagnostics` 提交精确范围与预算，成功返回 `id`、`digest` 和冻结配置代：

```json
{
  "proxy": "default",
  "route": "orders",
  "consumer": "operations",
  "ttl_seconds": 60,
  "max_samples": 16,
  "max_record_bytes": 4096,
  "max_total_bytes": 65536,
  "max_downloads": 1
}
```

复核者向 `/api/diagnostics/{id}/approve` 发送 POST，并用 `If-Match` 携带原摘要。批准前不采集；
`consumer` 只匹配认证后冻结身份，省略则不限已命中的消费者。范围绑定物理入口和初始命中路由，
不能使用通配符或客户端自报身份。`GET /api/diagnostics` 只列低敏元信息；下载与停止分别是
`POST /api/diagnostics/{id}/download` 和 `POST /api/diagnostics/{id}/stop`。

默认样本只有 method、响应 status 和到响应头的 elapsed_us，不复制 URL、请求头或响应头。
正文必须在申请时显式添加如下策略，由同一摘要和复核覆盖；所有允许字段的值也只输出 `[REDACTED]`：

```json
{
  "body": {
    "mask": "redact",
    "max_inspect_bytes": 16384,
    "request_fields": ["operation"],
    "response_fields": ["result"]
  }
}
```

只识别未压缩 JSON 顶层对象的字段是否出现，不保存原始 key/value、不递归导出嵌套内容、不解压正文。
每方向最多 16 个明确字段，名称最多 64 个 ASCII 字母、数字或下划线；认证、cookie、secret、token、
password、credential、private、key、certificate、session 类名称禁止。TLS 密钥、认证头、cookie 与
secret 原文永不采集。每方向最多检查 64 KiB、嵌套最多 16 层；格式不支持、畸形、截断或超限时
只报告状态，不保留部分字段。观察逐帧借用数据，业务字节、trailer 和背压保持不变；取消不继续预读。

每进程最多 8 个待批或活动会话，待批 60 秒到期；活动 TTL 为 1–300 秒，最多 128 条、单条
256–4096 字节、每会话累计最多 256 KiB、下载最多 3 次。正文采集先预约单条最坏字节与名额，
同时最多 64 个在途观察器；同一路由的重叠消费者正文范围不能同时批准。争用或预算不足直接跳过，
不等待业务流。停止、过期、关闭功能或任何配置换代都撤销审批并清除目录样本，过期清理周期为 250 ms。

下载先持久审计、原子扣次数，再完成审计与 TTL/配置复验后交付；传输失败不补回次数。进程最多
8 份在途下载，名额随交付字节存活，不被停止会话或重载重置。响应带 `Cache-Control: no-store`；
已交付到客户端的数据无法撤回，接收方仍需按自身权限和留存策略管理。

## 上游分层地域调度

`upstreams.services.<name>.locality` 在同一实例目录上执行地域分层。未设置 `local_region`
时保持单层 `local_zone` / `failover_zones` 合同；设置后使用显式 `targets` 描述允许的
region/zone/subzone，不再混用单层 zone 权重和降级列表。

```yaml
upstreams:
  services:
    backend:
      lb_policy: p2c
      locality:
        local_region: east
        local_zone: zone-a
        local_subzone: rack-a
        mode: failover
        allow_unlisted: false
        degraded_weight_percent: 20
        targets:
          - region: east
            zone: zone-a
            subzone: rack-a
          - region: east
            zone: zone-a
            subzone: rack-b
          - region: east
            zone: zone-b
          - region: west
            zone: zone-a
            priority: 1
            weight: 2
            degraded: true
      instances:
        - uri: http://10.0.1.10:8080
          region: east
          zone: zone-a
          subzone: rack-a
        - uri: http://10.0.2.10:8080
          region: west
          zone: zone-a
```

选择先排除不健康、强制下线和本次重试已用实例，再区分 primary / backup，最后执行 locality。
`priority` 越小越优先，范围 0–65535；**显式 priority 先于地理距离**。在同一 priority 内，
`failover` 依次选择本 subzone、本 zone、同 region 的其它 zone、其它 region。
`weighted` 不按距离细分同一 priority，而按目标权重 × 实例有效权重分配；多个健康实例自然
提供多份容量。`degraded: true` 只降低份额，不伪造健康状态，也不自动改变 priority。
需要让劣化地域进入后备层时，应明确提高其 priority。

轮询、随机、P2C、least-connection、ring-hash 和 Maglev 使用同一编译权重；least-connection
按容量比较负载，同分候选按权重分散。`first` 保持取首个允许实例的语义。
组合份额以宽整数累计，P2C 与 least-connection 以交叉乘法比较，不因大容量截断负载差异。
轮询先约去共同倍率；归一周期不超过 65536 时逐槽轮转，更大周期使用位反转分数游标，
在短请求窗口中分散大互质份额，不等待完整权重周期才访问后面的实例。
哈希表采用实例配置基础权重以保持映射稳定；slow-start 只影响逐次计算份额的非哈希选择。
会话亲和和一致性哈希都不能越过当前健康候选层。TCP/UDP 也使用相同目录和拓扑门禁；
L4 的 `hash_on: remote_addr` 使用传输层确认的来源 IP，不从隧道里的 HTTP 头取值。
HTTP header、cookie 或 consumer 等仅在有相应已解析请求上下文时生成哈希提示，缺失提示
遵循原有加权轮询回落，不把不透明 L4 数据猜测成 HTTP。

静态实例使用 `region`、`zone`、`subzone`；发现元数据还接受
`topology.kubernetes.io/region`、`topology.kubernetes.io/zone` 和 `sub_zone`。
同一维度的别名必须一致。标签只允许不超过 128 bytes 的 ASCII 字母、数字、点、下划线和横线；
客户端位置头不具有拓扑权威。不同 region 的同名 zone 不相等。

最多声明 256 个分层目标，权重范围 1–10000。目标省略 subzone 表示整个 region/zone，
不能再为该 zone 声明细分 subzone；重复或重叠目标在发布前拒绝。缺失或未列拓扑默认不能承接
流量，只有显式 `allow_unlisted: true` 才能在所有声明层无可用容量之后兜底。
无允许容量时就绪检查与真实选路一致地拒绝，不偷偷跨地域。配置热更和注册中心元数据更新
原子切换不可变视图；非法候选保留上一份完整有效视图。管理服务读面提供拓扑模型、实例位置、
等级和权重倍率，不将高基数地域值扩散到指标标签。

## 上游负载反馈与 ORCA

上游服务的 `load_feedback` 为 P2C / least-connection 选择提供延迟 EWMA 或后端利用率。
反馈只是同一健康候选层内的调度参考，不具有摘除实例的权力。缺失、非法、样本不足或超过
`freshness_ms` 的报告会退回基础算法；新鲜样本占比低于 `panic_threshold_bp` 时整服务
停止按反馈比较，避免把流量集中到少数有样本的实例。

默认制品支持真实响应 head/trailer 中的 ORCA：`endpoint-load-metrics` 接受 `TEXT`、
`JSON`、`BIN` 格式，`endpoint-load-metrics-bin` 接受标准 Base64 protobuf。兼容无前缀
JSON 与冒号文本；JSON 只提取 CPU、应用与内存利用率，不作为通用 OrcaLoadReport 解码 API。
应用利用率优先于 CPU，两者允许超过 1；内存利用率必须在 0 到 1。重复权威标量、歧义多值、
非有限值和坏 wire 内容拒绝。同一请求只采纳一次有效报告，不读取下游伪造的反馈头。
反馈读取发生在上游响应改写之前，不聚合、复制或重新编码业务 body，原始 trailers 继续透传。

启用 `upstream-orca` feature 后，可配置标准
`/xds.service.orca.v3.OpenRcaService/StreamCoreMetrics` 带外订阅。它复用业务实例目录、
HTTP/2 客户端、连接预算与 TLS 身份，在没有业务请求时仍可取得报告；L7 和 L4 引用同一服务时
共享同代反馈，L4 不解析不透明业务字节生成报告。不发现额外地址，也不跟随
报告指定的重定向。以下为服务配置片段：

```yaml
upstreams:
  services:
    backend:
      protocol: h2
      lb_policy: p2c
      instances:
        - uri: https://backend.internal:8443
      tls:
        server_name: backend.internal
        ca_file: /etc/naway/backend-ca.pem
        client_cert_file: /etc/naway/client.pem
        client_key_file: /etc/naway/client.key
      load_feedback:
        mode: utilization
        freshness_ms: 5000
        min_samples: 3
        smoothing_bp: 2000
        panic_threshold_bp: 5000
        out_of_band:
          report_interval_ms: 1000
          connect_timeout_ms: 3000
          idle_timeout_ms: 10000
          reconnect_backoff_ms: 500
          max_report_bytes: 4096
          allow_plaintext: false
```

带外仅允许 `h2` / `h2c`；TLS 必须验证服务端身份，禁止 `insecure_skip_verify`。
受控明文网络必须显式配置 `allow_plaintext: true`。连接期限为 100–60000 ms，报告间隔
为 100–60000 ms，完整报告空闲期限必须大于间隔且不超过 300000 ms。逐字节发送不能延长
完整报告期限。报告不超过 4096 bytes，gRPC 压缩报告不接受；响应元数据编码值同样受
4096 bytes 上限约束。每间隔最多容忍四份合并报告，持续超频则关闭并退避重连，退避最长一分钟。

全进程最多 256 个带外订阅，并受启用的平台工作区任务预算约束。目录超限时停止整批带外反馈，
不会只订阅任意前几个实例；已有样本自然过期后退回基础算法。反馈状态最多 65536 项，容量不足
不新建样本，不改变健康结论。动态实例退场后由低频维护回收状态。

反馈按逻辑服务、配置版本和实例入场代际隔离：同地址重入、策略变化和热更后从空样本开始；
发现刷新中持续存在的实例保留原样本。旧请求只能更新自己持有的旧对象，不能覆盖新代；
配置换代、实例撤销、发现过期和停机都会取消旧订阅。TLS 失败仅令反馈不可用，绝不通过关闭
证书校验重试。`gw_upstream_load_reports_total` 暴露固定结果计数，
`gw_upstream_orca_subscriptions` 表示活动订阅数，不以地址或报告内容作为标签。

## 注册中心与配置中心独立开关

Naway 原生支持中心服务，但不要求每次部署都依赖中心。两个总开关分别控制服务发现与远端配置输入：

```yaml
discovery:
  enabled: false
config_source:
  enabled: false
```

双关闭时使用本地文件和静态上游，可以多节点部署；文件热更、Admin 配置管理、静态成员的内部
gRPC 通信继续可用。跨节点文件分发和共享额度需要独立配置，不会因多启动一个节点就自动一致。

| 总开关 | 关闭后的边界 |
|---|---|
| `discovery.enabled` | 不启动 Nacos/Consul/Eureka/DNS/Kubernetes 发现及 Nacos 自注册；静态上游 URI 的普通 DNS 解析不受影响 |
| `config_source.enabled` | 不启动 Nacos 配置订阅和配置 provider；本地文件、Admin、独立 Redis 共享运行态不受影响 |

xDS client、Kubernetes 路由控制器和 Docker/Nomad/ECS 工作负载来源同时涉及配置与动态实例，
需要两个总开关均开启，并启用各自后端。普通配置 provider 只需要配置总开关；注册中心关闭时
仍可统一下发静态上游。xDS server 是对已授权本地对象的输出，不受远端输入开关影响。
使用 Nacos 共享动态规则存储的 `runtime_state.store.backend: nacos` 需要配置总开关开启；
关闭时明确拒绝该组合，不把共享黑名单等事实静默降级为本地文件。

总开关关闭会屏蔽后端的 `enabled: true`，无需删除保留的连接参数；仍依赖被关闭来源的动态
服务或 Nacos 集群成员声明会拒绝构建，应改为静态实例或静态成员。关闭的中心不参与启动、
订阅、心跳、重连或 readiness；其它显式配置的业务后端、Secret、遥测和共享存储仍独立生效。

总开关是启动期参数，修改后需要重启；文件 reload、管理 dry-run/发布和远端候选均拒绝在线
切换并保留活动配置。路由、规则与静态上游的正常热更不受影响。`GET /api/config/current`
的 `centers` 返回当前总开关及重启要求，不包含中心凭据。

新生成的 bootstrap 文件显式关闭两个总开关。为保持已有配置的后端启用语义，省略总开关时
按 `true` 处理，但各后端仍默认 `false`，因此空配置不会自动连接中心。启用 Nacos 时，
分别设置 `discovery.enabled` 与 `discovery.nacos.enabled`，或
`config_source.enabled` 与 `config_source.nacos.enabled`；两组互不代替。

## 外部配置来源

`config-providers` 是独立、默认关闭的控制面能力。HTTPS、Redis、Consul KV、etcd 和 ZooKeeper 中的完整声明先转成同一中间模型，
再经过原生路由编译、工作区归属、依赖授权、预算和资源准备，最后与来源水位共同原子发布。
来源读取失败、旧版本、同版异文和非法候选不刷新最大陈旧期限；到期撤回其路由依赖。
即使本地配置文件损坏、后台撤路不能发布，数据面也会在已冻结的期限后对该路由返回 503。
独立原生路由不受影响，已开始的请求仍按原快照完成。

来源必须在本地 `providers.sources` 固定 ID、namespace、workspace、priority、传输信任和能力范围。
需要开启 `ownership`、使用原生控制面和显式 `proxies`；不能与 xDS client 同时持有配置权威。
远端不能修改来源目录、认证凭据、控制面或任意 filter。namespace 内最高 priority 获胜；同级同文
可共存，同级异文将该对象标为冲突并撤回依赖路由，不按先到者选择赢家。删除、全文省略和过期都不回退到低优先级旧对象。跨 namespace 引用必须由
本地 `scope.references` 精确批准，不能因两个来源属于同一 workspace 而自动互信。

来源声明格式如下，`revision` 和每个对象的 `generation` 都是正整数；新增语义、删除后重建和语义回滚
必须使用更大的版本。`spec: null` 是显式删除，缺少 `spec` 不是删除。物理删除整个事实源键不带可靠版本，
按失联处理；需要立即撤回全部对象时发布更大 `revision` 的空 `objects`。

```json
{
  "schema_version": 1,
  "revision": 1,
  "objects": [
    {"kind":"listener","name":"web","generation":1,"spec":{"listen":"127.0.0.1:8081"}},
    {"kind":"service","name":"backend","generation":1,"spec":{"instances":[{"uri":"http://127.0.0.1:9000","weight":1}]}},
    {"kind":"route","name":"api","generation":1,"spec":{
      "listener":{"namespace":"apps","kind":"listener","name":"web"},
      "service":{"namespace":"apps","kind":"service","name":"backend"},
      "predicates":["Path=/api/"]
    }}
  ]
}
```

`middleware.spec.templates` 只引用本地已审核的 `snippets.definitions`；来源还需在 `scope.templates`
声明允许的名称，跨 workspace 模板遵循原生 grant。listener 只使用 `scope.listeners` 的精确地址；
service 只使用 `scope.backend_origins`，或 `scope.backend_networks` 中 CIDR 与明确端口的交集。
不能通过 DNS 名称使用 CIDR 授权。route 只允许 `Path`、`PathExact`、`PathTemplate`、`Host`、`Method`
断言；不能携带认证秘密或运行时变量。所有引用都包含 namespace、kind 和 name。
依赖还未到齐的合法声明可保存为等待态：先发布已经完整验证的基础对象，业务路由只有在 listener、
service 和全部 middleware 都可用时才一起开放，避免多来源互相等待而无法启动。等待期间不保留该
声明替代前的旧路由。非法字段、错误断言或越权仍拒绝整个候选并保留上一快照；合并前独立验证
新来源，因此低优先级与冲突状态都不能掩盖非法安全声明。

```yaml
providers:
  enabled: true
  sources:
    - id: application_config
      namespace: apps
      workspace: platform
      priority: 10
      poll_interval_ms: 1000
      deadline_ms: 2000
      max_stale_ms: 15000
      max_body_bytes: 262144
      scope:
        listeners: [127.0.0.1:8081]
        backend_origins: [http://127.0.0.1:9000]
      transport:
        type: https
        endpoint: https://configuration.example/config
        security:
          bearer_token: file://provider-token
          ca_certificate: file://provider-ca.pem
          client_certificate: file://provider-client.pem
          client_private_key: file://provider-client.key
```

HTTPS 支持 JSON/YAML、Bearer、CA 与配对的客户端证书/私钥，以及只基于已发布正文的 ETag/304。
禁止自动跳转、环境代理、压缩、URL 凭据、query 和 fragment；明文只允许显式授权的 IP loopback。
秘密字段只能使用本地 `env://`、`file://`、`k8s-file://`、`vault-agent://`，不能嵌入明文或调用远程 Secret。
秘密文件轮换进入配置指纹与 watcher；权威变化撤销旧任务，恢复相同配置也不能接受早先任务的迟到响应。

Redis 来源使用下面的 `transport`，正文是一个字符串键中的同一完整 JSON/YAML 声明：

```yaml
transport:
  type: redis
  endpoint: rediss://redis.example:6379/0
  key: gateway:apps:declaration
  protocol_namespace: gateway_config
  security:
    username: gateway_reader
    password: file://redis-password
```

Redis 连接、拓扑和命令复用 `nasa::redis`。需要 Redis 7 或以上的 `EVAL_RO`；先在同一只读脚本里执行
`STRLEN` 再 `GET`，超限正文不会传回网关。读源不修改配置键。NASA 初始化会通过 `INFO cluster` 探测
拓扑，并对 `nasa:protocol:gateway_config` 执行 `SET NX` / `GET` 的兼容协议校验。
应使用独立 ACL 用户：配置键只允许 `GET`、`STRLEN`、`EVAL_RO`，另一个 ACL selector 仅允许对专用
协议标记执行 `GET`、`SET`，不要给配置键写权限。需要连接握手对应的 `PING`、`CLIENT SETINFO` 权限。
Redis Cluster 的拓扑命令和节点网络权限也必须显式提供；namespace 不与其它协议 profile 混用。
具体 selector 语法参见 [Redis ACL](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/)。

Redis TLS 校验证书与主机名，使用进程启动环境的系统信任根；可以在启动时通过 `SSL_CERT_FILE`
指定 CA 文件。此信任配置不是来源级热换字段，改变它需要重启进程。当前 NASA 接口不提供来源级
客户端证书或自定义 CA，因此 Redis 不声明 mTLS 支持。`allow_loopback_plaintext: true` 仅允许
`redis://` 的 IP loopback 入口；远程必须 `rediss://`，不支持跳过证书验证。
当前 HTTPS/Redis 是有界周期拉取，Redis 不使用 Pub/Sub；没有把无版本通知当作新配置提交。

Consul KV 来源只读取一个精确键，不递归遍历目录，不请求 agent cache 或 stale consistency：

```yaml
transport:
  type: consul_kv
  endpoint: https://consul.example:8501
  key: gateway/apps/declaration
  long_poll_ms: 1000
  security:
    bearer_token: file://consul-reader-token
    ca_certificate: file://consul-ca.pem
    client_certificate: file://consul-client.pem
    client_private_key: file://consul-client.key
```

`endpoint` 仅包含 origin，键由路径段安全组装；键段只接受 ASCII 字母、数字、`_`、`-`、`.`，
不能是空段、`.` 或 `..`。该传输将 `bearer_token` 放入敏感的 `X-Consul-Token` 头，
ACL 只需目标键的 `key:read`。客户端始终请求 `consistent`，按 `X-Consul-Index` 长轮询，
索引倒退时先清空游标再重读；这不会重置统一声明的 revision/generation，也不会给旧路由续期。
`long_poll_ms` 为 100–20000 ms，deadline 必须至少留出长轮询时长、其十六分之一及 100 ms。
Base64 envelope、精确 Key、CreateIndex/ModifyIndex 和解码后正文均受校验；缺键、ACL 过滤、
无效索引或超限只触发失败和陈旧撤回。Consul 自身 KV 值上限仍适用。

写入方独立持有写权限，以 `ModifyIndex` 作 `cas` 条件，并提升声明 revision/generation；
读取者不发起 PUT/DELETE，也不把派生路由写回 KV。服务端写冲突与声明版本回退是不同门禁，
前者不能代替后者。详见 [Consul KV API](https://developer.hashicorp.com/consul/api-docs/kv)
及 [Blocking Queries](https://developer.hashicorp.com/consul/api-docs/features/blocking)。

etcd 来源通过 v3 JSON gRPC gateway 读取精确单键，固定集群身份：

```yaml
transport:
  type: etcd
  endpoint: https://etcd.example:2379
  key: /gateway/apps/declaration
  cluster_id: "12585971608760269493"
  long_poll_ms: 1000
  security:
    bearer_token: file://etcd-reader-token
    ca_certificate: file://etcd-ca.pem
    client_certificate: file://etcd-client.pem
    client_private_key: file://etcd-client.key
```

`cluster_id` 必须是目标集群实际返回的非零 u64 十进制字符串；YAML 中须加引号，避免配置工具将大整数
转为浮点数而丢失身份精度。不同集群不能继承旧来源权威。endpoint 仅为 origin，
key 为 1–512 字节的无控制字符 UTF-8 文本，内部转换成 protobuf JSON 的 Base64。令牌以原始 token
进入敏感 `Authorization` 头，不加 `Bearer` 前缀；读取账户只需该键的 read 权限，不授予写入权限。
TLS 客户端证书用于传输认证，不把证书 CN 当作 JSON gateway 的授权身份；etcd token 仍由部署方取得、
续期并通过 SecretSource 轮换。初始化和协议字段见 [etcd JSON gateway](https://etcd.io/docs/v3.6/dev-guide/api_grpc_gateway/)。

首次执行单键 `Range`，之后从完整读取的下一 revision 发起有界 watch。watch 仅为重读提示；更新、
compaction、取消、断流或等待超时之后，都重新执行 `serializable: false` 的线性一致单键读取，
通知本身不能续期路由。集群 ID、精确键、revision/version、结果条数和 Base64/正文大小均须通过。
传输 revision 倒退时复位 watch 游标再重读，但声明 revision/generation 不随之回退。
`long_poll_ms` 为 100–20000 ms，deadline 至少比它多 500 ms；每轮 watch 最多 16 条消息，全部字节
共享有限 envelope 预算。写入方应使用 etcd Txn 的 MOD 条件，并提升声明版本；网关不执行写回。

ZooKeeper 来源读取固定持久 znode，不遍历子树，不接受临时节点：

```yaml
transport:
  type: zookeeper
  endpoint: zks://zookeeper.example:2281
  path: /gateway/apps/declaration
  long_poll_ms: 1000
  security:
    digest_auth: file://zookeeper-reader-auth
    ca_certificate: file://zookeeper-ca.pem
    client_certificate: file://zookeeper-client.pem
    client_private_key: file://zookeeper-client.key
```

`digest_auth` 文件内容为 `username:password`，账户仅需目标 znode 的 READ ACL；写入方独立持有写权限，
使用 `setData` 的 version 条件做 CAS，同时提高统一声明 revision/generation。endpoint 是单个固定 origin，
必须显式端口；`zks` 强制验证服务端名称与显式 CA，可配置成对客户端证书/私钥。明文 `zk` 只允许显式
`allow_loopback_plaintext: true` 的 IP 字面量 loopback；不能向非本地地址发送明文 digest 凭据。
path 为最多 512 字节的绝对路径，段仅接受 ASCII 字母、数字、`_`、`-`、`.`、`:`，不接受空段及 `.`/`..`。

每轮新建短会话、认证、`sync`、完整 `getData`，同一事务的重复观察会登记单次 watch 并有界等待；
提示或等待超时之后再次 `sync`/重读。会话不进入只读降级模式，失联时关闭连接，下轮重新建立会话并重读。
watch 不是增量事实源，通知本身不能延长有效期；ZooKeeper 的 sync/read 也不等同于跨客户端线性一致读取，
部署须接受其读取一致性边界，见 [ZooKeeper Programmer's Guide](https://zookeeper.apache.org/doc/r3.9.6/zookeeperProgrammers.html)。
创建/修改 zxid 和同一节点 version 不允许倒退；重建节点必须有更高创建事务，并继续满足声明版本水位。
缺节点、ACL 拒绝、过期会话、非法帧、超限正文都按最大陈旧期撤回，不隐式生成版本化删除。

`long_poll_ms` 为 100–5000 ms，deadline 至少比它多 500 ms。单轮最多 32 帧，全部接收字节最多为
两倍正文预算加 16 KiB，每帧长度在接收正文前校验；等待取消保留半帧边界，不创建无界消息队列。
短会话适用于配置更新频率，部署应同时考虑服务端会话建立开销；不提供通用 ZooKeeper 客户端、SASL、
递归订阅或自动发现 ensemble 的能力。来源凭据及 TLS 材料轮换均随本地配置重新建立权威。

### Docker 工作负载来源

Docker 来源周期读取固定 Engine API `GET /v1.51/containers/json`，不接受 Unix socket、任意 API 路径或
自动版本降级。应在 Docker 前部署仅允许该只读接口的授权代理，并使用 mTLS 或受限 Bearer；网关无需
持有宿主 Docker socket 或创建、执行、删除容器的权限。HTTPS 信任、凭据与本机显式明文边界同其它 HTTP 来源。

```yaml
transport:
  type: docker
  endpoint: https://docker-api.example.internal:2376
  address:
    type: network
    name: applications
  security:
    ca_certificate: file://provider-ca.pem
    client_certificate: file://provider-client.pem
    client_private_key: file://provider-client.key
```

`address.type: network` 必须显式给出唯一 Docker 网络名，读取其 IPv4 地址和标签端口；网关必须能直接访问
该网络。`address.type: published` 则读取标签端口对应的唯一已发布 TCP 绑定，绑定 IP 必须明确可拨号，
不接受 `0.0.0.0`、`::`、多重绑定或隐式猜测宿主地址。最终目标还必须通过本地 `scope.backend_origins`
或 `scope.backend_networks`，标签不能扩大监听、后端网络或策略权限。

只读取 `State=running` 且标签 `naway.enable=true` 的容器；其它容器不会开放路由。标签合同为：

- 必填 `naway.name`、`naway.generation`、`naway.listener`、`naway.listen`、`naway.port`、`naway.predicates`。
  name/listener 为稳定 ASCII 标识，generation 为正整数；listen 为本地授权监听地址，port 为容器内部 TCP 端口。
- `naway.predicates` 是 JSON 字符串数组，例如 `["PathExact=/api/ping"]`；仅支持外部来源已经允许的公开断言。
  `naway.server_names`、`naway.templates` 同为 JSON 数组，默认空；模板只能引用本地审核并授权的 snippet。
- `naway.scheme` 默认为 `http`，可选 `https`；`naway.protocol` 默认为 `auto`，可选 `h1`/`h2`/`h2c`；
  `naway.order` 为可选整数。未知 `naway.*` 字段拒绝，不接受任意 filter、Secret 或 owner 标签。

同名规则的最高显式 generation 组成当前服务，旧部署副本不混入新策略端点；同 generation 异文整轮拒绝，
结果不依赖 API 数组顺序。端点变化自动生成下一本地投影 revision，重复集合保持相同 revision；标签版本
和投影水位只在完整网关候选成功后提交。规则全部消失或 enable 被撤销后，重新开放需提高标签 generation，
同版本旧值不能复活。任何坏标签、越权、歧义或超限都保留最近有效声明，直到最大陈旧期撤路。

每轮最多 4096 个返回容器、1024 个启用实例、512 条规则，每规则最多 256 个端点，历史规则最多 2048 个；
响应累计使用来源正文预算，不截断目录。Docker 没有该列表的全局事务版本，因此不能证明受信 API 返回的
端点集合绝非旧快照，也不提供跨容器原子读；不以事件到达顺序冒充配置版本。进程重启或本地来源权威改变会
重建投影水位，外部部署系统仍须维护单调标签版本。GitOps 导出是来源中立 IR，可迁移至声明型来源，不是可
直接写入 Docker 的 labels 或运行时操作指令；网关永不写回工作负载事实源。

### Nomad 工作负载来源

Nomad 来源仅请求本地固定 `namespace`、`region` 和 `service` 的 `/v1/service/{service}`，使用
`consistent=true` 与 `X-Nomad-Index` 阻塞查询。只需目标 namespace 的 `read-job` ACL；不需要提交作业、
删除注册或全域管理权限。`security.bearer_token` 引用的本地秘密作为原始 `X-Nomad-Token` 发送，不加 Bearer。

```yaml
transport:
  type: nomad
  endpoint: https://nomad.example.internal:4646
  namespace: default
  region: global
  service: gateway-applications
  long_poll_ms: 1000
  security:
    bearer_token: file://provider-token
    ca_certificate: file://provider-ca.pem
    client_certificate: file://provider-client.pem
    client_private_key: file://provider-client.key
```

service block 必须使用 Nomad 原生注册（`provider="nomad"`），每条注册的 `Tags` 采用与 Docker 相同的
`naway.key=value` 合同，包括显式 `naway.enable=true`。`naway.port` 必须等于该注册的端口，Address 必须
为明确 IP，仍受本地后端能力限制；不把外部 DNS 名称或注册存在性当作后端健康证明。
重复配置键、跨 namespace/service、部分分页、非法 CreateIndex/ModifyIndex、同索引异文及索引回退拒绝。
目录项和 tags 排序不改变语义。读取完整服务集合，不使用 `choose` 抽样或截断分页来判断删除。

`long_poll_ms` 为 100–20000 ms，deadline 至少保留等待时长的 1/16 加 100 ms 余量。每轮最多 4096 注册，
每注册最多 128 tags，每 tag 最多 4096 字节，启用实例/规则/历史身份与投影版本预算同 Docker。
服务索引和标签水位随同一网关候选提交；完整读取失败不刷新有效期。恢复旧 Nomad 备份导致索引回退时，
需管理员明确更换本地来源权威，不能自动忘记已发布水位。此来源不遍历其它 service，也不读取 Consul 注册。

### ECS 工作负载来源

ECS 来源只调用固定 endpoint 的 `ListTasks` 和 `DescribeTasks(include=["TAGS"])`，固定 region、完整
cluster ARN、service 和 container。IAM 凭据仅授予所需的 ECS 只读操作，并按 AWS 支持的资源与条件键
收窄范围；本地服务筛选不能替代 IAM 权限。不会执行 RunTask、更新服务、写标签、访问实例元数据或遍历集群。

```yaml
transport:
  type: ecs
  endpoint: https://ecs.us-east-1.amazonaws.com
  region: us-east-1
  cluster_arn: arn:aws:ecs:us-east-1:123456789012:cluster/gateway-applications
  service: gateway-applications
  container: application
  credentials:
    access_key_id: file://ecs-access-key-id
    secret_access_key: file://ecs-secret-access-key
    session_token: file://ecs-session-token
```

三项凭据使用本地 SecretSource，长期凭据可省略 `session_token`；不使用隐式 AWS 凭据链，轮换材料进入
配置指纹和文件观察。请求使用 ECS SigV4；`security` 可声明 CA、mTLS 或显式 IP loopback 明文，
但不能配置 `bearer_token`。endpoint 必须是无额外路径、query、内嵌凭据的 origin，禁止自动重定向。

只接受含集群名的现代完整 task ARN，并核对 account、region、cluster、service group 与选定容器。
任务和容器都需 RUNNING，明确 UNHEALTHY 不进入后端；UNKNOWN 或未提供健康状态不等于健康证明，
实际可用性仍由网关上游健康机制裁决。仅支持容器 `networkInterfaces` 提供的唯一明确 IP（优先 IPv4，
否则 IPv6）加标签端口，不推测 bridge/host 模式映射。地址仍受本地 backend_origins/backend_networks 约束。
每任务最多 50 tags、键 128 字节、值 256 字节；使用同一 `naway.*` 标签合同，默认不暴露未显式 enable 的任务。

每次 ListTasks 最多 8 页、800 个唯一任务，DescribeTasks 每批最多 100 个；描述后重新列举并要求集合一致。
所有请求共享来源 deadline 与正文预算，任何续页循环、逐任务失败、漏项、额外任务、越域或集合变化均整轮拒绝。
任务原生 version 与标签 generation 分别验证，标签更新不要求 task version 增长；删除任务以同版重新出现会被拒绝。
每来源保存最多 4096 个历史 task ARN 水位，耗尽后停止接纳，需管理员重新建立来源权威；不自动丢弃历史保护。
任务水位随完整候选发布，不在 HTTP 读取期间提前推进。共同规则的缩零、旧版和语义回滚边界同 Docker。

ECS 是最终一致 API；两轮列举只能发现可见集合变化，不能提供原子快照或证明端点集合不是旧内容。
不能以本地投影 revision 冒充 AWS 事务版本。导出只含来源中立 IR，不包含 AWS 凭据、任务状态或写云操作。
操作合同见 [ListTasks](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ListTasks.html) 与
[DescribeTasks](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTasks.html)。

### 共同运行预算

每进程最多 32 来源、4 个并发读取、每源最多 4 MiB 正文和 4096 对象；合并目录最多 8192 个历史身份、
16 MiB 声明。来源显式设置轮询 100–60000 ms、deadline 100–30000 ms、正文 1024–4194304 字节，
最大陈旧期为 100–3600000 ms 且至少为轮询加 deadline 再加 100 ms。失败指数退避最高 60 秒，
不延长租期。原生 reload、管理 dry-run 和候选审批保留已提交来源视图；远程 Nacos 配置不能更换来源权威。
来源每次成功确认仍执行完整构建，部署时应按配置规模选择轮询周期；这不是高频业务状态订阅总线。

### 来源状态、候选与 GitOps

控制节点提供 `GET /api/providers` 及 `GET /api/providers/{id}/status`。全平台配置读权限可查看全部来源，
工作区成员只能看自己的来源；未授权名称返回 404。目录不返回 endpoint、凭据引用、模板正文或原始错误。
`phase` 区分 warming/current/degraded/stale，revision、证据年龄、最近固定结果和连续失败数辅助定位漂移；
失败观测只更新诊断，不刷新路由权威。全平台目录附合并语义摘要，工作区目录不包含全局活动序列。

`GET /api/providers/{id}/explain?offset=0&limit=64` 分页说明本命名空间对象的选中来源、generation、
active/tombstone/expired/conflict、是否已编译及是否等待依赖。每页最多 128 项，后续页需带首轮响应的
`If-Match`；来源响应 ETag 绑定本地范围和已提交语义，重复成功续期不改变 ETag。

工作区写者或具有平台配置 dry-run 权限的主体，可用 `POST /api/providers/{id}/dry-run` 或 `/diff`，
提交 `application/json` 或 `application/yaml` 的单来源完整声明，必须带 `If-Match`。两者均运行同一完整
网关构建器，返回稳定身份的语义 added/removed/changed；仅改变 revision/generation 不算业务差异。
候选不会发布、刷新已提交期限或写回事实源。陈旧条件、撤权、非法权限或任何完整构建失败均拒绝；
输入、权限与远端错误不会原样回显。正文收集最多五秒、沿用该来源正文上限。

`GET /api/providers/{id}/export` 同样要求 `If-Match`，返回 source/namespace/owner/priority 与可重放的
`declaration`，不导出连接配置、秘密、展开后的模板或运行时派生路由。为了在新目录保留省略删除语义，
导出将历史省略转成显式 tombstone，提升相应 generation，并把 declaration revision 提高一；这只是候选，
不会占用或提交事实源版本。独立写入方应复验当前事实源、执行服务端 CAS，并再提交 `declaration`；
若期间事实已推进，必须重新导出或提高相应版本。未观察来源、版本耗尽或补全 tombstone 后超出对象预算时
导出失败，不截断删除历史。过期来源导出的是最近已提交期望状态，不是其仍可服务的证明。

导出与候选操作先取得审计确认。所有响应私有且禁止缓存；全进程最多八个在途管理操作、每工作区最多两个，
名额覆盖构建和响应正文生命周期，取消请求不提前释放仍运行的构建名额。指标
`gw_configuration_provider_observations_total{outcome="published|rejected|unavailable"}` 使用固定三种结果，
Prometheus 与 OTLP 复用 `nametrics-core` 的同一累计事实，不把来源、租户、URL 或错误字符串作为标签。

## 认证后的多层路由

`route.layer` 将公开根入口、公共策略层与终端叶子连接成有界单父图。根先匹配规范化的
path、Host、method；父层完成本地认证、head WAF 与公共限额后，子层才使用已验证身份、
claim、风险或只写一次的受信变量选路。没有 `layer` 的路由保持原有单层行为。

```yaml
routes:
  - id: account-entry
    predicates: [PathElementPrefix=/account]
    filters:
      - jwt_auth secret=file://secrets/account-jwt.key identity_headers=sub:X-Verified-Subject
      - Cors allow_origin=https://console.example.com
      - limit_req key=route rate=1000r/s
    waf:
      mode: monitor
      inspect_body: false
    layer:
      branch: true
      context:
        tenant: {type: claim, name: tenant}
  - id: operations
    layer:
      parent_ref: account-entry
      branch: true
      matches:
        - {type: claim, name: role, equals: operator}
        - {type: variable, name: tenant, equals: west}
  - id: reviewed
    uri: http://127.0.0.1:9001
    layer:
      parent_ref: operations
      matches: [{type: risk, equals: matched}]
  - id: ordinary
    uri: http://127.0.0.1:9000
    layer:
      parent_ref: operations
      matches: [{type: risk, equals: clear}]
```

只有叶子绑定一种终端后端；`branch: true` 不设置 `uri`。分支允许原生访问控制、本地
Basic/API-Key/JWT、CORS、`limit_req`、`limit_conn` 和不读取正文的 WAF。远端 JWKS、
外部鉴权、重写、业务外呼、缓存、计费、镜像、返回与正文处理不能放在分支上。公共策略
仅在实际选中的路径执行一次，失败后不尝试其它兄弟；根的 CORS 最终覆盖后端同名输出。
全局/工作区作用域策略仍逐层检查授权，同请求同工作区的同一公共额度只扣一次。

`matches` 为 AND 条件，支持 `authenticated`、`consumer`、字符串 `claim`、数组成员
`claim_contains`、`risk` 和 `variable`。`context` 只接受固定 `literal` 或已验证字符串
`claim`，不能读取客户端身份头。风险为 `not_evaluated`、`clear`、`matched`；monitor 命中
成为 `matched`，后代不能降级；enforce 命中直接 403。父身份冻结后，子层不能再次认证，
不能覆盖身份头，也不能启用公共响应缓存。当前层级路径不接受任意请求 mutation 插件、
OPA、internal reroute、early data 或升级隧道；普通 HTTP 正文与响应仍由叶子原生管线处理。

同一个 proxy 最多 1024 个层级节点，深度 8，每父 64 个子节点；单节点最多 8 条公开断言、
16 个受信条件、16 个变量声明，整条链最多 32 个变量，值最多 256 字节。层级公开断言限定为
字面量 Path/PathExact/PathElementPrefix、Host 和 Method，不接受 regex/glob/header/query。
单个 `parent_ref` 防止菱形重复执行；环、缺失父节点、空分支、相位非法变量、矛盾条件、
同优先级重叠、完全遮蔽与重复公共 filter/snippet 均拒绝整个候选。子节点按 `order` 升序
选择，直接访问子路径不能跳过父层。未命中子节点返回 404 `no matching child route`；
父层认证、访问或配额拒绝保留对应 401/403/429/503，不回退到普通路由。

listener、TLS、trace 采样与 access-log `route_id` 归根入口；`route_chain` 和自定义格式
`${route_chain}` 保存实际访问的稳定 ID 链，不记录主体或 claim。只有叶子进入后端与计量。
跨工作区父子引用要求两个方向的显式 grant：子域引用父 route，父域开放子 route；跨域
consumer 还需单独 grant。冻结主体不能在子域重映射为同名用户，每个域的在途名额保留到
整个响应完成或取消。异步公共策略结束与终端分派前复验快照和整条来源期限，失效返回
409/503，旧候选不能继续开放新业务动作。

`POST /api/explain` 在有权限的管理会话中使用真实本地凭据推演各层及候选子节点，返回
`layers.chain`、`layers.status` 与可能的 `layers.leaf`。它不消费额度、不计费、不访问后端，
也不执行叶子或作用域授权，`authorizes_execution: false` 明确表示推演结果不是业务许可。
一次最多 8 个并发层级推演，deadline 2 秒。`gw_layered_route_selections_total` 只使用
八种深度和固定结果标签，Prometheus 与 OTLP 复用 `nametrics-core` 的同一计数源。

## 固定脚本的 CGI 上游

`fastcgi`、`uwsgi`、`scgi` 是三个独立 feature。它们将普通 HTTP 路由直接接入记录协议后端，
复用服务选择、被动健康、TCP 主动探测、并发/连接预算、请求超时、幂等重试和访问日志。
没有启用对应 feature 的制品会拒绝相关配置，不会降级成 HTTP。

```yaml
schema_version: 1
server:
  listen: 127.0.0.1:8080
upstreams:
  services:
    php:
      protocol: fastcgi
      instances:
        - uri: http://127.0.0.1:9000
      health_check:
        type: tcp
        interval_ms: 1000
        timeout_ms: 500
routes:
  - id: application
    uri: lb://php
    predicates: ["Path=/application"]
    cgi:
      protocol: fastcgi
      script_root: /srv/app
      script_filename: /srv/app/index.php
      script_name: /index.php
      server_name: application.example
      server_port: 443
      fastcgi_termination: php_fpm
      keep_conn: true
      max_inflight: 64
      max_params: 64
      max_param_bytes: 32768
      max_headers: 64
      max_header_bytes: 16384
      max_stderr_bytes: 65536
      idle_timeout_ms: 30000
      request_headers: [host, accept, cookie]
```

这里 `http://host:port` 仅承载受信 TCP 地址，线上字节由 `protocol` 决定，不发送 HTTP 请求。
必须使用显式端口和无路径/query 的服务地址；不支持 CGI TLS、HTTP 预热或 HTTP/gRPC 健康探测。
后端应部署在受保护网络中。uWSGI 使用 `protocol: uwsgi`，仅允许标准 WSGI modifier `0/0`；
SCGI 使用 `protocol: scgi`，响应采用 CGI `Status`/MIME 头。两者每请求关闭连接，不使用持久协议变体。

脚本根、文件名、`SCRIPT_NAME` 和 server identity 只能取配置字面量，绝不由路径、query 或头拼接。
`PATH_INFO` 使用网关规范化后的完整路径；`QUERY_STRING` 保留查询；`REMOTE_ADDR` 和 `HTTPS` 取连接权威。
仅白名单请求头映射为 `HTTP_*`，重复头、名称歧义及 `HTTP_PROXY` 被拒绝。后端文件系统和符号链接的
权限由部署者管理，网关不能远程验证其真实文件布局。脚本计划不能与路径/实体改写、镜像、其它终端、
隧道、RPC envelope、任意 Wasm/外部插件或 DLP 正文删改混用。参数超限返回 400，不影响后端被动健康；
请求体必须有可证明的精确长度，否则返回 411；网关不为判长聚合正文。

FastCGI 不支持 multiplexing。默认 `fastcgi_termination: streams` 要求输出流终止记录；PHP-FPM 使用
`php_fpm`，允许完整 `END_REQUEST` 终止输出，但仍要求合法响应头、匹配的声明长度和成功的应用/协议状态。
仅当输入长度、输出长度和结束记录全部通过后，`keep_conn` 连接才返回该脚本计划的实例/协议独立池；
取消、半包、超时和畸形响应关闭连接。空闲连接在下一次池访问时按 `idle_timeout_ms` 淘汰，快照释放时全部关闭。

每个记录最多 65535 字节、每请求最多 1048576 个记录；数据块 16 KiB、通道两块，另保留一块到完整收尾。
参数块最多 65535 字节/128 项，响应头最多 64 KiB/128 项，诊断流最多 1 MiB，路由会话最多 1024 个。
`idle_timeout_ms` 同时限制每次协议 I/O，路由总 deadline 与既有响应空闲超时仍生效。
STDERR 不进入正文，只输出独立诊断字节数；不记录原始诊断内容，以免泄漏请求秘密。
管理摘要包含协议、预算和声明指纹，不包含脚本文件路径；`gw_cgi_session_failures_total{protocol}`
记录固定三种协议的流/记录失败，Prometheus 和 OTLP 共用同一事实源。

## 有界 WebDAV 文件访问

`webdav` 是默认关闭的独立 feature。它给显式路由增加标准文件方法、资源条件与锁语义；
普通静态路由和 HTTP 代理不会因此获得写权限。协议执行位于统一认证、工作区授权、WAF、限额和
熔断之后，代理模式继续使用同一 HTTP 上游选择、物理连接池、健康检查及超时体系。

两种模式的权威不同：

- `mode: local` 使用 `serve.static.root` 提供受限文件服务器。根目录必须已存在、专用且无外部写入者，
  不能包含配置目录或审计 spool，不能与其它 DAV/普通静态路由重叠。路径按统一规则规范化，
  符号链接、普通文件硬链接、隐藏路径与特殊文件被拒绝；所有文件操作被限制在目录能力内。
- `mode: proxy` 将公开 `mount_prefix` 映射到 `upstream_prefix`。`uri` 必须是固定 HTTP origin
  或 HTTP `lb://` 服务，不得携带额外路径；`Destination` 和 `If` 的资源标签使用**实际选中的实例**
  重写，响应 `Location` 与 DAV 资源 href 还原到公开入口，锁 token 与展示 owner 原样保留。
  文件存储、HTTP 条件裁决、递归操作配额与锁一致性由上游负责，网关不为上游补造另一份文件目录或锁表。
  部署者必须选择实施这些语义和存储配额的 DAV 后端；普通 HTTP 文件接口不能因此成为完整 DAV 服务。

下面的本地单节点配置要求预先创建 `data/documents/`，并在 `secrets/` 放置独立的 JWT 与审计密钥
（审计密钥至少 32 bytes）。生产环境应配置持久外部审计 `endpoint`；`allow_local_only: true` 明确用于
允许仅本地 spool 的单机部署。管理监听保持回环，业务入口应在实际部署中配置 HTTPS。

```yaml
admin:
  listen: "127.0.0.1:9090"
  audit:
    enabled: true
    file: "audit/actions.jsonl"
    signing_key: "file://secrets/audit.key"
    fsync: true
    allow_local_only: true
routes:
  - id: documents
    predicates: ["Path=/documents"]
    filters: ["jwt_auth secret=file://secrets/dav-jwt.key"]
    serve:
      static:
        root: "data/documents"
    webdav:
      mode: local
      mount_prefix: /documents
      methods: [GET, HEAD, OPTIONS, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK]
      lock_scope: process
      exclusive_process: true
      max_file_bytes: 67108864
      max_total_bytes: 1073741824
      max_entries: 1024
      max_path_depth: 16
      max_inflight: 16
      max_xml_bytes: 65536
      max_xml_nodes: 4096
      max_xml_depth: 16
      max_multistatus_bytes: 1048576
      max_locks: 256
      max_lock_seconds: 3600
      timeout_ms: 30000
```

切换到代理模式时，移除 `serve`、`lock_scope`、`exclusive_process`，增加例如
`uri: https://files.example.net`，并将 `webdav.mode` 设为 `proxy`、`webdav.upstream_prefix` 设为 `/storage`。
方法必须显式 allowlist。代理模式不接受本地锁范围声明；共享文件集群应统一连接具备一致性锁权威的外部后端。

本地锁的范围严格是**一个进程**：目录文件描述符上的排他锁阻止本机第二个 Naway 进程同时使用同一根，
但不是跨主机共识，也不能防止不遵守文件锁的其它程序修改目录。因此不允许把此模式当成共享网络文件系统的
多写者协调器。活动锁按单调时钟过期，同进程配置换代不丢失；进程退出后锁不持久化，客户端须重新取得锁。
秘密 token 和创建锁的已认证 consumer 必须同时匹配；XML `owner` 只是展示信息，不能代替身份。

资源与失败边界：

- `PROPFIND` 必须显式 `Depth: 0` 或 `1`，缺省/`infinity` 返回 403；GET/HEAD 允许无 Depth 或 `0`。
  COPY/LOCK 允许 `0` 或 `infinity`，MOVE/DELETE 仅允许无 Depth 或 `infinity`，本地递归始终受整根条目数和深度限制。
  Destination 必须同公开 origin、同挂载根；不接受 query、危险编码、跨根或祖先/后代循环目标。
- XML 只在受限控制实体上聚合；DTD、外部/自定义实体和处理指令被拒绝，字节、节点、深度与输出转义膨胀均受限。
  LOCK 请求体最多 4 KiB。文件上传、下载保留流式背压，不聚合文件实体。
- PUT 必须给出唯一精确 `Content-Length`，否则 411；超出单文件限额为 413。局部 PUT、编码上传、扩展 MKCOL、
  静态 index/fallback 与任意实体变换不支持。本地 PUT 先写同目录隐藏暂存文件，完整长度和权威复验通过后
  刷盘并原子 rename；取消、短实体或失权不会发布暂存文件。崩溃遗留暂存文件不可见但计入配额，须离线核对后清理。
- 本地整根配额包含已有文件和暂存空间；覆盖大文件需要容纳旧内容及新暂存内容。目录按请求串行，名额一直保持到
  响应完成/取消。相同本地根或代理后端/挂载组合跨快照共用并发事实，降低上限不能清零旧请求；全进程最多
  128 个 DAV 操作，最多 1024 个活动容量域，本地根登记最多 64 个。容量不足返回 503，不无界排队。
- macOS/Linux 的文件扩展属性保存 dead properties，每个资源最多 32 项、总编码 8 KiB，一次属性集合替换；
  COPY/MOVE/PUT 保留属性。需要支持 xattr 的本地文件系统。单文件发布和属性替换有原子边界，
  **整棵目录 COPY/MOVE/DELETE 不承诺事务回滚**；207 的逐资源状态必须由客户端逐项处理。
- 所有获准执行的写操作先把 `attempt` 刷入管理 HMAC 审计链，失败即拒绝副作用；结束后记录 `completed`。
  审计只保存主体和资源摘要、配置/工作区绑定，不保存路径原文、文件内容或锁 token。
  取消或远端断连可能留下只有 attempt 的记录；5xx 或完成收据失败返回
  `X-Naway-WebDAV-Outcome: indeterminate`，表示需要核对实际资源，**不表示已经回滚**。
  写操作没有自动重试；配置换代、来源过期和取消会停止后续本地动作/上传帧，但不能撤销已经提交的本地或远端动作。
- 禁止与其它终端、镜像、hedge、共享响应缓存、URI/正文变换、可变插件和响应改写组合；协议和条件头不能被
  公共策略或授权响应改写。只读路由可自行选择认证策略；写请求必须拥有统一认证层冻结的稳定 consumer。

管理语义摘要提供模式、挂载点、方法、容量与配置指纹，不输出本地根或凭据。
`gw_webdav_operations_total{mode,outcome}` 只有八个固定系列，Prometheus/OTLP 共用 `nametrics-core` 事实；
`completed` 表示控制响应已产生，不代表 207 中每个资源都成功。请求期限和取消复用 `nabudget`，配置继续由 `naml` 加载。

## 有界媒体点播

`media-streaming` feature 为显式静态 route 提供 MP4 时间起播和 FLV 字节起播，不调用外部程序，
不解码或重编码媒体。没有 `media` 的 route 不解释这些参数；有 `media` 但没有 `start` 的请求仍是普通静态读取。
媒体目录应只由部署系统更新，使用新文件原子替换旧文件；不要原地改写正在播放的文件。

```yaml
schema_version: 1
proxies:
  - id: video
    listen: 127.0.0.1:8080
    routes:
      - id: movie
        predicates: ["Path=/movies"]
        serve:
          static:
            root: ./public
            try_files: ["${uri}"]
        media:
          format: mp4
          max_file_bytes: 8589934592
          max_metadata_bytes: 4194304
          max_parse_bytes: 8388608
          max_box_bytes: 4194304
          max_boxes: 10000
          max_depth: 16
          max_samples: 200000
          max_inflight: 2
          timeout_ms: 1000
```

`GET /movies/example.mp4?start=12.5` 从 12.5 秒开始展示。支持非分片、单一 `mdat`、最多两条轨道
（至多一条 `avc1` H.264 视频及一条 `mp4a` AAC 音频），唯一自包含 sample description、普通
`stts/stsc/stsz/stco/co64/stss`、非负 `ctts` 与单段正常速率 edit list。服务器从前一个视频同步样本解码位置
保留原始数据，通过 edit list 隐藏前卷；重建 `moov`、时长和 chunk 偏移，原媒体区按文件流发送。
`moov` 原本位于前端或尾端均可。播放器需要支持 MP4 edit list；该能力不是转码、HLS/DASH、DRM 或直播。

FLV route 将 `format` 改为 `flv`。`start` 是**原文件字节偏移**，不是秒；回退到该位置之前的完整视频关键帧，
在前缀补齐 FLV header 和需要的 AVC/AAC 初始化 tag。支持 AVC/FLV1 视频及 AAC/MP3 音频，保持原时间戳；
不把旧脚本 metadata 中的文件位置当作权威索引。编码切换、复杂 MP4 编辑、分片 MP4、多 `mdat`、加密和其它
不支持的布局返回原文件，继续支持原有单段 Range，不产生猜测的片段。

- `start` 必须唯一、非负；MP4 最多六位小数，FLV 只接受整数。不支持 `end`，非法参数返回 400，越界位置返回 416。
- 请求只要带 `Range`，就按**原文件**执行 Range/If-Range，忽略合法 `start` 的裁剪意图；不会对虚拟片段再做 Range。
  无 Range 的片段返回 200、精确 Content-Length、`Accept-Ranges: none`、`Cache-Control: no-store` 和
  `X-Naway-Media: segment`，不继承原文件 ETag/条件 304。HEAD 生成相同表示头而不发送实体。
- 媒体 route 不允许响应压缩、正文变换/插件、共享 proxy cache、响应头覆盖、内部重定向及其它执行终端。
  静态整文件回退沿用静态缓存头；片段固定不缓存。现有 `limit_rate`/`limit_rate_after` 仍约束下游发送，
  其额度按发送字节计算，不按视频码率或播放秒数推算。
- 上述值是默认预算。元数据最多 16MiB，累计解析读取最多 32MiB，box/tag 最多 16MiB，结构最多 100000、
  嵌套最多 32，全部轨道样本或 FLV tag 合计最多 500000，文件最多 1TiB，解析期限最多 10 秒。
  `mdat` 载荷只检查文件范围，不计入需要聚合的单 box 字节限制；FLV 通过跳过载荷扫描有界 tag 头。
- 相同真实根在配置热换前后共用并发事实；响应结束或取消才释放名额，降低并发不清零旧响应。
  全进程额外限制八个活动操作和 256MiB 保守工作集预留；阻塞解析任务独立持有名额，调用者取消不提前归还。
  满额返回 503，文件/解析预算超限返回 413，畸形或截断结构返回 422，解析期限到达返回 504。
  文件读取或解析期间状态变化返回 503，发送期间文件缩短终止流；不承诺对外部原地文件写入提供快照隔离。

管理路由摘要包含容器、预算和资源域指纹，不公开本地根。`gw_media_operations_total` 只按固定
`format/outcome` 计数；`prepared` 表示响应已准备，不代表客户端已经播放或完整下载。

## 有界 Lua 脚本

`lua-scripts` 是默认关闭的独立 feature，使用 Lua 5.4 执行显式路由的小型纯计算策略。
头部处理不读取实体；完整 body 进入有界聚合慢路径，逐帧 body 保持背压。源码、权限和预算在
候选构建时冻结；语法错误、工厂执行超限或权限无效只拒绝候选，已经发布的路由继续服务。
源码文件受 naml watcher 观察并进入配置指纹，旧请求持有自己的源码快照。

```yaml
schema_version: 1
proxies:
  - id: public
    listen: "127.0.0.1:8080"
    routes:
      - id: annotated-api
        uri: "http://127.0.0.1:3000"
        predicates: ["Path=/api/"]
        script_plugins:
          - id: response-label
            source_file: policies/label.lua
            phase: response_headers
            failure_mode: closed
            circuit:
              failure_threshold: 3
              open_ms: 1000
            include_headers: [content-type]
            mutation_headers: [x-route-label]
            max_memory_bytes: 2097152
            max_instructions: 100000
            max_allocations: 10000
            max_cpu_ms: 50
            timeout_ms: 100
            max_header_bytes: 4096
            max_mutations: 8
```

在配置根下创建 `policies/label.lua`，以 `cargo build --features lua-scripts` 构建：

```lua
return function(ctx)
    if ctx.status >= 200 and ctx.status < 300 then
        return { set_headers = { ["x-route-label"] = "accepted" } }
    end
    return nil
end
```

脚本必须是返回一个函数的 UTF-8 文本文件，最多 64KiB，真实文件路径必须在配置根内。
`ctx` 只有 `method`、不含 query 的 `path`、可信 `scheme`、响应 `status`（请求阶段为 0）、
`eof`、白名单 `headers` 和实体相位的 `body`。每个头名对应有序字符串数组，不折叠重复值。
返回 nil 表示原样继续；表只接受 `set_headers`（名称到单字符串）、`remove_headers`（名称数组）、
`body`（字节字符串）和 `reject`（400–599 整数）。未知字段、越权字段和非法类型均拒绝。
每个脚本的整份输出验证通过后才发布，不提交半套变更；脚本异常文本不会进入响应或遥测。

阶段与资源约束：

- `request_headers`、`response_headers` 只能按 `mutation_headers` 修改头，不能访问 body。
  认证凭据、cookie、动态身份/签名字段、来源、framing、编码和宿主安全头不可读取或改写；
  最多 32 个输入/修改名称、128 个头值、64KiB 输入及最终修改后 head。
- `request_body`、`response_body` 必须显式配置 `max_body_bytes`（1–16MiB），只能读写实体，
  不得声明 `mutation_headers`。聚合先取得共享容量，读取最多等待 30 秒；修改后重建长度并去掉旧校验和与验证器。
- `request_body_stream`、`response_body_stream` 必须显式配置 `max_body_bytes`（1–1MiB），
  它限制每次输入切片和输出，不是整个流长度。每片独立 VM，没有跨片全局状态；数据切片 `eof=false`，
  最后额外调用一次空 body、`eof=true`。最多一槽输出，不能在此阶段改头。头已经发送后的错误或主动拒绝
  终止实体流，不能重新返回 HTTP 状态。取消会停止生产任务，后台客体退出前仍计入资源占用。
- body 阶段只接受完整 identity 编码表示，不解释压缩实体或 206/Content-Range。
  HEAD、204、304 和信息响应不执行响应 body 脚本。脚本不处理 CONNECT 或 HTTP Upgrade。
- 每次调用的内存 256KiB–32MiB、指令 1000–1亿、累计分配/扩容 100–100万次、线程 CPU
  1–1000ms、墙钟期限 1–1000ms，CPU 上限不得超过期限。时间包括 VM 初始化、工厂与回调，
  墙钟还包括阻塞队列等待；固定解释器引导分配不计入次数，随后环境、源码、输入、输出全部计费。
  Lua 指令以 100 条为中断粒度，分配时也检查时间，宿主发布输出前再次检查期限。
- Lua 与 Proxy-Wasm 共用进程级 64 个实例/保留工作集、512MiB 保守预留和八个同步客体执行席位。
  入队前预留资源，Wasm 暂停实例与 Lua 流包装继续持有容量；满额立即失败关闭，不建立无界队列。
  每路由两种语言合计最多 16 个插件，同一方向只能有一种运行时拥有 body。头相位顺序为 Wasm 后 Lua。

沙箱只开放 `assert/error/ipairs/pairs/next/select/tonumber/type`、选定的纯数学函数与
`string.len/sub`。没有 `_G`、动态加载、文件、网络、进程、时钟、随机数、元表访问、协程、
`pcall/xpcall` 或 Lua 模式匹配。Lua 不提供 callout；需要外呼的扩展继续使用 Proxy-Wasm 的
固定 cluster allowlist。没有内嵌 Perl。CPU 门依赖 macOS/Linux 的线程时钟，不支持的平台拒绝执行。

`failure_mode` 和 `circuit` 必须显式声明。`open` 只允许跳过解释器依赖不可用；输入、输出、
指令、CPU、内存、分配、期限、容量和脚本主动拒绝永不放行。熔断阈值 1–100、保护期 10–60000ms；
同一路由/脚本/源码的状态跨热更共享，保留原始失败原因，最多 1024 个活动域，迟到结果不覆盖新保护态。
启用工作区归属时，熔断状态同时占用该工作区的 `max_state_entries`，与 Wasm 共享状态、缓存等
共用额度；首个请求按可信归属绑定，旧快照仍持有的状态不会因换代而提前退额。
输入拒绝返回 413，期限 504，容量/依赖 503，其余执行异常 500；主动拒绝使用其声明的状态。

当前只允许普通公开 HTTP 代理路由，不与层级路由、专用终端、内部跳转、共享缓存、镜像/hedge、
外部处理器混用；同方向正文转换也必须只有一个执行体。完整源码和路径不出现在管理摘要，摘要仅含
脚本标识、阶段、预算、失败策略与内容指纹。`gw_script_invocations_total{phase,outcome}` 提供固定
相位和结果计数，Prometheus 与 OTLP 共享同一事实源。关闭 feature 后不编译 Lua，也不增加数据面分支。

## Spring Cloud Gateway 配置兼容

`scg-compat` 仅在构建期将 Spring Cloud Gateway Server WebFlux 声明翻译为普通 Naway 路由。
输出仍经过同一归属检查、Router 编译和原子发布，不运行 Spring、Java 工厂或第二套请求管线。
这是一种有明确边界的迁移入口，不是任意 Spring 应用配置的解释器。默认制品拒绝非空
`scg_imports`，不编译工厂解析器，也不增加依赖或请求期解释分支。

以 `cargo build --features scg-compat` 构建，在主配置指定来源与目标代理：

```yaml
schema_version: 1
scg_imports:
  - file: spring-routes.yml
    format: yaml
    proxy: imported
proxies:
  - id: imported
    listen: "127.0.0.1:8080"
    routes: []
```

同一配置根下的 `spring-routes.yml`：

```yaml
spring:
  cloud:
    gateway:
      server:
        webflux:
          default-filters:
            - "AddResponseHeader=X-Gateway,naway"
          routes:
            - id: catalog
              uri: http://127.0.0.1:3000
              order: 0
              predicates:
                - "Path=/api/**"
                - "Method=GET"
              filters:
                - "StripPrefix=1"
                - "SetRequestHeader=X-Service,catalog"
```

旧命名空间 `spring.cloud.gateway.routes/default-filters` 也可使用，但不能与 `server.webflux`
混用。`format: properties` 接受 UTF-8、Java Properties 转义和续行，例如：

```properties
spring.cloud.gateway.routes[0].id=catalog
spring.cloud.gateway.routes[0].uri=http://127.0.0.1:3000
spring.cloud.gateway.routes[0].predicates[0]=Path=/api/**
spring.cloud.gateway.routes[0].predicates[1]=Method=GET
spring.cloud.gateway.routes[0].filters[0]=StripPrefix=1
```

工厂可使用短写或 `name`/`args` 对象；列表参数使用 `patterns.0`、`methods.0` 等连续索引键。
短写按逗号切分并去除周围空白，含逗号的固定值应使用命名参数。重复 Properties 键、稀疏数组、
未知属性、metadata、SpEL、`${...}`、`#{...}`、Bean 与 Spring profile 均拒绝。监听、TLS、认证、
配额和发现留在原生配置。目标代理不能同时声明原生 routes，每个代理只允许一个导入来源。
全局策略、workspace 归属和依赖引用检查不会跳过。

### 断言兼容目录

下表覆盖 WebFlux 5.0.3 内置 Predicate；名称与参数参见
[Spring Predicate 目录](https://docs.spring.io/spring-cloud-gateway/reference/spring-cloud-gateway-server-webflux/request-predicates-factories.html)。
“拒绝”表示整个候选不发布，后续说明是显式迁移方向，不是自动采用近似行为。

| SCG Predicate | 导入状态及原生迁移边界 |
| --- | --- |
| After | 拒绝；使用原生配置定时发布，显式确定时区和时钟权威。 |
| Before | 拒绝；显式安排原生配置撤回，不把路由选择改成访问拒绝。 |
| Between | 拒绝；显式安排配置生效窗口，不导入 Java ZonedDateTime。 |
| CloudFoundryRouteService | 拒绝；固定上游与可信身份策略不能隐式替代 Cloud Foundry 签名协议。 |
| Cookie | 拒绝；重建原生认证或有界头策略，先核对重复 Cookie 与 Java regex。 |
| Header | 拒绝；显式使用 `Header=name,regex,expression`，先核对多值和逗号列表语义。 |
| Host | 固定 ASCII 主机/端口列表导入大小写敏感的整串 Host 头正则；通配和模板拒绝。 |
| Method | 大写方法列表导入原生 `Method`。 |
| Path | 下述受限模式导入原生 `PathRegex`。 |
| Query | 仅参数存在性可导入；正则值需显式迁移到原生 Query 的 form 解码合同。 |
| ReadBody | 拒绝 Java lambda；重建有 `max_body_bytes` 的校验或扩展，并核对未命中行为。 |
| RemoteAddr | 拒绝；显式使用原生地址策略，路由未命中不等于访问被拒。 |
| Version | 拒绝；使用 Header/Query/Path 并显式定义版本解析，不导入 Spring Bean。 |
| Weight | 拒绝；原生稳定请求分组不等于 Spring 独立随机采样。 |
| XForwardedRemoteAddr | 拒绝；先配置 `trusted_proxy` 和地址策略，不直接信任客户端转发头。 |

Path 支持普通 ASCII 字面段、完整 `{name}` 段、完整 `*` 段和末尾 `**`，保留请求百分号编码与
matrix 参数的匹配语义。混合通配、受约束变量、编码模式、`.`/`..` 和连续空段拒绝。变量仅用于
匹配，不建立 Spring 求值环境。当前合同不自动匹配尾斜杠，`matchTrailingSlash=true` 拒绝；
需要两种路径时显式列出两个模式。最多 16 个模式、每个 512 字节，展开后每条正则最多 32KiB，
正则编译器工作集上限 2MiB。

### 过滤器兼容目录

下表覆盖内置 GatewayFilter 和可选 CircuitBreaker 入口；名称参见
[Spring GatewayFilter 目录](https://docs.spring.io/spring-cloud-gateway/reference/spring-cloud-gateway-server-webflux/gatewayfilter-factories.html)。

| SCG GatewayFilter | 导入状态及原生迁移边界 |
| --- | --- |
| AddRequestHeader | 非空固定业务头值可导入原生追加操作。 |
| AddRequestHeadersIfNotPresent | 拒绝；用原生变量和头策略显式声明条件写入。 |
| AddRequestParameter | 拒绝；无通用原生 query 修改等价项，由客户端或后端构造参数。 |
| AddResponseHeader | 固定业务头值可导入；`override=false` 拒绝，需显式条件策略。 |
| CacheRequestBody | 拒绝；使用有 `max_body_bytes` 的原生慢路径或扩展，不保存 Java 对象。 |
| CircuitBreaker | 拒绝自动转换；显式配置 `circuit_breaker`、`error_page` 和资源上限。 |
| DedupeResponseHeader | 拒绝自动转换；同名原生过滤器需显式核对响应操作次序。 |
| FallbackHeaders | 拒绝自动转换；同名原生过滤器配合原生熔断使用，不暴露 Java 异常。 |
| JsonToGrpc | 拒绝自动转换；配置 `grpc_transcoding`、descriptor、方法和正文上限。 |
| LocalResponseCache | 拒绝自动转换；显式声明 `proxy_cache` 的键、授权、容量和过期策略。 |
| MapRequestHeader | 拒绝；通过原生变量和头操作显式声明来源与追加行为。 |
| ModifyRequestBody | 拒绝 Java 类型与函数；使用有界 `request_transform` 或 `script_plugins`。 |
| ModifyResponseBody | 拒绝 Java 类型与函数；使用有界 `response_transform` 或 `script_plugins`。 |
| PrefixPath | 拒绝自动转换；显式原生路径重写，并核对顺序和编码。 |
| PreserveHostHeader | 可导入 `preserve_host`，其它身份与上游门禁仍生效。 |
| RedirectTo | 拒绝自动转换；配置 `gateway_redirect` 的状态、authority、路径和 query 策略。 |
| RemoveJsonAttributesResponseBody | 拒绝自动转换；使用带正文预算的原生响应转换或脚本。 |
| RemoveRequestHeader | 可导入原生业务请求头删除。 |
| RemoveRequestParameter | 拒绝；无通用原生 query 删除等价项，需调整客户端或后端合同。 |
| RemoveResponseHeader | 可导入原生业务响应头删除。 |
| RequestHeaderSize | 拒绝自动转换；显式配置 listener `max_header_bytes` 的总量与拒绝合同。 |
| RequestHeaderToRequestUri | 拒绝；改用固定后端或带目的地白名单的正向代理。 |
| RequestRateLimiter | 拒绝自动转换；显式声明 `limit_req`/Sentinel 的键、容量和依赖失败策略。 |
| RequestSize | 拒绝自动转换；显式配置原生正文上限与流式拒绝合同。 |
| Retry | 拒绝自动转换；使用原生重试与预算，非幂等带正文请求不得自动重试。 |
| RewriteLocationResponseHeader | 拒绝自动转换；使用 `proxy_redirect` 或有界响应头扩展。 |
| RewritePath | 拒绝自动转换；用原生重写重新表达捕获替换和过滤顺序。 |
| RewriteRequestParameter | 拒绝；原生正文转换不修改 query，需调整客户端或后端合同。 |
| RewriteResponseHeader | 拒绝 Java regex 替换；使用有界响应头扩展并明确字符与匹配语义。 |
| SaveSession | 拒绝；使用原生 `oidc_rp` 会话策略，不导入 Spring session。 |
| SecureHeaders | 拒绝自动转换；显式配置 listener `security_headers`，不隐式采用框架默认值。 |
| SetPath | 一个固定绝对路径可导入；模板、编码、`.`/`..` 和连续斜杠拒绝。 |
| SetRequestHeader | 非空固定业务头值可导入原生覆盖操作。 |
| SetRequestHostHeader | 拒绝；用 `preserve_host` 与可信 Host 策略显式选择 authority。 |
| SetRequestUri | 拒绝；使用固定上游或显式目的地白名单，不导入 Java URI 函数。 |
| SetResponseHeader | 非空固定业务头值可导入原生覆盖操作。 |
| SetStatus | 拒绝；无通用上游响应状态重写。原生 `return` 仅适用终端本地响应，否则调整后端合同。 |
| StripPrefix | 0–128 段可导入；连同 default-filters 每路由只允许一个路径修改操作。 |
| TokenRelay | 拒绝；显式配置身份与 `upstream_credentials` 的归属和后端白名单。 |

默认过滤器与路由过滤器按各自下标交错，同序号默认项在前；响应操作逆序执行。头值不展开
`{variable}`。认证、Cookie、Host、转发身份、framing、编码、CORS 和宿主安全头不得由兼容层修改，
必须使用原生安全策略。源站只允许无凭据 HTTP(S) origin；路径、query、fragment、URI 表达式、
`lb://` 和 `forward:` 拒绝，避免规范化或服务发现隐式改变来源含义。

### 来源预算与运行观察

来源必须为配置根内普通文件，每份最多 1MiB；最多 16 个来源、每份 1–256 条路由，总计 1024 条。
每路由最多 16 个断言和 32 个过滤器，默认过滤器最多 16 个；全部展开 DSL 共用 2MiB 上限。
Properties 最多 8192 项、每逻辑行 16KiB、键 1024 字节、结构深度 16，工厂参数仅接受有界标量。

来源参与内容指纹和文件观察，单独变更也构建候选。任意来源解析、预算、引用或权限失败都保留当前
有效快照，不先清空旧路由，也不发布部分来源。管理面通过既有配置版本、发布结果、路由摘要和指标
观察生效状态，不产生第二套运行状态。停用全部导入时应撤回主配置中的来源声明，而非写入空文档。

## 构建镜像

组件依赖使用 crates.io 的 `nasa 2.0.3`、`naml 2.0.2`、`naauthz 2.0.0`、`nabudget 2.0.0`，
由 `Cargo.lock` 固定完整依赖图，构建不需要相邻组件源码。配置装配、热更新
和外部 YAML 文档读写统一使用 naml；管理面编辑保留 `${...}` 等字面量，不提前解析环境变量或 Secret。
镜像脚本只使用 Naway 产品上下文与 registry 构建缓存。最终运行镜像只复制 Naway 可执行文件与
默认配置，不携带组件源码或构建目录。

```bash
./scripts/build.sh
# 把 yml 放宿主 /data/naway，直接启动（挂载到容器同路径，修改 yml 即热更）：
./scripts/start.sh
# 或指定别的宿主配置目录：NAWAY_CONFIG_DIR=/your/conf ./scripts/start.sh
```

## xDS 客户端资源边界

`xds-client` 启用 Envoy v3 ADS SotW/Delta 客户端。资源逐字段校验后进入依赖闭包，完整候选经唯一
快照写入者发布；未知执行字段、重复单值字段、类型歧义和超预算资源均 NACK，不部分应用。
`xds-client-extensions` 是另一个默认关闭的 feature，并自动包含 `xds-client`。它只增加命名
ECDS 的空 Router 子集，不提供通用 Envoy 扩展运行时，不加载 Wasm、Lua 或控制面指定的外部代码。

| 资源 | 当前接入范围 | 明确拒绝的边界 |
| --- | --- | --- |
| LDS/RDS/CDS/EDS/SDS | 单 TCP HCM listener、原生可映射路由、ADS EDS cluster、端点和内存 TLS 身份 | 非白名单执行字段与第二配置来源 |
| ECDS `TypedExtensionConfig` | 仅扩展 feature：一个命名、空 `envoy.extensions.filters.http.router.v3.Router` | 非空 Router、其它 Any 类型、TypedStruct、默认配置、可选/禁用 filter、matcher |
| RTDS `Runtime` | 不支持，NACK | Envoy runtime layer 不是 Naway 原生配置覆盖层，不能把任意 Struct 键当作运行参数 |
| VHDS `VirtualHost` | 不支持，NACK | 增量虚拟主机覆盖、别名和按需发现不能用整个 RDS 替换近似执行 |
| SRDS `ScopedRouteConfiguration` | 不支持，NACK | 有序 scope key、缺失片段和按需 RDS 语义不能退化成普通 header predicate |

ECDS 仅用于 LDS 持有的 listener。HCM 必须只有一个 HTTP filter，其 `name` 是订阅名；
`config_discovery.config_source` 只允许当前 ADS，`type_urls` 必须恰为一个完整 Router type URL。
静态 Router 配置仍按原白名单执行。以下是 HCM 中对应的 Envoy 配置片段，不是 Naway bootstrap：

```yaml
http_filters:
  - name: terminal
    config_discovery:
      config_source:
        ads: {}
      type_urls:
        - type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

控制面发布同名 `TypedExtensionConfig`，`typed_config` 为上述 Router 类型且正文为空。首次证明到达前
listener 保持等待；合法更新原子生效，非法更新保留上一份有效证明。SotW 完整集合中移除资源、Delta
显式删除或 TTL 到期会关闭依赖 listener，未依赖该资源的入口保持。这里采用关闭入口的保守映射，
不声称复现 Envoy 缺失动态 filter 时的 HTTP 500 响应。已进入管线的请求仍使用其不可变快照；
旧 keep-alive 连接或 H2 连接上的新请求不能借连接快照继续使用已撤回的动态终结器，而是返回 503。

Delta 支持有界 TTL、同版本无正文续期和重连 `initial_resource_versions`；已过期的资源不能靠空心跳
复活，必须重新发送完整正文。SotW ECDS 不支持 Resource wrapper/TTL，不能以裸 Any 偷带期限。
无 TTL 的有效证明在控制面暂时断线时保留；断线不是撤权通知。LDS 不再引用资源时清除本地证明和
Delta 版本，之后重新引用必须重新取得正文。ECDS 与其它资源共用响应、单资源、缓存数量和应用队列
硬预算；管理面 `/admin/xds/status` 展示 `ecds` 接受版本、有效资源数和缺失依赖，不输出资源正文。

字段及失败语义依据 [Envoy ExtensionConfigSource](https://www.envoyproxy.io/docs/envoy/v1.36.0/api-v3/config/core/v3/config_source.proto)
与 [HttpFilter](https://www.envoyproxy.io/docs/envoy/v1.36.0/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto)；
不支持的 [VHDS 合并](https://www.envoyproxy.io/docs/envoy/v1.36.0/api-v3/config/route/v3/route.proto) 和
[SRDS scope key](https://www.envoyproxy.io/docs/envoy/v1.36.0/api-v3/config/route/v3/scoped_route.proto) 不会被静默忽略。

## xDS 管理端

`xds-server` 是独立、默认关闭的 feature。它把已经发布的 Naway 配置快照投影为 Envoy v3
LDS/RDS/CDS/EDS/SDS，通过 ADS SotW 或 Delta 向获授权的数据面分发。它不接收下游配置写入，
也不引入另一份路由事实源。独立部署可运行 `naway --config /data/naway/naway.yml admin`，
不在管理进程绑定所投影的业务 listener。

必须显式选择 `http_routing` 合同：它只生成固定 HTTP 路由及静态 TLS 身份，**不是完整 Naway
执行管线的复制**，不复制进程内配额、运行期封禁、连接池状态或运维动作。已有原生路由包含
鉴权、Sentinel、接口守卫、插件、正文处理等私有策略时，不能省略策略后继续发布。

```yaml
xds_server:
  profile: http_routing
  listen: 127.0.0.1:18000
  tls:
    ca_file: xds-ca.pem
    cert_file: xds-server.pem
    key_file: xds-server.key
  resource_ttl_ms: 30000
  nodes:
    edge-one:
      certificate_sha256: <客户端叶证书DER的64位小写SHA-256>
      workspace: production
      proxies: [public]
      allow_sds: false
```

这是已有配置的管理端片段：必须另行启用 `ownership`、建立 `production` 工作区，并为 `public`
及其路由建立一致归属。管理连接强制 mTLS，客户端证书还须与配置摘要绑定，首请求的 `node.id`
必须精确一致。TLS 材料限定为配置根内的有界 PEM 文件；不存在明文、匿名或未知节点默认授权。
节点只能订阅其 `proxies` 的 `proxy/<id>/...` 命名空间，通配订阅也不会越过工作区。

| 资源 | 生成范围 |
| --- | --- |
| LDS | 固定 TCP 地址、HTTP Connection Manager、Router；每入口可含明文和静态 TLS listener |
| RDS | 按原生 `order` 排序的单虚拟主机；一个字面量 `Path` 前缀或 `PathExact`，可加单个标准 `Method`；支持 `preserve_host` |
| CDS/EDS | 每路由一个 EDS cluster，后端是固定 IP 的 HTTP origin；不接受域名、HTTPS、路径、凭据或动态服务名 |
| SDS | 静态证书链和私钥；可附严格 CA 客户端认证，不接受 SPIRE、ACME、外部 signer、SNI、OCSP 或会话票据配置 |

只接受默认原生 listener 预算和超时，不把自定义进程治理参数近似映射为 Envoy 参数。
路径不执行规范化、合并斜杠或解码转义斜杠，配置字面量不接受通配、变量或点路径段。
route 完整响应期限显式关闭，流空闲期限使用原生默认值；投影不生成重试策略，且清除客户端
提交的 Envoy 重试和截止期控制头。私网地址不会自动成为可信内部请求。

SDS 私钥需要节点单独声明 `allow_sds: true`，同时要求管理审计启用并设置 `fsync: true`。
每次含秘密正文的发送先取得持久审计收据，再复验当前快照和授权；审计不可用时失败关闭。
审计记录是下发尝试，不是接收确认，内容不含证书或私钥。已经进入传输或被客户端接收的材料
无法撤回；撤权会阻止后续出队并关闭旧流，泄漏处置仍需在数据面轮换证书和私钥。

状态机按流、资源类型维护 nonce 与 ACK/NACK，旧 nonce 不能确认新响应。资源内容版本是 SHA-256，
响应版本包含本地单调快照代数和随机流域，进程重启不会复用旧 wire version。回滚内容仍发布为新快照；
被 NACK 的同代内容不重复发送或续期。Delta 支持命名、通配、取消和首请求的
`initial_resource_versions`；SotW 显式命名订阅之后的空列表表示取消。参数化 locator 不支持，明确拒绝。
各类型通过 ADS 关联，但不承诺不同下游引擎的跨资源原子切换。

非零 TTL 允许 1000–300000 毫秒，默认 30000。客户端须声明
`xds.config.supports-resource-ttl`，SotW 还须声明 `xds.config.supports-resource-in-sotw`；
能力不足拒绝连接，不静默降级。在线时以约 TTL 的三分之一间隔续期，失联后的删除由客户端执行。
Delta 的局部更新也会为同类型其它已订阅资源附带心跳，避免频繁更新使未变化资源失去续期。
期限已经可能耗尽时重新发送完整正文，而不是用空心跳假定客户端仍保有缓存；迟到 ACK 不推迟该判定。
设为 0 明确关闭到期撤回；此时断线数据面可以继续持有旧资源。
协议语义见 [Envoy xDS protocol](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol)。

最多 32 节点、每节点 32 个 proxy、每 proxy 256 条路由；每节点总计不超过 1024 资源和 4MiB，
整代缓存不超过 32MiB，单资源不超过 512KiB。每节点最多四条认证连接、两条 ADS 流，全局各 64；
握手最多八并发、三秒期限。请求最多 64KiB、每流每秒 100 条，响应最多 5MiB，输出队列只有一项，
发送背压两秒或 ACK 等待五秒后关闭对应流。更新只保留最新候选，慢流不排队积压历史代数；
流和连接名额在真实传输销毁后释放，热更不清零占用。

监听地址变更先绑定候选 socket，再随唯一快照发布接管；绑定失败保留旧状态。证书、节点绑定、
工作区授权或 TTL 合同变化使旧流失权。管理读面 `GET /admin/xds-server/status` 受 cluster-read 权限约束，
只输出投影容量和固定协议计数；Prometheus 与 OTLP 共用 `gw_xds_server_events_total{outcome}`、
`gw_xds_server_streams`，没有节点名、资源名或秘密标签。`secret_send` 表示审计后进入输出队列的次数，
不表示下游已接收。

## 实例窗口摘除

`upstreams.services.<name>.outlier` 显式开启按失败率或慢调用比例判断的被动健康策略，
替代同服务的 `max_fails`/`fail_timeout_ms` 连续失败策略。省略时不创建窗口统计。
须使用 `cargo build --release --features upstream-outlier` 编入能力；默认制品拒绝该配置，
不携带窗口状态机、探测计时器和窗口指标。
HTTP 与 TCP/UDP 使用同一实例目录、负载反馈注册表和服务健康状态；不会为该策略另做服务发现。

```yaml
upstreams:
  services:
    orders:
      instances:
        - uri: http://127.0.0.1:9001
        - uri: http://127.0.0.1:9002
      outlier:
        window_ms: 10000
        min_samples: 20
        failure_percent: 50
        slow_percent: 50
        slow_ms: 500
        max_ejection_percent: 50
        base_ejection_ms: 1000
        max_ejection_ms: 30000
        probe_timeout_ms: 5000
```

上例也是各字段默认值。窗口为固定十六个时间桶，桶宽为 `ceil(window_ms / 16)`，边界误差
不超过一桶；每次完成的真实尝试最多增加一个样本。达到 `min_samples` 后，任一已启用比例
达到阈值即可摘除。两个比例各允许 0（停用该条件）至 100，但不能同时为 0。
`window_ms` 范围 160–300000，`min_samples` 为 1–1000000，`slow_ms` 为 1–300000。

同时摘除数量不超过 `floor(可调度目录实例数 × max_ejection_percent / 100)`；比例限于 1–99，
单实例服务因此不会被被动摘除。上限判断与健康状态写入在同一服务锁内完成。
主动健康、服务发现失效和其它准入门仍独立生效，比例上限并不保证其余实例一定可用。
每进程最多保留 1024 个窗口服务、65536 个实例状态，每服务最多 4096 个目录实例；
超过容量或无法用当前目录对账时拒绝该次调度，不跳过健康门。

冷却从 `base_ejection_ms` 开始，真实探测失败按倍数增加，最高 `max_ejection_ms`；
必须满足 `1 <= base_ejection_ms <= max_ejection_ms <= 300000`。到期后的真实请求取得独占
恢复探测权，其余请求不能并发探测同实例。`probe_timeout_ms` 为 1–60000；期限从取得权威时
开始，超时取消实际操作。只有成功且未达到已启用慢阈值的探测才能恢复；取消不能证明健康，
仍保留冷却但不增加失败退避阶数。先销毁真实 I/O，再归还探测权，避免取消后重叠探测。

健康证据边界如下：

- HTTP、WebSocket 握手和 HTTP 扩展外呼：观察到响应头为止，5xx、连接失败和实际超时计失败。
  耗时包含请求上传、连接池等待和上游背压，不是纯后端处理时间；响应正文传输和下游慢读不计入。
  gRPC 只依据 HTTP 响应头，不解释后续 `grpc-status` trailers。
- TCP：观察连接及可选上游 TLS 握手，连接成功不代表不透明业务协议成功。
- UDP：首个有界上游响应才构成成功证据；已发送但没有响应的空闲/总期限耗尽计失败。
- 本地容量拒绝、CGI 输入拒绝以及未完成的普通取消不产生后端失败样本。

同实例和策略的无关热更新保留窗口与冷却。策略变化撤销旧请求的结果写入权，保留保护事实；
成员移除后再加入不会接受旧请求的迟到结果。目录缩小或比例降低时按稳定实例身份顺序保留
上限内的冷却，其余实例回到采样态；仍在执行的探测继续独占到实际 I/O 结束。
这些状态仅存在当前进程，不跨节点同步，也不在进程重启后恢复。

受权 `/admin/upstreams` 返回 `outlier_runtime` 服务摘要。Prometheus 与 OTLP 共用
`gw_upstream_outlier_events_total{outcome}` 的八种固定结果和
`gw_upstream_outlier_state{resource}` 的 `groups`/`instances` 两个保留数量；不以实例地址、
服务名或请求字段生成指标标签。

## 限流桶实时观测

当前限流器的只读观测由 `gw_rate_bucket_observation{status}` 报告：每个节点在 `local`、
`shared`、`preallocated`、`unsupported`、`busy`、`capacity`、`unavailable` 中恰有一个状态为 1。
只有本地观测成功时才提供 `gw_rate_local_buckets{state}`，包括 `total` 和互斥的 `steady`、
`cold`、`warming`、`warm`、`expired`。这些是当前本地后端保留的桶实例，包含等待按需回收的过期桶，
不是配置规则数。`cold` 表示已达到预热空闲冷却期，`warming` 表示尚未达到预热周期，`warm` 表示
已经达到基础速率；`steady` 是没有启用预热的有效桶。

读取不补充令牌、不推进预热、不清理状态，也不枚举客户键。锁忙时立即报告 `busy`，表长度或容量
超过 16384 时报告 `capacity`；后端热替换后只观察当前 owner。Redis 精确桶和批领分别报告
`shared` 与 `preallocated`，不执行 Redis 全局枚举，也不以本地缓存冒充共享桶总数。
Prometheus、OTLP 和内置实时页面使用相同口径。集群页面区分业务节点与控制节点，混合后端或
缺席节点明确标为部分覆盖，不把未知当作零，也不沿用已失联节点的旧值。

## Sentinel 速率预热

独立 Sentinel 规则文档的 `flow` 支持普通快速拒绝和线性预热，按 route 绑定已有的
IP/header/query 等维度。未声明 `behavior` 时保持 `reject`；预热使用同一套本地或 Redis
令牌桶、活跃维度上限、工作区预算和依赖失败策略，无需外部控制器。

```yaml
schema_version: 1
flow:
  - id: orders-cold-start
    route: orders
    key: ip
    rate: 100r/s
    behavior: warmup
    warmup_ms: 10000
    cold_factor: 5
    cold_after_ms: 30000
    max_active_keys: 10000
    active_keys_fail: closed
degrade: []
```

每个维度从首次请求开始，以稳定速率的 `1/cold_factor` 为初始速率和容量，在 `warmup_ms`
内线性增加到稳定值。补充额度按曲线的实际时间区间积分，不以最终速率回填整个预热期；极低
速率的冷态容量至少容纳一个请求。持续无请求达到 `cold_after_ms` 后重新预热，已有余额先收紧
到冷态容量，空闲本身不补发新额度。相同曲线热更保留进度；速率或曲线变更使用独立状态。

`warmup_ms` 必填，`cold_factor` 默认 3，`cold_after_ms` 默认等于预热周期。两个时间参数为
1–600000ms，除数为 2–1000，稳定窗口额度不超过 2³²，`burst` 必须为 0；并发规则不能选择
预热，普通 `reject` 规则不能夹带预热字段。原生过滤器也支持
`limit_req key=ip rate=100r/s warmup_ms=10000 cold_factor=5 cold_after_ms=30000`。

本地后端各节点独立预热；Redis 后端在同一个原子令牌操作内使用 Redis 时间，节点共享同一维度
的预热起点和余额。预热始终执行精确准入，即使启用了本地批领，也不会使用可能过时的预扣余额。
关闭预热时保留原有准入和批领路径。预热不读取或复制请求正文。

## Sentinel 有界匀速排队

`behavior: queue` 在同一规则、工作区和维度内按固定间隔授予入口准入，吸收有限突发。
空闲时首个请求立即通过，后续请求按预约顺序等待；调度停顿后仍复验实际授予间隔，不集中补发。
这里约束的是网关准入时刻，连接建立和网络延迟仍可能影响上游实际收到请求的间隔。

```yaml
schema_version: 1
flow:
  - id: orders-paced
    route: orders
    key: ip
    rate: 10r/s
    behavior: queue
    max_queue: 32
    max_wait_ms: 2000
    max_active_keys: 10000
    active_keys_fail: closed
degrade: []
```

`max_queue` 必填，范围为 1–4096；`max_wait_ms` 必填，范围为 1–60000ms。队列仅用于速率规则，
`burst` 必须为 0，不能组合预热字段或 `nodelay`。原生过滤器写法为
`limit_req key=ip rate=10r/s queue_capacity=32 queue_wait_ms=2000`。

等待期限从首次排队准入开始，包含共享账本往返，并受请求绝对期限约束；多层规则只能收紧期限。
进程全部等待请求共用 4096 名额和 64 MiB 保留预算，按请求头与已知正文上界计费，不预读或复制
正文。未知正文只能尝试立即准入，不能转入等待。容量、等待期限或实体预算不足返回 429，配置
撤销返回 409，共享权威不可用返回 503。取消或配置撤销后不能继续转发。

本地后端在每个进程独立调度；Redis 后端以服务端时间在节点间共享同一规则的队列和实际授予间隔。
Redis 断连、未知回执、类型或权限异常始终拒绝准入，不继承普通令牌桶的依赖故障放行策略。
队列绕过本地批领。取消释放排队名额但保留已承诺的调度空洞；相同策略热更保留调度债务，改变
策略参数使用独立身份。`active_keys_fail: open` 仅允许活跃维度软上限无状态放行，不能绕过进程、
工作区或队列物理预算。

`gw_sentinel_queue_events_total`、`gw_sentinel_queue_waiting`、等待次数与等待时长累计指标可用于
当前区间观测；标签只包含固定结果类别，不包含请求维度原值。取消的 Redis 清理仍占用原保留预算，
直至有限清理完成或超时；进程消失后的远端预约由有限租期回收。

## Sentinel 熔断与降级

主配置的 `sentinel_rules_file` 指向独立规则文档，使用相同的 naml 加载、候选校验和原子热更链。
`degrade` 按实际 route id 绑定，支持错误次数、错误比例和慢调用比例；不存在的路由、未知字段、
重复 DSL 参数和互斥阈值组合会拒绝整个候选，继续使用上一份有效配置。

```yaml
schema_version: 1
flow: []
degrade:
  - id: orders-errors
    route: orders
    strategy: error_ratio
    ratio_bps: 5000
    min_requests: 20
    window_ms: 10000
    break_ms: 5000
    fallback_status: 503
    fallback_body: orders temporarily unavailable
  - id: orders-latency
    route: orders
    strategy: slow_ratio
    ratio_bps: 5000
    slow_ms: 300
    min_requests: 20
    window_ms: 10000
    break_ms: 5000
```

`strategy` 默认 `error_count`，必须配置正整数 `failure_threshold`；`error_ratio` 只接受
`ratio_bps`，`slow_ratio` 同时要求 `ratio_bps` 和 `slow_ms`。万分比范围为 1–10000，例如
5000 表示 50%；窗口样本达到 `min_requests` 后，次数或比例达到阈值才进入保护。
`window_ms`、`break_ms`、`slow_ms` 为正数且不超过 365 天。直接路由 DSL 使用同名参数，
例如 `circuit_breaker id=orders strategy=error_ratio ratio_bps=5000 min_requests=20`。

错误样本来自原始上游 5xx、连接失败或超时；`error_page` 和响应插件不能覆盖该事实。
慢调用采用转发分支开始至取得原始响应头或终止错误的单调耗时，包含连接等待、请求发送和重试，
不含前置鉴权、流控排队及后置响应插件，也不等待流式响应体结束。RT 严格大于 `slow_ms` 才是
慢样本；快速错误不计为慢样本，可同时声明错误规则。缓存命中、静态资源、本地拒绝及其它没有
上游结果的分支不计入统计。普通 HTTP、LLM、Dubbo 与 WebDAV 转发沿用各自的原始结果判定。

保护期内返回声明的短文本和 `X-Gateway-Circuit: open`。到期后每节点每规则只授予一个半开
探测，取消会归还探测权；探测必须成功，慢调用规则还要求及时返回，才能先清空旧窗口再解除保护。
相同策略热更保留状态，统计依据或阈值变化会使用独立窗口，在途请求继续绑定原策略和原状态实例。
熔断不聚合或重编码请求/响应实体。

默认使用每节点独立的有界聚合窗口。`runtime_state.circuit_breaker.shared: true` 复用
`runtime_state.rate_limiter.redis`，需要 `redis-runtime`；只共享窗口统计，开闭状态和唯一
半开探测仍由各节点维护。一个节点的结果达到集群阈值后，该节点进入保护，其他节点在后续记账
时自行判断。平台共享统计依赖不可用时不主动跳闸；工作区统计容量或依赖失败则进入本地保护。
状态实例与窗口继续受工作区预算约束，容量不足不能创建额外状态。

## Sentinel 本地批领令牌

`rate-preallocation` 是默认关闭的独立 feature，仅优化 Sentinel QPS 与 `limit_req`。
启用后从同一个 Redis 令牌桶预扣小批额度，在有期限的本地凭据上扣减；LLM token 结算、
产品计量、bot 和并发连接准入不经过这层缓存。Redis 连接、协议和传输仍使用 NASA 组件。

```yaml
runtime_state:
  rate_limiter:
    backend: redis
    fail_mode: closed
    redis:
      url: redis://127.0.0.1:6379
      namespace: gateway
    local_preallocation:
      batch_size: 8
      lease_ms: 100
      max_outstanding_tokens: 32
      max_local_keys: 4096
```

编译时添加 `--features rate-preallocation`；未编译、后端不是 Redis 或配置超限时拒绝候选。
`batch_size` 为 1–4096，`lease_ms` 为 20–1000 毫秒，`max_outstanding_tokens` 必须介于
批量大小与 4096 之间，`max_local_keys` 为 1–65536。每桶最多保留 64 个远端批次；每进程
所有在线和退休后端合计最多 65536 个本地维度、4 个后端代际，每后端最多 128 个在途准入。
达到硬资源上限时闭合拒绝，不扩张队列或以依赖降级放行。
批领规则的令牌容量不得超过 `2^52`，补充窗口和空桶补满时间不得超过一年；不满足数值边界时拒绝候选。

共享扣减与批次账本在同一 Redis slot 原子执行。全部节点同一桶的未结算令牌总额不超过
`max_outstanding_tokens`，包括已经本地消费但尚未结算的批次；这也是延迟使用造成的额外突发
上界，而不是每节点各自允许这么多误差。凭据从领取发起时刻计时，往返、等待和进程暂停均消耗
本地期限。需要逐请求精确共享时省略 `local_preallocation`。
批领判定的剩余额度只表示本地余额，不是集群总余额。精度边界依赖共享 Redis 状态连续、
时钟正常推进且不走 fail-open；Redis 数据丢失、时钟跳跃和明确配置的依赖放行不具备同样保证。

余额用尽、策略变化、后端退休与空闲回收都先撤销本地凭据，再幂等归还已知未用额度。
归还失败、领取结果未知或节点崩溃时不猜测退款；批次到期撤销权威，原桶持续按配置补充，
最多损失当时未结算额度，不会形成永久租约。普通崩溃后的额度可用性恢复由桶的补充周期决定，
不是必然在 `lease_ms` 内恢复满桶。空闲回收每轮检查最多 64 条、最多 8 个并发归还，扫描延迟
可能导致保守损失，但不延长凭据。已过期或策略不匹配的退款不能向新账本追加信用。

规则与工作区硬预算保持独立：`max_active_keys` 仍在 Redis 原子检查，只有新维度满表时的
显式 `active_keys_fail=open` 可以放行；桶与批次账本各占一个远端工作区状态名额，本地条目也
持有工作区租约。工作区、本地目录、批次上限、无效输入和旧代请求拒绝不受 `fail_mode` 放宽。
Redis 短暂不可用时，尚未到期的预扣额度仍可消费；需要新额度时才应用依赖 open/closed 策略。
权限、协议类型、slot、响应解析等确定性错误始终拒绝，不归入可放行的依赖不可用。
更改规则时不混用旧批次；跨节点滚动变更可能保守拒绝到旧权威到期，不能承诺瞬时全局切换。

`/admin/config/status` 的 `summary.rate_preallocation` 展示已发布配置边界；固定低基数指标
`gw_rate_preallocation_events_total{outcome}` 区分领取、本地命中、拒绝、退回令牌、依赖错误和过期，
`gw_rate_preallocation_state{resource}` 展示包括退休引用的后端与本地维度数量。Prometheus 与 OTLP
共享同一原子事实，不携带规则、用户、地址或凭据标签。

## 源码结构(按模块目录组织)

```
src/
├── main.rs              最小进程入口
├── lib.rs               功能模块入口
├── app/                 CLI、启动、监听器交接与 L4 连接调度
├── admin/               管理 API、审计与 Console 静态资源
├── ai/                  模型路由与 AI 协议治理
├── cache/               HTTP 缓存
├── config/              配置类型、YAML 文档与不可变快照构建
├── control/             热更、历史、Kubernetes、xDS 客户端与管理端
├── edge/                gRPC 边缘会话、订阅、relay 与目录
├── extensions/          外部处理、Wasm、Lua 沙箱、GraphQL 与扩展协议
├── io/                  有界读写、响应、压缩与静态文件
├── observability/       指标、访问日志、日志投递与 tracing
├── portal/              开发者门户与静态资源
├── protocols/           HTTP/3、MQTT、Kafka、Dubbo 等传输适配
├── proxy/               HTTP 请求管线与上游转发
│   └── traffic/         多窗口准入、逐帧整形与响应成本结算
├── routing/             路由、断言、过滤计划与变量
├── runtime/             连接注册、准入、限速与共享运行态
│   └── ratelimit/       本地批领、共享账本、固定指标与原子 Lua 操作
├── security/            认证、授权、Secret、WAF 与接口守卫
├── tls/                 TLS、ACME 与 SPIRE 身份
└── upstream/            实例目录、服务发现、健康与负载均衡
```

`config/model/` 按配置领域拆分：监听与 TLS、路由与上游、服务发现与来源、认证与 Secret、
扩展与协议、共享状态、遥测、管理与门户各有独立文件；`mod.rs` 只负责领域组合与统一导出。
配置使用方继续从 `config::model` 引用类型，不依赖内部文件位置。配置解析和快照装配留在
`config/`，动态来源与发布留在 `control/`，运行态资源留在对应功能模块。

`control/xds_server/` 内继续按职责划分：`proto` 负责协议消息，`projection` 负责资源投影，
`plan`/`security` 负责可见域与证书，`state` 负责订阅和 ACK 状态，`runtime`/`stream` 负责监听及传输，
`admission`/`metrics` 负责容量与观测。入口文件不承载这些功能的实现。

`control/xds_resources/extensions/` 将命名扩展的原始字段验证、类型映射与证明状态分离；
其结果仍进入同一资源依赖闭包和快照发布链，不建立另一份数据面配置。

`upstream/passive/` 分离共享健康注册、窗口与探测状态机、阈值判定和指标；
配置声明留在 `config/model/upstream.rs`，HTTP 响应头观察适配留在 `proxy/health.rs`。

Redis 原子操作分别保存在 `runtime/redis/`、`runtime/ratelimit/redis/`、`cache/redis/`、`control/ownership/redis/` 和
`control/providers/redis/`；Lua 源文件按业务操作命名，由所属 Rust 模块在编译期包含，
部署不需要查找外部脚本文件。

## 开源协作

贡献流程、安全报告、社区行为与治理规则采用英文开源文档：

- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)
- [行为准则](CODE_OF_CONDUCT.md)
- [支持范围](SUPPORT.md)
- [项目治理](GOVERNANCE.md)

## 许可证

本项目采用 `Apache-2.0 OR MIT` 双许可证，使用者可自行选择其一：

- [Apache License 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)
