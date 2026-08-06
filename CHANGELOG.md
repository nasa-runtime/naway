# Naway 变更日志

本项目遵循语义化版本；架构、产品语义与验收口径随代码和公开契约同步演进。

## [Unreleased]

### gRPC/H2 90% 硬门与 V8-6 最终回归（2026-08-06）

- Linux `perf` 将 gRPC 每请求主要额外成本定位到 Hyper H2 task 构造时搬运大 future：下游 service future 在 H2 stream 边界装箱，低频 ACME/redirect/LLM/external/Wasm 状态只在命中分支分配，上游 `H2ClientFuture` 由专用 executor 装箱后再交给 Tokio。请求/响应 DATA、trailer、取消、flow-control、连接预算和全部治理 timeout 保持不变。
- profiler 中 glibc `__memcpy_generic` 从原始 `31.26%` 收敛到 `7.42%`。正式门使用 Linux Docker、`7×400000`、8 条下游 H2 连接、总并发 64、三方交错和固定 `ratio >= 0.90`：Naway `38227.65 RPS`（CV `0.0575`），Envoy `42274.27 RPS`（CV `0.0286`），比例 `0.9043`，脚本判定 **PASS**；七轮均无 cgroup throttling，Naway 中位 CPU `99.93µs/request`。
- 当前 release 的 V8-6 正式回归 **PASS**：100k 成员与 64KiB 档零丢；10k stream 五轮中位 `525195 deliveries/s`、CV `0.0594`；最大调度停顿 `208908µs`；正式波次 drain 后 RSS `136276KiB → 82812KiB`、FD `14 → 14`。慢消费者 RSS 增长约 10.5MiB，三节点三档 peer copies 精确且 rejected/unknown 为 0。
- 最终确定性门为 401 passed、0 failed、22 个外部 live 用例按环境门 ignored；全 feature/target Clippy 以 `-D warnings` 通过。Java SDK SCM developer URL 已修正，跟踪文件不再引用内部恢复/架构草稿文件。

### 下游连接拓扑扫描:h2 锁"争用"排除为 gRPC 剩余差距主因（2026-08-05 晚）

发布判断里最后一个未确立项(h2 每连接锁占 gRPC 对 Envoy 剩余 19~22% 差距的比例)**已确立:争用成分 ≈ 0**。纯测量轮,无源码改动。

- **设计**:总并发恒 64,只改下游连接数 c=1/4/16/64(h2 server 锁每连接一把,c=1 时 64 流挤一把锁、争用最大;c=64 零跨流争用),nginx/envoy 同轮交错对照,5 轮×400k,配对符号检验。
- **两个决定性形状**:①争用最大点 c=1 恰是 naway 相对最好的点(对 envoy **1.03**、3/5 打平,锁争用假说预测这里输得最狠);②争用稀释 4×/16× 后差距不收窄(0.838→0.867,0/5)。⇒ 结合 08-04 上游 shard 扫描(16 分片已饱和),**锁争用在上下游两侧都被排除**;剩余 ~13-16% 是与连接拓扑无关的**每请求成本**(p50 一致地 envoy 2.7ms vs naway 3.2~3.3ms)。
- **方法学警示**:预设判据"锁是瓶颈⇒吞吐随连接数上升"在 naway 单曲线上是成立的(+44%),但 envoy 升得更陡(+71%)——单连接钉单核是共性形状;**没有对照曲线这轮会做实一个错误归因**。nginx 单连接不吃亏(17.2k)同时排除了压测客户端瓶颈。
- **口径如实**:测量期机器非静默(用户明确选择带噪声跑),绝对值整体压低一成多,结论只建立在噪声稳健的配对比值上;c=64 块 nginx/envoy CV 超 0.15,按 A2 口径判 INCONCLUSIVE 未采用。§4.3 主攻方向由"锁粒度细化"修正为"h2/hyper 每请求路径成本";锁的非争用固定开销仍需真 profiler 分离(A4/Instruments 路径)。
- 报告:`target/a2-down-{1,4,16,64}.jsonl`;沙箱终端跑基准的三个环境卡点是 buildx 写 `~/.docker`、daemon 代理导致 frontend 镜像拉取失败，以及本机代理拦截 `benchmark.local` TLS 探测形成假 502。

### E1 `interest_route=auto` 运行时闭环（2026-08-05）

- EdgeHub 在 tenant/group 首成员加入、末成员离开时产生兴趣变更；新 peer 建链先接收 `reset/up/ready` 全量快照，随后按 revision 增量更新并每 10 秒心跳。控制队列或 ACK 异常会拆链，revision 断档、未 ready 或 30 秒过期一律 fail-open 广播，优化提示永不决定消息正确性。
- 热路径不解析业务 protobuf，只查询由已验证 header/身份得到的 tenant/group 稳定摘要；摘要碰撞只会多发，不会漏发。`interest_route=auto` 允许超过 32 节点，显式 `broadcast_all` 仍受 32 节点全量 payload 广播门限制。
- 新增 `gw_edge_relay_interest_filtered_total` 与 `gw_edge_relay_interest_ready_peers`；协议/config 单测和三节点真实 socket 用例证明无兴趣 peer 被过滤、订阅变化后恢复投递。

### C5 节点级流量指标进集群页 + watcher 用例环境适配（2026-08-05）

- **C5 完成**:新增 `GET /admin/cluster/metrics`,用**本节点自己的 admin 凭据**抓取同集群成员的 `/metrics`,聚合每节点的 `gw_requests_total` / `gw_responses_5xx_total` / `gw_active_connections`;Console 新增「节点流量」面板。
- **三条安全边界,缺一不可**:
  1. **必须显式开启** `admin.auth.allow_cluster_metrics_scrape`(默认 false)。它让 admin 从"只被访问"变成"**会主动外连**",是攻击面的实质变化——被打穿的 admin 可以借它探测内网。
  2. **凭据只从进程内已解析的运行态取**,绝不透传调用方请求里的任何凭证。否则控制面就成了可被借用的跳板:调用方带什么凭据,网关就拿什么去连内网别的机器。
  3. **只抓 Nacos 自注册成员表里的地址**,不接受调用方指定目标。
  单节点失败(超时/401/非 2xx)标 `ok=false` + 低基数 reason,**不伪造零值**——把抓不到显示成"没流量"比看不到更糟。响应体设 1 MiB 上界。契约单测锁死凭据来源、bearer 优先与 base64 标准编码。
- **6 个依赖文件 watcher 的热更用例改为环境探测后跳过**。它们在本机恒定失败,**排查中我判断反复了三次**:先误判"沙箱限制"(方向对但无证据)→ 又因一次单线程恰好全绿改判"并发争用"→ 最后写独立探针程序在系统 temp / scratchpad / 项目目录各试 10 次,**全部 0/10 收不到 rename 事件**,才定性为环境能力缺失。**结论是靠受控实验定的,不是靠反复跑测试猜的**;同样的换版逻辑经 SIGHUP 触发一切正常(实测 v1→v2)。用运行时探测跳过而非 `#[ignore]`——后者会让支持 watcher 的正常环境也默认不跑。
- 门禁:fmt + clippy(all-features)干净,三形态 **353 / 388 / 395 passed,0 failed**。

### A3 10k WS 四阶段容量矩阵 + 连接内存泄漏判据（2026-08-05）

发布判断里两个未完成缺口之一(A3)已完成。

- **容器口径 10k 容量矩阵**:naway **10000 条 WS 全部建立**,四阶段容器 RSS 28.1 → 220.0 → 228.7 → 224.9 MiB,**每连接 ≈19.7 KiB**,peak 323 MiB(nginx 344 MiB)。**Envoy 在同一配置下建到 9940 条即开始返 503**——其自身日志确认未配置连接数上限,naway 与 nginx 都建满。
- **新增原生两轮泄漏判据** `tests/scripts/a3_ws_capacity_leak.sh`:容器矩阵只能看到"关闭后 RSS 几乎不降",**分不开「allocator 不归还 OS」与「真泄漏」**。连跑两轮建满/全关后结论明确——**每轮全关后 RSS 都回到基线(驻留 ≈0),NO LEAK**,连接内存完整归还 OS。
- **三处会让判据假通过的坑,已修并写进注释**:
  1. **空跑保护**:首版因 `ws` 子命令没有 `--path` 参数导致 0 连接建立,判据却给出 "NO LEAK" 绿灯。现在峰值不显著高于基线即直接失败——**在空数据上给绿灯比漏判更危险**。
  2. **判据修正**:只看"第二轮峰值增幅"会把采样噪声误判成泄漏(实测两轮峰值差 13.7%,而两轮全关后都精确回到基线 17.0 MiB)。改以**驻留**为主判据——那才是泄漏的物理证据;峰值靠固定间隔轮询,是否采到最高点带随机性。
  3. **原生跑法上限 ≈8000 条**:客户端/网关/上游共享同一台机的临时端口,macOS `net.inet.ip.portrange` 仅 16384 个而每条 WS 隧道占**两个**,10k 必然撞墙(实测 8080 条即 502)。**那是内核限制不是 naway 的容量上限**;两轮之间还须等端口离开 TIME_WAIT。
- **两个读表警告**:①nginx 的四阶段 RSS 采的是 master 进程(全程 6.4 MiB 不动),承载连接的是 worker,该列**只有 peak 可比**;②`A2_RESOURCE_RECOVERY_DELAYS` 默认为空,不设就没有回收采样点,`after_close` 立即采会看起来像"完全不回收"。
- 配合 Dockerfile 迁到 `scripts/`,修 3 处路径引用(`a2_compare.sh` ×2、`p1_artifact_gates.sh` ×1);**P1 五门复测全过**(二进制 34.42 MiB、ready 1110 ms、idle RSS 21.83 MiB、smoke ok、镜像 49.0 MiB)。

### Redis Stream 裁剪责任划分：naway 永不裁剪 + trim-gap 检测（2026-08-05）

**产品决定:stream 裁剪完全归业务侧,naway 不做。**本轮把这条决定固化并补上它的必要配套。

- **锁死不变量**:契约门断言 `edge_redis_bus.rs` 不出现 `x_trim` / `MAXLEN` / `MINID`,防止以后有人"顺手"加上。同时写清一条容易搞混的所有权边界——`runtime_state.rs` 里确实有 `x_trim_maxlen_approx`,但那裁的是 **naway 自己拥有**的运行态事件流(黑名单/禁用广播,naway 是唯一写者),与业务拥有的 edge 扇出流是两回事。
- **补上这条决定的必要配套:trim-gap 检测**。naway 不裁剪 ⇒ 保留窗口不受它控制 ⇒ 业务裁到本节点 cursor 之前时,Redis 的 XREAD **不报错**,只从现存最早 entry 开始给,**中间那段被静默跳过、无人知晓**。这不是"替业务裁剪",是"naway 要知道自己丢没丢"。实现:启动期一次 `XRANGE - + COUNT 1`,流中最早 entry 严格晚于本节点 cursor 即判缺口,计 `gw_edge_redis_stream_trim_gap_total` 并告警。
- **三个刻意的设计取舍**:①只在**启动**查一次——那正是缺口最可能出现的时刻(节点停机期间业务照常裁剪),稳态逐条查既贵也没有额外信息;②**查询失败一律不报缺口**——可观测性增强不能因一次 Redis 抖动就把节点误报成丢数据,更不能阻断启动;③entry id 按 `<ms>-<seq>` **两段整数**比较而不是字典序(`10-0` 字典序小于 `9-0`,比反了会在真有缺口时漏报),单测锁死含畸形 id 的降级行为。
- 真 Redis 端到端用例:跑一轮 → 杀节点 → 业务 XADD 后 `XTRIM MAXLEN 1`(用例自己扮演业务侧)→ 重启,计数器必须 ≥1。**变异验证**:停用检测后用例如期失败。
- 门禁:fmt + clippy(all-features)干净,三形态 **351 / 386 / 393 passed,0 failed**;SDK gates ALL PASS;Redis 跨进程 **4 passed**。

### 审查 Codex Redis 集群传输 + 补跨进程端到端验证（2026-08-05）

Codex 新增了 `redis_pubsub` / `redis_stream` 两套集群传输。审查结论:**实现本身正确**——跨进程扇出实测通过,cursor 也确实生效;问题出在**门禁覆盖**与**语义表述**上。

- **`RedisFanoutEnvelope` 是公开 wire 契约却没被锁(已补)**:它比 FramePush 更需要锁——业务用 protoc 生成的代码**直接往 Redis 写这个信封**,而 Naway 侧是手写编解码,字段号漂移**不会有任何编译错误**,后果是**静默错路由**(例如 tenant 被读成 scope、消息投到别的租户)。现把 `.proto` 声明与手写编码器/解码器的 7 个字段号逐一钉进契约门,并**变异验证**(把解码器的 scope 字段号 5 改成 9,门禁如期失败)。
- **`mode: relay` 夹带 Redis 配置的检查其实存在,但零测试覆盖(已补)**:我最初误判为缺失,写了失败用例才发现校验在,只是文案不同——用例反倒避免了我"修一个不存在的 bug"。现按真实文案补上回归覆盖。
- **补上 Codex 自列的最大缺口:跨进程端到端**(`tests/edge_redis_cluster.rs`,3 条 ignored 用例,需本机 Redis)。此前只有 codec/config 单测和「同进程两个订阅者都收到」的 live 用例,证明的是编解码与 Redis 客户端,**证明不了两个真 Naway 进程 + gRPC ingress + 两端订阅**这条真链路。实测:**pubsub 与 stream 的跨进程扇出都通过**。
- **修正被高估的 at-least-once 语义(本轮最重要的发现)**:文档称 stream「重启后按持久 cursor 补读,语义为 at-least-once」。实测把它拆成了两半——`gw_edge_redis_stream_received_total=1` 证明 **cursor 生效、XREAD 确实把停机期间的 entry 拉了回来**,但**客户端可见=false**:补读发生在网关启动后的极短窗口,客户端此时还没重连完,散出打到空 group 就丢了。所以 **at-least-once 只到网关为止,不是终端保证**,这与「无离线堆积」是同一条语义、不是缺陷。用例据此断言总线层补读并显式记录客户端可见性不在保证之内——断言"客户端一定收到"会是假承诺。架构规范 与 验收记录 口径同步修正,并写明 Stream 相对 Pub/Sub 的**真实收益**是消费者侧背压与网关侧不丢,而非终端离线补偿。
- 顺带:Codex 交付时只跑了 clippy 与局部用例,未跑三形态全量(项目门禁要求)。本轮补齐。
- 门禁:fmt + clippy(all-features)干净,三形态 **351 / 386 / 392 passed,0 failed**;SDK gates ALL PASS;Redis 跨进程 3 passed(`GW_EDGE_TEST_REDIS=redis://:<password>@127.0.0.1:6379 cargo test --features grpc-edge,redis-runtime --test edge_redis_cluster -- --ignored --test-threads=1`)。

### 审查 Codex 复审改动 + 实现 PublishStream SDK（2026-08-05）

Codex 复审提出 7 条,其中 4 条是我的真错(FramePush 信封不兼容、proto 默认 header 文档漂移、Rust SDK 无内存/协议上界、Java 关闭泄漏),方向都对。本轮审查其改动、修其不完整处,并实现它列出的未修缺口。

- **FramePush 信封修复不完整,两侧都拒绝合法输入(已修)**:①**proto3 省零**——`bytes payload = 1` 取默认值(空)时 protoc **不上 wire**,空帧序列化成 0 字节 message,而两个 SDK 都把"字段缺失"当错误,protoc 客户端的心跳/ping 帧会被直接拒,**正是信封本要解决的互通问题**;②**Java 侧还拒绝扩展**——原实现断言"首字节必是 0x0a 且 payload 占满整条 message",任何新增字段都被拒,而 `.proto` 明确允许"只增字段",且 Rust 侧正确跳过未知字段、两侧行为不一致。现 Java 改为真正的字段遍历,两侧统一把缺失解释为空 payload,各加两条回归用例(空帧、未知字段前后置)。
- **Java 关闭泄漏修复补上测试(已补)**:声称修复但无用例证明。补真进程用例并做**变异验证**——还原成"只翻 AtomicBoolean"的原始形态后用例超时失败,确认断言有效;顺带查明真正起作用的是 `worker.interrupt()`(grpc-java 阻塞迭代器响应线程中断),Context 取消属纵深防御。
- **实现 `PublishStream`(Codex 第 5 条未修缺口)**:Rust `publish_stream` 与 Java `publishStream` 均落地,各带端到端用例锁**到界语义**——route 配 `max_messages: 2` 时发 3 条必须返回 `messages=2` 且状态 OK(**优雅轮转不是报错**),已处理两条保序散出,越权流式发布同样 7。两个 SDK 都"先全部编码再发",任何一条越界都在**一条都没发出去**之前失败(流式面没有逐条 ack 可对账,不能留"发了一半"的不确定状态)。
- **契约门扩到锁 SDK 覆盖**:`.proto` 声明四个方法,SDK 少一个**不会有任何编译错误**——E2 就是这样被记成完成的。现按方法名钉死两个 SDK。
- 修交付时未过的 `cargo fmt`;修正 Rust SDK `subscribe()` 的文档(它是**惰性**的,首次 `next()` 才建流,"先 subscribe 再 publish"存在竞态、会诚实返回 accepted=0)。
- 用例注释记下一条真实约束:`Path=` 是**前缀**谓词,`Path=/X/Publish` 会连 `/X/PublishStream` 一起吃掉,两个方法必须挂同一条 route(单独开一条排在后面的永远匹配不到,请求被当普通 L7 转发,实测 502)。
- 门禁:fmt + clippy(all-features)干净,三形态 **350 / 385 / 386 passed,0 failed**;SDK gates ALL PASS(Rust 9 单测 + 3 端到端,Java 11 测)。

### 自检第二轮：补齐两处自认的弱覆盖，并用变异测试验证断言不是空转（2026-08-04）

上一轮自检末尾我如实列了两处"测了近似物"的弱覆盖,这轮补上,并额外发现自己的验证手法本身有假阴性。

- **C8 热更围栏此前只测了 helper。** 原用例断言 `same_runtime_topology` 返回 false,那是在测函数,不是在测"网关真的拒绝了这次换版"。新增 `relay_fanout_budget_change_is_rejected_by_real_reload`:起**真实网关进程**、只改 `grpc_edge_cluster.fanout_limits`、触发 `/admin/reload`,断言 ①配置版本**不推进** ②拒绝原因进 `/admin/config/history`(只拒不记会让运维查不到为什么没生效) ③进程仍存活且旧配置继续服务(拒绝 ≠ 自杀)。**顺带发现整个 relay 热更围栏此前在测试里零覆盖**,不止 C8。
- **Java SDK 的跨帧大消息此前是"理论上没问题"。** grpc-java 由框架负责重组,理论上不受 Rust SDK 那个 bug 影响——但理论不算验证。新增 60 KiB(route 默认上限 64 KiB 之内、远超单帧 16 KiB)端到端用例,实测逐字节一致。
- **用变异测试验证新断言不是空转。** 逐条把被测的守卫改成恒不触发,确认用例会失败:reload 围栏(摘掉后版本从 1 涨到 2,**正是"换版成功但新预算永不生效"的静默失效**)、gRPC 授权、WS 桥接授权,三条全部确认有效。
- **自检的自检:第一次变异测试出了假阴性。** 我用字符串替换关闭 WS 桥接的授权检查,而 rustfmt 早已把那个调用拆成多行,替换**静默没生效**,于是得出"摘掉检查仍通过 ⇒ 断言空转"的错误结论。修法是给每次变异加 `assert count==1` 的锚点校验——**没有断言的验证步骤本身就是不可信的**,这条比结论更值得记。
- 门禁:fmt + clippy(all-features)干净,三形态 **350 / 385 / 386 passed,0 failed**;SDK gates ALL PASS(Rust 6 单测 + 2 端到端,Java 6 测含大消息)。

### 深度自检：修 1 个真 bug、堵 2 处未测的安全路径、纠 1 处错误注释（2026-08-04）

对本轮全部产出做了一次对抗式复查,不是复述成果。四项发现:

1. **Rust SDK 无法处理跨 DATA 帧的大消息(真 bug,已修)。** hyper/h2 把超过 max_frame_size(默认 16 KiB)的负载拆成多帧,而 route 的 `max_msg_bytes` 默认 **64 KiB**——**默认配置下就会跨帧**。原实现按"一条消息 = 一个 chunk"处理,读到半帧即报错,再被订阅循环当成断线,**退化为静默重连死循环**:调用方只看到"消息一直不来",拿不到任何错误。已改为增量重组(`take_message` 从缓冲取完整帧;断线清空缓冲,截断消息绝不外发)。新增端到端用例发布 60 KiB 消息断言逐字节一致,以及半帧/多消息同帧两个单测。**这个缺陷只有跑真链路才会暴露**,单测再多也发现不了。
2. **授权的两条路径此前从未被测。** 代码路径正确不等于被验证:补上 **PublishStream 越权返回 7**(防止将来把流式分流挪到授权之前)与 **WS 桥接越权返回 403**(桥接只换传输外壳,少这条断言它就可能悄悄变成绕过 group 策略的旁路)两条集成断言。
3. **一处安全注释写错了出处。** 原注释称"身份为空时相位 4 已经拒绝"——实际相位 4 **不检查空**,principal 非空来自**构建期**认证策略校验(`api_key` 的 `consumer=` 走 `validate_basic_auth_user`,JWT claim 走非空校验)。鉴权判定不该依赖三个模块之外、且我描述错了的不变量,已改为**代码显式兜住**:变量展开为空一律不匹配,否则一旦上游放松,`user.%{user}` 会退化成放行字面量 `user.`。配套单测锁死。
4. **一个差点混进去的测试脚手架陷阱。** 新加的 403 探测用 `raw_http`(`read_to_end`),而被拒的 WS Upgrade 返回普通 HTTP 响应且保持 keep-alive(这符合 HTTP 语义,不是产品缺陷),于是阻塞到空闲超时,把同用例里的 native 长连接一起拖死,表现为"stream 计数到不了 2"这种完全误导的失败。新增 `raw_http_head` 只读到响应头结束。**若不做这次自检,这会是一个慢且难查的偶发失败。**

门禁:fmt + clippy(all-features)干净,三形态 **350 / 384 / 385 passed,0 failed**;SDK gates ALL PASS(Rust 6 单测 + 2 端到端,Java 6 测)。

### V8-9 边缘客户端 SDK：Rust 与 Java（2026-08-04）

把 `.proto` 从"一个文件"变成"能跑通的接入路径"。两个 SDK 都**与真实网关进程做过端到端联调**,不是只跑自洽单测。

- **共同取舍**:①payload 收发原始字节,SDK **不做 protobuf 编解码**——网关本就不解析业务 payload,SDK 不该强迫使用方绑定某种 protobuf 实现;②SDK 真正兜住的是三件手写客户端最容易写错的事:**metadata 契约**(action/group/target 头名与**精确**方法路径)、**回执解析**(proto3 省零 ⇒ 字段缺失即 0,不是"未知")、**订阅断线的退避重连**,且授权类错误(7/16/3)**不重试**——重试只会把真问题掩埋成"一直连不上"。
- **Rust**(`sdk/rust/naway-edge-client`):基于 hyper/h2,无 prost/tonic。刻意**不进网关 workspace**——P1 制品门依赖稳定的依赖解析,拉进同一个 lock 会让 feature 统一影响网关二进制。4 个单测 + 1 个起真实网关进程的联调用例。
- **Java**(`sdk/java`):基于 grpc-java 真栈(正确处理 trailer/状态码/deadline,可与使用方既有 channel、拦截器、TLS 约定整合),但**不做 protoc 代码生成**——回执是平坦 varint 结构,手写 marshaller 避免了平台相关的 protoc/protoc-gen-grpc-java 构建期依赖。5 个单测 + 1 个联调用例。
- **端到端联调抓到两个真 bug**,这正是"必须和真网关对上"的价值:
  1. Rust SDK 的默认 target 头名写成了 `x-naway-target`,而网关默认是 **`x-naway-target-user`**,导致 push 拿到 `3 push-requires-target-header`。两个 SDK 的默认值现已对齐网关。
  2. 联调 fixture 里给一条 route 写了两个 `Path` predicate 想表达"或"——predicate 是 **AND** 关系,永远匹配不上,于是返回 404 HTML 页,而 SDK 把 HTML 首字节当成了压缩位,报出"不支持压缩帧"这种完全误导的错误。**顺带修好了 SDK**:非 `application/grpc` 响应现在直接报"这不是 gRPC 响应,请检查方法路径与 route 的 grpc_edge.methods 是否一致"。
- 联调覆盖:订阅 → 群播 → **逐字节一致**收到;离线 push 返回 `accepted=0` 且**不报错**(无离线堆积);越权订阅立即拿 `PERMISSION_DENIED` 且**不进重连循环**(超时即判失败,防止把不可重试错误当可重试)。
- 新增 `tests/scripts/sdk_gates.sh`:两个 SDK 都在网关构建单元之外,`cargo test` 带不到,没有这个脚本就等于"有 SDK 但没人验"。脚本先替端到端用例构建网关二进制,确保跑的是真链路而不是静默跳过的空壳。
- 门禁:SDK gates ALL PASS(Rust fmt+clippy+5 测,Java 6 测);主仓 fmt 干净、all-features **385 passed / 0 failed**,未受影响。

### V8-9 对外 `.proto` wire 契约（2026-08-04）

补上 gRPC 边缘架构四项缺口的第二项。此前对外契约只以 架构规范 的文字描述 + golden bytes 单测存在,接入方需自行照描述写 proto,极易错位。

- 新增 `proto/naway/edge/v1/edge.proto`:`NawayEdge` 四个方法(Subscribe / Publish / PublishStream / Push)与四个消息(SubReq / FramePush / PublishSummary / PushSummary)。
- **从既有实现反推,不是另起炉灶**:字段号与 proto3 省零语义由 `edge_hub` 的手写编码器决定。为此把调用点的裸数字提成具名常量 `edge_hub::summary_field`(ACCEPTED=1 / DROPPED=2 / CLOSED_SLOW=3 / MESSAGES=4 / PEERS_ACCEPTED=5 / PEERS_REJECTED=6 / PEERS_UNKNOWN=7),`proxy` 侧一律用别名引用,禁止再写裸数字。
- **新增契约锁死用例 `edge_proto_matches_wire_contract`**:`include_str!` 读入 `.proto`,抽出每个 message 的 (字段名, 字段号) 与 Rust 常量逐一比对,并断言 `PushSummary` 的 `reserved 2, 3, 4;` 仍在。**这是本项最关键的部分**——网关刻意不引 prost,回执由手写编码器产生而接入方照 `.proto` 生成 SDK,两侧独立演进时改一边不会有任何编译错误,SDK 会**静默把值解析到错误字段**。用例还固定了省零编码的 golden bytes(`[0,0,0,0,4,08,02,20,01]`),锁死"字段缺失 = 0 而不是未知"这条解析方必须遵守的语义。
- 刻意**不引入 `prost-build`**:它需要外部 `protoc` 二进制,会让门禁的可复现性依赖开发机环境,代价远大于收益;朴素文本解析足以达成"防漂移"这个唯一目的。
- `.proto` 注释里写清了三件容易踩错的事:①路由与身份**不在消息体里**(group/target/action 走 metadata,tenant/user 只取自已验证 principal,客户端自报一律不采信,越权返回 7);②`FramePush` 网关**不反序列化**,只有"订阅响应类型与发布请求类型必须是同一 wire message"这一条硬约束;③所有计数止于"已进入散出队列",**没有任何字段表示终端已收到**——这也是刻意不用 `delivered` 命名的原因。
- 门禁:fmt + clippy(all-features)干净,三形态 **350 / 384 / 385 passed,0 failed**。

### V8-9 边缘面发布/订阅授权策略（2026-08-04）

补上 gRPC 边缘架构四项缺口中的安全项。此前相位 4 只解决了"你是谁"——身份一律取自已验证 principal(JWT claim 或已认证 consumer),客户端自报 header 永不作数——但 `group`/`target` 是**客户端给的**,只过了长度与字符集校验,于是**同一租户内任何已认证用户都能订阅任意 group、任何已认证服务都能向任意 group 发布**。

- 新增 route 级 `grpc_edge.authz`,三个 action 各自独立:`subscribe_groups` / `publish_groups` / `push_targets`。判定点在**相位 4 之后、任何订阅登记/散出/入队之前**,拒绝时返回 `7 PERMISSION_DENIED` 且**不回显 group**——否则"存在但无权"与"不存在"可被区分开。
- **全局 deny-by-default**:edge route 必须显式配置 `authz`;块内每个 action 独立判定，**空列表 = 全拒**，刻意公开也必须写 `*`。给本 route 未开放的 action 写规则直接构建期报错。
- 模式语法:字面量、末尾 `*`、`%{user}` / `%{tenant}`(均取自已验证身份)。构建期编译成片段,运行期**逐段比较、零分配、不拼接字符串**。`*` 只允许收尾——中置等于引入回溯匹配,既有代价又难审查。
- **踩到并封死一个真实的静默陷阱**:变量前缀刻意用 `%{}` 而非全仓通用的 `${}`。gateway.yml 加载器会先把 `${NAME}` 按环境变量解析,实测把 `user.${user}` 静默替换成了 `user.tour`(本机登录用户名)——**同一份授权配置在不同机器上放行范围不同,且毫无提示**。现在模式里出现 `${` 会在构建期直接报错并提示改用 `%{}`,并有专门的回归用例锁死。
- **WS 桥接同步覆盖**:桥接只换传输外壳,少这一段就等于留一条绕过 group 策略的旁路(HTTP 语义下返回 403)。
- 测试:2 个契约单测(缺省不限制 / 空列表全拒 / 变量绑定已验证身份 / 换个人进不去别人的 group / 末尾通配吞空 / 前缀不能沾边就放行 / 五类坏规则构建期拒绝)+ 1 个真实链路集成用例,后者除了正反例还断言**被拒请求不创建 group**——否则攻击者可用探测请求从资源占用反推 group 是否存在。门禁:fmt + clippy(all-features)干净,三形态 **350 / 383 / 384 passed,0 failed**。
- 同轮补齐 `架构规范` §25.2.2b **对外产品语义**:at-most-once(不重传,靠 payload 的 seq/event_id + 后端补拉)、**无离线堆积**(用户不在线时没有任何队列为其保存,重新上线不补发)、**无最终客户端 ACK**(`PublishSummary` 止于"已进入散出队列",不代表终端收到)。并写明适用/不适用场景,避免集成方按 MQ 直觉产生错误预期。

### 本地优化穷举：七条路径全部实测否定（2026-08-04）

锁定 h2 根因后,系统性排查"不改依赖也能拿到的收益",**逐条实测,全部否定**——记录下来是为了防止后续重复投入:

1. **学 envoy 用更少上游连接**(靠单连接大批量写):1/2/4 = 13381/16895/18118 rps,**越少越差**,方向相反。
2. **加更多连接分散锁**:16/32/64 = 19549/19589/19050,**16 已饱和**,出厂默认恰在平台点。
3. **加大 H2 流控窗口**以减少 WINDOW_UPDATE(每次都要拿锁):stream window 64K/256K/1M = 72015/70773/**63057** rps,**加大反而更差**——gRPC Echo 是小消息,窗口从不耗尽,加大只增内存压力与局部性损失。当前默认 65535 即最优。
4. **`upstream_uri` 每请求 `format!` + 完整 URI 重解析**:估算 100~150 ns,占 full-proxy **54.75 µs/req 的 0.2%**;要消除需改 8 个调用点并在实例上预存已解析的 scheme/authority。**收益不抵风险,不做。**
5. **遥测关闭态的每请求成本**:已是 thread-local splitmix64(无系统调用)、单次 106 字节分配同时供 W3C 与 B3、编译期 HeaderName——已优化到位。
6. **响应体逐帧读时钟**:`CountedBody::poll_frame` 已显式跳过同步 ready 帧的时钟读取。
7. **实现与配置不符**:负载下 `lsof` 实测上游 **16** 条连接、下游 **8** 条,与配置精确一致,无问题。

另:`prepare_attempt_parts` 的 `base_parts.clone()`(整个 HeaderMap)**不能去掉**——它在重试循环内,下一次尝试必须拿到未被改写的原始 parts。

**结论:每请求的我方逻辑总和远小于 1 µs**(与路由计划实测 0.010 µs 相互印证),而 full-proxy 是 54.75 µs/req。**本地已无有意义的优化空间**;后续投入只应放在依赖层,不要再在路由/header/URI/遥测方向上找——这些已被量化排除。本轮**未改动任何生产代码**,门禁维持 348/380/381。

### gRPC 性能差距根因定位：h2 crate 每连接一把阻塞锁（2026-08-04）

- **先证伪一个调参假设**:envoy 默认把全部并发流压在一条上游连接上,我们默认 16 个 shard,原以为它靠单连接大批量写占便宜。扫描 `h2_connection_shards_per_upstream` ∈ {1,2,4,16,32,64} 结果**完全相反**:gateway 13381 / 16895 / 18118 / **19549** / **19589** / 19050——**越少越差,16 以上已饱和**,当前默认即最优,**调参拿不到任何收益**。
- **根因(直接栈证据)**:`h2::proto::streams::Streams::poll_complete → std::sys::unix::sync::mutex::Mutex::lock → __psynch_mutexwait`。`Streams` 内部是 `Arc<Mutex<Inner>>`,一条 H2 连接的全部流状态由一把**阻塞** mutex 串行保护,线程真的挂在内核等锁上。(我们自己的热路径用 parking_lot,在 macOS 走 `__ulock_wait`;pthread mutex 只可能来自 h2/std。)
- **两组独立数据印证**:①上游连接数 1→16 提升 46%,即"锁变多、争用分散"的收益;②§4.2 归因表里同为 64 并发,`downstream-static` 1×64=52508 vs 8×8=152842(**2.9×**),而**不经我们**的 `backend-direct` 是 61028 vs 207329(**3.4×**)——形状一致。
- **结论:这是 hyper/h2 栈的特性,不是 naway 代理逻辑的问题**(路由计划 0.010 µs/req 早已排除)。**gRPC 90% 线靠调参或本地重构到不了**,必须走依赖层。据此把 §4.3-2 从"不可实施"修正为"**收益空间很大但在依赖里**",应排期评估向 h2 提改进或替代实现;按 §4.3-6 仍不自行 fork。
- **诚实边界**:这把锁占剩余 19~22% 差距的**具体比例未确立**——`sample` 的叶子归因会把 tokio runtime 脚手架帧算成叶子,不可用;要定量需要真 profiler(A4 的已知阻塞项)。
- 同轮更新 §4.2 归因表(改用长窗口口径 400k/请求):8×8 下 full-proxy 54.75 µs cpu/req、downstream 24.93、**上游侧 29.82**——上游腿没有 TLS 也没有路由匹配却比下游腿更贵,与上述锁争用一致。

### 撤回：L4 TCP 超越项未确立（2026-08-03，长窗口复测）

- 400k×7 那轮 gateway CV 0.249 / envoy 0.178 超门判 INCONCLUSIVE,按方法学拉长到 **800k×9 轮**重跑,三家 CV 降到 0.108/0.052/0.052 全部达标。
- 结果:gateway 36101 / nginx 34583 / envoy 34042 → 对最强对手 **1.0287 但逐轮只赢 5/9(p=0.50)**;对 envoy 1.0605(7/9,p=0.090)、对 nginx 1.0439(6/9,p=0.254)。**中位数占优而逐轮胜率撑不住**——gateway 的分布更宽(CV 0.108 vs 对手 0.052),高峰高但也有低轮。按 A2 三条判据不得宣布超越,旧记 **1.0610 撤回**。
- 诚实边界:对 envoy 的 p=0.090 说明"可能存在小幅优势",加轮数或许能判到显著,但**不得先行宣布**。
- **三个预声明超越项的最终状态:WebSocket ✅ 成立(1.0300,p=0.033);h1 ❌ 不成立(0.9584);tcp ❌ 未确立(1.0287,p=0.50)。**

### 撤回：h1 keep-alive 超越项不成立（2026-08-03，长窗口复测）

- 长窗口 3 方(每 case ≈14 秒,`A2_REQUESTS=400000`,7 轮交错,三家 CV 0.076/0.033/0.051 全达标):gateway 27392 / nginx 27311 / envoy 27671 → **对最强对手 0.9584**、对 envoy 0.9899(2/7 胜)、对 nginx 1.0030(4/7 胜,p=0.50)。
- 结论:长窗口下 h1 是**三家打平且略输 envoy**,此前的 **1.0455 撤回**。三个预声明超越项目前只有 **WebSocket(1.0300,长窗口静默机)成立**,tcp 待长窗口复测(400k 那轮 gateway CV 0.249 / envoy 0.178 超门,已按方法学拉长到 800k×9 轮重跑)。

### 撤回：Envoy 90% 最低线并未达标（2026-08-03，长窗口复测）

**今天早些时候记录的 gRPC ratio 0.9612「Envoy 90% 达标」是短窗口假象,现予撤回。**

- 长窗口复测(每 case ≈20 秒,`A2_REQUESTS=400000`,8×8,7 轮交错,四家 CV 全部达标):
  - **3 方**:gateway 19063 / nginx 19878 / envoy 22875 → **对 envoy 0.8334**、对 nginx 0.9590;CV 0.037/0.040/0.070。
  - **4 方(含 Higress)**:gateway 19548 / nginx 19375 / envoy 24113 / higress 23017 → **对 envoy 0.8107、对 higress 0.8493**;CV 0.063/0.025/0.044/0.056。逐轮 **0/7** 胜,不是噪声。
- **归因已用对照实验分离**:变量不是"多了一个 Higress 容器",是**窗口长度**。gateway 在三种环境下稳定在 19~20k,而 envoy 随窗口拉长 21097 → 22875 → 24113(+14%)。**短窗口测的是 Envoy 还没进入稳态的样子**,1 秒的测量窗对它是系统性惩罚。
- 因此:**gRPC 上 Naway ≈ Envoy 的 81~83%,也低于 Higress(85%)、略低于 NGINX(96%)**。§4.1 的 90% 最低线**未达标**,发布判断相应回退。
- 同一原因,h1(1.0455)与 tcp(1.0610)的短窗口超越结论一并存疑,已排入单协议长窗口复测。**WS 不受影响**——它的 1.0300 本来就是长窗口(600k/case)静默机测得,四家 CV 达标。
- 顺带留档一次失败尝试:四协议 × 四方一次跑完的组合**整轮 INCONCLUSIVE**(gateway CV 0.16~0.29,连 envoy/higress 自己都超门),说明该负载已超出本机稳定测量能力。对策是**每次只测一个协议**,不是加轮数。

### V8-3 C8 relay 面散出预算改为显式配置（2026-08-03）

- **修掉一处本地与跨节点行为不一致**:relay 收到的 record 来自对端节点、不经本地路由匹配,因此没有 route 计划可依,此前硬编码 `GrpcEdgeLimitsCfg::default()`。后果是运维把某条 route 的 `grpc_edge.limits` 调大之后,**本地发布放宽了,而同一条消息经 peer 中继仍按默认值被拒**,且没有任何配置能改。
- 新增 `grpc_edge_cluster.fanout_limits`(与 route 级 limits 同形),走**同一套**范围校验与「payload 预算至少容得下一条最大帧」交叉约束。**刻意不从各 route 取并集**——那是隐式推导,改一条 route 会静默改变整个集群面的准入,审查时看不出来;要放宽必须在集群块写明。不配置即维持既有默认,已部署行为不变。
- 三个配套约束:
  - `build_limits` 的报错路径参数化,集群块的错误指向 `grpc_edge_cluster.fanout_limits.*` 而不是某条 route;校验放在值校验段**末尾**,既保持「值校验先于 feature 门」(三形态报错一致),又不抢身份/拓扑等更根本字段的报错优先级。
  - `max_msg_bytes` 恒为协议硬上限、不可配置放宽,并加**编译期断言**钉死 `RELAY_MAX_PAYLOAD_BYTES - 5 == RELAY_FANOUT_MAX_MSG_BYTES`——否则会出现「配置校验通过、解码层仍拒收」的死角。
  - 预算变更判为**拓扑变化拒绝热更**:`EdgeRelay` 持有启动时那份 `Arc<Plan>`,若判"可继续服务",reload 会成功但新预算永远进不了运行态(静默失效)。
- **`fanout_limits` 刻意不进 `config_fingerprint`**:指纹是防两端队列/顺序语义劈叉的协议契约,而散出预算是节点本地容量。不同规格的节点本来就该有不同预算,收方按自己预算准入、超出经 summary 的 `dropped_budget` 如实回报;若纳入指纹,给单节点扩容就会裂开 mesh——与"成员滚动不应硬分裂"同一条理由。
- 门禁:fmt + clippy(含 all-features)`-D warnings` 干净;三形态 t4 全量 **348 / 380 / 381 passed,0 failed**。

### A2 WebSocket 超越项确立 + 判据方法学修正（2026-08-03）

- **WS 超越项达成**:11 轮 × 600k msg/case 静默复测,gateway 中位数 36516 rps、CV **0.034**;对 nginx ratio **1.0471**(逐轮 9/11 胜,符号检验 p=0.0327)、对 envoy **1.0680**(11/11,p=0.0005)、对最强对手 **1.0300**(p=0.0327)。三个预声明超越项中最后一个悬而未决的,现已确立。
- **两个独立缺陷被定位并修掉**:
  1. **稳态窗口太短**。此前 `A2_REQUESTS=20000/30000` 在 WS 上每个 case 只跑 **0.9~1.9 秒**(报告 `elapsed_ms` 直接可见),一次 200 ms 调度打嗝即甩掉 20%,于是三方 CV 0.249/0.341/0.266 全部超门。提到 600000(每 case ≈17 秒)后 CV 降到 **0.034/0.063/0.108**。**加轮数救不了,拉长窗口能救。**顺带否掉一个直觉:逐轮**比值**不能抵消噪声——三家是**顺序**跑的不是同时,比值是两个独立噪声相除,实测 raw CV 0.249 时 gateway/nginx 比值 CV 反而 0.429。
  2. **判据错配**。预声明超越幅度(+1.4%)小于单实现 CV(0.05)时,**中位数比较在原理上判不出来**。新增 `tests/scripts/a2_paired_verdict.py`:利用 `a2_compare.sh` 同轮轮转执行的事实做**逐轮配对符号检验**(精确二项,不用正态近似——n=9 时近似误差足以改变 0.05 边界上的判定),三条全满足才算超越(CV 达标 / ratio>1 / 单尾 p<0.05)。
- **一次自伤必须留档**:同参数的**前一轮**(9 轮)结论是"对 nginx 打平(5/9,p=0.50)",唯一差别是那轮跑的时候本机在做 cargo build 和全量测试。**在这台机器上,测量期间的本地构建足以翻转结论**——此后进发布判定的数字,跑之前确认机器空闲、跑之中不编译不跑测试。
- **连带影响(尚未解决)**:h1(1.0455)与 tcp(1.0610)的旧数字同样出自 20k 短窗口且只做了中位数比较,按新方法学不可信,已排入长窗口四方复测,不能对 WS 用严标准而对它们用松标准。

### P0-3 C2b Console 上游拓扑面板（2026-08-03）

- 集群页新增**上游拓扑**面板:每个服务一行(服务名、`critical` 标记、来源 static/nacos/consul/eureka/dns/kubernetes、**LB 策略**、被哪些 `proxy/route` 引用、`可选/总数`),下挂实例明细行(URI、backup、TLS 及 SNI、非 1 权重、DOWN/可选/不可选)。
- 后端 `/admin/upstreams` 补两个字段:`lb_policy`(新增 `LbPolicy::as_str`,刻意输出 `first`/`round_robin`/`least_conn` 这三个**规范**写法而非 `wrr`/`least-conn` 别名,使视图输出可原样写回配置)与 `selectable_count`(与 `instances_for` 同一份可用集,再扣 down/未 healthy——管理面要回答"现在还有几个能被选中",不是"目录里登记了几个")。
- **口径诚实性**:该视图的 `healthy` 是**发现态**(静态 yml 标记或注册中心 last-known-good),**不含主动探测结果**——后端原注释已说明主动探测判死由 `/metrics` 的 `gw_upstream_healthy{service}` 反映、不并入此视图以免管理面与探测器强耦合。因此前端一律用"可选"而非"健康"措辞,且不可用时的空态直接点明去 `/metrics` 看主动探测。
- 真机验证:`least_conn` + critical + weight=3 + backup 实例的配置下,接口返回 `lb_policy/selectable_count/weight/backup/route_refs` 齐全;重建后 `/` 与 `/ui/app.js` 均可取到新面板。门禁:fmt + clippy 干净,三形态 t4 全量 **347 / 379 / 380 passed,0 failed**。

### P1 轻量制品量化门：五门全过，且原「必须 feature 拆分」的前提被实测推翻（2026-08-03）

- 新增 `tests/scripts/p1_artifact_gates.sh`,把 验收记录「一、6」的目标做成可复现门:G1 strip 二进制 ≤50 MiB、G2 冷启动 ready ≤2s、G3 idle RSS ≤64 MiB、G4 零外部依赖 all-in-one smoke(不接 Nacos/Redis/Kafka/sidecar,起最小 python 上游真实转发一次)、G5(可选,需 Docker)压缩 OCI 镜像 ≤80 MiB。每次运行按 label 追加 `target/p1-artifact-gates.jsonl`,任何后续改动都能前后对照。
- **实测(默认 feature):** 二进制 34.36 MiB(未 strip 40.61)、ready 1312~1727 ms、idle RSS 20.86~23.61 MiB、smoke 通过、OCI 压缩 48.98 MiB —— **五门全过**。
- **实测(全 feature `grpc-edge,redis-runtime,nacos-sdk,log-kafka`):** 44.64 MiB / 1661 ms / 25.59 MiB / smoke 通过 —— **同样全过**。
- **必须如实记的反向结论:** P1 章原本假设"重能力(wasmtime/Casbin/OTel/Kafka/Redis/Nacos)必须逐项 feature gate **才能**达标"。实测证明该假设不成立——不拆分即全过,连全 feature 也过。因此 **core/full 拆分的正当性从"达标必需"降级为"次级收益"**(缩小攻击面、压 ready 余量),要不要做应作为产品决定重议,不能再以"否则达不了标"为由推进。五项里余量最紧的是 ready(1.3~1.7s 对 2s 门只余 14~35%)。
- 修一处会让 G5 直接失败的问题:`Dockerfile` 的构建上下文是 **`rust/` 父目录**(要同时 COPY `naway` 与路径依赖 `nasa-runtime-rust`),在仓库目录内 `docker build .` 会报 `"/naway": not found`;脚本改为 `cd repo/.. && docker build -f repo/Dockerfile .`。
- 诚实边界:测量在 macOS 原生进程;镜像体积以 `docker save | gzip` 近似 registry 传输量;ready 含 macOS 首次页错误开销,Linux 容器内应更低。门禁:fmt 干净,t4 全量 347 passed / 0 failed。

### P0-2/P0-3 Console 前端：配置发布闭环与集群收敛页（2026-08-03）

- 配置面板由"只能 dry-run"升级为**编辑-发布闭环**:载入按钮取回线上 gateway.yml 并显示 `version / source / ETag`;发布按钮携 `If-Match` 走 CAS。**412 冲突单独分支**——提示 rebase 并用响应回带的当前 ETag 替换本地值,不让用户拿着过期 ETag 反复盲发。发布结果按三态区分:`applied`(网关已确认换版,不是"已调度 reload")、`published`(Nacos 集群 CAS 成功,转 rollout 面板看收敛)、`pending`(已提交但未确认)。ETag 只保存服务端给的那一个,绝不自行拼造。
- 新增集群页两个面板:**节点收敛表**(node_id/地址、版本、**指纹**、启动时间、UP/UNHEALTHY/DISABLED),状态按后端口径显示 `CONVERGED`/`DIVERGED`/`UNKNOWN FINGERPRINT`——同版本不同内容不会被显示成"已收敛";**rollout 进度表**按后端 pending 名单标 PENDING/APPLIED。单机部署下两接口分别返回 409/404,前端降级为"仅 Nacos 集群可见""尚未发起集群发布",不伪造视图。
- 真机验证:资产内嵌于二进制,重建后 HTML/JS 新控件与新逻辑均可从 `/` 与 `/ui/app.js` 取到;`GET /api/config/current` 返回 200 + ETag。门禁:fmt + clippy 干净,t4 全量 0 failed(347)。
- WebSocket 超越项复测结果**不可用**:11 轮 30k 那次三方 CV 0.248/0.341/0.266 全部超门、`stable=false`,整轮作废(ratio 0.8921 无意义)。**WS 超越项因此仍未确立**——7 轮那次虽 stable 但 +1.4% 落在 CV 0.053 噪声内。已在 验收记录 A2 如实标注,需更安静环境或更长稳态窗口重测。

### P0-4 §4.1 三方对照首轮权威实测：Envoy 90% 最低线达标（2026-08-03）

- **更正一个错误前提**：此前把三方对照标为"需另找固定 Linux 基准机"是判断错误。本机 Docker Desktop 的 engine 就是 **linux/arm64**，而 `a2_compare.sh` 的设计正是把 Naway/NGINX/Envoy/Higress 与全部后端放进同一 Docker network 的容器里同轮交错跑——那就是它的基准环境；三个 pinned digest 镜像（nginx 1.27-alpine / envoy v1.35.3 / higress v2.2.1）已在本地。此前遇到的 2~3% 漂移属于 **macOS 原生进程**（`p04_*` 工具），与容器内交错对照是两回事。
- **实测结果（7 轮交错，20k req/轮，Higress 未纳入）**：gRPC 8×8 H2C gateway 20279 rps vs envoy 21097 → **ratio 0.9612**，三方 CV 0.029/0.054/0.067 全部 <0.15、`stable=true`——**Envoy 90% 最低线达标**，验收记录 旧记的 75.79% 作废。三个预声明超越项：h1 keep-alive **1.0455**、L4 TCP **1.0610** 达成；**WebSocket 稳态 1.0138 的 +1.4% 落在 CV 0.053 噪声带内，按 A2 口径不算"稳定超过"，标为待复测**。
- 诚实边界写入 验收记录：本机 arm64 VM 与历史 75.79% 那次的宿主/架构不同，两者不可直接相减（旧数字作废而非"提升 20 个点"）；Higress 四方对照与 10k WS 四阶段容量矩阵仍待补。
- 相应地，§4.3 候选 A/B 的载体建议改用 `a2_compare.sh`（control 镜像 vs candidate 镜像、同轮交错、自带 CV 门），原生 `p04_*` 工具保留做 CPU 归因与自比。

### P0-4 §4.3-2/3 候选评估与测量方法学修正（2026-08-03）

- **第 2 项(sender→driver batching)判定为不可实施**:上游 direct sender 就是 `hyper::client::conn::http2::SendRequest`，sender→driver 唤醒完全在 hyper/h2 内部；我们自有的 `Notify` 只用于冷启动门与 idle 回收，不在每请求唤醒路径上。按 §4.3 第 6 项（禁止无确定收益的私有 h2 fork），只能走官方栈升级，且须先有 Linux perf 的 poll/wake 计数。
- **第 3 项(上游 shard 局部性)已实测并回退**:候选把 shard hint 由 per-request 改为 per-connection（同一下游连接固定落同一上游 shard，不减并行度，与被证伪的 §4.3-1 钉扎有本质区别）。两次 7 轮实测**互相矛盾**——首次 h1-tls −13.4%/h2 −9.0% 判 REGRESSED，同一二进制复跑 h1-tls **+3.0%**/h2 −0.5% 全部 ok。按 A2 口径记 INCONCLUSIVE；§4.4 要求 CPU/request 至少下降 5% 才可采纳，故回退，不在树上留未经证实的改动。
- **方法学修正(本轮最有价值的产出)**:本机不具备判定 3% 门的分辨率——顺序跑完 control 再跑 candidate，整机基线会漂 2~3%。`p04_compare_baseline.py` 因此增加**漂移哨兵**:tcp(L4) 不经过 HTTP 转发链，任何 HTTP 侧候选都不该改变它，tcp 移动超过判据阈值一半(1.5%)即警告"该对比不足以判定"。哨兵上线后回看历史对比，§4.3-1 的 reverse-control 那次(tcp −3.0%)同样会报警，故此前"reverse-control 证明回退干净"修正为**与干净回退一致但不构成证明**。
- 下一步定为方法学优先:先把基线改成同一次运行内 control/candidate **交错**，或迁到固定 Linux 基准机；在此之前不再判定任何 §4.3 候选。

### P0-4 §4.3-1 connection affinity 候选：实测拒绝并已回退（2026-08-03）

- 按 §4.3 第 1 项做了"可关闭、可 A/B 的最小原型"：pinned 单线程 runtime 池，accept 后按轮转把整条下游连接的 future 固定到某线程，env 开关、默认关、不改协议语义。
- A/B（control → candidate → reverse-control，各 7 轮）：h1-tls −6.0%、h2 **−21.0%**、ws −12.3%，判据链输出 `REJECT`。**已按 §4.4 回退**：生产挂钩与原型模块整体删除，reverse-control 复测五项回到基线（最大偏差 −3.0%，噪声带内）。
- 结论比数字更有价值：**per-connection 线程钉扎在 1×N 拓扑上是结构性错误**——我们想修的正是"单连接承载 64 个并发 stream"，而钉扎把这 64 个 stream 压到一个核上，越是目标形态伤得越狠。h2 的 cpu/req 反而从 86 降到 52 µs：瓶颈不是 CPU 效率而是并行度。§4.3 第 1 项的假设（迁移开销主导 1×64 劣势）被实测**证伪**。
- 方法学修正：§4.2 归因矩阵**不能**用于跨运行 A/B——同一次对比里不经过网关的 `backend-direct` 也掉了 40%，说明机器状态不同；该矩阵单轮无 CV，只适合同一次运行内做减法，跨运行判定必须用 §4.1 的多轮 + CV 基线。
- 剩余候选：§4.3 第 2 项（减少跨 worker wake/poll 的有界 batching）不牺牲并行度，与本次证伪不冲突，仍成立；第 4 项 fast-path 编译计划已被 §4.2 数据判掉。

### P0-4 §4.1 分协议保护基线与回退判据链（2026-08-03；core 发布链，只测量不改生产模块）

- 新增 `tests/scripts/p04_protect_baseline.sh`：网关**自比**多轮基线（h1 / h1-tls / h2 / ws / tcp 五条受保护路径），每协议丢弃一轮预热后跑 N 轮，逐轮记 throughput、p50/p99、网关 CPU-seconds、RSS 峰值，汇总中位数与 CV；CV 超门限只记 INCONCLUSIVE，不挑单轮峰值。不依赖三方容器——三方对照仍由 `a2_compare.sh` 在固定 Linux + Docker 承担。
- 新增 `tests/scripts/p04_compare_baseline.py`：执行 §4.4 判据「任一受保护协议中位数回退 >3% 即拒绝候选（即使 gRPC 上升也默认回退）」，任一侧 CV 超限则该协议记 INCONCLUSIVE，退出码可直接用于阻断。已用**注入 −10% 的假候选**验证它确实会 REGRESSED + 退出 1，而不是永远放行。
- control 基线（本机，7 轮，30k req/轮，并发 64）：h1 67318 rps（CV 0.037）、h1-tls 70159（0.031）、h2 43647（0.017）、ws 74943（0.020）、tcp 75465（0.009）。h2 一项与 §4.2 归因的 full-proxy 1×64（41.7k rps / 97.2 µs cpu/req）同量级，两套工具互为交叉验证。
- 修正两处会让基线失真的配置：TLS 材料改用 CA→server 两级链（自签叶证书带 CA:TRUE 会被 rustls 以 `CaUsedAsEndEntity` 拒绝）；上游连接池上限放开到与并发匹配（默认 64/128 会把 64 并发压成 6k rps / 139ms p99，测到的是排队深度而非协议成本）。

### P0-4 §4.2 双 H2 单位 CPU 归因脚手架与首轮结论（2026-08-03；core 发布链，只测量不改生产模块）

- 新增 `tests/scripts/p04_h2_cpu_attribution.sh`：四个测量模式（plan-only 进程内路由计划 / backend-direct 直连后端 / downstream-static 网关静态响应 / full-proxy 完整双 H2）× 三种下游 multiplex 拓扑（1×64、4×16、8×8），共用同一后端与 payload，输出 RPS、p50/p99 与**网关侧 µs CPU per request**，并自动做"上游侧 ≈ full − downstream"的减法归因。
- `local_a2_benchmark` 新增 `plan-bench` 子命令：用真实 gateway.yml 构建真实 Snapshot 后，在进程内反复驱动 route/filter 计划，**不开 socket、不走 H2、不碰 body**，用 `getrusage` 取自身 CPU；H2 客户端补 `--connections`，让 worker 可共享物理连接以表达真实 multiplex 拓扑。工具全部只在 `tests/`，生产 `src/` 不含 profiler 分支。
- 首轮归因（本机原生，100k req/档，绝对吞吐不作发布判定）：**路由计划 0.010 µs cpu/req**，而全链 58~97 µs/req——业务 L7 管线与热点差三个数量级；上下游两侧成本相当（27.9 vs 31.4 µs）；**1×64 是最差拓扑**（97.2 µs/req，约为 8×8 的 1.7 倍）。
- 据此按 验收记录 §4.5 决策树定序：route/filter 微优化与 fast-path 编译计划**明确不做**（收益上限就是那 0.01 µs）；两侧均高 → 官方协议栈升级仍在候选；**下一步先做可 A/B 的 connection affinity 最小原型**，用同一脚本复测 1×64 的 µs/req 是否下降。结论与缺口（poll/wake 与 HPACK 细粒度计数需 Linux perf；三方对照须固定 Linux 重跑）已写入 验收记录 §4.2。

### P0-3 集群 rollout 闭环与指纹级收敛判定（2026-08-03；core 发布链）

- `GatewaySnapshot` 新增 `config_fingerprint`（**已上线**配置集指纹），自注册 metadata 随之增加 `gateway.fingerprint` 与 `gateway.started_at_ms`（启动时刻只取一次，注册 payload 每次 refresh 带同一值，避免把同一节点误判成"刚重启"）。
- 集群收敛判据收紧为 **(version, fingerprint) 双一致**：同版本号不同内容（某节点从别处物化了不同配置）此前会被判成"已收敛"，现在报 `diverged`；enabled 成员未上报指纹时判 `fingerprint_unknown` 而不是谎称收敛。
- Nacos 配置源下 `PUT /api/config/current` 走**原子 bundle CAS**：只替换 gateway 文档、另两份取当前线上归档，保证 bundle 永远是完整一致的三件套（watcher 不会读到新旧混合配置）；发布前先本地 build-only 预校验，坏配置绝不进集群事实源；CAS 成功生成 rollout id（进程内有界登记，重启归零——事实源仍是 Nacos + 成员表）。三 dataId 兼容模式明确 409，不用多次单 dataId CAS 冒充事务。
- 新增 `GET /api/cluster/rollout`：逐节点判定并给出 pending 名单，状态为 `in_progress`/`diverged`/`fingerprint_unknown`/`succeeded`——**全部 enabled 节点版本越过 base 且 (version,fingerprint) 一致才算成功**。刻意不预测"期望指纹"：各节点物化后的指纹还取决于本地依赖文件，发布端算不出，集群自身收敛到的值才是唯一诚实的期望值。
- 测试：4 条 rollout 判定单测 + 2 条集群一致性单测（分叉检测、未知指纹不收敛）+ 集成用例（Nacos 源缺 bundle_data_id → 409 且本地物化文件一字节未动；未发起 rollout → 404 不编造结果）。门禁：fmt + clippy 四形态 `-D warnings` 干净；三形态 t4 全量 0 failed（default 347 / grpc-edge 379 / all-features 380）。
- 已知缺口（验收记录 P0-3 留档）：节点级 QPS/5xx/活跃连接需跨节点认证抓取，未做；两节点 rollout 端到端 live 用例未跑通（Nacos 3.x REST 播种与 SDK 鉴权不通，nasa 客户端只暴露 CAS 发布，测试无法预置初始 bundle）。

### P0-2 Console 配置发布闭环（本地/all-in-one）（2026-08-03；core 发布链）

- 新增 `GET /api/config/current`：有界读取当前主 YML，返回 `version` + `fingerprint` + `ETag`（也写进响应头）。ETag 取**整份配置集**指纹（含 OpenAPI/schema/WASM/文件型 SecretSource），依赖文件被旁路改动同样让旧 ETag 失效——CAS 语义是"你基于的整份配置状态"，不是单文件哈希。只在 full control-plane 开放。
- 新增 `PUT /api/config/current`：`If-Match` **强制**（缺失 428、失配 412 并回带当前 ETag 供 rebase）；`application/yaml` 有界收取；先写临时文件做 **build-only 候选校验**（坏配置 400，此时线上文件一字节未动）；再同目录 **原子 rename** 覆盖主 YML 并 SIGHUP 唤醒唯一 reload worker；最后**等待确认生效**——必须同时观察到目标版本的 history 成功事件与 ArcSwap 版本前进才返回 `applied`。被 reload 明确拒绝时**还原发布前文件内容**（保持"文件 == 线上快照"）并返回 400；观察窗口内无结论返回 202 `pending`，绝不谎称成功。
- 配置源为 Nacos 时 `PUT` 返回 409 并指向集群 rollout API：本地物化文件会被下次 watch 覆盖且不集群生效，不做"看起来成功"的写。集群 rollout（bundle CAS + rollout id + 逐节点收敛）与 P0-3 集群页面同批交付。
- 发布/冲突/拒绝全部进 RBAC（Config,Write）与持久防篡改审计；浏览器写请求继续受 Origin/Referer 限制。原子写复用 `reload::write_atomic`（提为 `pub(crate)`），不另造一份实现。
- 测试：真实进程闭环用例——GET 拿 ETag → 缺 If-Match 428 → 陈旧 If-Match 412 → 坏配置 400 且线上快照与文件均不变 → 合法发布 200 `applied` 且**数据面立刻切到新上游**（只写文件、只发 reload 都不算生效）→ 旧 ETag 重放 412。门禁：fmt + clippy 三形态 `-D warnings` 干净；三形态 t4 全量 0 failed（default 341 / grpc-edge 373 / all-features 374）。

### P0-1 gRPC L7 声明式 Header predicate（2026-08-03；core 发布链）

- 新增路由断言 `Header=<name>,<op>[,<value>]`，算子 `exact`/`prefix`/`present`/`absent`。构建期把 header 名编译成 `HeaderName`（HTTP 规范下名大小写不敏感，归一化为小写），请求期只借用 header 值切片比较——不建 map、不分配、**热路径不编译 regex**（`regex` 算子刻意不提供）。
- 安全语义写进实现与测试：**多值 header 任一值命中即命中，绝不拼接后匹配**（拼接会让 `a`+`b` 被 `a,b` 命中，是典型 header smuggling 模糊面）；`absent` 要求一次都不出现；**值大小写敏感**（值是 tenant/灰度标签这类业务数据，忽略大小写会串路由）；断言值必须是可见 ASCII，控制字符/CR/LF 一律构建期拒绝。
- 资源有界：header 名 ≤128B、期望值 ≤256B、每 route header 断言 ≤16 条且总断言 ≤32 条（每请求线性扫描，条数必须有界）。Header 断言进 `predicates_signature`，参与同 order 同断言集合的冲突检测；header 值不同即视为不同断言集合，可并存。
- 测试：4 条单测（算子与大小写矩阵、多值反 smuggling、解析拒绝矩阵含长度与控制字符、冲突检测与条数上限）+ 真实 h2c 集成矩阵（同一 listener 按精确 `:path` + metadata 分流两个 h2c 上游，`proxy_set_header` 改写透传到选中上游，`grpc-status` 跨 L7 保真，缺 header 落默认候选，`absent` 排除后 404 而非静默兜底，多值任一命中）。
- 门禁：fmt + clippy 三形态 `-D warnings` 干净；三形态 t4 全量 0 failed（default 340 / grpc-edge 372 / all-features 373）。

### V8-7/V8-8 gRPC 边缘模式：Redis SessionDirectory 与 Web WS 桥接（2026-08-03；V8 全阶段完成）

- **V8-7 SessionDirectory(redis，可选加速)**:新增 `grpc_edge_cluster.session_directory`(url/namespace/profile/prefix/ttl_ms/command_timeout_ms，逐项构建期校验，值校验先于 `redis-runtime` feature 门)与 `src/dataplane/edge_directory.rs`。key=`{prefix}:{cluster}:{tenant}:{user}` hash、**field=`node_id#boot_id#stream_id`**——旧连接的 on_done 只能删自己那条，结构上不可能误删重连后的新 lease(§25.2.7 generation-safe，无需 Lua)；多端=多 field，`locate` 返回节点集合；租约与订阅流同生共死(Drop 即摘除)，在线按 TTL/3 续租，崩溃由 TTL 兜底；命令全带硬超时。
- push 路径:命中→只打被寻址 peer(`push_to_nodes`)，目标只在本地→完全跳过 probe；脏条目(命中零投递)→回落一次全量 probe；miss/不可用→直接回落。**目录永不是正确性单点**:Redis 不可达时数据面照常启动，后台指数退避重连，连上即挂载。/metrics 补 `gw_edge_directory_leases` gauge 与 hit/miss/error/fallback counter。
- **V8-8 Web WS→gRPC 桥接**:新增 route 级 `grpc_edge.ws_bridge_path`(要求 allowed_actions 含 subscribe，路径合法性与 edge 方法路径互斥)与 `src/dataplane/edge_ws_bridge.rs` RFC 6455 服务端 shim。握手 Accept 用 `nasa::crypto::sha1` + 标准 base64;升级复用管线既有 `OnUpgrade`(连接预算 lease 一并移交)；**每条广播 = 一个 binary 帧，字节与 native gRPC 订阅者完全相同的 `[5B prefix + payload]`**;Ping→Pong、上行数据帧丢弃、入站读取有界;治理关闭映射 WS Close(policy/slow=1008，drain/max-age/idle=1001)。鉴权、身份、group 索引、队列预算、§6.1 注册表全部复用同一条订阅路径——只换传输外壳。
- 修复:`ConnGuard::ws_close_code()` 未关闭时也返回默认 1001，桥接把它当关闭哨兵会导致连接刚建立就自关——改用 `requested_close_code()`。
- 测试:目录契约单测(拒绝矩阵/默认值/none 忽略，三形态一致)、`edge_cluster` 死 Redis 三节点集成(网关照常起、定向 push 照常送达、目录未挂载)、live 命中用例(默认 ignored，断言命中时无关 peer 零 probe + 断开租约归零);`edge_matrix` 桥接矩阵(缺 group 自答 400、RFC 6455 金样 Accept、与 native 字节一致、Ping/Pong、close_by_consumer→1008 且索引归零)。
- **live 验证(2026-08-03,source.md 本机 docker 后端)**:全部 6 个 ignored live 用例对真实后端跑通——V8-7 目录命中(Redis `127.0.0.1:6379`,断言命中时无关 peer 零 probe + 断开租约归零)、V8-5 Nacos 成员 watch 与自注册发现(`127.0.0.1:8848`)、Redis 跨节点 HTTP/语义缓存与流式 RSS 有界。V8 链路不再只有 mock 证据。
- 门禁:fmt + clippy 四组合(默认/grpc-edge/grpc-edge+redis-runtime/all-features)`-D warnings` 干净;三形态 t4 全量 0 failed(default 335 / grpc-edge 367 / all 368);A2.4 默认路径三轮 48.4k/44.0k/46.7k RPS 对基线 48.0k(首轮紧接三套全量测试后测得 33.7k 属机器争用，静置复测恢复;按 A2 的 CV 口径记录，正式判定固定 Linux)。

### V8-6 gRPC 边缘模式：性能与资源门首轮基线（2026-08-03；最终 Linux 门见 2026-08-06 条目）

- 新增压测入口：`tests/support/local_edge_benchmark.rs`（fanout/slow/subscribe/publish 四模式独立 h2 客户端，5B 前缀增量收帧 + summary varint 解析，订阅者按 200 API key 轮转分摊 user）+ `tests/scripts/v8_edge_fanout_probe.sh`（三场景驱动；资源断言是硬门：快读者零丢、每档端态 payload/queue_refs/active_streams 三归零、慢消费者 RSS 增长上界、三节点收满 + relay 计数精确、mesh 收敛）。
- 本机参考基线（release，Apple Silicon macOS；正式门固定 Linux）：64B 阶梯零丢——1 订阅端到端 867k msg/s；100 订阅 3.52M 投递/s；1000 订阅 320k 投递/s；10000 订阅 265k 投递/s；1000×1KiB 393k 投递/s。慢消费者 20k×1KiB 突发 RSS 增长 9.4MiB（门 <64MiB），丢帧如实。三节点 2000 record 广播 peer_copies 恰 1,000,000、rejected/unknown 0、远端各收满 50 万、relay_sent 恰 4000。A2.4 默认路径 48.6k RPS p99 2.93ms vs 基线 48.0k/4.76ms，无回归（≤3% 门 PASS）。
- 基准口径：队列配到容下整段突发测无损容量；丢弃语义由慢消费者场景/集成/单测覆盖。Linux 正式门现已覆盖 100k 成员、64KiB 载荷、CPU/调度停顿、放大率多档、10k 流容量五轮 CV 与 RSS/FD drain，并在 2026-08-06 当前 release 上通过。
- V8-7 Redis SessionDirectory 与 V8-8 WS 桥接均已完成，真实 Redis/三节点和 native gRPC↔WS 同字节回归由各自独立用例覆盖。

### V8-3b/V8-4/V8-5 gRPC 边缘模式：relay mTLS、broadcast-probe 定向单播、Nacos 成员 watch（2026-08-03，Codex 实现 + 审查修复；feature `grpc-edge` 门控）

- **V8-3b relay mTLS**：`grpc_edge_cluster.tls`（server_name/ca/cert/key/握手硬超时）；非 loopback 集群构建期强制 TLS（明文仅限 127/8、::1 开发集群）；`peer_auth=mtls` 要求 tls.enabled 且 secret 必空，cluster_secret 可与 TLS 叠加作纵深；WebPki 强制客户端证书 + 固定 server_name 身份 + ALPN `naway-edge/1`；证书材料 notify watcher 原子热换（坏材料保留旧配置）。reload 守卫 `same_runtime_topology`：relay 拓扑字段变更拒绝热更，证书内容轮换不算拓扑。
- **V8-4 broadcast-probe**：Push 复用 relay 双向流向全部 peers 广播 hop=1 probe（同 payload 引用、固定 ack_deadline 聚合、multi_session 等全部回执）；peer 本地 users 索引 O(1) 判定、命中多端全投；PushSummary 聚合 (1=本地,5=peer copies,6=rejected,7=unknown)。
- **V8-5 Nacos 成员 watch**：自注册 metadata 注入 `gateway.edge.{protocol,cluster_id,node_id,relay_addr}`；watch 自注册 service，快照过滤（同 cluster/健康/node_id 合法/同 node 多址与同址多 node 拒/上限门）后 `reconcile_membership` 原子对账；坏快照 last-known-good，断线退避重连；live 用例默认 ignored。
- **Codex 对 V8-0..V8-3 的硬化（审查确认）**：EdgeHub 准入 CAS `try_reserve` 精确预留；解码器零长度 message 边界修复；relay in-flight 双维记账并入队列预算；DropOldest 双计数修正；水位线推进移至散出成功后；boot_id 改墙钟纳秒可比较；收包 record 语义校验；身份表上限；PublishStream 进 §6.1 注册表；`single_session`/`redis`/`group_owner` 未实现选项构建期拒绝。
- **本轮审查修复（4 处）**：①补 V8-4 验收项 `gw_edge_probe_miss_total`（本地+全部 peers 入队皆 0 计 miss，/metrics 渲染，三节点集成断言 ghost push 恰 1）；②Nacos 成员级执行——携带 node_id 集：**握手拒绝出集节点**（摘除成员双向失效，此前被摘但存活的节点可重拨且被接受）、**定向关停出集链路**（替代一刀切全关）、**回收出集水位线**（修复水位表只增不减、成员长期换代填满 full-mesh 上限后新成员被永久拒为 RejectedInvalid 的投毒）；③passive 拨号任务改 60s 低频重探（修复对端重建换 node_id 后拨号方向翻转无人拨号、finished 任务残留 dial_tasks 使 reconcile 无法复活）；④成员滞后窗口 at-most-once 口径按计划要求补进 live 用例注释；陈旧注释同步（payload 预算已是 CAS 精确预留）。
- 门禁：fmt+clippy 三形态 `-D warnings` 干净；三形态 t4 全量 0 failed（Codex 树 335/366/366，修复后复跑见 验收记录）。

### V8-3 gRPC 边缘模式：静态 peers 集群中继（2026-08-02，feature `grpc-edge` 门控；mTLS 归 V8-3b）

- 新增 `src/dataplane/edge_relay.rs`——**RelayRecord v1**（§25.2.6）：固定头 20B（magic/version/kind/flags/hop + record/metadata/payload 三长度自洽校验）+ 平坦 varint/bytes 元数据段（未知字段跳过，v1 前向兼容）+ 业务 payload 原样段；发送侧〔头+元数据〕与〔payload〕两段写出、payload 全 peers 共享同一 `Bytes` 引用；接收侧增量状态机任意 DATA 切分产出恒等、同 chunk payload 零拷贝 slice（指针级断言）、跨 chunk 恰量重组诚实计数；`hop` 上 wire 固化（data=1，伪造未中继即拒）。事件身份 128 位 = boot_id(hi) + 单调 seq(lo)。
- **peer 运行时**：node_id 较小者拨号唯一化（同时拨号经身份交换收敛，错向转被动）；握手校验 protocol/cluster/node/boot/config_fingerprint（FNV64 覆盖中继语义参数）；同 node 新 boot/更高 generation 原子替换旧链；per-peer 双维有界队列（默认 drop_new，弹旧策略对被弹 record 诚实结算）；在途上限 + ack deadline sweep→unknown；断线指数退避不盲重试，队列/在途残余按 Down/Unknown 结算；(node,boot) 水位线 dedupe，重复回幂等 ack（copies=0）。握手与稳态共享同一 decoder/body，同 chunk 紧跟 hello 的 record 不丢。
- **鉴别**：`cluster_secret`（SecretSource）端到端落地（专用头 + 常数时间比较 + 固定路径，非 relay 凭证一律 403）；`peer_auth=mtls` 构建期 fail-fast（relay TLS 证书 schema 归 V8-3b，不静默降级），§25.2.9 示例与契约单测同步。
- **发布路径聚合**：unary Publish 本地散出后向全部 peers 广播（同 payload 引用），固定 `ack_deadline_ms` 聚合；PublishStream 逐消息广播挂 FuturesUnordered 异步聚合、不阻塞散出节奏；`PublishSummary` 增 varint 字段 **5=peer 接受份数、6=拒绝 peer 数、7=断线/无回执 peer 数**（§25.2.6 accepted/rejected/unknown 口径，绝不叫 delivered）；Push 仍本地（跨节点 broadcast-probe 归 V8-4）。收包侧 hop=1 只做本地散出，结构上无二次 relay 路径。
- /metrics 补 `gw_edge_relay_peers_connected`/`gw_edge_relay_queue_depth` gauge 与 `gw_edge_relay_sent_total`/`failed_total`/`unknown_total`/`dedup_total` counter（低基数，无 per-peer label）。
- `publish_group`/`push_user` 入参收窄为 `&GrpcEdgeLimitsPlan`（relay 收包侧无 route 计划，用 §25.2.9 默认节点预算）。
- 测试：codec 单测 4 条（全切分点/坏 record 矩阵/零拷贝指针/未知字段跳过）；新增 `tests/edge_cluster.rs` 三节点真实进程矩阵——mesh 收敛、跨节点群播 summary 与实收一致且无双投、同 ingress 保序、错 secret/业务凭证 403、跨 cluster 握手拒、kill peer 后其余照常 + summary 如实 + `relay_failed_total` 递增 + 不积压、节点重启（boot 换代）恢复。三形态 t4 全量 0 failed ×3（default 331 / grpc-edge 356 / all 356）；clippy 三形态 `-D warnings` 干净；A2.4 单轮 47.5k RPS p99 3.86ms（基线 48.0k/4.76ms，无回归）。
- 测试资产附带：`wait_for_liveness` 窗口 4s→12s 对齐 2026-08-02 整治口径（debug 并发下 ACME 自签引导贴窗导致的轮换偶发根因）。
- 已知缺口（验收记录 V8-3 行留档）：mtls peer 鉴别待 V8-3b 证书 schema；relay 不随 reload 换版（V8-5 Nacos watch 接管）；relay 链路与发布长流未进 §6.1 注册表。

### V8-2 后半 gRPC 边缘模式：PublishStream 流式发布（2026-08-02，feature `grpc-edge` 门控；V8-2 就此完成）

- §25.2.9 schema 扩 `grpc_edge.publish_stream` 四门：`max_lifetime_ms`(默认 1h)/`max_messages`(默认 1M)/`max_msgs_per_sec`(默认 10k)/`max_total_bytes`(默认 4GiB，帧全长计费)；构建期 1..=硬上限逐项校验 + 累计字节须容得下一条最大帧（max_msg_bytes+5），`deny_unknown_fields`，契约单测 13 条三形态语义一致。
- 执行语义定型（写入 架构规范 §25.2.3）：**每秒消息数 = 背压节流**——`StreamRateGate` 令牌桶（容量=1 秒配额，整数定点），无令牌即暂停读请求体，经 HTTP/2 流控传导到发布方，消息不丢、流不杀；paused-clock 单测锁死突发、稳态间隔与"空闲不无限积攒突发额度"。**生命周期/累计消息/累计字节 = 优雅轮转**——`timeout_at` 粒度到界即停读，返回已聚合 `PublishSummary` + `grpc-status: 0`，发布方凭 `messages` 字段判断进度重建流；越界消息不散出。节点预算耗尽 8、framing 错 3、传输错 14。
- `run_publish_stream` 增量散出主循环：逐消息 解帧→令牌→`publish_group`，聚合 accepted/dropped/closed_slow/messages；跨 DATA 重组字节逐消息报增量（计数器不重不漏）；请求侧 trailers/半帧 EOS 按协议错拒。
- `PublishSummary` v1 wire 定型：varint 字段 1=accepted、2=dropped、3=closed_slow、**4=messages**（unary Publish 恒 1，流式为已处理条数；PushSummary 仍仅 accepted）；架构规范 遗留 `delivered_local` 示例命名清除（§25.2.8 口径）。
- 测试：`edge_matrix` 新增流式矩阵——单/多消息流保序散出（ingress FIFO）、`max_messages=2` 轮转恰停在门上、700ms 生命周期门实测等待下界、5 msg/s 节流 10 条实测 ≥600ms 且一条不丢、半帧 EOS→3、全程 summary golden bytes 与 `gw_edge_publish_total` 50 次精确账。三形态 t4 全量 0 failed ×3（default 331 / grpc-edge 351 / all 351）；fmt+clippy 三形态 `-D warnings` 干净；A2.4 单轮 46.5k RPS p99 5.42ms（基线 48.0k，−3.1% 在本机噪声带内；默认路径本轮零改动，全部变更 feature 门控）。

### V8-2 gRPC 边缘模式发布面：unary Publish/Push 本地散出（2026-08-02，feature `grpc-edge` 门控；PublishStream 留待速率门 schema）

- `edge_hub.rs` 发布内核：ring 元素改 `QueuedFrame{Bytes + Arc<PayloadLease> + QueueRefGuard}`，节点 payload/queue_refs 预算全部经 Drop 链自动结算（弹旧/清队/交付/注销 `drain_remaining` 任何路径零泄漏）；`publish_group`/`push_user` 共享 fanout 内核——FanoutJobGuard 在途门、唯一 payload 先占后验回滚、queue_refs 满按 `dropped_budget` 降级不中断其余成员、FANOUT_CHUNK=256 逐 chunk `yield_now`（cooperative budget，§25.2.5）；`LocalFanoutOutcome{members,accepted,dropped_oldest,dropped_new,closed_slow,dropped_budget}`（§25.2.8 诚实口径，禁 delivered 命名）。
- 回执自产：`encode_flat_grpc_message` 手工 varint protobuf（proto3 0 值省略，不引 prost；控制面小消息不违反"业务 payload 零解析"）+ `UnaryGrpcResponseBody`（恰一帧 + `grpc-status: 0` trailer）。`read_single_message` 改返（帧, 跨 DATA 重组字节）供 `gw_edge_reassembly_bytes_total` 诚实计量。
- proxy 发布面接线：交叉校验矩阵（publish 需 group 禁 target；push 需 target 禁 group）；`grpc-encoding` 非 identity 拒 3（逐消息压缩位另由解帧器强制，两道都要）；身份门 16 前置于 12 范围门（未认证方探测不到方法实现状态）；unary `Publish`→PublishSummary（1=accepted，2=dropped_new+dropped_budget，3=closed_slow），`Push`→PushSummary（1=accepted），空组/目标不在线诚实全 0（订阅天然竞态不是错误）；`PublishStream` 保持 12——§25.2.9 尚无流生命周期/速率/累计门 schema，先扩契约再落地。
- /metrics edge 块补齐：`gw_edge_payload_bytes`/`gw_edge_queue_refs` gauge + `gw_edge_publish_total`/`gw_edge_publish_rejected_total`/`gw_edge_dropped_frames_total`/`gw_edge_reassembly_bytes_total` counter。
- 测试：单测 17 条（共享 payload 单次记账、预算拒绝回滚、queue_refs 降级、push 多端不串投、varint 金样、unary 帧序、Drop 链双维零泄漏）；`tests/edge_matrix.rs` 新增发布面真实 h2 矩阵（401 前置/16 兜底/3 全文案/8 超限/12 范围门、空组全 0 summary、1→N 群播 golden bytes、multi_session 定向单播、64B 流控窗口在真实链路逼出 drop_oldest 弹旧保新、34 次散出 0 拒绝 0 重组、端态 payload+queue_refs 双零泄漏）。三形态 t4 全量 0 failed ×3（default 330 / grpc-edge 349 / all 349）；fmt+clippy（含 all-features）`-D warnings` 干净；A2.4 单轮 48.6k RPS p99 5.14ms vs 基线 48.0k/4.76ms 无回归信号（本机多轮 CV>13%，正式判定固定 Linux）。

### V8-1 gRPC 边缘模式 Subscribe + EdgeHub（2026-08-02，feature `grpc-edge` 门控）

- 新增 `src/dataplane/edge_hub.rs`：§25.2.4 增量 gRPC 解帧器（同 chunk 零拷贝、跨 chunk 恰量有界重组）、恰一条 SubReq+EOS 有界读取、EdgeRing 双维有界发送环（messages+bytes；drop_oldest 同临界区弹旧、drop_new、close_slow）、tenant 作用域 EdgeHub 订阅索引（四类基数准入 + 幂等摘除）、channel-backed 订阅响应 Body（治理关闭合成合法 trailer：draining/policy/max-age/idle）。
- proxy 接入 §25.2.3 四重门：精确 `:path` 命中才进 edge（未命中含同 route 普通 gRPC 照常转发）；单值/可见 ASCII/有界元数据；身份仅取已验证 principal（JWT claim → consumer 回落，无认证来源 → 16）；publish/push 方法返回 12（V8-2 落地）；成功自响应 200 + application/grpc，初始 HEADERS 不带 grpc-status。
- 治理与观测：edge 流登记 §6.1 注册表（close_by_route/ip/consumer、drain_stale、SIGTERM drain 生效）；route 级 idle/max_lifetime；`gw_edge_active_streams`/`gw_edge_groups` 低基数 gauge 接 /metrics（admin 启动期注入）。
- 测试：12 条运行时单测（任意 DATA 切分矩阵、双维预算、close 竞态）+ `tests/edge_matrix.rs` 真实 h2 socket 集成矩阵；三形态 t4 全量 0 failed ×3。A2.4 默认路径复测因本机轮间 CV>13% 记 INCONCLUSIVE（默认热路径唯一改动为 ladder 一次 Option 检查）。

### 测试套件稳定性整治（2026-08-02，产品数据面零改动）

- 6 处测试网关 spawn 点加 `kill_on_drop(true)`：失败用例 panic 不再泄漏网关子进程（此前泄漏进程握管道致后台套件冻结、占端口致跨 binary 级联失败）。
- `external_header_plugins` 用例显式 `timeout_ms: 3000`：产品默认 200ms 在 debug 并发下被首连争用击穿（`total deadline expired`），该用例不测默认超时语义；产品默认不动。
- `admin_config_history` 改 SIGHUP 确定性触发 reload（macOS FSEvents 在全套件并发下延迟无上界；notify 通道由 reload_stress 专测）。
- `wait_for_health`/`wait_for_ready_version` 轮询窗口 4s/6s → 12s（通过路径首轮返回）。
- 门禁跑法固化 `cargo test -- --test-threads=4`（重型真实 socket 集成 binary 的设计负载口径，验收记录 留档）；t4 下三形态全量 0 failed ×3。
- 品牌断言同步（"Nate Control Plane"→"Naway Control Plane"，7-25 迁移遗留）。

### V8-0R gRPC 边缘模式契约修订（2026-08-02，按 架构规范 §25.2 深审修订版）

- route `grpc_edge` 补齐目标 schema（§25.2.9）：**精确 `methods`**（subscribe/publish/publish_stream/push 的 `/pkg.Service/Method` 两段路径，allowed action 与方法一一对应、未允许 action 声明方法即拒绝、路径两两不同）；**`identity` claim 映射**（tenant_claim/user_claim，拒绝 `-bin`、tenant=user）；**`limits` 节点级预算**（max_msg_bytes 迁入 + max_id_bytes/max_streams_per_node/max_groups_per_node/max_members_per_group/max_sessions_per_user/max_payload_bytes/max_queue_refs/max_fanout_jobs，逐项 1..=硬上限）；`send_queue` 增 **`max_bytes` 双维**且必须容下一条最大帧（max_msg_bytes+5）。
- 顶层旧 `max_msg_bytes` 降为**兼容别名**：仅旧位生效、双位冲突报明确错误。
- overflow 策略修订：`drop_batch` 移除，新增 **`drop_new`/`latest_by_key`**；`drop_oldest` 语义注明需自有 EdgeRing（PollSender 冒充不了）。
- `grpc_edge_cluster` 补齐：**`cluster_id`/`node_id`**（relay 握手身份，必填+字符集校验）、`peer_auth` 改 **`mtls`(默认)/cluster_secret**（`mtls_san` 移除）、relay_queue 双维（默认 1024/64MiB/**drop_new**，`close_slow` 拒绝）、**`ack_deadline_ms`**(默认 100，§25.2.9 示例 `100ms` 对应本仓 `_ms` 整数约定)、**`full_mesh_max_nodes`**(默认 32，静态 peers 超门拒绝)、**`interest_route`**(auto/broadcast_all)、**`ordering`**(best_effort/ingress_fifo/group_owner)、**`session_mode`**(multi_session/single_session)；旧 `interest_hint` 字段移除（serde 拒绝）。
- 单测更新为 12 条 V8-0R 契约用例（新增 methods/identity/别名迁移/双维与节点预算/cluster 身份与策略矩阵），三形态语义一致。数据面仍 no-op：Subscribe/EdgeHub/decoder/relay 归 V8-1..V8-5（§25.2.1 状态口径）。

### V8-0 gRPC 边缘模式契约落地（2026-08-02）

- 新增 Cargo feature `grpc-edge`（默认不编）：V8「gRPC 边缘模式」(架构规范 §25.2 / 验收记录 V8) 的编译门。未编 feature 或未开启时，gRPC 数据面保持 Nginx/Envoy 式 L7 透传，一字节不碰（A10 零侵入契约）。
- 配置模型新增 route 级 `grpc_edge`（enabled/allowed_actions/action‖group‖target header/auth/send_queue/delivery/encoding/max_msg_bytes）与进程级 `grpc_edge_cluster`（mode/membership nacos|static/relay_listen/peer_auth/relay_queue/interest_hint/session_registry），全部 `deny_unknown_fields`。
- 构建期拒绝矩阵（验收记录 V8-③）落地于 `extensions/grpc_edge.rs`：值校验先于 feature 门，三种构建形态报错一致；`enabled=true` 无 feature、actions 空/重复、header 非法/大写/重名、队列 0/超硬上限、msg 上限越界、static peers 空/非法/重复、nacos 成员未启用 Nacos、relay_listen 缺失/非法、`session_registry=redis` 无 `redis-runtime` —— 逐条拒绝且 reload 保留旧快照。
- 快照接线（数据面 no-op）：`Route.grpc_edge` 编译计划、`GatewaySnapshot.grpc_edge_cluster`、摘要新增 `grpc_edge_routes`/`grpc_edge_cluster` 低基数字段。
- 新增 `tests/unit/grpc_edge.rs` 9 条契约用例（拒绝矩阵逐条 + 三形态分支断言）。
- 修复既有测试漂移：7-25 品牌迁移后 `admin_ui.html` 标题已为 "Naway Control Plane"，7-23 的 `codex_v2_review` 仍断言 "Nate Control Plane"（与 V8-0 无关，已同步）。

### Naway 品牌迁移（2026-07-22）

- Cargo 包、默认可执行文件、容器镜像与 UI 品牌统一为 `naway` / **Naway**。
- 新部署默认使用 `/data/naway/naway.yml` 和 `NATE_*` 环境变量；`GW_*` 保留兼容但不再提供 `/data/gateway/gateway.yml` 兜底。
- A2 的参赛角色字段仍保留 `gateway`（表示“被测网关”而非品牌），镜像与源码指纹标签改为 Naway。

### V2–V4 基础实现复核（2026-07-19）

- A2 新增固定摘要 Nginx/Envoy 的同网络横评，覆盖 h1/h2c/TLS、4-message gRPC server-streaming、持久 WebSocket echo 和 L4 TCP；10k/64 吞吐与资源重放/WS 容量已解耦，避免 `docker stats` 污染亚秒测量和组合长跑耗尽宿主端口；新增 gRPC 64 并发回归探针。
- TLS 可选 `keypair_manifest_file`：校验后的 pair 写不可变版本目录，只原子切一个 manifest；证书 watcher 精确过滤目标文件并兼容 macOS `/var` 路径规范化。
- SecretSource 文件依赖独立 watch/fingerprint/audit reload；reload 后回收无声明且空闲的 upstream identity/client/RR/失败状态，并暴露低基数 entry gauge。
- SSE/gRPC route 级 idle/max-age、current/stale/oldest 长流指标；Nacos 自注册与 `/readyz` 共用 critical-upstream 判定。
- Nacos 新增单 dataId 原子 JSON bundle；watcher 一次物化完整三文档，rollback 对整个 bundle 做一次 CAS；旧三 dataId 模式继续兼容但拒绝多文档伪事务。
- A1 自包含真实协议/运行安全矩阵：h1 keep-alive、h2c、TLS ALPN h1/h2、gRPC trailer/server-streaming、SSE、WS/WSS、证书热换、slowloris/停滞上传下载与 SIGHUP×100；本轮 64 MiB 慢消费响应 RSS 增长 8080 KiB。
- 上游 connector pre-dial 严格物理 socket 预算；keepalive 按 pool generation 请求数轮换；保留 HTTPS ALPN `Connected` 元数据。
- ACME HTTP-01/DNS-01、无 seed 同进程 TLS 激活、Redis 锁、私有目录 CA 与固定镜像摘要 Pebble live。
- 管理面/route 鉴权 SecretSource；WS/gRPC 长连接按 consumer 关闭及 reload 宽限 drain。
- `source.md` 本地环境验证：Redis live 6/6，Nacos live 1/1；完整测试 64 lib + 1 bin + 76 integration 通过（6 Redis、1 Nacos、1 RSS 在普通套件中显式 ignored）。
- 未完成边界：A2 gRPC 性能参考线、10k WebSocket/长时资源稳定归档、证书版本目录 GC、外部 Nacos bundle 发布工作流；详见 `验收记录` 第四轮。

### R1 — 单机数据面走通(walking skeleton)

- hyper 反向代理:HTTP/1.1 + HTTP/2 自动协商,`serve_connection_with_upgrades` 放开 WebSocket Upgrade 通道。
- SCG 风格路由:`Path=` / `Method=` 断言 + `StripPrefix=` 过滤器,顺序匹配。
- ★接口级拦截★:独立 `interface-guard.yml`,path glob + methods 匹配 → 直接返回配置的 response(status/headers/body),命中即短路,零上游成本。
- ★无感热重载★:单快照 `ArcSwap`,两触发通道——`notify` 监听配置目录(防抖)+ `SIGHUP`(`naway -s reload`,nginx 风格);事务化 build,坏配置保留旧版不上线。
- 复用 `nasa::yml` 解析配置占位符(`${ENV:default}`)。
- 流式转发:下游/上游 body 全程流式直通,不全量 buffer(少拷贝)。

### 路线图(见 架构规范 §34,阶段名与主合同对齐)

- **V2-A** 协议底座:h1/h2c/ws/TLS/ALPN/gRPC + 流式 O(1) 内存 + 慢连接防护 + reload 压测(A1.1–A1.8)。
- **V2-B** 上游体系 + 连接守卫 + 基础观测(metrics/access log)+ 资源预算 + 基础安全。
- **V3** 动态配置深化 + Redis 分布式限流/熔断/降级 + 动态黑名单 + 管理面联动。
- **V4+** 集群统一配置 / 安全 / 管理面 / 缓存 / 追踪 / AI 网关 / 插件,详见 架构规范 §34。
