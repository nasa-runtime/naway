# Naway

**Naway** 是面向高性能与有界资源的 Rust **流量网关 + 业务网关**。产品收敛目标是以单一 `naway` 制品覆盖 nginx + Spring Cloud Gateway 的主流场景：核心数据面主指标全部稳定达到 Envoy 的 90%，预声明的 h1、WebSocket、L4 TCP 主指标超过 Envoy；gRPC 提供按 service/method/header 治理的原生 L7 代理；独立管理端口内置 Higress 风格的 YML 编辑、CAS 发布、生效确认、集群收敛和回滚；同时保留无外部依赖可启动的轻量 all-in-one。量化口径由公开配置 schema、自动化验收和变更日志共同锁定，未过门项目不会标记完成。

- 数据面:`hyper`/`tokio` 自建反向代理；h1/h2c、WebSocket/WSS、TLS/ALPN、SSE/gRPC streaming、证书热换和慢连接 deadline 已有真实 socket 自动测试，64 MiB 流式响应 RSS probe 已通过。
- 本地配置直接使用 `naml` 的分层加载、来源追踪和精确 watcher；Nacos、Redis、axum 等运行组件复用 nasa-runtime-rust 的 `nasa` 门面。

实现行为以公开配置 schema、protobuf 契约、SDK 文档和自动化测试为准。

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

naml watcher 只观察主配置、活动 profile 候选和已构建快照声明的 Secret、schema、策略及扩展文件，
同目录日志和临时文件不会触发 reload。候选必须先完成运行态资源 prepare 和 watcher 对账，随后才
原子发布快照；读取、校验、资源准备或新增目录观察失败时继续使用上一份有效配置。

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

## 当前状态（基础功能闭环，性能与产品门持续收敛）

Naway 已提供统一的 gRPC 边缘发布、订阅、群播与定向单播契约。Naway 不解析业务
protobuf 内容，业务消息按不透明字节传递，只依据 gRPC metadata/header 与订阅兴趣执行规则散出。
集群传输可在原生 gRPC Relay、Redis Pub/Sub 与 Redis Stream 之间显式选择；单个部署只启用
一种集群通信方式，Redis Stream 的历史消息裁剪由业务生产侧负责。

已走通：流式 h1/h2c/TLS/gRPC/WS/WSS 反代、真实 Nacos 发现与网关自注册、Redis/Nacos 共享运行态、Sentinel 防护、配置 build-then-swap、管理面/RBAC/审计、HTTP L1/L2 缓存、OTel、压缩与 OpenAPI 校验、OpenAI/Anthropic/Google LLM 网关，以及 WASM/外部插件、OPA/Casbin、GraphQL、Dubbo/MQTT/Kafka、TCP/UDP/TLS stream、K8s/Consul/Eureka/DNS 发现和开发者门户。

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
  gateway_bind_address: "0.0.0.0"
  gateway_stream_bind_address: "127.0.0.2"
  gateway_stream_bind_addresses:
    - "127.0.0.2"
    - "127.0.0.3"
```

AI route 对下游保持 OpenAI Chat Completions 契约，可把 text-only 请求转换为 Google Gemini
Developer API 的 `generateContent`/`streamGenerateContent?alt=sse`；不能无损表达的 tool、多模态或
未知字段会在调用 provider 前拒绝。可选 external moderation 使用 OpenAI-compatible
`/v1/moderations`，明确 `flagged=true` 永远拒绝，依赖故障则按 route 的 `closed|open` 策略处理。
token quota 在 cache miss 后预留，依据 provider 最终 usage 幂等多退少补；非 2xx/transport 失败退款，
成功但 usage 缺失或流中断保留保守预留。

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

提交前应执行 `cargo test --all-targets` 与 `cargo clippy --all-targets --all-features -- -D warnings`。
需要 Redis、Nacos、Kafka、ACME 或长时资源环境的用例保持显式 ignored，须按对应测试说明单独运行；
外部系统能力不能用 mock 结果替代。

代表性 gRPC-H2C 正式窗口固定为 Linux Docker、7×400000、8 条下游 H2 连接和总并发 64；Naway 中位数 38227.65 RPS（CV 0.0575），Envoy 42274.27 RPS（CV 0.0286），比例 **90.43%**，达到 90% 硬门。当前 release 的 gRPC 边缘资源回归同样通过：100k 成员与 64 KiB 档零丢，10k stream 五轮中位 525195 deliveries/s、CV 0.0594，最大调度停顿 208908µs，drain 后 FD 14→14 且 RSS 低于波次前基线。声明式 gRPC Header predicate、管理页 YML 编辑/CAS 发布/生效确认、relay interest routing、严格 group owner、全网 single-session fence 与可回滚热换代均已闭环。

HTTP/3 / QUIC 通过独立 `http3` feature 提供下游与上游双向代理，同一 TLS listener 端口承载 TCP h1/h2 与 UDP h3；DATA/trailers、取消、GOAWAY、Retry、连接迁移、证书热换和资源预算均复用现有数据面语义。curl/quiche、Envoy v1.35.3 和真实 Chrome 150 Alt-Svc→H3 回访均已通过；正式 Envoy H3 7×300k 门的吞吐比为 **1.2332**、p99 比为 **0.8371**。HTTP/3 默认关闭，0-RTT、WebTransport、MASQUE 与应用可见 QUIC DATAGRAM 不在当前承诺范围。

## 构建镜像

当前开发树暂时要求同级目录存在 `nasa-runtime-rust`：Nacos 首次原子 bundle 发布依赖尚未进入已发布的 `nanacos 1.0.0`，因此 Cargo 使用带版本约束的 sibling path 联调。公开发布前必须先发布包含这些 API 的兼容 `nanacos`/`nasa` 版本，再移除 path 并通过 `cargo publish --dry-run`；不能把本地路径依赖伪装成可独立发布状态。

```bash
./scripts/build.sh  # 默认构建 naway 镜像；上下文仍同时纳入源码目录和 nasa-runtime-rust
# 把 yml 放宿主 /data/naway，直接启动（挂载到容器同路径，修改 yml 即热更）：
./scripts/start.sh
# 或指定别的宿主配置目录：NAWAY_CONFIG_DIR=/your/conf ./scripts/start.sh
```

## 源码结构(按模块目录组织)

```
src/
├── main.rs              入口:CLI / pidfile / 监听 / 启动热更
├── lib.rs               模块声明 + 响应助手 re-export
├── cache/
├── admin/
├── config/
├── dataplane/
├── extensions/
├── io/
├── guard/
├── observability/
├── proxy/
├── reload/
├── routing/             路由:mod.rs(Router)+ predicate.rs(断言解析)
└── security/            身份、策略与安全边界
```

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
