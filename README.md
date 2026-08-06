# Naway

**Naway** 是面向高性能与有界资源的 Rust **流量网关 + 业务网关**。产品收敛目标是以单一 `naway` 制品覆盖 nginx + Spring Cloud Gateway 的主流场景：核心数据面主指标全部稳定达到 Envoy 的 90%，预声明的 h1、WebSocket、L4 TCP 主指标超过 Envoy；gRPC 提供按 service/method/header 治理的原生 L7 代理；独立管理端口内置 Higress 风格的 YML 编辑、CAS 发布、生效确认、集群收敛和回滚；同时保留无外部依赖可启动的轻量 all-in-one。量化口径由公开配置 schema、自动化验收和变更日志共同锁定，未过门项目不会标记完成。

- 数据面:`hyper`/`tokio` 自建反向代理；h1/h2c、WebSocket/WSS、TLS/ALPN、SSE/gRPC streaming、证书热换和慢连接 deadline 已有真实 socket 自动测试，64 MiB 流式响应 RSS probe 已通过。
- 控制面/发现/配置/限流/观测/管理:复用 nasa-runtime-rust 的 `nasa` 门面(Nacos/Redis/axum)。

实现行为以公开配置 schema、protobuf 契约、SDK 文档和自动化测试为准。

## 配置目录（固定 `/data/naway`，便于 Docker 挂载）

外部 yml **统一放一个固定目录**（默认 `/data/naway/`），做容器时整目录挂进去即可：

```
/data/naway/
├── naway.yml              # 监听 + SCG 风格路由(Path=/Method= 断言、StripPrefix= 过滤器)
└── interface-guard.yml   # 接口级拦截(独立文件):某接口对外关闭 → 直接返回配置的 response
```

配置路径优先级：`--config <路径>` > `NATE_CONFIG=<路径>` > `GW_CONFIG=<路径>` > `${NATE_CONFIG_DIR:-/data/naway}/naway.yml`。
`interface-guard.yml` 相对主配置目录解析，因此与 `naway.yml` 同目录、一起挂载和热更。

## 快速开始

```bash
# 本地开发:用仓库示例配置目录 zcf/
NATE_CONFIG_DIR=zcf cargo run
# 或显式指定主配置
cargo run -- --config zcf/naway.yml

# 生产：把 yml 放宿主 /data/naway，直接运行（默认读 /data/naway/naway.yml）
naway

# 热更(nginx 风格,向运行进程发 SIGHUP);或直接改 yml,notify 自动热加载(无感、零抖动)
naway -s reload
```

```bash
# 例:export 接口已在 interface-guard.yml 里下线 → 直接 403,不走上游
curl -i http://127.0.0.1:8080/api/export/orders     # → 403 {"code":40301,"msg":"export 接口已下线"}
curl -i http://127.0.0.1:8080/api/hello             # → 命中路由 demo,转发上游
```

## 当前状态（V1–V8 基础功能闭环，性能与产品门持续收敛）

V8 已提供统一的 gRPC 边缘发布、订阅、群播与定向单播契约。Naway 不解析业务
protobuf 内容，业务消息按不透明字节传递，只依据 gRPC metadata/header 与订阅兴趣执行规则散出。
集群传输可在原生 gRPC Relay、Redis Pub/Sub 与 Redis Stream 之间显式选择；单个部署只启用
一种集群通信方式，Redis Stream 的历史消息裁剪由业务生产侧负责。

已走通：流式 h1/h2c/TLS/gRPC/WS/WSS 反代、真实 Nacos 发现与网关自注册、Redis 共享运行态、Sentinel 防护、配置 build-then-swap、管理面/RBAC/审计、HTTP L1/L2 缓存、OTel、压缩与 OpenAPI 校验、OpenAI/Anthropic LLM 网关，以及 V7 的 WASM/外部插件、OPA/Casbin、GraphQL、Dubbo/MQTT、TCP/UDP/TLS stream、K8s/Consul/Eureka/DNS 发现和开发者门户。

2026-08-06 最终门禁：`cargo test --all-features -- --test-threads=4` 为 401 passed、0 failed、22 个外部 Redis/Nacos/Kafka/RSS live 用例按环境门 ignored；`cargo clippy --all-features --all-targets -- -D warnings` 零 warning。此前的 Redis、Nacos、Kafka 与 ACME live 验收继续保留独立入口，不用 mock 结果替代外部系统证据。

代表性 gRPC-H2C 正式窗口固定为 Linux Docker、7×400000、8 条下游 H2 连接和总并发 64；Naway 中位数 38227.65 RPS（CV 0.0575），Envoy 42274.27 RPS（CV 0.0286），比例 **90.43%**，达到 90% 硬门。V8-6 当前 release 回归同样通过：100k 成员与 64 KiB 档零丢，10k stream 五轮中位 525195 deliveries/s、CV 0.0594，最大调度停顿 208908µs，drain 后 FD 14→14 且 RSS 低于波次前基线。声明式 gRPC Header predicate、管理页 YML 编辑/CAS 发布/生效确认、relay interest routing、严格 group owner、全网 single-session fence 与可回滚热换代均已闭环。

## 构建镜像

当前开发树暂时要求同级目录存在 `nasa-runtime-rust`：Nacos 首次原子 bundle 发布依赖尚未进入已发布的 `nanacos 1.0.0`，因此 Cargo 使用带版本约束的 sibling path 联调。公开发布前必须先发布包含这些 API 的兼容 `nanacos`/`nasa` 版本，再移除 path 并通过 `cargo publish --dry-run`；不能把本地路径依赖伪装成可独立发布状态。

```bash
./scripts/build.sh  # 默认构建 naway 镜像；上下文仍同时纳入源码目录和 nasa-runtime-rust
# 把 yml 放宿主 /data/naway，直接启动（挂载到容器同路径，修改 yml 即热更）：
./scripts/start.sh
# 或指定别的宿主配置目录：NATE_CONFIG_DIR=/your/conf ./scripts/start.sh
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
