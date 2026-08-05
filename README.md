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

2026-07-23 自检：全功能集 318 passed、0 failed、13 个外部 live/独立 RSS 用例按默认门禁 ignored；随后按 `source.md` 实跑 Redis 10/10、Nacos 1/1、Kafka 1/1，自包含 A1 协议矩阵 10/10，Pebble DNS-01 真实签发/热装载/清理通过。64 MiB 流式响应 RSS 增长 9 MiB，没有随 payload 线性聚合。10k WebSocket 已在统一 Linux bridge 下由 Naway/NGINX/Envoy 全部建立并保持 10000/10000。

仍需诚实保留：当前代表性本地 gRPC-H2C 最终稳定轮 Naway 为 NGINX 的 110.24%，但仅为 Envoy 的 75.79%，未达到新的 90% 最低线；1×64 深 multiplex、TLS-H2 和 WS close 后堆页高水位仍在性能 backlog。gRPC 已有 L7 Path/Host/Method 和 header-map 动态 upstream，但声明式 Header predicate 尚未补齐。内置管理页已有 dashboard、RBAC、审计、YML dry-run、历史/回滚和只读集群一致性，尚缺“读取当前 YML → 编辑 → CAS 发布 → 确认本地/集群实际生效”的闭环；core/full 轻量制品也尚未完成量化。后续差距与实施顺序统一记录在公开路线图和变更日志中。

## 构建镜像

```bash
./build.sh          # 默认构建 naway 镜像；上下文仍同时纳入源码目录和 nasa-runtime-rust
# 把 yml 放宿主 /data/naway，直接启动（挂载到容器同路径，修改 yml 即热更）：
./start.sh
# 或指定别的宿主配置目录：NATE_CONFIG_DIR=/your/conf ./start.sh
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
├── security/
└── reload/              无感热重载(notify 文件 + SIGHUP)
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
