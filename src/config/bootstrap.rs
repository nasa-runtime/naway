//! 启动自举(对标 Higress 首次启动生成默认配置)。
//!
//! 检测固定配置目录(默认 `/data/naway`)下的 yml 是否齐全:
//! - 目录不存在 → 创建;
//! - `naway.yml` 不存在 → 写入**最低运行默认**(能监听、无路由,请求 404,可正常起);
//! - `interface-guard.yml`(名取自主配置的 `interface_guard_file`)不存在 → 写入**空守卫默认**(不拦任何接口)。
//! - `sentinel-rules.yml`(名取自主配置的 `sentinel_rules_file`)不存在 → 写入**空流控默认**。
//!
//! 只新建缺失的,**绝不覆盖已存在的**文件。

use std::path::Path;

use anyhow::{Context, Result};

/// 最低运行默认:能监听、无路由(请求 404),operator 按需加 routes。
const DEFAULT_GATEWAY_YML: &str = r#"# 默认主配置(启动自举生成的最低运行默认)。改此文件即热更;或 `naway -s reload`。
# 配置 schema 版本(架构规范 §6):便于长期演进期迁移;缺省按 v1 处理并告警。
schema_version: 1

server:
  # 明文数据面监听;支持 HTTP/1.1、h2c prior-knowledge、h1 WebSocket 隧道。
  listen: "0.0.0.0:8080"
  # TLS 与明文是两个 socket,不做同端口 sniffing。需要时取消注释。
  # tls:
  #   listen: "0.0.0.0:8443"
  #   cert_file: "tls/server.crt"
  #   key_file: "tls/server.key"
  #   # 可设 bootstrap_without_seed: true：TLS 端口先绑定、readiness=503，首签落盘后同进程激活。
  #   # acme:
  #   #   bootstrap_without_seed: true
  #   #   directory_url: "https://acme-v02.api.letsencrypt.org/directory"
  #   #   # directory_ca_file: "tls/private-acme-ca.pem" # 私有 ACME/Pebble，勿导入系统 trust store
  #   #   domains: ["gateway.example.com"]
  #   #   contacts: ["mailto:ops@example.com"]
  #   #   challenge: "http-01"
  #   #   # DNS-01 通配符示例:
  #   #   # challenge: "dns-01"
  #   #   # dns01: { provider: "command", command: "bin/dns-hook", timeout_ms: 30000 }
  #   #   account_credentials_file: "tls/acme-account.json"
  #   #   renew_before_days: 30
  #   #   check_interval_ms: 43200000
  #   #   retry_backoff_ms: 300000
  #   #   order_timeout_ms: 300000
  #   #   lock_backend: "local"       # 多节点改 redis，并打开 redis-runtime feature
  #   #   lock_key: "gateway:acme"
  #   #   storage_mode: "local-file"  # Redis 锁模式必须 shared-file + 共享卷
  limits:
    max_connections: 10000
    max_headers: 100
    max_header_bytes: 65536
    max_body_bytes: 67108864
    max_concurrent_streams: 256
    # 有界 H2 flow-control：stream 保持细粒度背压，connection 放大到 1 MiB 减少并发更新帧。
    h2_initial_stream_window_bytes: 65535
    h2_initial_connection_window_bytes: 1048576
    max_path_bytes: 8192
    max_path_segments: 128
    upstream_pending_limit: 1024
    pool_max_per_upstream: 64
    # h2/h2c 仍在每条连接内 multiplex；多分片避免所有 runtime worker 争用单个 h2 stream 锁。
    h2_connection_shards_per_upstream: 16
    pool_max_connections_per_upstream: 128
    keepalive_requests: 1000
    pool_idle_timeout_ms: 60000
    old_pool_retain_ms: 60000
  timeouts:
    upstream_ttfb_timeout_ms: 30000
    header_read_timeout_ms: 30000
    connection_timeout_ms: 0
    stream_idle_timeout_ms: 60000
    downstream_write_timeout_ms: 30000
    websocket_idle_timeout_ms: 60000
    websocket_max_lifetime_ms: 86400000
    drain_timeout_ms: 30000

# MQTT 3.1.1/5.0 治理需使用 `--features mqtt-governance` 构建；保持注释时不创建 stream listener。
# persistent session、shared subscription 或 topic-alias-only 空 topic 应使用不含 mqtt 段的透明 TCP profile。
# stream:
#   listeners:
#     - id: mqtt-public
#       protocol: tcp
#       listen: "0.0.0.0:1883"
#       preread:
#         mqtt_connect: true
#         timeout_ms: 3000
#         max_bytes: 4096
#       mqtt:
#         enabled: true
#         max_connections: 256
#         max_packet_bytes: 1048576
#         packet_timeout_ms: 10000
#         max_buffered_bytes: 536870912
#         max_topic_bytes: 1024
#         max_subscriptions: 1024
#         max_inflight_messages: 128
#         client_id_allow: [device-a]
#         publish_topic_allow: [sensors/+/temperature]
#         subscribe_topic_allow: [sensors/#]
#       routes:
#         - id: broker
#           default: true
#           upstream: "10.0.0.20:1883"

# Kafka client data-plane 治理需使用 `--features kafka-governance` 构建；完整 API 面使用透明 TCP profile。
# 多 broker 必须分别暴露可达代理 endpoint，且所有成功 Metadata/FindCoordinator 地址都要显式映射。
# stream:
#   listeners:
#     - id: kafka-broker-1
#       protocol: tcp
#       listen: "0.0.0.0:19092"
#       kafka:
#         enabled: true
#         max_connections: 256
#         max_frame_bytes: 1048576
#         frame_timeout_ms: 10000
#         max_buffered_bytes: 536870912
#         max_inflight_requests: 128
#         max_client_id_bytes: 256
#         max_topic_bytes: 249
#         max_group_bytes: 255
#         max_array_items: 4096
#         client_id_allow: [orders-client]
#         topic_allow: [orders]
#         group_allow: [orders-consumers]
#         sasl_mechanism_allow: [PLAIN]
#         broker_rewrite:
#           - from_host: kafka-1.internal
#             from_port: 9092
#             to_host: kafka.example.com
#             to_port: 19092
#       routes:
#         - id: broker-1
#           default: true
#           upstream: "10.0.0.31:9092"

# 管理/观测面(只绑内网,与数据面端口隔离):/healthz /readyz(+ 后续 /metrics、admin API)。
admin:
  listen: "127.0.0.1:18080"
  expose_metrics: true
  max_config_body_bytes: 2097152 # UI/API 候选 gateway.yml dry-run 上限；不覆盖真实文件
  # V5 RBAC：启用后旧 admin.auth 单凭据必须清空，每个凭据绑定不可伪造的 principal。
  # auth:
  #   enabled: true
  # rbac:
  #   enabled: true
  #   principals:
  #     - id: platform-viewer
  #       bearer_token: "env://GATEWAY_VIEWER_TOKEN"
  #       roles: [viewer]
  #     - id: security-oncall
  #       bearer_token: "file://secrets/security-token"
  #       roles: [security-sre]
  # audit:
  #   enabled: true
  #   file: ".gateway-audit/audit.jsonl"
  #   signing_key: "file://secrets/audit-hmac-key" # 至少 32 bytes
  #   endpoint: "https://audit.internal.example/v1/events" # 外部 2xx 前写动作不执行
  #   authorization: "file://secrets/audit-authorization"
  #   timeout_ms: 3000
  #   fsync: true

access_log:
  enabled: true
  queue_size: 4096
  # format: '$remote_addr "$method $path" $status $elapsed_ms $upstream'
  # if: "$status >= 500"
  # sample: 1.0
  # V5 多出口：每个 sink 有独立 bounded queue/批处理/超时，慢端只丢自己的记录。
  # 未配置 sinks 时兼容旧行为，自动输出到 tracing。HTTP header 值支持 env:// / file://。
  # sinks:
  #   - id: audit-http
  #     type: http
  #     endpoint: "http://127.0.0.1:9000/logs"
  #     headers:
  #       authorization: "file://secrets/log-token"
  #     queue_size: 4096
  #     batch_size: 128
  #     batch_delay_ms: 200
  #     timeout_ms: 3000
  #   - id: search
  #     type: elasticsearch
  #     endpoint: "http://127.0.0.1:9200/_bulk"
  #     index: gateway-access
  # Kafka 需使用 `--features log-kafka` 构建，并配置 bootstrap_servers/topic/lane。

# V5 OpenTelemetry。关闭导出时仍生成 W3C trace-id 并向上游传播；启用后用有界批处理，
# collector 故障不反压数据面。以下字段属于 bootstrap 层，修改后需重启。
telemetry:
  enabled: false
  endpoint: "http://127.0.0.1:4318"
  service_name: "nate"
  sample_ratio: 1.0
  queue_size: 2048
  batch_size: 512
  scheduled_delay_ms: 5000
  export_timeout_ms: 3000
  b3_compat: true

# 热重载控制面预算：启动时创建有界 channel，修改后需重启生效。
reload:
  channel_capacity: 16
  debounce_ms: 300

long_connections:
  drain_on_config_change: false
  drain_grace_ms: 0

# V3 nginx set/map/变量系统。默认不开放任意 header/query,避免高基数或敏感字段误用。
variables:
  allow_headers: []
  allow_queries: []
  set: {}
  maps: []

# V2/V7 动态服务发现。所有远端 I/O 都在后台 worker；请求路径只读本地不可变实例快照。
discovery:
  nacos:
    enabled: false
    server_addr: ""
    namespace: ""
    group: "DEFAULT_GROUP"
    app_name: "nate"
    # 网关节点自注册。启用时需设置 discovery_ip 或 self_register.ip,避免把 0.0.0.0 注册到 Nacos。
    discovery_ip: null
    self_register:
      enabled: false
      service_name: "" # 空 = 使用 app_name
      ip: null          # 优先级:self_register.ip > discovery_ip > 非 wildcard listen IP
      port: 0           # 0 = 使用默认数据面 proxy listen 端口
      weight: 1.0
      ephemeral: true
      cluster: null
      metadata: {}
      deregister_timeout_ms: 3000
    poll_interval_ms: 5000
    stale_ttl_ms: 30000
    reconnect_backoff_ms: 1000
  consul:
    enabled: false
    base_url: ""       # 例如 http://consul.service:8500
    token: ""          # SecretSource: env/file/k8s-file/vault-agent/literal
    datacenter: ""
    tag: ""
    passing_only: true
    poll_interval_ms: 5000
    request_timeout_ms: 2000
    stale_ttl_ms: 30000
    max_response_bytes: 4194304
    max_instances: 1024
  eureka:
    enabled: false
    base_url: ""       # 例如 http://eureka.service:8761
    username: ""
    password: ""       # SecretSource
    poll_interval_ms: 5000
    request_timeout_ms: 2000
    stale_ttl_ms: 30000
    max_response_bytes: 4194304
    max_instances: 1024
  dns:
    enabled: false
    poll_interval_ms: 5000
    request_timeout_ms: 2000
    stale_ttl_ms: 30000
    max_addresses: 256
  kubernetes:
    enabled: false
    api_server: ""     # 集群内通常为 https://kubernetes.default.svc
    namespace: "default"
    bearer_token: ""   # 例如 k8s-file:///var/run/secrets/kubernetes.io/serviceaccount/token
    ca_certificate: "" # 例如 k8s-file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    poll_interval_ms: 5000
    request_timeout_ms: 2000
    stale_ttl_ms: 30000
    max_response_bytes: 4194304
    max_instances: 1024

# V7 Kubernetes 路由控制器。复用 discovery.kubernetes 的 API/凭据；对象先原子物化，
# 再经唯一 reload worker 完整校验和 ArcSwap 发布，不允许在数据面直接解释 K8s JSON。
kubernetes_routes:
  enabled: false
  target_proxy: "default" # proxies[] 模式改成目标 proxy id
  materialized_file: ".gateway-kubernetes-routes.json"
  ingress_enabled: true
  ingress_classes: ["gateway"]
  gateway_api_enabled: true
  gateway_controller_name: "gateway.rust.dev/controller"
  gateway_api_version: "v1.5.1" # 固定 CRD 与 conformance 契约，版本不匹配时拒绝启动 controller
  gateway_bind_address: "0.0.0.0" # HTTP/HTTPS listener 物化为数据面 socket 时使用的本地地址
  gateway_stream_bind_address: "0.0.0.0" # TLS/TCP/UDP listener 的绑定地址；同端口混用 L7/L4 时应隔离
  gateway_stream_bind_addresses: [] # 非空时逐 Gateway 分配独立 stream 地址；池耗尽的 Gateway 不进入数据面
  grpc_backend_protocol: "h2c"    # 明文集群用 h2c；后端启用 TLS 时改为 h2
  status_updates_enabled: false    # 开启前需授予 Route/Gateway/GatewayClass status patch 权限
  finalizers_enabled: false        # 开启前需授予 Route metadata patch 权限
  watch_enabled: true              # LIST 后从同一 resourceVersion watch，事件只负责唤醒完整 relist
  watch_timeout_seconds: 30
  deletion_drain_timeout_ms: 5000  # 数据面快照确认撤销后才解除删除 finalizer
  max_status_updates: 4096         # 单轮 status/finalizer 外部副作用预算
  namespaces: []           # 空 = 全部 namespace
  poll_interval_ms: 5000
  request_timeout_ms: 2000
  stale_ttl_ms: 30000
  max_response_bytes: 4194304
  max_objects: 4096
  max_routes: 4096

# V4 统一配置来源。默认关闭;启用后 watch Nacos 配置中心三份 yml,坏配置不上线。
config_source:
  nacos:
    enabled: false
    server_addr: ""
    namespace: ""
    group: "DEFAULT_GROUP"
    app_name: "nate"
    username: ""
    password: ""
    gateway_data_id: "gateway.yml"
    interface_guard_data_id: "interface-guard.yml"
    sentinel_rules_data_id: "sentinel-rules.yml"
    materialized_dir: ".gateway-nacos-config"
    reconnect_backoff_ms: 1000

# 运行态共享后端。默认 file/local，无外部依赖；Nacos 真实传输需 nacos-sdk feature。
runtime_state:
  store:
    backend: file
    file:
      root: "runtime-state"
    redis:
      url: ""
      namespace: "gateway"
      profile: "RustV2"
      prefix: "gw:dynamic"
    nacos:
      server_addr: ""
      namespace: ""
      group: "DEFAULT_GROUP"
      app_name: "naway-dynamic-store"
      username: ""
      password: ""
      data_id_prefix: "naway.dynamic"
      max_document_bytes: 1048576
  blacklist:
    enabled: false
    collection: "acl_blacklist"
    refresh_interval_ms: 1000
    auto_ban:
      enabled: false
      limit_req_rejections: 10
      window_ms: 60000
      ban_ttl_ms: 300000
  interface_disable:
    enabled: false
    collection: "interface_disable"
    refresh_interval_ms: 1000
  rate_limiter:
    backend: local
    fail_mode: open
    redis:
      url: ""
      namespace: "gateway"
      profile: "RustV2"
  # V5 HTTP response cache L2。默认 local=仅 route 有界 L1；跨节点命中/失效显式切 redis，
  # 并在对应 `proxy_cache` filter 增加 `l2=true`。连接参数变更需重启。
  http_cache:
    backend: local
    redis:
      url: ""
      namespace: "gateway"
      profile: "RustV2"
    prefix: "gw:http-cache:v1"
    invalidation_channel: "gw:http-cache:invalidate:v1"
    reconcile_interval_ms: 5000

# 接口守卫独立配置(相对本文件目录或绝对路径)。
interface_guard_file: "interface-guard.yml"
# Sentinel 流量防护独立规则(相对本文件目录或绝对路径)。
sentinel_rules_file: "sentinel-rules.yml"

# V7 套餐目录。consumer 只能来自已验证的 Basic/JWT/API-Key 身份；Redis limiter 可把
# 额度变成跨节点一致状态。route 没有 usage_plan 时不会构造配额 key。
usage_plans:
  plans: {}
  consumers: {}

# V7 开发者门户默认关闭。OpenAPI 在 build/reload 阶段有界导入并物化普通 route；key
# 申请只写 pending 记录，不在公网路径直接签发 secret。Redis 后端用单条 Lua 原子守住
# max_pending，file 后端用进程内写锁守住，不能用 list + put 拼接 admission。
developer_portal:
  enabled: false
  public_catalog: false
  max_document_bytes: 4194304
  catalogs: []
  key_applications:
    enabled: false
    authorization_token: "" # 独立 SecretSource；不要复用 admin/API-key secret
    collection: developer_key_applications
    max_body_bytes: 16384
    max_pending: 10000

# 静态上游目录;routes[].uri = "lb://demo" 时按 upstream 策略选择 healthy 实例(默认带权轮询)。
upstreams:
  # 低频 worker 只扫描新实例；请求路径不扫描目录。100..=60000ms。
  prewarm_scan_interval_ms: 1000
  services: {}
#  services:
#    demo:
#      protocol: h1 # h2/h2c 只预热一条 multiplexed 物理连接
#      prewarm:
#        connections: 2
#        path: /healthz # 固定 HEAD，无下游 header/body/身份
#        timeout_ms: 1000
#      instances:
#        - uri: http://127.0.0.1:9001

# 路由表(空 = 所有请求 404;按需添加)。示例(取消注释并改上游):
# routes:
#   - id: demo
#     uri: "${GW_DEMO_UPSTREAM:http://127.0.0.1:9001}"   # R1 直连;R2 支持 lb://service
#     predicates:
#       - "Path=/api/"
#       - "Method=GET,POST"
#     filters:
#       - "StripPrefix=1"
#       # V5 响应压缩：未知长度保持流式，不会为 min_length 聚合 body；默认 br 优先。
#       - "compression algorithms=br,gzip min_length=1k types=text/*,application/json gzip_level=6 brotli_quality=5 chunk_bytes=16k"
#       # V5 公共 L1/L2 缓存：最多复制 1MiB 未压缩实体；Redis L2 需上方 backend=redis。
#       - "proxy_cache public=true ttl_ms=60000 stale_while_revalidate_ms=0 ttl_jitter_percent=10 max_body_bytes=1m max_entries=10000 statuses=200 vary=Accept-Language l2=false singleflight=true singleflight_wait_ms=1000 max_inflight=1024"
#     # V5 OpenAPI/JSON Schema 显式慢路径。只有 body schema 才聚合正文，且上限必填；
#     # schema 在 reload/build 时编译，外部 $ref 被拒绝。也可改用 head_schema/body_schema(_file)。
#     request_validation:
#       openapi_file: "api/openapi.yml"
#       operation_id: "createOrder"
#       max_body_bytes: 1048576
#   # V7 GraphQL：只在显式 route 上有界解析；fragment 每次展开重复计费。
#   # 支持 GET query、POST application/json 与 application/graphql；multipart/subscription
#   # transport 尚未实现。degraphql 是下面单独的、固定 query 的 REST 映射终端。
#   - id: graphql
#     uri: "${GW_GRAPHQL_UPSTREAM:http://127.0.0.1:4000}"
#     predicates:
#       - "Path=/graphql"
#     graphql_guard:
#       max_body_bytes: 262144
#       max_query_bytes: 131072
#       max_tokens: 32768
#       max_depth: 16
#       max_complexity: 1000
#       allow_introspection: false
#   # V7 degraphql：客户端只能填显式 path/query/header/literal variables，不能上传 query。
#   # JSON envelope 在 max_body_bytes 内一次生成；固定 query/operation 在 reload 时校验。
#   - id: rest-to-graphql
#     uri: "${GW_GRAPHQL_UPSTREAM:http://127.0.0.1:4000}"
#     predicates: ["PathTemplate=/rest/pets/{id}", "Method=GET"]
#     degraphql:
#       query: 'query Pet($id: ID!) { pet(id: $id) { id name } }'
#       operation_name: Pet
#       upstream_path: /graphql
#       rest_path_template: "/rest/pets/{id}"
#       max_body_bytes: 8192
#       variables:
#         id: { source: path, name: id, kind: string, required: true, max_value_bytes: 256 }
#   # 原生 Dubbo2 generic invocation。公网 body 只有 arguments；interface、method、Java 类型
#   # 和 attachments 都由可信 route 固定。JSON 使用 id=6；Hessian2(id=2) 需编译
#   # `dubbo-hessian2` feature，并把下方 serialization 改为 hessian2。
#   - id: dubbo-greet
#     uri: "http://127.0.0.1:20880"
#     predicates: ["PathExact=/rpc/greet", "Method=POST"]
#     dubbo:
#       interface: org.example.Greeter
#       method: greet
#       parameter_types: [java.lang.String]
#       serialization: json
#       max_request_body_bytes: 1048576
#       max_request_frame_bytes: 4194304
#       max_response_body_bytes: 4194304
#       max_hessian_string_bytes: 1048576
#       max_hessian_binary_bytes: 1048576
#       max_hessian_collection_items: 65536
#       max_hessian_depth: 32
#       connect_timeout_ms: 1000
#       request_timeout_ms: 3000
#       max_idle_connections: 8
#       attachments: { tenant: "env://GW_DUBBO_TENANT" }
#   # V7 稳定加权灰度：同组成员必须有完全相同的非 Weight predicates 和 order；基于
#   # request-id 做稳定 hash，无每请求候选 Vec/随机数。组至少两条、每组最多 32 条。
#   - id: release-stable
#     uri: lb://stable
#     order: 10
#     predicates: ["Path=/api/", "Weight=release,90"]
#   - id: release-canary
#     uri: lb://canary
#     order: 10
#     predicates: ["Path=/api/", "Weight=release,10"]
#   # OPA 授权：先完成本地认证，再把有界 input 发给外部 Data API 或签名 embedded bundle。
#   # 默认不读取业务 body/完整 JWT claims；Authorization/Cookie/API-Key 永不复制给 OPA。
#   # 显式 include_headers 位于 request_headers_untrusted，不能作为可信 principal。
#   - id: opa-protected
#     uri: "${GW_PROTECTED_UPSTREAM:http://127.0.0.1:9002}"
#     predicates:
#       - "Path=/protected/"
#     filters:
#       - "api_key header=X-Api-Key value=env://GW_CLIENT_API_KEY consumer=tenant-a"
#     opa_authorization:
#       target: "${GW_OPA_UPSTREAM:http://127.0.0.1:8181}" # 也支持 lb://opa
#       path: /v1/data/gateway/allow
#       timeout_ms: 500          # response head + 完整 decision body 的总 deadline
#       fail_open: false         # 只影响依赖/协议错误；超限 input 和缺身份永不放开
#       authorization: "env://GW_OPA_AUTHORIZATION"
#       include_headers: [X-Resource]
#       max_header_value_bytes: 4096
#       max_input_bytes: 65536
#       max_response_bytes: 65536
#       require_identity: true
#       cache:
#         ttl_ms: 1000            # allow TTL
#         deny_ttl_ms: 250
#         max_entries: 10000
#         singleflight: true
#         singleflight_wait_ms: 1000
#         singleflight_max_keys: 1024
#         distributed: false      # 开启时通过当前 DynamicStore 跨节点复用
#         distributed_collection: opa_decisions
#         distributed_max_entries: 100000
#         # 外部 OPA 必须显式声明；embedded 自动取 bundle manifest revision 或 SHA-256。
#         policy_revision: bundle-sha256-or-release-id
#       input:
#         include_body: false
#         max_body_bytes: 65536
#         content_types: [application/json]
#         include_jwt_claims: false
#       obligations:
#         request_headers: [X-Verified-Tenant]
#         response_headers: [X-Policy-Decision]
#         audit_metadata: [reason]
#         max_entries: 32
#         max_value_bytes: 4096
#         max_bytes: 32768
#       backoff_initial_ms: 100
#       backoff_max_ms: 5000
#   # `--features opa-embedded` 可执行标准 `.tar.gz` Rego bundle；签名覆盖压缩原始字节。
#   # bundle、detached signature 或 public key 文件替换均触发同一 build-then-swap；坏候选保留旧策略。
#   # opa_authorization:
#   #   engine: embedded
#   #   bundle:
#   #     source: policies/gateway.tar.gz
#   #     signature: file://policies/gateway.tar.gz.sig.b64
#   #     public_key: file://policies/opa-ed25519.pub.b64
#   #     query: data.gateway.authz
#   #     max_bundle_bytes: 8388608
#   #     max_expanded_bytes: 33554432
#   #     max_files: 256
#   # V7 内嵌 Casbin RBAC/ABAC。model/policy 热更重建整个只读 Enforcer，旧快照
#   # 不被就地修改。consumer 只取本地已验认证结果；header:* 永远是不可信 ABAC 属性。
#   - id: casbin-protected
#     uri: "${GW_PROTECTED_UPSTREAM:http://127.0.0.1:9002}"
#     predicates:
#       - "Path=/rbac/"
#     filters:
#       - "api_key header=X-Api-Key value=env://GW_CLIENT_API_KEY consumer=tenant-a"
#     casbin_authorization:
#       model_file: policies/rbac-model.conf
#       policy_file: policies/rbac-policy.csv
#       arguments: [consumer, path, method] # 顺序必须与 model r = ... 一致
#       require_identity: true
#       max_argument_bytes: 4096
#       max_input_bytes: 16384
#       fail_open: false
#   # V7 Proxy-Wasm ABI v0.2.1 HTTP 插件。替换 module_file 会触发 build-then-swap，
#   # 无需重编/重启 gateway；旧 snapshot 继续服务在途请求。沙箱不挂 WASI，
#   # 不提供文件或网络。request_body/response_body 是显式有界聚合慢路径；
#   # PAUSE 必须注册 timer，并在统一 timeout 内由 proxy_on_tick 调用 continue_stream。
#   - id: wasm-protected
#     uri: "${GW_WASM_UPSTREAM:http://127.0.0.1:9003}"
#     predicates:
#       - "Path=/wasm/"
#     wasm_plugins:
#       - id: request-policy
#         module_file: plugins/request-policy.wasm
#         phase: request_headers
#         config: { mode: enforce, tenant_header: X-Tenant }
#         fail_open: false
#         max_module_bytes: 16777216
#         max_memory_bytes: 8388608
#         max_fuel: 10000000
#         timeout_ms: 10
#         max_mutations: 64
#         max_header_bytes: 65536
#         max_body_bytes: 1048576
#         max_local_response_body_bytes: 65536
#       - id: response-policy
#         module_file: plugins/response-policy.wasm
#         phase: response_headers
#         config: { add_security_headers: true }
#         fail_open: false
#   # OpenAI-compatible 统一入口。该 route 不再配置 uri；模型/moderation/embedding 各自声明后端与凭据。
#   - id: llm-chat
#     predicates:
#       - "Path=/v1/chat/completions"
#       - "Method=POST"
#     llm:
#       max_body_bytes: 1048576
#       max_prompt_tokens: 131072
#       max_completion_tokens: 8192
#       selection:
#         strategy: cost                 # ordered | cost | latency | weighted
#         required_capabilities: [json]  # 先按固定能力筛选，再执行首选策略/fallback
#       token_quota:
#         tokens: 100000
#         window_ms: 60000
#         burst: 10000
#         dimension: consumer
#         max_active_keys: 100000
#         active_keys_fail_open: false
#       guardrails:
#         system_prompt: "Follow the audited gateway policy."
#         blocked_substrings: ["ignore previous instructions"]
#         blocked_response_substrings: ["private-output-marker"]
#       moderation:
#         uri: "${GW_MODERATION_URI:http://127.0.0.1:8001}"
#         model: omni-moderation-latest
#         path: /v1/moderations
#         api_key: "env://GW_MODERATION_API_KEY"
#         timeout_ms: 2000
#         max_request_bytes: 1048576
#         max_response_bytes: 1048576
#         fail_mode: closed
#       semantic_cache:
#         ttl_ms: 300000
#         max_entries: 10000
#         max_response_bytes: 1048576
#         similarity_threshold: 0.92
#         max_candidates: 128
#         l2: false  # true 复用上方 runtime_state.http_cache Redis；local 模式 build fail-fast
#         scope: consumer
#         embedding:
#           uri: "${GW_EMBEDDING_URI:http://127.0.0.1:11434}"
#           model: text-embedding-3-small
#           path: /v1/embeddings
#           api_key: "env://GW_EMBEDDING_API_KEY"
#           max_dimensions: 4096
#       models:
#         - id: primary
#           provider: openai
#           uri: "${GW_LLM_PRIMARY_URI:http://127.0.0.1:8000}"
#           model: local-chat
#           api_key: "env://GW_LLM_PRIMARY_API_KEY"
#           capabilities: [json]
#           weight: 100
#         - id: fallback
#           provider: anthropic
#           uri: "${GW_LLM_FALLBACK_URI:http://127.0.0.1:9000}"
#           model: claude-fallback
#           api_key: "env://GW_LLM_FALLBACK_API_KEY"
#           capabilities: [json]
#           weight: 10
#         - id: gemini
#           provider: google
#           uri: "${GW_GEMINI_URI:https://generativelanguage.googleapis.com}"
#           model: gemini-2.5-flash
#           api_key: "env://GW_GEMINI_API_KEY"
#           # 默认自动生成 generateContent 与 streamGenerateContent?alt=sse path。
#           capabilities: [json]
#           weight: 10
routes: []
"#;

/// 空守卫默认:不拦任何接口,operator 按需加 rules。
const DEFAULT_INTERFACE_GUARD_YML: &str = r#"# 接口级拦截(启动自举生成的最低运行默认)。rules 空 = 不拦任何接口;按需添加。
# 配置 schema 版本(§6);缺省按 v1 处理并告警。
schema_version: 1

# 未单独配 response 的规则用的默认响应。
default_response:
  status: 503
  headers:
    Content-Type: "application/json"
  body: '{"code":50300,"msg":"该接口已暂停对外服务"}'

# 示例(取消注释即把 export 接口对外下线,直接返回下面的 response):
# rules:
#   - id: close_export
#     enabled: true
#     match:
#       path: "/api/export/**"
#       methods: [GET, POST]
#     response:
#       status: 403
#       headers: { Content-Type: "application/json" }
#       body: '{"code":40301,"msg":"export 接口已下线"}'
rules: []
"#;

/// 空 Sentinel 默认:无流控规则,operator 按需加 flow。
const DEFAULT_SENTINEL_RULES_YML: &str = r#"# Sentinel 流量防护规则(启动自举生成的最低运行默认)。flow 空 = 无额外限流/并发规则。
schema_version: 1

# 示例:
# flow:
#   - id: demo_ip_qps
#     enabled: true
#     route: demo
#     key: ip
#     rate: 100r/s
#     burst: 50
#     max_active_keys: 100000
#     active_keys_fail: open
#   - id: demo_ip_conn
#     route: demo
#     key: ip
#     limit: 100
#   - id: demo_failures
#     route: demo
#     failure_threshold: 5
#     window_ms: 10000
#     min_requests: 5
#     break_ms: 30000
#     fallback_status: 503
#     fallback_body: circuit_open
flow: []
degrade: []
"#;

/// 确保配置目录与所需 yml 齐全,缺失则新建最低运行默认。在 `load_snapshot` 之前调用。
pub fn ensure(cfg_path: &Path) -> Result<()> {
    // 1. 配置目录不存在则创建(便于「首次挂空目录 / 全新机器」直接起)。
    if let Some(dir) = cfg_path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create config dir {}", dir.display()))?;
            tracing::info!(dir = %dir.display(), "config directory created");
        }
    }

    // 2. 主配置 gateway.yml 缺失 → 写最低运行默认。
    if !cfg_path.exists() {
        write_new(cfg_path, DEFAULT_GATEWAY_YML)?;
        tracing::warn!(path = %cfg_path.display(), "gateway.yml missing; bootstrapped minimal default");
    }

    // 3. 接口守卫文件(名取自主配置)缺失 → 写空守卫默认。
    let guard_name = guard_file_name(cfg_path).unwrap_or_else(|| "interface-guard.yml".to_string());
    let guard_path = super::resolve_relative(cfg_path, &guard_name);
    if !guard_path.exists() {
        write_new(&guard_path, DEFAULT_INTERFACE_GUARD_YML)?;
        tracing::warn!(path = %guard_path.display(), "interface-guard.yml missing; bootstrapped minimal default");
    }

    // 4. Sentinel 规则文件缺失 → 写空流控默认。
    let sentinel_name = configured_file_name(cfg_path, "sentinel_rules_file")
        .unwrap_or_else(|| "sentinel-rules.yml".to_string());
    let sentinel_path = super::resolve_relative(cfg_path, &sentinel_name);
    if !sentinel_path.exists() {
        write_new(&sentinel_path, DEFAULT_SENTINEL_RULES_YML)?;
        tracing::warn!(path = %sentinel_path.display(), "sentinel-rules.yml missing; bootstrapped minimal default");
    }

    Ok(())
}

/// 只在文件不存在时写入(create_new 语义:并发/竞态下也不会覆盖已存在文件)。
fn write_new(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut f) => f
            .write_all(content.as_bytes())
            .with_context(|| format!("write default {}", path.display())),
        // 竞态下别的实例刚建好了 → 视作已存在,放行。
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).with_context(|| format!("create default {}", path.display())),
    }
}

/// 从(已存在的)主配置里读 `interface_guard_file` 字段名(用 nasa::yml 解析,占位符已解析;失败回退默认名)。
fn guard_file_name(cfg_path: &Path) -> Option<String> {
    configured_file_name(cfg_path, "interface_guard_file")
}

fn configured_file_name(cfg_path: &Path, key: &str) -> Option<String> {
    let tree = super::loader(cfg_path).load_tree().ok()?;
    tree.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
