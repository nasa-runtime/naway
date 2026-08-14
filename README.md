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

已走通：流式 h1/h2c/TLS/gRPC/WS/WSS 反代、真实 Nacos 发现与网关自注册、Redis/Nacos 共享运行态、Sentinel 防护、配置 build-then-swap、管理面/RBAC/审计、HTTP L1/L2 缓存、OTel、压缩、OpenAPI 请求/响应契约、声明式 JSON/XML/SOAP 转换、OpenAI/Anthropic/Google LLM 网关，以及 WASM/外部插件、OPA/Casbin、GraphQL、Dubbo/MQTT/Kafka、TCP/UDP/TLS stream、K8s/Consul/Eureka/DNS 发现和开发者门户。

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
仍会重新验证摘要及全部供应链证明；获取、验签、编译或实例化失败时，当前路由快照保持不变。

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
