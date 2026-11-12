# 结构化候选编辑

`POST /api/operations/proposals/draft?domain=gateway` 对调用者提交的候选原文进行对象编辑。
它要求启用持久管理提案、当前范围的读取和写入权限，以及 `Content-Type: application/json`。
`domain` 可选 `gateway`、`sentinel`、`interface-guard`；工作区请求另带 `workspace`。
独立 Data 不提供该入口。

编辑只改变响应中的候选，不读取节点配置、保存提案、批准变更或发布路由。结果应继续通过
[持久管理提案](admin-operations.md)保存，并由冻结的各原目标执行预检和应用。
接入 Admin 的编辑成功不代表其它节点已经接受配置。

服务端使用 NAML 读取原始 YAML，不执行环境插值、profile、imports 或 SecretSource。
编辑范围是文档中的显式声明；profile 或导入内容对运行配置的影响，仍由目标完整构建器验证。
候选、字段和结果只驻留本次请求，响应使用 `no-store`。输入不应包含无需编辑的秘密明文。

每个请求包含 `candidate` 原文字符串和 `action`：

```json
{
  "candidate": "schema_version: 1\nroutes: [{id: orders, uri: 'lb://orders', order: 0}]\n",
  "action": {
    "type": "patch",
    "object": { "kind": "route", "proxy": "default", "id": "orders" },
    "fields": { "order": 10, "request_timeout_ms": 3000 },
    "remove": ["backend_request_timeout_ms"]
  }
}
```

路由 `request_timeout_ms` 限制进入上游转发后的总耗时，覆盖准入等待、重试、并行副本和完整响应。
`backend_request_timeout_ms` 为每次实际上游发送建立独立预算；后续重试与延迟启动的副本不会
继承前一次尝试已经消耗的预算，但累计时间仍受请求总时限约束。两个字段省略或设为0时均不
增加对应绝对截止点，连接、响应头和帧间空闲等独立预算仍生效。总时限非0时，单次预算不得
大于总时限。响应头与正文共用原截止点，持续收到帧也不续期；响应头发出后超时只能终止正文。
Connect unary 的完整响应转换在单次预算内完成。WebSocket 预算覆盖升级握手及非101响应正文，
升级后的隧道使用 WebSocket 自身的空闲和最长寿命策略。
并行副本优先交付未过期的非5xx响应，4xx属于业务结果；先到的5xx不能遮蔽后到的成功。
等待其它尝试期间已经耗尽预算的失败响应不再获得交付资格；没有可交付结果时按失败或超时处理。

路由常用字段提供上述总时限、单次时限以及 `long_stream_idle_timeout_ms` 和
`long_stream_max_lifetime_ms`。帧间空闲期限省略时继承入口，0 关闭；最长存活时间用于
SSE / gRPC 长流，0 不限制。原生边缘桥接也使用这两项长流参数；普通上游 WebSocket
隧道沿用独立策略。`hedge` 子字段提供明确的幂等确认、延迟和固定两次尝试，
不会自动启用。并行副本要求固定 `lb://` 服务及 `proxy_pass_request_body off`，仅对 GET / HEAD
执行；关闭策略须移除完整声明。候选仍须经过原目标预检和审批发布，表单不会代替业务幂等判断。

路由 WAF 提供模式、正文检查、扫描与结构预算、内置规则选择，以及精确例外的类型化列表。
声明 `waf` 即启用，缺省模式为 `enforce`，关闭须移除完整策略。空 `enabled_rules` 启用全部
内置规则；例外仅绑定已启用规则与精确检查位置，不接受通配符。`monitor` 仍受独立正文
容量门约束，超限返回 413，正文读取失败返回 400。只有 `inspect_body=true` 才对 JSON / XML
启用有界聚合，不能与不转发正文或非零长流最长寿命混用。未编辑声明保持原值。

外部 WAF 规则包支持独立编辑本地来源、SHA-256 摘要、Ed25519 签名、公钥及四项构建预算。
签名覆盖原始 JSON 字节；签名与公钥使用 Base64 SecretSource，页面不解析秘密或上传文件。
目标节点必须具备声明的本地文件；相对路径以主配置目录为基准，URL 来源会被拒绝。
候选须通过原目标的摘要、签名、格式和资源检查。包只支持有界 literal 规则，正文检查仍受
`inspect_body` 与独立容量门约束。移除完整 `waf.rule_pack` 保留内置 WAF，父段与子字段不能
在同次动作中重叠编辑。

路由 Bot 提供 User-Agent 名单、必需头、自动化信号、稳定指纹、行为分数和挑战响应字段，
六个字符串列表支持按原位置编辑。声明 `bot` 即启用，缺省为 `enforce`；关闭须移除完整策略。
非空允许名单要求匹配，拒绝名单命中即挑战，glob 忽略大小写且不能在两份名单中重复。
必需头须恰有一个非空合法值，行为分数达到阈值时挑战，`monitor` 记录后继续转发。
拒绝指纹按原 User-Agent 与所选头值的顺序计算，不包含客户端 IP。普通挑战使用除 429
以外的 4xx，429 用于速率拒绝；未编辑的速率和可信机器人签名声明保持原值。

Bot 速率表单提供基础令牌量、补充窗口、突发量、活动指纹上限与溢出放行开关。
声明 `bot.rate` 即启用，新建须填写 `limit` 与 `window_ms`；初始容量为 `limit + burst`，
按 `window_ms` 补充基础量；速率指纹
另包含可信客户端地址。`active_keys_fail_open` 缺省为 false；明确开启后，表满时可放行
未记账的新指纹且不新增桶，已有指纹仍受额度限制，创建真实桶仍须满足工作区状态预算。
速率拒绝返回 429，等待建议按完整窗口向上取整为秒。移除完整 `rate` 保留其它 Bot 信号；
没有任何有效信号的候选会被拒绝，关闭全部策略须移除 `bot`。

可信搜索机器人使用六字段类型化列表，提供名称、User-Agent glob、签名密钥引用、签名头、
时间戳头和最大时钟偏差，支持按原位置编辑、插入、替换、移动和确认删除。最多 32 条声明，
名称须唯一；密钥经 SecretSource 解析后至少 32 字节，两个头名称须不同，时钟偏差为 1–900 秒。
不同名称可以覆盖相同 User-Agent，任一声明验签通过即可在 Bot 层获得豁免，以支持密钥重叠。
清空或移除完整 `trusted_search_bots` 列表会撤销豁免，保留其它 Bot 信号与速率限制。

每次验签将以下六项的 UTF-8 字节按顺序以单个 LF 分隔，末尾不追加换行：解析后的十进制
Unix 秒时间戳、可信客户端 IP、方法、请求 URI 的 authority（缺失时使用严格单值 Host）、
原始 path/query、原始 User-Agent。签名为 HMAC-SHA256 的无填充 Base64URL 编码。
Bot 信任只影响 Bot 门禁，业务认证照常执行；正文由既有路由策略处理，不属于此身份签名的输入。
无效声明在 `enforce` 下挑战，在 `monitor` 下保持非可信并记录后继续。

路由 DLP 表单提供命中动作、启用规则、请求与响应 header 目标、query 与日志路径检查、
两个正文方向、允许的正文类型、独立字节容量、遮蔽文本和完整精确例外列表。
四个字符串列表支持逐项编辑，例外使用 `rule` 与 `target` 两字段类型化操作。
空 `enabled_rules` 启用全部内置规则；空 `exclusions` 撤销全部例外。
例外只作用于已启用规则及精确位置：`request_header:<小写名称>`、`response_header:<小写名称>`、
`query:<名称>`、`request_body`、`response_body` 或 `path_log`，不接受通配符。
声明 `dlp` 即启用，至少保留一处检查；关闭须移除完整策略，未编辑的其它保护保持原值。

`monitor` 保留命中字节，正文资源或结构门仍会拒绝；`redact` 遮蔽命中字段，正文长度和
失效的摘要、validator、range 元数据同步更新。只有显式正文方向才聚合 JSON / form / text，
每方向容量为 1–16777216 字节，遮蔽文本为 1–128 字节可打印 ASCII。请求命中 `block` 返回 403，
聚合超限 413，读取或结构失败 400；响应检查失败返回 502。压缩实体与不支持的 media type
不进入内容放行。请求正文检查不能关闭转发正文，正文检查不能配置非零长流最长寿命；
响应正文检查不能与 `proxy_cache` 混用，internal 路由不能声明 DLP。

路由 CSRF 表单提供模式、受保护方法、允许来源、Referer 兜底与缺失来源开关、Token 模式、
Cookie 与回传头名称、签名密钥引用、最大年龄及签发开关。方法与来源支持逐项编辑；
方法为 1–16 个不重复的大写状态变更方法，不接受 GET / HEAD / OPTIONS / TRACE。
允许来源为至多 64 项精确 HTTP(S) origin 或 `same-origin`，空列表须同时明确允许缺失来源。
Origin 存在时必须严格验证；Referer 只在 Origin 缺失时兜底，允许缺失来源不会绕过 Token。
声明 `csrf` 即启用，关闭须移除完整策略；internal 路由与 `early_data` 不接受该策略。

`double_submit` 使用 256-bit 随机 Token 且密钥声明须为空；`signed` 使用至少 32 字节的
HMAC SecretSource，并验证路由绑定及 1–604800 秒最大年龄。切换至 `double_submit` 时须明确
移除旧密钥声明，未编辑的引用保持原值。只有启用签发、方法未受保护且最终响应成功或重定向
时才生成头与 `__Host-` Cookie 中的同一 Token；Cookie 固定 `Path=/; Secure; HttpOnly; SameSite=Strict`，
并通过 `private, no-store` 禁止共享缓存存储。浏览器使用须 HTTPS。CSRF 不聚合正文；
`enforce` 拒绝返回 403，`monitor` 记录后继续，业务认证照常执行。

路由 GeoIP 表单提供三类本地 MMDB 路径、国家与 ASN 的允许/拒绝名单、匿名网络 trait、
记录缺失与查询错误动作，以及数据库过期动作和构建时年龄上限。五个列表支持逐项编辑，
ASN 元素保持非零 `u32` 数值；国家为两位 ASCII 字母并转大写。单国家名单最多 256 项，
单 ASN 名单最多 4096 项，重复及允许/拒绝重叠会被拒绝。
声明 `geoip` 即启用，至少保留一种规则并配置对应数据库；关闭须移除完整策略。
页面不上传或下载数据库，目标节点按本地路径有界读取，单库最多 128 MiB，并检查 MMDB 用途。

每类数据库必须恰好对应非空规则，清空本类名单时须同时移除其路径；
留下无规则的数据库声明会拒绝候选。判断依次经过国家、ASN 和匿名网络；
库内记录或字段缺失、查询或解码错误会立即返回所选整体动作，`allow` 不继续后续库检查。
数据库年龄在候选构建时复核，上限为 1–31622400 秒；过期 `reject` 保留原快照，`allow`
放行整个 GeoIP 门，`deny` 拒绝整个门。坏文件、错误用途和超出一天容差的未来 build epoch
仍会拒绝候选。请求使用可信客户端地址，数据面不读取文件或发起远程地理查询；
未编辑的其它安全声明保持原值。

路由请求校验表单提供十项 `request_validation` 字段：内联或本地文件形式的 head / body
JSON Schema、OpenAPI 文件和操作选择器、正文字节上限及空正文语义。每种 Schema 的内联与
文件来源互斥，OpenAPI 与显式 Schema 互斥。OpenAPI 必须恰选 `operation_id` 或成对的
`operation_path` / `operation_method`；切换时须明确移除旧来源或选择器。
文件路径相对主配置目录解析，页面不读取、上传或下载文件。Schema 在候选构建时读取并编译，
只接受文档内部引用，请求不执行文件或网络解析。关闭校验须移除完整策略。

显式 head Schema 使用 `method`、`path`、`query`、`headers` 和空 `path_params` 的稳定
envelope；query 和小写 header 的值保留为字符串数组。OpenAPI 操作另按声明解析基本类型的
query、header、path 与 cookie 参数，并拒绝重复标量。正文为 JSON，有正文 Schema 时必须
显式设置 `max_body_bytes` 为 1–16777216，head-only 必须为 0。未声明 `body_required` 时，
显式正文 Schema 要求非空，OpenAPI 遵从 `requestBody.required`；显式 `false` 只允许空正文，
非空正文仍需符合媒体类型、JSON 语法、Schema 和大小上限，head 也仍须通过。
通过校验的原始正文字节与 trailers 继续转发；不符合同或下游读取失败返回 400，超限返回 413，
拒绝请求不进入上游。请求校验不能与长流生存期并用，正文 Schema 不能与公共响应缓存并用；
其它能力组合由目标构建器校验。

响应合同表单提供 `response_contract` 的十项原生字段，以及本地 catalog 和八字段签名
HTTPS 文档的逐项编辑。OpenAPI 操作须通过 `operation_id` 或成对的路径与方法唯一选择。
所有模式均要求 1–16777216 字节上限；缺省 `observe` 透传原响应，用有界副本在流结束后
记录结论。`block` 在发送实体前校验，合同、大小或读取失败返回固定 502；`replace_error`
改用配置的非成功 HTTP 状态与固定纯文本。替代文本至多 4096 UTF-8 字节，按多行字符串编辑。
压缩实体在观察模式透传并记录不支持，在阻断模式使用失败动作。关闭须移除完整策略；
响应合同不能与长流生存期并用。

Schema 的外部引用只可指向显式 `catalog_files` 或 `registry_documents`；连同根文档
最多 32 个，原文字节总量最多 8 MiB，循环、过深引用和 `$dynamicRef` 拒绝候选。
文件路径相对主配置目录解析。签名文档须使用无凭据和 fragment 的固定 HTTPS URL，
不跟随重定向，原始字节同时核对固定 SHA-256 与 detached Ed25519 签名；CA 缺省使用
系统信任。单文档容量为 1–4194304 字节，总期限为 100–30000 毫秒，已验签字节最长复用
时间为 1–86400000 毫秒；命中仍复验当前 CA、签名、公钥和预算，不延长加载时间。
这些解析只发生在候选构建阶段，数据面不访问来源，页面也不求值 SecretSource。
删除来源时须明确处理依赖它的引用，未编辑的其它合同与安全声明保持原值。

路由实体转换表单分别提供 `request_transform` 的十三个合法字段和 `response_transform` 的
十四个字段；SOAP Fault 状态映射仅供响应侧使用。两方向各有 JSON 操作、XML 提取和 XML
输出字段的逐项编辑，以及输出根、namespace 映射、SOAPAction 和独立资源预算。
声明策略即启用对应方向，关闭须移除完整策略，不生成另一方向或物化未编辑的默认值。
输入与输出容量各为 1–16777216 字节，XML 深度为 1–256、节点事件为 1–1000000、
单元素属性为 1–4096、文本总量为 1–16777216 字节；JSON 方向的这些声明也须合法。
转换不能与非零 `long_stream_max_lifetime_ms` 组合，缓冲及重建的实体有明确终态。

JSON 操作依序执行：`rename` 移动已有值，`add` 要求位置尚不存在，`remove` 缺失时幂等，
`default` 只补缺失，`type_check` 要求类型而不转换值。切换 `action` 时须明确移除旧类型的
多余字段；固定 `value` 接受任意 JSON，`null` 是实际值，不能代替移除动作。
路径使用非根 RFC 6901 JSON Pointer，`*` 按字面键处理，不执行 JSONPath、通配展开或脚本。
JSON 到 JSON 至少需要一项操作；XML/SOAP 输入须有提取，输出须有固定输出结构。
操作及每类 XML 映射最多 256 项，add/default 常量累计最多 1 MiB；namespace 映射最多
64 项且 URI 不重复。冲突的 JSON 写目标、rename 环、重复的提取来源或目标、重复的
输出来源及重叠的输出元素路径拒绝候选。
XML 路径按 namespace URI 和本地名匹配，输出路径相对业务根，提取和输出的 `required`
只在明确编辑时写入。SOAP 输入映射锚定标准 `Envelope` / `Body`；输出通过 `namespaces.soap`
选择标准 SOAP 1.1/1.2 URI，缺省 SOAP 1.2。SOAPAction 在请求侧校验输入或设置输出；
响应侧只校验声明合法性，不检查或写入响应头。

转换有界聚合完整实体并重新序列化，成功后重建类型与长度，移除失效的编码、完整性、
range、分块及 Trailer 声明。压缩实体、partial entity、实际 trailers、DTD 和外部实体拒绝。
请求结构或格式失败返回 400，容量超限返回 413；响应转换失败返回 502。
响应转换也覆盖路由内产生的拒绝，组合策略时须保证对应格式兼容。未编辑的其它治理声明
保持原值，最终组合与合法性由原目标候选构建器校验。

GraphQL 查询预算表单提供 `graphql_guard` 七项原生字段。声明即启用，关闭须移除整段；
未编辑的缺省预算和两个放行开关保持原声明。POST 实体为 1–4194304 字节；解码后的完整
query 文档为 1–1048576 UTF-8 字节，token 为 1–262144 且不超过 query 字节上限，
深度为 1–128，选定 operation 的字段复杂度为 1–10000000。根字段深度为 1，每字段成本
为 1，fragment 每次展开重新计费。batch 逐 envelope 复验文档和选定操作的预算，累计成本
交给计量与成本准入；这些字段
不声明额外的 HTTP batch 总复杂度上限。

GET 使用唯一 `query` 和可选唯一 `operationName`，只允许 query 操作且不聚合实体；
POST 支持 JSON 单操作或 batch、`application/graphql` 原文及 multipart 中唯一的
`operations` 部分，通过后原始实体和 trailers 继续转发。body/query/token 超限返回 413，
结构、深度或复杂度不符返回 400，不支持的 POST 媒体类型返回 415，错误方法返回 405。
默认拒绝实际字段名以 `__` 开头的 introspection（包含 `__typename`），alias 不绕过该门。
显式允许标准或 legacy GraphQL WebSocket 订阅后只执行透明转发，消息级查询解析与预算
由上游承担，握手前认证和连接治理仍生效；关闭的 GraphQL 握手和禁止的 introspection
返回 403。该策略需要 HTTP 上游，不与终端静态、固定响应、BFF 或 LLM 后端组合；
其它组合及 `graphql_cost` 的原正文和订阅约束由原目标构建器校验。

`degraphql` 表单提供固定 `query`、可选 `operation_name`、`upstream_path`、
`rest_path_template`、完整 `variables` 映射与 `max_body_bytes`。仅用于精确
`Method=GET` 的 HTTP 路由；原请求须已知空正文，未知 chunked 与 Upgrade 也拒绝。
网关生成固定文档的 POST JSON envelope，客户端 query 参数不能替换文档；固定文档
在构建时按显式 `graphql_guard` 或原生缺省预算检查。生成正文上限为 1024–1048576
字节，超限返回 413；上游 path 不得带 query、fragment 或控制字符，最多2048字节。

变量可按 GraphQL 名称逐项新增、编辑六字段、整值替换或确认删除，最多64项；未编辑
子树和缺省值保持原声明。来源为 `path`、`query`、`header` 或 `literal`。文本来源
明确命名字段，单值上限为1–65536 UTF-8字节；重复 query/header、必需值缺失、坏类型
或超限返回400。`required=false` 时缺失变量省略；integer 使用 i64，number 必须有限，
boolean 只接受 `true`/`false`。path 变量模板须与路由 `PathTemplate` 签名一致；path
逐段百分号解码，query 使用表单解码语义。literal 的 name 须空且 value 必须是非 null
JSON，不按 kind 转换，固定值受生成正文总预算。切换来源须显式移除不再合法的旧字段。
请求校验/请求转换、缓存、internal、终端后端、镜像及路径改写组合由原目标构建器拒绝；
其它未编辑治理继续保持。命名变量动作独立生成候选，不连带提交普通字段的待写修改。

Casbin 授权表单提供 `model_file`、`policy_file`、有序 `arguments`、
`require_identity`、`max_argument_bytes`、`max_input_bytes` 与 `fail_open`。
两份受信本地文件在候选构建时按单文件4 MiB上限读取 UTF-8 并编译；相对路径以主配置
目录解析，请求期不读文件或业务正文。参数按 model 的 `r` 顺序指定，支持 consumer、
path、method、route_id、client_ip、scheme 和显式 `header:Name`，必须为1–16项。
header 提供未可信原始值，不能代替已通过认证链的 consumer；缺省参数不在页面物化。

单参数预算为1–65536 UTF-8字节，合计预算不得低于单参数预算且不超过262144字节。
明确拒绝和缺主体返回403，无效UTF-8或输入超限返回431；内部求值异常默认500，仅此
异常可由 `fail_open=true` 放行。`require_identity=false` 时缺 consumer 使用 anonymous，
已有已认证 consumer 仍保持；开启身份要求须具备原生认证链或父层身份来源。internal 和
公共 proxy_cache 组合拒绝。参数列表支持按位置插入、替换、移动和确认删除；整段移除
Casbin 声明不移除原认证、WAF 或其它独立策略。

OPA 授权表单提供全部十七主声明、bundle 七字段、input 四字段、obligations 六字段和
cache 十字段。四个完整子组可显式设置或移除，子字段操作保持未编辑的秘密引用、开关
和未知声明；父子路径不能在同次动作中重叠。五个字符串名单支持按位置插入、替换、
移动和确认删除，不自行去重或扩大权限。关闭 OPA 须移除完整 `opa_authorization`；移除
cache 只关闭缓存，移除 input 或 obligations 恢复对应原生默认。

external 使用 HTTP(S) origin 或 `lb://service` 和独立绝对路径，路径最多2048字节且不能
带 scheme、authority 或 query，不能同时声明 bundle。完整服务 Authorization 值支持
SecretSource。embedded 需要 `opa-embedded` 能力、非空签名 bundle，并禁止非空
target、path 和 authorization；切换模式须显式处理旧声明，页面不自动删除。bundle
为本地 tar.gz，相对主配置目录解析；detached Ed25519 签名覆盖压缩原始字节，签名和
公钥为64与32字节的标准Base64 SecretSource。压缩、regular file 展开总量和文件数分别
最多64 MiB、256 MiB与4096；链接与特殊条目拒绝，至少有一个Rego模块。静态查询为
`data.<package>.<rule>`，manifest 未提供或 revision 为空时使用材料摘要；候选构建期验签、
有界解包并编译，请求不重新读取来源。页面不读取秘密或上传文件。

输入头名单最多32个原声明，构建时规范化去重；敏感凭据、实体和连接头拒绝，值仍是不可信
属性。单值1–65536字节、完整编码输入256–1048576字节、响应16–1048576字节，决策总
期限1–60000毫秒含响应正文。body 与已验证JWT claims 均单独显式开启；正文上限1–1048576
字节，1–32项去参数精确media type须唯一、无通配符或参数，并且正文必须为合法JSON。
通过后原字节和trailers重放；类型不支持415、正文超限413、读取或JSON失败400，缺主体403，
头值无效或输入过大431。consumer 只来自认证链，客户端身份头不能提供身份。

明确deny返回403；依赖传输、期限、求值、响应协议及非法obligation默认503，仅这些依赖
失败可由 `fail_open=true` 放行，本地输入和身份门仍拒绝。义务先整组验证再应用，失败义务
从不部分执行，失败开放也不执行它。请求/响应头及审计key名单各最多256项；义务头禁止
Authorization、Cookie、Host和连接/分帧控制字段，审计key为1–64字节ASCII字母、数字、
下划线、连字符或点。单次条目1–256、单值1–65536字节、名称和值总量1–1048576字节。

cache 只保存明确allow/deny，分别使用1–300000毫秒TTL，本节点容量1–1000000；外部策略
须声明1–128可见ASCII字节的policy_revision，embedded使用bundle revision或摘要。相同
输入及策略域共享决策，域包含可信身份、策略修订和实际服务凭据摘要。singleflight仅合并
本节点同键并发miss，follower等待1–30000毫秒、活跃key上限1–65536；表满有界绕过。
distributed经DynamicStore复验修订、过期与义务，启用时共享容量1–1000000且collection
须合法。依赖错误不缓存；首次退避1–60000毫秒，上限不低于首次且最多300000毫秒，
不能把退避期间不外呼当成缓存错误结果。原认证、WAF和其它独立治理保持原声明。

外部 HTTP 头部插件链在有序列表中提供全部十四个原生字段。既有元素按原始位置编辑
十三个非身份字段，id 保持原声明；新增或整值替换须显式填写 id，替换会移除旧元素的
其它字段。id 在整条链中唯一，使用1–128字节ASCII字母、数字、下划线、连字符或点。
最多16项；先按 `request_headers` 与 `response_headers` 分组，各相位内保持原数组
顺序，跨相位移动本身不改变同相位的先后。空数组或移除完整 `external_plugins` 停用链，
不移除认证、WAF或其它独立治理；internal和公共proxy_cache不能声明该链。

固定目标支持HTTP(S) origin或 `lb://service`，独立path为1–2048字节绝对路径且不能有
scheme、authority或query。完整服务Authorization值支持SecretSource，构建时冻结，
不复用业务请求凭据。请求头、响应头和mutation名单均按逐行字符串编辑，各最多32个
原声明并在构建时规范化去重；Authorization、Cookie、X-Api-Key、Host、Forwarded、
X-Forwarded-For、X-Forwarded-Host、X-Forwarded-Proto及连接/分帧控制头禁止读写。请求相位的
响应头名单必须为空。单次调用总期限1–60000毫秒含响应正文；单输入/输出头值1–65536
UTF-8字节、编码输入256–1048576字节、处理器响应16–1048576字节、本地响应正文
1–1048576字节。页面只编辑声明，不解析秘密来源。

处理器输入只有固定相位、路由身份、method/path/query/scheme及名单头；响应相位
另有状态和名单响应头。不会发送业务body，也不提供consumer或JWT claims字段。响应所需请求头
只快照其名单并集，发生在完整请求插件链成功之后；正常继续时业务body和trailers保持原流。
`continue` 的头部变更整组通过权限、重复/冲突和资源门后才提交；不能同时返回本地响应
字段。`local_response` 不能带continue变更，须提供有效非1xx状态和有界正文/名单头，
并短路当前管线。每插件原子提交，前面插件已提交的合法变更不会因后续失败开放而回滚。

传输、期限、非2xx、畸形响应和越权输出等依赖失败默认500；`fail_open=true` 仅丢弃
本插件结果后继续，不执行部分变更，也不覆盖明确本地响应。请求名单头非UTF-8、单值
或编码输入超限返回431，编码错误500；响应输入错误500，均不受失败开放。列表操作
只提交本次元素动作，未修改秘密引用、宽整数和开关保持原声明，不物化运行时默认值。

Envoy External Processing 表单提供 `ext_proc` 的十九项原生声明与两个逐项字符串名单。
节点制品必须启用 `ext-proc` 能力；至少选择一个head、body或trailer相位，关闭须移除
完整声明。开启head或trailer会发送其全部原始头字节，请求里的业务凭据也对受信处理器
可见；mutation名单仅限制写权限。服务Authorization metadata使用独立SecretSource，
解析后最多16384字节。目标为无userinfo、path或query的HTTP(S)origin，或≤253字节
安全ASCII服务名的 `lb://service`，使用固定标准ExternalProcessor.Process双向流。

body模式为none、buffered或streamed。none不发送body相位，但头部明确
`CONTINUE_AND_REPLACE` 仍可有界替换或清空原实体；buffered收集完整有界实体，
streamed逐DATA等待唯一同相位响应并施加背压。trailer开启且非streamed时也会先有界
读取正文。streamed body相位禁止head变更；即时响应仅允许请求相位，响应相位收到
ImmediateResponse须拒绝。处理器不能用mode_override或期限覆盖扩大原声明权限。

每相位期限1–60000毫秒，整流期限不得更小且最多900000毫秒。单条protobuf payload
为256–16777216字节；双向累计含每条5字节gRPC envelope，不得低于单条预算且最多
134217728字节。每方向body上限1–67108864字节且不得超过总量；每路由同时处理流
1–65536，连续依赖失败阈值1–10000，circuit冷却1–60000毫秒。可写头最多128项，
修剪并规范化后须唯一；凭据、伪头、连接分帧/目标字段、全部x-forwarded-/x-naway-
及本地认证拥有的身份头冻结。metadata namespace最多32项，每项1–128字节安全ASCII
字母、数字、点、连字符或下划线且唯一，仅在当前请求和后续相位间保存。

`fail_open` 只覆盖已分类的连接、期限、服务不可用、入流容量与circuit等Dependency；
Protocol和Input始终关闭，包括错序、重复、畸形protobuf、越权mutation、错误namespace、
gRPC明确拒绝及本地预算。依赖开放后当前请求永久bypass，后续相位不再外呼，之前已
通过的合法变更保持。入流依赖失败默认503，头部协议失败500；buffered请求body超限
413、读取400，响应body失败500，均不受失败开放。流式head发出后的失败只能终止body。
每次变更先整组验证再提交，未编辑的原预算、开关、秘密引用与其它治理保持。

Descriptor 驱动 gRPC JSON 表单提供 `grpc_transcoding` 的十二项原生声明与 service、method
两个逐项名单。节点必须启用 `grpc-descriptor`；FileDescriptorSet 为受信本地文件，相对路径
以主配置目录解析，快照绑定同一份有界文件字节和 RPC 计划。`google_http` 与 `connect_json`
至少开启一个；移除完整声明停止 descriptor JSON 转码。

service full name 必须显式列出1–128项，method full name 子集最多2048项；名称不得含斜杠、
空白或重复项。methods 空名单允许所选 service 的全部方法，descriptor 新增方法时暴露范围
可能随之变化；固定范围应逐项列出。名单只约束 JSON 转码入口，原生 gRPC 透传另由路由与
鉴权策略控制。未知 Connect JSON schema 返回404，unary/streaming 媒体类型不匹配返回415；
未匹配 google.api.http 的普通 JSON HTTP 请求保持原路由语义。

descriptor 文件预算1024–33554432字节，输入/输出消息、JSON 文档与未完成流缓冲分别为
1–67108864字节；JSON 上限不能超过输入和输出预算，缓冲不能超过两者的较大值。每 stream
消息上限1–10000000。`reject_unknown_fields` 显式关闭时忽略 descriptor 未声明的 JSON
字段，不改变原生 protobuf 的未知字段语义。逐项编辑和整段移除保持未编辑的引用、宽整数、
名单、开关与其它治理，不物化运行时默认值。

完整 descriptor pool 还独立限制为最多256个文件、1024个 service 和8192个 method，不能
通过缩小白名单绕过。转码独占 request/response body 和 RPC path，不能叠加请求/响应校验、
实体转换、GraphQL、缓存、hedge、镜像、内部路由、直接响应及路径改写，也不能与 grpc_edge
或静态服务、聚合、Dubbo 等专用终端后端组合；候选须由原目标构建器完整复验。

路由级 `grpc_edge` 表单提供三十五项原生叶字段与四个逐项名单，包括动作、精确方法、身份、
授权、发送队列、PublishStream 和节点预算。仅 `enabled=true` 且节点启用 `grpc-edge` 能力时
接管精确 RPC；关闭或移除后保持普通 L7 透传。关闭时可预置声明，类型与未知字段仍须合法。
subscribe 与 publish/push 必须使用不同路由和认证配置，分别声明 `required` 与 `service`；
动作 header 只确认已匹配的方法，不能把普通业务 RPC 改成边缘动作。

user 来自已验证主体的 claim 或已认证 consumer，客户端自报 header 不产生身份。
`tenant_claim` 省略时使用 default tenant，声明时必须从已验证主体取得，不能与 `user_claim`
相同。启用时必须显式声明 `authz`，空名单拒绝对应动作；未允许的动作不得声明 RPC 或非空
授权名单。模式支持字面量、末尾 `*`、`%{user}` 和 `%{tenant}`，单项最多512字节。
WS 桥接只适用于 subscribe，沿用同一身份、授权和预算，路径不能与边缘 RPC 相同。

消息 body 最多16777216字节，另计5字节 gRPC 前缀；队列字节、节点 payload 驻留字节和
PublishStream 累计字节各须能容纳一条最大完整帧。旧顶层 `max_msg_bytes` 与权威位置
`limits.max_msg_bytes` 同时声明时须相等，逐项移除旧别名不会改写权威预算。
队满按 `drop_oldest`、`drop_new`、`latest_by_key` 或 `close_slow` 处理，`at_most_once`
不承诺离线补发。PublishStream 速率门通过背压节流，其余寿命、消息数、累计字节门到界返回
已处理 summary 供发布方轮转。表单不自动启用能力，不物化默认预算，不重写其它策略或引用。
全局 `grpc_edge_cluster` 独立决定跨节点传输与目录，不由路由表单隐式创建或更改。

Proxy-Wasm 插件链按原始位置提供二十三项原生声明。新增或整值替换必须明确填写稳定 id；
已有元素字段编辑不开放 id 变更，移动和确认删除只作用于选中元素。`module_file` 与
`module_source` 二选一；切换来源须显式移除旧声明。远程来源的十项声明与 attestation
六项约束可逐项编辑，未编辑的材料引用、未知字段与宽整数继续保留在服务端原始候选中。

远程模块固定最终字节 SHA-256，并验证 detached Ed25519 signature/public_key 或签名
in-toto statement；同时声明时两者都须有效，OCI tag 还须绑定 manifest 摘要。候选构建时
获取或读取内容缓存，再验证和编译模块；缓存命中仍复验当前字节上限、模块摘要、凭据格式、
附加 CA、签名及 provenance。内容缓存不访问 registry，不证明 tag 当前状态，manifest 与
layer 的对应关系在下载路径校验。来源引用和 manifest 声明的变化仍属于独立的配置比较身份。
页面只编辑 SecretSource 文本，不获取模块或信任材料。

`config` 为最多65536字节的编码 JSON。`callout_clusters` 使用明确完整的 JSON 列表，
每项字段为 `name`、`origin`、`ca_certificate`、`allow_cleartext`、`http2_prior_knowledge`；
最多32项、名称唯一，origin 只接受不带 userinfo、业务 path、query 或 fragment 的 HTTP(S)
origin。明文 HTTP 须显式允许，HTTP/2 prior knowledge 仅用于已允许的明文 origin。
客体只能引用固定名称；运行时不提供 WASI、文件、socket 或环境访问。

六种相位分别处理请求或响应的 head、聚合 body、逐帧 body；同一方向不能混用聚合与流式
body，相位选择不会自动授予 callout。每 route 的 Wasm 与脚本总数最多16项。
显式 fail_open 只跳过可开放的客体执行错误并丢弃本插件部分输出，保留前一插件已提交结果；
共享资源准入拒绝仍关闭。未编辑的预算不会因控件展示而物化为运行默认值。

有界 Lua 脚本链提供十五项原生声明，按原始位置新增、替换、移动或确认删除；已有元素的
字段编辑不开放 id 更改。新增与替换须显式填写1–128字节的 ASCII 字母、数字、`-`、`_`、`.`
稳定 id。两项 `circuit` 子字段可独立编辑；`include_headers` 与 `mutation_headers`
使用完整字符串名单，未编辑名单不重写。表单不自动补入失败策略、熔断声明或预算。

目标须启用 `lua-scripts`，源码真实路径必须在配置根内，候选构建期校验并冻结源码。
`failure_mode=open` 只跳过解释器依赖不可用；客体错误、主动拒绝、输入输出和本地资源预算
始终关闭。同一路由、id 与源码内容的熔断事实跨热更共享，不能通过修改预算清空原始失败原因。
head 相位须移除 `max_body_bytes`；body 相位须显式配置预算且不得声明可写头，聚合与逐帧
预算分别限制完整实体与每片输入输出。切换相位不会自动扩大可见头或写权限；沙箱不提供网络、
文件、进程或 callout。未编辑的路径引用、未知声明和宽整数保留在服务端原始候选中。

BFF 聚合提供三项原生根声明及七项子请求声明。两项共享预算可独立修改，`targets` 可整段
明确设置，也可按原始位置插入、替换、移动或确认删除。已有目标 id 受保护；新增与替换须明确
填写1–64个 ASCII 字母、数字或 `.`、`_`、`-` 组成的 id，不能为 `_errors`，实际构建还须通过
唯一性与1–16项数量门。
`forward_headers` 按完整字符串名单显式编辑；未编辑目标、引用、未知声明与宽整数保持原文。

普通 `uri` 与 BFF 是互斥的终端后端，切换须显式移除旧声明；页面不替用户选择后端或补默认值。
只支持固定 GET 子请求，不拼接客户端 query/body，不展开路径模板。每个成功子响应须是有界的
JSON 值且没有 trailers；`required=false` 的目标失败产生 null 与 `_errors` 固定分类，总期限与
完整输出编码预算仍约束整个聚合。保留的普通认证和 WAF 不因启用聚合而绕过。

固定 `mock_response` 提供 `status`、`headers` 与 `body` 三项独立字段。响应头以完整 JSON
单值映射显式编辑；头名大小写别名同值合并、冲突拒绝。正文使用多行字符串控件，保留换行、
末尾换行和显式空串，不按名单拆分。未编辑的引用、未知子项与宽整数保持原声明。

mock 是不访问上游的终端固定响应；与普通 `uri` 切换时须显式移除旧后端声明，页面不替用户
选择后端或补入默认状态、头及正文。204/304 必须为空正文，禁止声明 Connection、
Transfer-Encoding 与 Content-Length；实际状态、正文和头部限制由原目标候选构建核验。
原有认证和 WAF 不因启用 mock 而绕过。

路由 `fault_injection` 提供比例、延迟、固定错误状态及多行错误正文四项独立字段。
比例须在1–10000 basis points，0 不是关闭开关；关闭时显式移除整段策略。
`abort_status` 可独立移除以保留延迟后继续原后端，延迟和错误状态至少保留一项有效动作。
正文保留换行、末尾换行和空串；表单不补入默认比例、延迟或错误，不自动修改后端声明。
未编辑的引用、未知子项和宽整数保持原值，原目标候选构建核验实际数值与组合边界。

`dubbo` 提供十七项独立原生声明，覆盖 interface、业务方法、Java 参数类型、service version/group、
codec、请求/响应 frame 与 Hessian2 资源门、建连/调用期限、空闲连接容量及固定附件。
调用路由须显式声明精确的 `Method=POST` 断言及不含变量模板的固定 `uri`，表单不自动添加。
`parameter_types` 使用完整字符串名单，也可按原始位置插入、替换、移动或确认删除；其顺序须与
下游 `arguments` 一致。附件以完整 JSON 字符串映射显式编辑，值保持 SecretSource 引用，不在
浏览器求值；`path`、`interface`、`version`、`group`、`generic` 由调用计划保留。

页面不自动选择 serialization、扩大预算或修改原上游 URI；Hessian2 须目标制品显式具备
`dubbo-hessian2`，其专有预算不作用于 JSON codec。空闲容量0表示关闭复用，空 version/group
和空附件映射是实际声明；未编辑的引用、未知子项与宽整数保持原值。

`gateway_redirect` 提供七项独立声明，覆盖 scheme、hostname、port、status_code、完整路径替换
和成对的前缀替换。它是终端后端；启用时须显式移除普通 `uri` 等其它终端后端，停用时须移除
完整策略并明确选择后端，页面不自动切换。未声明的字段不补入默认值。

scheme 只接受 `http` / `https`；省略时保留可信监听协议。hostname 省略时保留入站 authority 的
host；port 省略且 scheme 未覆盖时保留原端口，显式覆盖 scheme 时省略端口表示目标协议默认端口。
状态码只接受301、302、303、307、308；省略时原生默认302。完整路径和前缀替换不能同时声明，
前缀替换须同时有 `matched_prefix`；路径以 `/` 开头、最多2048字节，不含空白、控制字符或 `#`。
未替换的路径遵循入口安全规范化，原 query 保持；前缀不匹配或入站 authority 无效时本次请求
返回400。编码分隔符等危险请求路径仍由入口校验拒绝，重定向不豁免该门。

`ws_frame` 提供十一项独立声明，包括单帧、整条消息、分片、插件载荷、解压比、两个期限、压缩
许可、违规动作和双向完整消息链。每个方向也有原始位置的类型化列表，支持插入、字段编辑、
整值替换、移动和确认删除；消息插件没有 id，按当前位置定位，不生成稳定身份。

消息项明确选择 acl、json_schema、redact、rate_limit 或 external，只填写相应字段；改变类型须
明确移除旧类型字段，整值替换只包含本次新声明。外呼 authorization 与 ca_certificate 保留
SecretSource 文本，页面不读取材料；三个布尔权限分别显式编辑，不因配置 endpoint 自动开启。
清空某方向的列表保留其它帧策略，移除完整 `ws_frame` 恢复透明模式，不修改上游 URI。

`forward_proxy` 提供八项独立声明及端口、域名、CIDR 三个原位置列表。端口使用数值数组，其余
名单每行一项；端口名单不得为空，域名和 CIDR 至少有一种。域名精确或子域规则只授权域名身份，
字面量 IP 必须由 CIDR 授权；开启私网不开放环回、链路本地、元数据或网关自身监听。

启用时须明确声明仅 CONNECT 方法的断言，移除普通 `uri` 等其它终端后端。停用须移除完整
`forward_proxy`，并显式选择所需后端和匹配方法；页面不自动改写断言、URI 或私网权限。
空闲、寿命和双向总字节预算为0时不增加相应限制；建连期限为0仍按至少1毫秒执行。
三类名单可按原位置插入、替换、移动或确认删除，候选构建继续验证组合，原目标授权不会因
无效候选发布而失效；未编辑的引用、未知子项和宽整数保持原值。

`webtransport` 提供固定 HTTPS 上游、精确 Origin 名单、可选 CA 文件和八项会话预算，共十一项
独立字段；Origin 名单另可按原位置插入、替换、移动或确认删除。上游与 CA 信任在候选构建时
冻结，相对 CA 路径按主配置目录解析；页面只编辑路径，不读取证书。来源不得为空、重复或包含
通配符、路径、查询参数及用户信息。

WebTransport 必须显式只匹配 CONNECT，并与其它终端后端二选一；实际会话还需监听器同时声明
HTTP/3、`webtransport` 与 `datagram` 能力。普通 HTTP CONNECT 不能替代 extended CONNECT。
两类流不能同时为0，队列数量、单包字节和空闲期限必须为正，单方向队列预算不超过16 MiB；
总字节和最长寿命的0表示不增加对应限制，建连期限必须为1–60000毫秒。编辑器不补默认预算、
Origin 授权或监听能力；停用须移除完整策略，并显式选择普通后端和匹配方法。

`early_data` 的启用声明和 nonce 保留窗口分别编辑。`enabled: false` 不生成执行计划，仍保留
窗口原声明；开启时窗口必须位于1000–600000毫秒，且路由须明确使用固定 HTTP 上游、唯一的
安全读方法断言与关闭请求体转发，不能包含认证、凭据注入或外部副作用。监听器的 0-RTT 恢复、
能力和适用的共享重放保护须另外显式配置；编辑器不联动修改这些声明。普通请求伪造早期请求
头不会获得 0-RTT 权威，这些字段会在进入上游前剥离；真实早期请求未通过门禁时返回425。
停用可明确关闭启用声明或移除完整策略。

支持的动作如下：

| `type` | 其它字段 | 结果 |
|---|---|---|
| `inspect` | 可选 `object` | 有限对象目录；选择对象时返回其原始字段 |
| `patch` | `object`、`fields`、可选 `remove` | 设置完整字段值，明确移除指定字段 |
| `patch_nested` | `object`、`edits` | 精确设置或移除映射子字段，保留其它子项 |
| `patch_sequence` | `object`、`path`、`edit` | 对指定有序列表执行一个元素动作，保留其它元素 |
| `keys` | 路由 `object`、`edit` | 低敏密钥目录、摘要新增、启用状态或准确声明删除 |
| `create` | `object`、`fields` | 在所属集合中新建一个对象，重复身份返回冲突 |
| `delete` | `object` | 只删除指定声明，引用关系留待目标预检验证 |

`null` 是实际字段值，移除覆盖应使用 `remove`。同一字段不能同时设置和移除，`id` 不能通过
字段编辑改名。新对象的稳定身份由 `object` 提供，`fields` 不含 `id`。其它未修改字段保持原值。
上游凭据与远程秘密源的稳定字段为 `name`，同样不能通过普通、嵌套或列表编辑改名；创建时
`fields` 不能重复提供 `name`。同名的不同对象类型独立定位，同类型重名会拒绝整个目录。
有变化时会重新编码 YAML，原注释、锚点和排版不保留；没有实际变化时返回完全相同的原文字节。

嵌套修改使用独立字符串数组作为映射路径，不解释斜线或点号，也不使用数组下标：

```json
{
  "type": "patch_nested",
  "object": { "kind": "interface_rule", "id": "maintenance" },
  "edits": [
    { "op": "set", "path": ["match", "path"], "value": "/internal/**" },
    { "op": "set", "path": ["response", "status"], "value": 503 },
    { "op": "remove", "path": ["response", "body"] }
  ]
}
```

一次最多 128 个动作，每条路径最多八段、每段最多 128 字节。重复路径、父子路径同时修改、
顶层 `id` 和含控制字符的键均拒绝。设置可以补充缺失的映射祖先；已有 null、标量或数组祖先
不能隐式覆盖。移除不存在的子项不创建父对象；移除最后一个子项仍保留空父映射。任一动作
非法时整个局部文档丢弃，不返回部分修改。服务端保留未修改的原始子项，包括大整数和未知
声明；只移动新值，真实变化后才统一编码一次候选。

列表逐项编辑用 `path` 选择对象中的列表，用数值下标选择元素，不将下标混入映射路径：

```json
{
  "type": "patch_sequence",
  "object": { "kind": "service", "name": "orders" },
  "path": ["instances"],
  "edit": {
    "op": "patch",
    "index": 0,
    "edits": [{ "op": "set", "path": ["down"], "value": true }]
  }
}
```

`edit` 支持 `insert`（`index`、`value`）、`set`（`index`、`value`）、`remove`（`index`）、
`move`（`from`、`to`）和对象元素的 `patch`（`index`、`edits`）。下标从零开始，插入位置
可以等于列表长度；移动的 `to` 是移动后的最终位置，必须小于原列表长度。不接受负数、
小数、字符串下标或越界位置。每个请求只有一个列表动作，后续动作应基于本次返回的候选。

列表最多 4096 个元素，插入后仍受同一上限。只有首次零下标插入可以创建缺失的列表和映射
祖先，已有 null、标量或其它类型不会被覆盖。元素 `patch` 只适用于对象，继续使用上述
嵌套动作限制；列表路径、元素位置和子字段合计最多八层，稳定 `id` 不可改写。设置相同值、
原位移动或移动后完全相同的重复元素保留原文。移动只转移服务端原有元素，未编辑的对象
子树和精确大整数不经浏览器重写。任一失败都不返回部分候选。

对象使用独立字段定位，名称中的斜线或点号不会被解释为路径：

| 领域 | `object` |
|---|---|
| Gateway 路由 | `{"kind":"route","proxy":"入口 id","id":"路由 id"}` |
| Gateway HTTP 入口 | `{"kind":"proxy","id":"入口 id"}` |
| Gateway 具名服务 | `{"kind":"service","name":"服务名"}` |
| Gateway 上游凭据 | `{"kind":"credential","name":"凭据名"}` |
| Gateway 远程秘密源 | `{"kind":"secret_provider","name":"秘密源名"}` |
| Gateway 用量套餐 | `{"kind":"usage_plan","name":"套餐名"}` |
| Gateway 消费者组 | `{"kind":"consumer_group","name":"组名"}` |
| Gateway 消费者套餐绑定 | `{"kind":"consumer_binding","name":"消费者身份"}` |
| Gateway 身份作用域策略 | `{"kind":"scope_policy","id":"策略 id"}` |
| Gateway stream 入口 | `{"kind":"stream","id":"入口 id"}` |
| Sentinel 流控 | `{"kind":"flow","id":"规则 id"}` |
| Sentinel 熔断 | `{"kind":"degrade","id":"规则 id"}` |
| 接口守卫 | `{"kind":"interface_rule","id":"规则 id"}` |

根级单入口 `routes` 的入口身份是 `default`。显式多入口下新增路由必须引用已有入口；不能通过
路由操作创建另一个监听器。重复身份、同时声明非空根路由和显式入口路由、集合类型错误均拒绝。

成功结果包含共享 `cluster_id`、授权 `scope`、所选 `domain`、`schema_version: 1`、
`validation: declaration_only`、`published: false` 与原文 `base_sha256`。
`scope` 为 `platform` 或 `workspace.<工作区名>`，不表示目标节点已验证。读取返回
`objects`、`selected`、`fields`；编辑返回 `changed`、
`candidate` 与 `candidate_sha256`。这些摘要用于核对原文，不授予节点动作权限。
调用方必须在页面范围、输入或权限变化后丢弃旧结果。

单候选沿用提案容量，最多 1024 个显式对象，身份最多 256 字节，一次设置和移除合计最多
128 个字段，JSON 响应上限 4 MiB。处理与完整候选共用每 Admin 两个任务名额，取消等待不会
提前释放真实工作单元。非法输入返回 `400`，无权限为 `403`，对象不存在为 `404`，身份重复或
请求期间权限快照变化为 `409`，输出容量不足为 `429`，候选任务忙碌为 `503`。所有失败均不发布
配置，错误不会回显原文或底层解析错误链。

## 管理页面

共享提案页在“候选 YAML”下提供“按对象编辑候选”。先读取原文中的对象目录，再选择对象读取字段。
对象选择包含类型、父入口与名称，名称中的斜线或点不作为路径。路由、HTTP 入口、上游服务、
流协议监听、Sentinel 流控和降级提供常用字段控件；其它已声明字段可展开单独编辑，新增字段
以 JSON 值明确输入。接口守卫匹配与响应、TLS 材料路径、HTTP/3 和上游健康探测另有子字段
分组控件，不把整个父对象从浏览器回传。父字段整值编辑与其子项编辑不能同时使用。

HTTP 与 stream 入口的 TLS 子字段覆盖默认文件或 manifest 来源、外部签名引用、SPIRE、
客户端 CA/CRL/SPIFFE 验证、客户端在线 OCSP、当前身份的 OCSP staple 及会话票据。
stream 单独提供握手期限，HTTP 的 TLS 监听地址不会写入 stream TLS 对象。切换来源时必须
显式移除不再适用的声明；表单不会替调用者清空互斥配置，也不会解析 SecretSource。
HTTP 默认 TLS 身份还提供 ACME 账户、签发、续期、锁与存储子字段，以及 command、Cloudflare、
RFC2136、Vault 的 DNS-01 配置。域名、账户联系地址和固定命令参数支持逐项列表编辑。
DNS 凭据只编辑 SecretSource 原文引用，固定命令参数不得携带秘密；页面不会读取凭据、创建
账户或订单，也不会证明 DNS 控制权。切换 provider 不会自动删除其它字段。Redis 续期锁必须
配合 `shared-file` 和实际共享卷，是否可用由原目标完整预检及运行时签发确认。stream 和 SNI
身份没有独立 ACME 声明。新增 HTTP TLS 身份、改变账户凭据路径、directory CA 路径或
DNS provider 声明属于目标节点本地配置，不能通过共享预检和执行切换。保留已有身份与秘密
引用时，域名、续期窗口等签发设置仍须经过原目标完整预检与审批。草稿能生成不代表共享任务
有权发布。其它复杂策略仍可按完整值或原始 YAML 编辑。

HTTP/3 控件覆盖协议扩展与 Alt-Svc、入口及来源 IP 连接数、未决握手、双向和单向流、请求头、
请求流缓冲、CONNECT-UDP 与 DATAGRAM、Retry 及早期数据的全部声明。握手总缓冲和 DATAGRAM
队列总字节仍受原生组合预算约束；单向流包含 control/QPACK，不能全部作为业务流额度使用。
0-RTT 必须同时具备 `early_data` 扩展、明确的路由授权及适用的共享重放保护；单独打开
`zero_rtt` 不会获得这些权限。实际能力、参数和路由依赖由原目标完整预检确认。

HTTP 入口还提供完整的 `limits`、`timeouts` 和 `proxy_protocol` 子字段。零值含义按字段
分别展示：有的表示不限制，有的表示不保留空闲连接或不按请求数轮换。HTTP/2 接收窗口授予
流控额度，不预分配等量内存；连接总寿命会终止仍在进行的长流，应与帧间空闲、下游待写和
WebSocket 期限分别配置。旧代连接池缓存淘汰不终止已持有该代的在途请求。

开启 PROXY protocol 后，仅 `accept_from` 内的直连对端可以提供客户端来源前导，普通 HTTP
请求不能冒充此前导。协议版本和可信网段可以按原列表位置编辑；空版本列表接受 v1、v2，
但开启解析时可信来源列表必须非空。该 TCP 前导不能与 HTTP/3 组合使用；最终由原目标
预检检查可信来源、期限和协议组合，再进入审批与执行。

流监听器提供 `preread`、`udp`、`proxy_protocol` 和 `proxy_protocol_to_upstream` 的子字段。
入站前置信任与发往上游的来源前导相互独立。TLS ClientHello 与 MQTT CONNECT 预读不能同时
开启；TLS 预读和终止组合需要明确的 `terminate_tls` 路由。UDP 不支持这些 TCP 前导或预读，
并要求单个明文默认路由；无可转发目标时可显式声明 `reject_all`。UDP 会话数、空闲回收、
报文长度和队列容量分别限制资源，队列满时丢弃当前报文，不进行分片或业务消息重组。

“SNI 证书身份”列表按当前候选的原下标选择、插入、替换或移动身份。每个身份提供名称、
证书链、私钥、外部签名引用与自己的 OCSP 控件，不继承默认 manifest、SPIRE 或 OCSP。
编辑原元素只提交明确选择的子字段，未编辑字段和其它身份继续保留。替换整个身份会移除其
未重新填写的字段；删除仍需明确确认。TLS 授权与会话密钥列表也支持逐项编辑，顺序不会自动调整。

具名服务和流路由提供相同的上游 TLS 子字段：SNI、仅加密模式、文件或内联 CA、证书 SAN、
客户端证书与私钥文件，以及 SPIRE 身份选择、资源和重连策略。非空 SAN 列表最多五项，使用
`dns:` 或 `uri:`；此时 SNI 不再作为证书认证名，证书链仍须校验。服务的 SAN 和 SPIRE 联邦
信任域支持按原位置逐项编辑；流路由在所选元素内显式设置相应列表，不重写其它路由。
内联客户端证书和私钥可在完整声明中维护，常用字段不回填私钥；两个运行时身份截止与归属
字段不能通过配置设置。仅加密模式与信任约束、客户端身份互斥，切换材料来源须明确处理旧声明。
`lb://service` 的 TLS 在服务声明，HTTP 路由通过服务或命名上游凭据使用身份。SPIRE 需要
目标具备 `spire-workload` 能力和已授权的本地 Workload API；编辑草稿不会取得身份或连接上游。

服务表单还提供上游协议、换实例条件、总尝试次数、退避、被动失败阈值、重试预算与连接预热。
`next_upstream` 的显式空列表禁用触发，移除声明则恢复默认；条件支持 `error`、`timeout`、
`http_502`、`http_503`、`http_504` 和 `non_idempotent`。GET/HEAD 之外的方法还须有
`Idempotency-Key` 或显式允许 `non_idempotent`，待转发正文必须为空。预算不会授予重放许可；
总尝试次数包含首次，0 表示遍历可用候选，每个候选最多尝试一次。预算按比例与两项最低额度
中的较大值限制窗口重试量和在途重试数，比例为 0 仍保留最低额度。`outlier` 存在时替代
`max_fails` 被动摘除策略。

预热没有独立启用开关；整段缺省关闭，设置任一子字段即声明策略，关闭须移除完整 `prewarm`。
预热只发送不带下游身份和正文的 HEAD 请求，成功取得响应头不代表业务健康。`h3` 需要 HTTPS
实例及 `http3` 能力；明文 HTTP/2 使用 `h2c`。编辑候选不连接上游，协议及参数边界由原目标
预检检查。

服务并发准入表单提供启用开关、并发上下界、采样与最低 RTT 标定周期、抖动、有界队列和
排队期限。准入按逻辑服务限制等待上游响应头的在途尝试；队列为 0 时直接拒绝，队列满或
等待到期也按过载拒绝。字段编辑不自动启用自适应策略，有限场景的并发上限不代表吞吐保证。

窗口摘除表单提供统计窗口、最小样本、失败与慢调用比例、慢调用阈值、摘除比例及冷却与恢复
探测期限。`outlier` 整段存在即启用，并替代连续失败摘除；关闭须移除整段，目标必须具备
`upstream-outlier` 能力。两种观察比例不能同时为 0。最大摘除数按实例数乘比例向下取整，
单实例服务不会被摘除；冷却到期只开放一个真实恢复探测，取消或失败不解除摘除状态。

会话保持表单提供服务的 Cookie／Header 载体、名称、滚动 Cookie 有效期、绝对与空闲期限，
以及持久 Cookie、Path、Domain、SameSite、Secure 和 HttpOnly。整段缺省关闭，声明
`session_affinity` 即启用，关闭须移除整段。亲和令牌只在当前服务的可用候选中选择实例，
不作为认证凭据，也不能绕过健康、下线、备用或地域边界；无效、过期或不再可选时回落常规选择。
`ttl_seconds` 与绝对／空闲期限互斥；持久 Cookie 必须有绝对期限，后续响应不会延长原期限。
Header 模式不能配置 Cookie 有效期。Cookie 的 Secure、HttpOnly 缺省为 true，
SameSite=None 必须同时 Secure=true；省略 Path 与声明 path 互斥。亲和 Cookie 追加到响应，
不替换已有 Set-Cookie 头。编辑字段不求值令牌，合法组合仍由原目标预检确认。

服务来源字段包含注册服务名、命名空间、数字端口、Kubernetes 端口名称与 MCS ServiceImport、
发现 URI scheme 和 Nacos cluster 过滤。动态来源须启用对应发现服务并移除静态实例；
启用 Nacos 发现须编译 `nacos-sdk`，缺少时拒绝候选。发现总开关与 Nacos 连接身份属于启动配置。
Kubernetes 数字端口与端口名称互斥，ServiceImport 使用 MCS EndpointSlice。Nacos cluster
空列表允许全部 cluster，可在有序列表中逐项编辑；scheme 不改写静态实例已声明的 URI。
`lb_policy` 优先于兼容字段 `lb`。`ring_hash`／`maglev` 须声明 `hash_on`，`ip_hash` 固定按
`remote_addr`，不能同时声明 `hash_on`。哈希环虚拟节点数限1–1000，Maglev 期望槽位数限
1–655373，并从预设质数表选择不小于期望值的首项，最小251；这些参数仅用于哈希策略。
哈希与亲和只改变当前可用候选的选择顺序，不绕过健康、备用或地域边界。

地域选择表单提供本地 region／zone／subzone、模式、未列实例兜底、单层备用顺序、权重映射
和劣化份额。单层 `failover` 按本区及备用顺序选层；`weighted` 才允许 `zone_weights`，
让已列可用区同层分流。声明 `local_region` 后须使用非空 `targets`，不混用单层备用、权重
和劣化列表。分层目标可逐项编辑 region、zone、subzone、priority、weight、degraded，
也可插入、替换、移动或删除；未编辑目标保留原文。分层先按 priority，`failover` 再按距离，
`weighted` 在同 priority 内分配份额。同一可用区的整体目标与细分子区不得重叠。
劣化只减少同层份额，不提升优先级或替代健康摘除；未列拓扑仅在显式允许且已列层全部不可用时
兜底。策略只使用可信配置或发现元数据，不读取客户端位置声明；移除整段 `locality` 才关闭
地域约束。目标预检仍验证拓扑、容量、数值边界及模型组合。

负载反馈表单提供口径、有效期、最低样本、平滑系数、新鲜反馈覆盖下限及 ORCA 文本响应头名。
`least_conn` 和 `weighted_least_request`（`p2c`）可在当前候选层中使用反馈评分；
无效、缺失、陈旧、样本不足或服务覆盖不足时回退基础算法，不将实例判为不健康。
覆盖下限为 0 仍要求至少一份有效反馈。反馈来自真实上游响应或固定实例订阅，不接受客户端
声明；标准二进制头 `endpoint-load-metrics-bin` 不能配置成文本头名。
带外订阅的报告周期、连接与空闲期限、重连退避、报告容量和明文许可可独立编辑。
声明 `out_of_band` 即要求目标具备 `upstream-orca`，并使用 `utilization` 及 `h2`／`h2c`；
订阅沿用业务实例 authority 与 TLS 身份，不允许 `insecure_skip_verify`。明文仅在显式
`allow_plaintext=true` 时允许，部署方须保证该网络的身份边界。移除整段 `out_of_band`
才停止订阅；关闭全部反馈时同时移除订阅，并将模式改为 `none` 或移除整段 `load_feedback`。

路由的 LLM 入口表单独立提供 `api_type`、`max_body_bytes`、`max_prompt_tokens`、
`max_completion_tokens`、`max_response_bytes`、`max_stream_frame_bytes`、`max_duration_ms`
和 `max_cost_microusd`。API 类型必须与原模型兼容；请求实体、提示词、补全、响应累计量、流记录、
单次模型调用期限及估算费用各自受原目标的完整策略约束。SSE 事件与 NDJSON 行跨 HTTP DATA 块计量；
流已建立后超额会中止正文，不能再改成另一个 HTTP 状态。预算与编码语义见[模型入口说明](../README.md)。

这些字段缺省保持原声明，不补模型、价格、凭据或默认授权，也不重建未编辑的模型目录、配额、
护栏、moderation、缓存与治理声明。费用的 `u64::MAX` 仅观测声明可在保持状态下保留原文；
显式宽整数须通过原始 YAML 输入，字段控件不会以浮点近似值重建它。单项移除恢复该字段原生缺省，
移除完整 `llm` 才解除模型后端；切换普通 HTTP 等终端须显式设置对应 URI，并满足原有认证和路由约束。

“逐项编辑有序列表”中的“LLM 固定模型目录”定位 `llm.models`，提供原位置新增、整项替换、
字段补丁、移动与确认删除。模型目录须包含1–16个模型；新增或替换明确填写 `id`、provider、URI
与模型名，不从其它元素继承字段。已有 `id` 不通过字段补丁改写；删除或替换不会自动调整选择策略
中的模型引用，完整候选仍由原目标预检确认。

模型字段涵盖固定端点与 API path、provider 凭据与云 scope、原生透传、价格、能力、预期首 token
声明及权重；运行时物化的秘密、租约和策略摘要不进入表单。能力以完整有序字符串名单编辑，最多32项，
不允许重复；模型身份与能力名均为1–64字节安全 ASCII token。价格0表示未知，正数固定费用优先于
token 单价；权重0只排除 weighted 首选资格，仍保留回退资格。编辑引用不解析秘密或连接模型端点，
provider/API/云字段组合与实际权限仍由目标构建器裁决。

“LLM 模型选择与独立副本”提供八项选择声明及必需、软偏好能力的原位置名单操作。必需能力在
全部策略之前过滤目录；joint 按首 token 排序边界、软偏好缺失数、单价与可用延迟事实排序。
首 token 边界用于排序，不能替代请求期限或当作硬超时。latency 优先探索未采样模型，已有样本
再按本进程 EWMA 升序；weighted 按固定请求身份选择首项，零权重仍可回退，不能全部为零。

shadow 模型与正数采样份额须成对声明，副本结果永不进入主响应或回退；Realtime 不允许复制升级，
请求治理也不能与 shadow 并用。rollout 只提升灰度模型首选，失败仍回落常规模型顺序，且不能与
shadow 使用同一模型。份额范围0–10000，关闭须显式解除模型引用并清零或移除份额。
移除完整 `llm.selection` 恢复原生选择缺省，不改写模型、凭据、价格或调用者认证；所有变化仍需
原目标完整预检、独立审批和持久执行。

“LLM Token 预留与结算配额”提供六项独立字段。请求先预留提示估算加补全上限，随后按有效
usage 结算；窗口补充量、突发容量与活跃维度上限分别声明。维度只使用路由身份、已验证
consumer 或 API-Key 指纹，客户端自报身份不能创建额度权威，api_key 维度缺少验证事实时拒绝。
配额仅用于 Chat；其它 API 与配额组合由目标预检拒绝。

活跃维度表满时，只有显式 `active_keys_fail_open=true` 才允许未记账的新维度，已有桶仍受额度
限制，工作区状态名额不足仍拒绝。缩小上限不删除真实旧桶，扩大突发也不重建已有信用。
移除完整 `llm.token_quota` 关闭该项配额，模型、调用者认证与其它治理声明继续保留。

“LLM 外部 Moderation 判定”提供服务、模型、固定 path、SecretSource 与三项调用预算，以及
明确的依赖故障策略。固定模型和凭据不受客户端同名字段覆盖；页面不读取秘密或访问服务。
输入必须能在请求预算内表达为统一纯文本，无法表达或超限时先拒绝，`open` 不能豁免输入门。
单次期限覆盖上游响应头与完整判定正文，响应超限或坏 JSON 都属于依赖不可判定。

只有显式 `fail_mode=open` 才在依赖故障时继续模型请求；明确 `flagged=true` 始终拒绝。
该判定只用于 Chat，结果在模型、缓存和 Token 配额准入之前生效。移除完整 `llm.moderation`
只关闭该项判定，原模型、认证、护栏与其它治理配置继续保留，正式生效仍需原目标预检和审批。

“LLM 本地内容规则与可信提示”提供五项声明与两份短语名单的原位置操作，可信 system 提示
保留完整换行。结构化规则有六项字段；已有稳定 id 不通过字段补丁改写，新增或整值替换须明确
身份、分类、非空方向及恰好一种 contains、regex、detector 来源。切换匹配器须显式移除旧来源。
名单支持插入、替换、编辑、移动与确认删除；规则方向以完整有序名单声明。

本地匹配忽略 ASCII 大小写，正则须有有限最大长度且不能空匹配；分类使用固定词表。有结构化
规则或输出阻断短语时，文本窗口须在64–65536字节内，并覆盖最长响应匹配及字符边界。
非流式命中不交付模型正文；流式保留尚可能命中的完整事件，命中时终止交付。完整 rules 值会
替换整份规则名单；移除 `llm.guardrails` 同时解除本地规则与可信提示，保留外部判定、模型和认证。

已有对象另提供“逐项编辑有序列表”，覆盖路由断言、处理链、凭据引用、静态实例、接口请求
方法、HTTP/3 扩展及已声明的其它数组。静态实例有 URI、权重、下线、备用、健康、慢启动及
地域字段控件；对象元素也可单独设置扩展字段。每次列表操作单独生成候选，不带上普通字段
面板中尚未生成的修改。删除元素需要明确确认，替换整个元素只包含新输入的值。切换列表、
元素或操作后，先前请求的迟到结果不得回填。

流监听器的 MQTT 表单提供连接、完整包、包读取期限、双向缓冲预留、topic 字节、订阅及在途
消息预算，并支持逐项编辑 client id、发布和订阅名单。空 client id 名单不额外限制身份；空发布
或订阅名单拒绝对应操作。订阅过滤器必须整体处于授权边界内，包读取期限不包含纯空闲时间。
启用治理需要目标编译 `mqtt-governance`、使用 TCP 并明确启用 CONNECT 预读，不能与 Kafka
治理同时启用。草稿不检查 broker 是否可达，也不因填写名单而获得执行权限；原目标预检仍须
检查协议组合和总预留预算。受支持的 MQTT 协议边界见[项目说明](../README.md)。

Kafka 表单提供连接、完整帧、帧期限、缓冲预留、correlation 与字符串／数组预算，以及四种
精确访问名单和 broker 地址映射。地址列表可按原位置编辑四个主机／端口字段，或明确插入、
替换整个映射。空 client id 名单不额外限制；空 topic、group 或 SASL 名单拒绝对应操作。
Metadata 必须显式查询授权 topic，不能用空列表枚举集群；响应中任一 broker 地址缺少映射时
拒绝转发。启用需要目标编译 `kafka-governance`、使用 TCP，并关闭 MQTT 治理、CONNECT 预读
和 TLS 透传预读。完整声明仍由原目标检查，支持的 API 与版本范围以[项目说明](../README.md)
为准；表单不扩大协议兼容范围，也不检查目标 broker 的可用性。

流监听器的“流路由”列表按原位置提供 SNI、MQTT client id、默认路由、TLS 终止和上游字段。
编辑现有元素保留稳定 `id`，不允许通过子字段改名；插入或替换整个元素必须明确填写新的
`id`，替换不继承旧元素的未填写声明。带权上游和上游 TLS 目前按完整声明编辑，不能把列表
下标写入字段路径来修改更深层的元素。路由匹配、重复身份、TLS 组合和上游声明仍由原目标
完整预检确认，草稿生成不代表路由已获得转发权限。

字段缺省保持原声明；只有选择“设置值”或“移除声明”的键才参与生成候选。布尔 false、空串、
JSON null 与移除互不等价。每行一项的列表保留行顺序及重复项，不自动裁剪。浏览器不能精确
表示的整数拒绝通过字段控件写入，应使用原始 YAML 输入。复杂字段作为完整值替换，编辑时
需要保留该字段内部仍需要的属性。

上游凭据与远程秘密源提供类型、注入位置、允许后端、SecretSource 引用、TLS 身份、固定端点、
认证和值/版本指针，以及刷新、陈旧期和请求预算控件。展示的是调用者提交的原始引用，草稿
编辑不会解析秘密或访问远程源。适配器与 envelope 等扩展可通过复杂字段明确编辑；删除对象
不会自动改写引用关系，是否允许发布仍由原目标预检决定。

用量套餐和消费者组分别定位 `usage_plans.plans` 与 `usage_plans.groups` 的映射键，不向对象
内容注入 `name` 或 `id`。身份作用域策略定位 `usage_plans.policies` 的稳定 `id`。表单提供
固定窗口额度、消费者成员、组套餐、作用域选择、认证要求、拒绝策略、产品交集及上下文头；
路由提供 `usage_plan` 绑定子字段。作用域切换时需显式移除旧类型专属字段，目标完整构建器
拒绝不匹配的声明。删除对象不级联修改引用；关闭上下文头继承也不能解除上层认证、拒绝或额度。
本地额度仍按节点独立计算，共享额度须使用相应运行配置；套餐表单本身不签发消费者密钥；密钥由路由下的独立面板管理。

消费者套餐绑定定位 `usage_plans.consumers` 的字符串映射。读取时以 `{"plan":"套餐名"}` 展示，
创建必须且只能提供字符串 `plan`，普通 `patch` 仅支持设置该字段。实际配置仍保持
`消费者身份: 套餐名`，不会保存展示用的字段对象；同值设置保持原文字节。解除绑定使用对象
`delete`，不支持字段移除、嵌套或列表动作。显式消费者套餐优先于组套餐；删除后由当前组或
路由默认规则裁决，不自动修改成员、撤销 API-Key 或承诺清零额度。

“新增对象”要求显式身份；新增路由还须填写所属 HTTP 入口，根单入口使用 default。删除对象
需要勾选确认，删除父对象同时删除其子声明。所有动作仅生成候选，不自动保存或执行。提案
目标和有效期不会随草稿编辑改变。保存后的原文仍须由另一主体审阅；执行按全部原目标的
完整基线、当前权限与独立开关校验。

页面不将草稿存入浏览器持久存储。原文变化、范围切换、页面隐藏或退出会撤下字段；权限
拒绝还会清空输入并关闭写入控件。响应须匹配原集群、领域、范围和完整源摘要，修改结果
还须匹配完整候选摘要，任何迟到或不一致的结果均不回填。

## 路由密钥

`keys` 动作仅接受 Gateway 路由。`edit.op` 支持以下操作：

| `op` | 字段 | 行为 |
|---|---|---|
| `inspect` | 无 | 返回 `selected` 与 `keys`，不返回候选或校验材料 |
| `add` | `consumer`、`source`、`name`、`sha256` | 追加一条已启用的原生 API-Key 声明 |
| `set_enabled` | `index`、`fingerprint`、`enabled` | 仅改变精确声明的启用状态 |
| `remove` | `index`、`fingerprint` | 删除精确声明，但拒绝删除最后一条 API-Key |

目录包含处理链原始 `index`、完整声明 SHA-256 的 `fingerprint`、`source`、`name`、可空
`consumer`、`enabled` 和 `material`（`sha256` 或 `secret_source`）。该指纹只证明选中了
原声明，不是用于认证的密钥摘要。目录不包含原值、SecretSource 引用或认证摘要。
下标和指纹须同时匹配当前候选，错位或替换后返回 `409`。启用状态相同则逐字节保留候选；
变化只替换原 filter 的 enabled 参数，其余材料和参数不变。

新增只接收64位 ASCII 十六进制 SHA-256，不接收明文。`source` 为 `header` 或 `query`；
`consumer` 与 `name` 限1至128字节的字母、数字、点、下划线、短横线或斜线，且须通过
原生来源与消费者校验。已有声明与运行时共用严格解析器，重复或非法字段使整个动作失败。
身份或来源包含未求值占位符时，此面板明确拒绝；可继续通过原文与目标完整构建流程处理。
整个处理链最多4096条且必须为字符串列表，不跳过非法 API-Key，也不读取秘密依赖。

路由面板用 Web Crypto 在浏览器内生成256位随机密钥，只有最终密钥文本的摘要提交到
Admin。候选更新成功后，原值本次显示60秒；请先安全保存，再保存、审批和执行提案。
原值不写入浏览器存储、URL 或共享提案，不自动复制剪贴板。关闭展示、候选或对象变化、
范围切换、请求失败、页面隐藏和退出均清除展示；异步摘要或请求完成后还须复验当前页面。
Web Crypto 不可用时拒绝生成，部署应使用受信 HTTPS 管理入口。

撤销使用 `enabled=false`，最后一把禁用后仍保留认证保护。`remove` 拒绝删除最后一条，
避免把撤销误写成匿名开放；该约束属于密钥动作，拥有完整配置写权限的原文编辑仍能显式
改变认证方式。其它认证方式和 `satisfy` 不变。所有操作仅改变当前候选，不调用本机消费者
写接口；发布仍经全部原目标预览、独立审批及持久执行。各节点原文不同需要各自基线的提案，
此面板不提供跨不同原文的原子发布。
