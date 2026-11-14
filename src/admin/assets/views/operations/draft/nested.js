import { element } from "../../../core/dom.js";
import { fieldRow } from "./controls.js";
import { tlsFieldGroups } from "./tls.js";
import { upstreamTlsFieldGroups } from "./upstream_tls.js";
import { upstreamRetryFieldGroups } from "./upstream_retry.js";
import { upstreamCapacityFieldGroups } from "./upstream_capacity.js";
import { upstreamAffinityFieldGroups } from "./upstream_affinity.js";
import { upstreamLocalityFieldGroups } from "./upstream_locality.js";
import { upstreamFeedbackFieldGroups } from "./upstream_feedback.js";
import { http3FieldGroups } from "./http3.js";
import { listenerFieldGroups } from "./listener.js";
import { streamTransportFieldGroups } from "./stream.js";
import { mqttFieldGroups } from "./mqtt.js";
import { kafkaFieldGroups } from "./kafka.js";
import { routeDeadlineFieldGroups } from "./route_deadline.js";
import { routeWafFieldGroups } from "./route_waf.js";
import { routeWafPackFieldGroups } from "./route_waf_pack.js";
import { routeBotFieldGroups } from "./route_bot.js";
import { routeBotRateFieldGroups } from "./route_bot_rate.js";
import { routeBotTrustedFieldGroups } from "./route_bot_trusted.js";
import { routeDlpFieldGroups } from "./route_dlp.js";
import { routeCsrfFieldGroups } from "./route_csrf.js";
import { routeGeoipFieldGroups } from "./route_geoip.js";
import { routeRequestValidationFieldGroups } from "./route_request_validation.js";
import { routeResponseContractFieldGroups } from "./route_response_contract.js";
import { routeBodyTransformFieldGroups } from "./route_body_transform.js";
import { routeGraphqlGuardFieldGroups } from "./route_graphql_guard.js";
import { routeDegraphqlFieldGroups } from "./route_degraphql.js";
import { routeCasbinFieldGroups } from "./route_casbin.js";
import { routeOpaFieldGroups } from "./route_opa.js";
import { routeExtProcFieldGroups } from "./route_ext_proc.js";
import { routeGrpcTranscodingFieldGroups } from "./route_grpc_transcoding.js";
import { routeGrpcEdgeFieldGroups } from "./route_grpc_edge.js";
import { wasmSourceFieldGroups } from "./route_wasm.js";
import { scriptCircuitFieldGroups } from "./route_script.js";
import { routeBffFieldGroups } from "./route_bff.js";
import { routeMockFieldGroups } from "./route_mock.js";
import { routeFaultFieldGroups } from "./route_fault.js";
import { routeDubboFieldGroups } from "./route_dubbo.js";
import { routeRedirectFieldGroups } from "./route_redirect.js";
import { routeWsFrameFieldGroups } from "./route_ws_frame.js";
import { routeForwardProxyFieldGroups } from "./route_forward_proxy.js";
import { routeWebTransportFieldGroups } from "./route_webtransport.js";
import { routeEarlyDataFieldGroups } from "./route_early_data.js";
import { routeLlmFieldGroups } from "./route_llm.js";
import { routeAiSecurityFieldGroups } from "./route_ai_security.js";
import { routeRagFieldGroups } from "./route_rag.js";
import { routeOutputModerationFieldGroups } from "./route_output_moderation.js";

const groups = {
  route: [
    [
      ["usage_plan"],
      "用量套餐绑定",
      [
        ["default_plan", "未单独映射身份的套餐", "string"],
        ["require_consumer", "要求可信消费者身份", "boolean"],
      ],
    ],
  ],

  scope_policy: [
    [
      ["scope"],
      "策略作用域（只填写所选类型的字段）",
      [
        [
          "type",
          "类型：global / workspace / product / service / route / group / consumer",
          "string",
        ],
        ["workspace", "工作区身份", "string"],
        ["product", "产品身份", "string"],
        ["version", "产品版本", "string"],
        ["service", "上游服务身份", "string"],
        ["proxy", "HTTP 入口身份", "string"],
        ["route", "路由身份", "string"],
        ["group", "消费者组身份", "string"],
        ["consumer", "消费者身份", "string"],
      ],
    ],
  ],

  interface_rule: [
    [
      ["match"],
      "接口匹配",
      [
        ["type", "匹配类型（Exact / Prefix / Glob）", "string"],
        ["path", "匹配路径", "string"],
        ["methods", "请求方法（每行一项）", "lines"],
      ],
    ],
    [
      ["response"],
      "拒绝响应",
      [
        ["status", "HTTP 状态码", "number"],
        ["body", "UTF-8 响应正文", "string"],
        ["headers", "响应头映射", "json"],
      ],
    ],
  ],

  service: [
    [
      ["health_check"],
      "主动健康探测",
      [
        ["type", "探测协议", "string"],
        ["path", "HTTP 探测路径", "string"],
        ["interval_ms", "探测间隔（毫秒）", "number"],
        ["jitter_ms", "间隔抖动（毫秒）", "number"],
        ["timeout_ms", "探测期限（毫秒）", "number"],
        ["healthy_threshold", "连续成功阈值", "number"],
        ["unhealthy_threshold", "连续失败阈值", "number"],
        ["expected_status", "HTTP 期望状态码", "number"],
        ["grpc_service", "gRPC 服务名称", "string"],
        ["udp_payload", "UDP 探测载荷", "string"],
        ["udp_expected_response", "UDP 期望响应", "string"],
      ],
    ],
  ],
};

/**
 * 业务作用：为常用嵌套策略提供独立子项控件，不让浏览器重写其它声明或大整数。
 * 参数说明：
 * - `kind`：当前对象类别。
 * - `values`：原始字段的展示投影，不用作输出子树。
 * - `capacity`：输入容量。
 * 返回：只包含明确新值及精确路径的动作；已有非映射祖先仅提示使用整值编辑。
 */
export function nestedFields(kind, values, capacity) {
  const node = element("div", "", "draft-nested");
  const rows = [];
  if (kind === "ws_message_plugin") {
    node.append(
      element(
        "p",
        "每项只声明所选 type 的字段：acl 使用 consumers/opcodes；json_schema 使用 schema；redact 使用 pointers；rate_limit 使用 messages/window_ms；external 使用 endpoint、authorization、ca_certificate 和三个明确权限开关。切换类型须显式移除旧类型字段，整值替换只包含本次填写的新声明。",
        "subtle",
      ),
      element(
        "p",
        "消息链按顺序处理完整载荷，控制帧不进入插件；身份在握手时冻结。外呼发送原始消息字节，不跟随重定向；只有依赖错误可受 fail_open 影响，非法动作、未授权改写和输出超限不会开放。页面只编辑 SecretSource，不读取材料。",
        "subtle",
      ),
    );
  }
  if (["bff_target", "bff_target_new"].includes(kind)) {
    node.append(
      element(
        "p",
        "BFF 只发起固定目标和路径的 GET 子请求，不使用客户端 query 或 body 生成目标参数。uri 只含 HTTP(S) origin 或 lb://service；path 独立声明，构建时校验 HTTP URI 表示并保留编码，不展开模板。目标 id 唯一且不能为 _errors。",
        "subtle",
      ),
      element(
        "p",
        "forward_headers 使用明确完整名单；Authorization、Cookie、X-Api-Key 和固定 hop-by-hop 头不能转发。子响应须是有界的成功 JSON 值，不接受 trailers。required=false 只隔离该目标失败，不豁免总期限或完整聚合 JSON 编码上限。",
        "subtle",
      ),
    );
  }
  if (["script_plugin", "script_plugin_new"].includes(kind)) {
    node.append(
      element(
        "p",
        "目标节点须编译 lua-scripts；源码在候选构建时验证并冻结，真实路径必须在配置根内。沙箱不提供文件、网络、进程、时钟、随机数或 callout。每路由 Lua 与 Wasm 合计最多16项，头相位先 Wasm 后 Lua；同一方向正文只能由一种运行时处理。",
        "subtle",
      ),
      element(
        "p",
        "failure_mode 和 circuit 必须显式声明。open 只跳过解释器依赖不可用；输入、输出、指令、CPU、内存、分配、期限、容量、客体错误和主动拒绝始终关闭。熔断保留原始失败原因，同一路由、脚本 id 与源码内容的状态跨热更共享，修改预算不会清空失败事实。",
        "subtle",
      ),
      element(
        "p",
        "include_headers 与 mutation_headers 按完整名单显式编辑；凭据、cookie、动态身份、来源和协议安全头不可读写。head 相位须移除 max_body_bytes；body 相位必须显式设置预算并清空可写头名单。聚合预算限制完整实体，流式预算限制每片输入和输出；每片独立 VM，末尾另以空 body 和 eof=true 调用。",
        "subtle",
      ),
    );
  }
  if (["wasm_plugin", "wasm_plugin_new"].includes(kind)) {
    node.append(
      element(
        "p",
        "本地 module_file 与远程 module_source 必须二选一，切换时须显式移除旧来源。模块在候选构建期验证并编译；不提供 WASI、文件、socket 或环境访问。只有显式 body 相位才检查对应正文预算，聚合与流式 body 相位不能在同一方向混用。",
        "subtle",
      ),
      element(
        "p",
        "远程模块必须固定最终字节 SHA-256，并声明成对 detached signature/public_key 或签名 attestation；两者同时声明时都须通过。OCI tag 还须固定 manifest 摘要。页面只编辑 SecretSource，不获取材料。内容缓存命中仍复验当前字节上限、模块摘要、凭据格式、CA、签名和 provenance；命中时不访问 registry，不证明 tag 当前状态。manifest 与 layer 对应关系在 registry 下载路径校验。",
        "subtle",
      ),
      element(
        "p",
        "callout_clusters 以明确的完整 JSON 列表编辑，每项只声明 name、固定 HTTP(S) origin、可选 ca_certificate、allow_cleartext 和 http2_prior_knowledge；名称须唯一，origin 不得带业务 path、query、fragment 或 userinfo。HTTP 必须显式允许明文，prior knowledge 仅适用于已允许的明文 HTTP；客体只能引用名称，不能自行选择网络目标。fail_open 不开放共享资源准入拒绝，前一插件已提交输出保持，本插件部分输出丢弃。",
        "subtle",
      ),
    );
  }
  if (kind === "route") {
    node.append(
      element(
        "p",
        "BFF 与普通 uri 等终端后端二选一。启用聚合须显式移除旧 uri，关闭时须移除整个 bff_aggregation 并显式选择后端；页面不会自动改写后端。仅支持 GET，下游认证、WAF 和其它允许组合的治理继续执行。",
        "subtle",
      ),
      element(
        "p",
        "请求总时限覆盖上游转发的准入等待、重试、副本和完整正文；单次时限从每次实际上游发送开始，各次独立计时。两项省略或设为 0 均不增加对应截止点，入口阶段期限仍生效；总时限非 0 时单次时限不能更大。响应头发出后的超时只能终止正文。帧间空闲期限省略时继承入口，0 关闭；最长寿命约束 SSE / gRPC 长流，原生边缘桥接也使用这两项长流参数；普通上游 WebSocket 升级后的隧道使用自身策略。",
        "subtle",
      ),
      element(
        "p",
        "并行副本须固定 lb:// 服务、明确 idempotent=true，并通过 proxy_pass_request_body off 关闭请求正文。运行时仅 GET / HEAD 可启动副本，总次数固定为 2；主请求在延迟内成功时不会发送副本，失败时可提前发送。胜出后取消另一尝试，4xx 作为业务结果；移除完整 hedge 声明才关闭策略。填写时间预算不会授予重复执行许可。",
        "subtle",
      ),
      element(
        "p",
        "声明 waf 即启用策略，缺省为 enforce；关闭须移除完整 waf。monitor 对规则命中只记录并继续转发，正文容量超限和读取失败仍会拒绝。仅明确开启 inspect_body 才聚合 JSON / XML 正文，不能与关闭转发正文或非零长流最长寿命同时声明。空 enabled_rules 启用全部内置规则；精确例外只能引用已启用规则及 path、query、body、header:framing 或 header:<小写名称>，不接受通配符。",
        "subtle",
      ),
      element(
        "p",
        "内置规则 id：sql_injection、xss、command_injection、template_injection、path_traversal、protocol_smuggling、abnormal_encoding、dangerous_header、json_threat、xml_threat。外部签名规则包沿用原声明及原目标预检，未编辑的包引用不随常用字段回传。",
        "subtle",
      ),
      element(
        "p",
        "外部规则包使用本地 JSON 文件和 detached Ed25519 签名，来源、摘要、签名与公钥须同时有效；页面只编辑声明，不上传文件或读取 SecretSource。目标节点必须具备对应文件，候选预检与正式发布均会验证原始字节、签名及资源预算。包内容为有界 literal 规则；移除完整 rule_pack 保留内置 WAF，父段编辑与子字段编辑不能在同次动作中重叠。",
        "subtle",
      ),
      element(
        "p",
        "声明 bot 即启用，缺省为 enforce；关闭须移除完整 bot。非空允许名单要求 User-Agent 匹配，拒绝名单命中即挑战；glob 忽略大小写，名单间不能有相同 glob。必需头须是单个非空值。行为分数达到阈值时挑战，monitor 记录后继续；429 留给速率信号，普通挑战可选其它 4xx。指纹始终包含 User-Agent，再按声明顺序加入所选头值；这里的拒绝指纹不包含客户端 IP。未编辑的速率和可信机器人签名声明保持原值，声称可信仍须逐请求验签。",
        "subtle",
      ),
      element(
        "p",
        "声明 bot.rate 即启用速率信号，容量为基础令牌量加突发量，按补充窗口恢复基础量；速率指纹另含可信客户端地址。active_keys_fail_open 缺省为 false，只有明确开启才在指纹表满时放行未记账的新指纹，不创建新桶；已有指纹仍受额度限制，需要创建真实桶时仍须工作区状态名额。速率拒绝返回 429 和覆盖完整窗口的整秒等待建议，monitor 记录后继续。移除完整 rate 保留其它 Bot 信号；如果已无任何有效信号，候选仍会被拒绝，关闭全部策略须移除 bot。",
        "subtle",
      ),
      element(
        "p",
        "可信搜索机器人最多声明 32 条，名称须唯一，签名与时间戳头须不同，密钥引用解析后至少 32 字节。只有 User-Agent 匹配且逐请求 HMAC-SHA256 验签通过才豁免 Bot 信号和速率，后续业务认证照常执行。签名绑定时间戳、可信客户端地址、方法、authority、原始 path/query 与 User-Agent。无效声明在 enforce 下挑战，在 monitor 下保持非可信并记录后继续；页面只编辑 SecretSource 文本，不读取密钥。清空或移除完整列表撤销豁免，保留其它 Bot 规则。",
        "subtle",
      ),
      element(
        "p",
        "声明 dlp 即启用，关闭须移除完整策略；至少启用一处检查。空 enabled_rules 启用全部固定规则：email、phone、credit_card、national_id、jwt、api_key、private_key、secret。header 目标名称须合法且唯一；精确例外绑定已启用规则和原 target，不接受通配符，header target 使用小写名称。monitor 保留命中字节，redact 替换命中字段；日志路径命中时使用固定 /redacted，不记录原值。",
        "subtle",
      ),
      element(
        "p",
        "只有明确开启正文方向才聚合检查 JSON、form 或 text；media type 支持 application/json、application/*+json、application/x-www-form-urlencoded、text/*、text/plain。正文超限、压缩或无法检查时仍拒绝，monitor 不豁免资源和结构门。请求命中 block 返回 403，容量超限 413，结构或读取失败 400；响应检查失败返回 502。正文遮蔽后更新长度并移除失效摘要、validator 和 range 元数据。请求正文检查不能关闭转发正文；任一正文检查不能配置非零长流最长寿命，响应正文检查不能与 proxy_cache 混用；internal 路由不能声明 DLP。",
        "subtle",
      ),
      element(
        "p",
        "声明 csrf 即启用，关闭须移除完整策略。受保护方法先验证严格单值 Origin，再验证 Cookie 与头中的同一 Token；只有 Origin 缺失时才可用 Referer 兜底，错误来源不能被兜底或缺失放行开关覆盖。same-origin 使用监听协议与当前 authority，显式来源只接受 HTTP(S)。允许缺失来源不会跳过 Token 门；enforce 拒绝返回 403，monitor 记录固定原因后继续，不提供业务认证身份。internal 路由和 early_data 不能声明 CSRF。",
        "subtle",
      ),
      element(
        "p",
        "double_submit 使用 256-bit 随机 Token 且 token_secret 必须为空；signed 还要求至少 32 字节密钥、有效时限与路由绑定。切换到 double_submit 时请明确移除旧密钥声明，页面只编辑 SecretSource 文本。头名称不能复用 Cookie、Host、Authorization、Content-Length、Origin 或 Referer。只有开启签发且方法未受保护、响应成功或重定向时才生成 Token，固定 Cookie 的 Path=/、Secure、HttpOnly、SameSite=Strict，并设置 private, no-store；浏览器使用须 HTTPS。CSRF 只检查 head，不聚合正文。",
        "subtle",
      ),
      element(
        "p",
        "声明 geoip 即启用，至少保留一种国家、ASN 或匿名网络规则；关闭须移除完整策略。对应规则需要本地 MMDB，构建时有界读取并核对用途，单库最多 128 MiB；请求按可信客户端地址判断，不信任自报国家或地址头。国家代码转大写，单名单最多 256；ASN 为非零 u32，单名单最多 4096；名单内重复和允许/拒绝重叠均拒绝。匿名 trait：anonymous、anonymous_vpn、hosting_provider、public_proxy、residential_proxy、tor_exit_node。页面只编辑路径与规则，不获取数据库。",
        "subtle",
      ),
      element(
        "p",
        "每类数据库必须恰好对应非空规则；清空本类名单时须同时移除路径，留下无规则的数据库声明会拒绝候选。判断按国家、ASN、匿名网络的顺序进行；库内记录或字段缺失、解码错误会立即返回对应整体动作，选择 allow 不会继续后续库检查。数据库年龄在构建时复核，过期 reject 保留原快照，allow 显式放行整个 GeoIP 门，deny 关闭整个门；坏文件、错误用途及超过一天容差的未来时间仍拒绝候选。移除不再需要的路径或规则须明确操作，其它保护保持原值。",
        "subtle",
      ),
      element(
        "p",
        "请求校验至少需要 head Schema、正文 Schema 或 OpenAPI 操作；关闭须移除完整 request_validation。每种 Schema 的内联与文件来源互斥，OpenAPI 与所有显式 Schema 互斥。OpenAPI 必须恰选 operationId 或路径模板加 HTTP 方法；切换来源或选择器时须明确移除旧字段。路径相对主配置目录解析，页面不读取或上传文件；Schema 在候选构建时编译，引用只允许当前文档内部，不在请求时访问文件或网络。",
        "subtle",
      ),
      element(
        "p",
        "显式 head Schema 校验 method、path、query、headers、path_params；query 和小写 header 的每个值保持字符串数组，原始 path_params 为空。OpenAPI 操作另按声明解析基本类型的 query、header、path 和 cookie 参数，重复标量拒绝。正文只接受 JSON；有正文 Schema 必须显式设置 1–16777216 字节上限，head-only 上限为 0。未声明 body_required 时，显式正文 Schema 要求非空，OpenAPI 遵从 requestBody.required；false 仅允许空正文，不绕过 head、非空正文类型、结构或大小检查。合同不符及下游读取失败返回 400，正文超限返回 413；不能与长流生存期并用，正文校验不能与公共响应缓存并用。",
        "subtle",
      ),
      element(
        "p",
        "响应合同必须从 OpenAPI 选择 operationId 或成对的路径与方法，所有模式都须设置 1–16777216 字节检查容量。observe 缺省透传原响应并以有界副本记录结论；block 在发送实体前校验，失败返回固定 502；replace_error 使用配置的非成功 HTTP 状态和固定文本。替代文本按多行字符串编辑，最多 4096 UTF-8 字节。压缩实体在 observe 中透传并记录不支持，在阻断模式中使用失败动作；响应合同不能与长流生存期并用。关闭须移除完整 response_contract。",
        "subtle",
      ),
      element(
        "p",
        "响应 Schema 的外部引用只能指向显式 catalog 或签名 HTTPS 文档；连同 OpenAPI 根最多 32 文档、原文总量最多 8 MiB，循环、过深引用及 $dynamicRef 拒绝。HTTPS 必须无凭据和 fragment，不跟随重定向，原始字节同时核对固定 SHA-256 与 Ed25519 签名；未声明 CA 时使用系统信任。单文档最多 4 MiB，总期限 100–30000 毫秒，字节缓存复用 1–86400000 毫秒，命中仍复验当前信任、签名和预算且不续期。所有文件和网络解析在候选构建时执行，页面只编辑声明，请求不访问这些来源。移除来源前须同时处理依赖它的引用。",
        "subtle",
      ),
      element(
        "p",
        "request_transform 与 response_transform 分别启用对应方向，关闭须移除完整策略。输入与输出容量均须为 1–16777216 字节；转换有界聚合并重新序列化完整实体，重建类型、长度及必要 SOAPAction，移除失效的完整性、编码、分块和 Trailer 元数据。压缩实体、partial entity 和实际 trailers 拒绝；请求结构或类型失败返回 400，超限返回 413，响应转换失败返回 502。响应转换也作用于路由内产生的拒绝响应，需避免不兼容的格式组合。",
        "subtle",
      ),
      element(
        "p",
        "JSON 操作按顺序执行，rename 移动已有值，add 仅写不存在的位置，remove 缺失时幂等，default 仅补缺失，type_check 不转换类型。切换 action 须明确移除旧操作不再接受的字段；value 的 JSON null 是实际值，删除字段请选择移除。路径使用非根 JSON Pointer，* 为字面键，不执行 JSONPath 或通配展开。JSON 到 JSON 至少需要一个操作；XML / SOAP 输入须有 xml_extract，输出须有 xml_emit。",
        "subtle",
      ),
      element(
        "p",
        "XML 路径按 namespace URI 与本地名匹配，不要求发送方使用相同 prefix；DTD 与外部实体拒绝，深度、节点、属性和文本预算也须合法。SOAP 输入映射须锚定标准 Envelope / Body，输出用 namespaces.soap 选择 SOAP 1.1 或 1.2 URI，未声明时输出 SOAP 1.2。SOAPAction 在请求侧校验输入或设置输出，响应侧仅校验声明合法性，不检查或写入响应头；SOAP Fault 状态映射只在响应侧提供。切换格式时请明确处理旧映射，页面不会自动删除或填充其它声明。",
        "subtle",
      ),
      element(
        "p",
        "声明 graphql_guard 即启用，关闭须移除完整策略。GET 要求唯一 query 和可选唯一 operationName，且只允许 query；POST 支持 JSON 单操作或 batch、application/graphql 原文及 multipart 的唯一 operations 部分。POST 有界读取，通过后原字节和 trailers 继续转发。每个 envelope 检查完整查询文档的字节、token 与深度，再检查选定 operation 的字段复杂度；batch 成本累加用于计量，不把单 operation 预算当作整个 HTTP batch 的总预算。",
        "subtle",
      ),
      element(
        "p",
        "fragment 每次展开重新计费，alias 不能隐藏 __* introspection 字段，默认也拒绝 __typename。body/query/token 超限返回 413，结构、深度或复杂度失败返回 400，禁止 introspection 或关闭的 GraphQL WebSocket 握手返回 403，错误方法返回 405，不支持的 POST 媒体类型返回 415。显式允许 graphql-transport-ws / graphql-ws 后只透明转发，消息级查询门由上游负责，握手前认证和连接治理仍生效。该策略需要 HTTP 上游，最终组合由原目标构建器校验。",
        "subtle",
      ),
      element(
        "p",
        "degraphql 将精确 Method=GET 路由的已知空请求转换为固定 GraphQL POST。query 与 operation_name 由配置冻结，客户端 query 参数不能替换文档；固定文档在构建时按显式或缺省 GraphQL 预算检查。上游 path 不带 query/fragment，path 变量模板须匹配路由 PathTemplate 签名，最多64个命名变量。非空、未知 chunked 或 Upgrade 输入拒绝，生成 JSON 超限返回413。",
        "subtle",
      ),
      element(
        "p",
        "path/query/header 来源只读取明确名称，重复 query/header、必需值缺失、坏类型或文本单值超限返回400；required=false 时缺失变量省略。integer 为 i64，number 必须有限，boolean 只接受 true/false。literal 使用固定非 null JSON 值且 name 须为空，不按 kind 转换；固定值受生成正文总预算。切换来源须显式移除旧 name/value，不自动丢弃原声明；请求校验/转换、缓存、终端后端、镜像及路径改写等组合由原目标构建器拒绝。",
        "subtle",
      ),
      element(
        "p",
        "Casbin model 与 policy 在候选构建时有界读取并编译，请求期只组装固定参数，不读取业务正文。arguments 按 model r 顺序指定 consumer、path、method、route_id、client_ip、scheme 和 header:Name；header 是未可信原始值，不能代替已通过认证的 consumer。相对文件以主配置目录解析。",
        "subtle",
      ),
      element(
        "p",
        "require_identity=false 时无主体使用 anonymous；开启身份要求须有原生认证链或父层身份来源。明确拒绝与缺主体返回403，参数过大或无效UTF-8返回431，内部求值异常默认500，只有该异常受 fail_open 控制。该策略不能与 internal 或公共 proxy_cache 组合；关闭须移除完整声明，原认证和其它治理保持。",
        "subtle",
      ),
      element(
        "p",
        "OPA external 使用 HTTP(S) origin 或 lb://service 与独立绝对路径，不能同时声明 bundle；embedded 需要 opa-embedded 能力和受信本地签名 bundle，须明确移除旧 target、path 与 authorization。页面只编辑路径与 SecretSource，不读取或上传材料；bundle 的 detached Ed25519 签名覆盖原始压缩字节，候选构建先验签再有界解包和编译静态 Rego 规则。",
        "subtle",
      ),
      element(
        "p",
        "OPA 默认只读请求 head；正文与已验证 JWT claims 分别显式开启。正文须精确匹配去参数 media type 且为合法 JSON，通过后原字节与 trailers 继续转发；类型不支持415、正文超限413、读取或JSON失败400。输入头为未可信属性，敏感凭据、实体和连接头不能加入；缺主体403，头值或编码输入超限431，均不受 fail_open。客户端身份头不能替代已认证 consumer。",
        "subtle",
      ),
      element(
        "p",
        "OPA 明确 deny 返回403；依赖传输、期限、求值或响应协议失败默认503，仅此类失败受 fail_open 控制。返回义务须先整组通过名单、重复/冲突和预算检查，再应用请求头、延迟响应头及审计元数据；非法义务不部分执行，失败开放也不执行失败义务。义务名单禁止 Authorization、Cookie、Host 及连接和分帧控制头；审计 key 为1–64字节ASCII字母、数字、下划线、连字符或点。",
        "subtle",
      ),
      element(
        "p",
        "OPA cache 存在即启用，只缓存明确 allow/deny，不缓存错误；external 缓存须有策略修订，embedded 使用 bundle revision 或摘要。singleflight 仅合并本节点同键 miss，follower 有期限；distributed 通过 DynamicStore 复验修订、过期与义务，退避独立于缓存。移除 cache 只关闭缓存，关闭授权须移除整个 opa_authorization；输入与义务子组移除恢复原生默认，不物化缺省值，父段和子项不能在同次动作中重叠。",
        "subtle",
      ),
      element(
        "p",
        "external_plugins 最多16项，按 request_headers 和 response_headers 分组，各相位内保持原数组顺序。处理器仅接收固定请求元数据和头名单，不发送业务正文，也不提供 consumer 或 JWT claims 字段；服务 Authorization 使用独立 SecretSource。响应相位只保存所需请求头的并集，且在完整请求插件链成功后快照。正常继续时原 body 与 trailers 按流转发，continue 不能改写正文。",
        "subtle",
      ),
      element(
        "p",
        "外部 HTTP 插件的 continue 先整组验证再提交本插件头变更，local_response 返回有界正文与非1xx状态并短路。依赖、响应协议或越权输出失败默认500，fail_open 只丢弃本插件结果后继续；前面插件已提交的合法变更保持。请求输入坏UTF-8或超限431、响应输入错误500，均不受失败开放。明确本地响应也不会被失败开放覆盖。名单禁止敏感凭据、Forwarded、X-Forwarded-For、X-Forwarded-Host、X-Forwarded-Proto 和连接分帧头，构建时规范化去重。",
        "subtle",
      ),
      element(
        "p",
        "插件 id 在整条链中唯一，字段编辑保持原 id；新增和整值替换须显式填写，替换会移除旧元素其它字段。请求相位不能声明可见响应头；目标必须是 HTTP(S) origin 或 lb://service，路径独立且无 query。列表支持插入、字段编辑、替换、移动和确认删除；空数组或移除完整 external_plugins 停用链，原认证与其它治理保持。internal 和公共 proxy_cache 组合由原目标构建器拒绝。",
        "subtle",
      ),
      element(
        "p",
        "ext_proc 需要目标制品启用 ext-proc 能力，至少选择一个 head、body 或 trailer 相位。启用 head 或 trailer 会发送其全部原始头字节，请求中包含的业务凭据也对处理器可见，只应配置受信 gRPC 服务。服务 Authorization 使用独立 SecretSource；可写头名单不限制输入可见范围，认证拥有的身份头、凭据、伪头、目标及连接分帧字段始终禁止改写。",
        "subtle",
      ),
      element(
        "p",
        "none 不发送 body 相位，但头部明确 CONTINUE_AND_REPLACE 仍可在正文预算内替换或清空原实体。buffered 有界聚合，streamed 每个 DATA 等待唯一匹配响应形成背压；开启 trailer 且非 streamed 时也会先有界读取正文。streamed body 阶段不能改写 head；请求相位允许有界 ImmediateResponse，响应相位不接受即时响应。处理器不能动态扩大相位或修改既定期限。",
        "subtle",
      ),
      element(
        "p",
        "ext_proc 的 fail_open 只覆盖连接、期限、服务不可用、容量和 circuit 等已分类依赖错误；错序、重复、畸形 protobuf、越权 mutation、未授权 metadata、gRPC 明确拒绝及本地输入资源门始终关闭。依赖开放后本请求永久 bypass，后续相位不再访问处理器；先前合法变更保持。buffered 请求体超限413、读取失败400，响应体与协议失败500；入流依赖失败默认503，流已发 head 后的失败只能终止正文。",
        "subtle",
      ),
      element(
        "p",
        "grpc_transcoding 需要目标制品启用 grpc-descriptor 能力。FileDescriptorSet 来自受信本地文件，相对路径以主配置目录解析；文件内容在有界读取后编译为当前快照的 RPC 计划。google_http 和 connect_json 至少启用一个，移除完整声明才停用 descriptor JSON 转码。",
        "subtle",
      ),
      element(
        "p",
        "service 和 method 使用 protobuf full name，不接受斜杠、空白或重复项；services 必须非空，methods 空名单表示允许所选 service 的全部方法，descriptor 扩展时暴露范围可能随之变化。名单仅约束 JSON 转码入口，原生 gRPC 透传仍由路由和鉴权策略控制。未知 Connect JSON schema 返回404，错误 unary 或 streaming Content-Type 返回415；未命中的普通 JSON HTTP 请求保持普通路由语义。",
        "subtle",
      ),
      element(
        "p",
        "JSON 文档预算不能超过输入或输出消息预算，未完成 stream 缓冲不能超过输入输出消息预算的较大值。reject_unknown_fields 显式关闭时允许忽略 descriptor 未声明的 JSON 字段；不改变原生 protobuf 的未知字段语义。展示和逐项编辑不填入协议默认值，不改未编辑的 descriptor 引用、名单、开关和其它治理。",
        "subtle",
      ),
      element(
        "p",
        "grpc_edge 仅在 enabled=true 且原目标具备 grpc-edge 能力时接管精确动作 RPC；关闭或移除后保持普通 L7 透传。subscribe 与 publish/push 必须分路由及认证配置，分别使用 required 和 service。动作 header 只是二次确认，不能覆盖精确 RPC 路径。客户端 header 不产生可信身份；user 取已验证 claim 或已认证 consumer，显式 tenant_claim 必须在已验证主体中存在，且与 user_claim 不同。",
        "subtle",
      ),
      element(
        "p",
        "启用边缘模式必须显式声明 authz；对应名单为空即拒绝，未允许的 action 不能声明 RPC 或非空授权名单。模式只支持字面量、末尾 * 和 %{user} / %{tenant}，不使用会被配置环境展开的变量语法。WS 桥接只提供订阅传输，复用同一身份、授权及预算，不提供另一套权限。",
        "subtle",
      ),
      element(
        "p",
        "边缘消息上限不含5字节前缀；发送队列字节、节点 payload 驻留和 PublishStream 累计字节须各能容纳最大完整帧。旧 max_msg_bytes 与 limits.max_msg_bytes 同时声明必须相等。队满按声明丢弃、合并或关闭慢客户端，at_most_once 不提供离线补发；PublishStream 速率通过背压节流，寿命/消息数/累计字节到界返回已处理 summary 供发布方轮转。逐项编辑不填入默认值，不改未编辑的身份映射、名单或其它路由策略。",
        "subtle",
      ),
    );
  }
  if (kind === "service") {
    node.append(
      element(
        "p",
        "动态实例来源须启用对应发现服务，并移除静态 instances。Nacos 发现要求制品编译 nacos-sdk；发现总开关与 Nacos 连接身份属于启动配置。Kubernetes 数字端口与端口名称互斥，ServiceImport 使用 MCS EndpointSlice；Nacos clusters 空列表允许全部 cluster。scheme 用于拼接发现实例 URI，不改写已声明的静态 URI。lb_policy 优先于兼容字段 lb。ring_hash 和 maglev 须有 hash_on；ip_hash 固定按 remote_addr，不能再声明 hash_on。哈希参数仅用于哈希策略，Maglev 从预设质数表选择不小于期望值的槽位数；算法与亲和仍受健康、备用和地域候选层约束。",
        "subtle",
      ),
      element(
        "p",
        "换实例条件支持 error、timeout、http_502、http_503、http_504、non_idempotent；显式空列表禁用触发，移除字段恢复默认。GET/HEAD 以外的方法须有 Idempotency-Key 或显式 non_idempotent，且待转发正文必须为空；预算不会授予重放许可。总次数包含首次，每个候选最多尝试一次。预算比例与两项最低额度取较大值，同时限制窗口重试量和在途重试数；比例为 0 仍保留最低额度。窗口摘除 outlier 存在时替代 max_fails 策略。",
        "subtle",
      ),
      element(
        "p",
        "预热整段缺省关闭，设置任一预热子字段即声明该策略；关闭须移除完整 prewarm。预热使用不带下游身份或正文的 HEAD 请求，不证明业务可用。h3 需要 HTTPS 实例及 http3 能力；h2 用于 TLS，明文 HTTP/2 使用 h2c。目标预检仍检查协议和配置组合。",
        "subtle",
      ),
      element(
        "p",
        "自适应并发须显式 enabled，按服务限制等待上游响应头的在途尝试；达到上限后只有有限队列可等待，队列满或到期返回过载。窗口摘除没有 enabled，声明 outlier 即启用并替代 max_fails，移除整段才关闭；目标须具备 upstream-outlier 能力。失败与慢调用比例不能同时为 0，摘除上限按实例数向下取整，单实例不会被摘除。冷却到期仅开放一个真实恢复探测，成功前仍处于摘除状态。",
        "subtle",
      ),
      element(
        "p",
        "会话保持整段缺省关闭，声明 session_affinity 即启用，关闭须移除整段。亲和令牌只选择当前服务仍可用的实例，不是认证凭据，不能绕过健康、下线或地域边界。滚动 ttl_seconds 不能与绝对或空闲期限混用；持久 Cookie 的 Max-Age 随原绝对期限递减。Header 模式不接受 Cookie 有效期，切换载体时请明确处理旧字段。SameSite=None 须同时 Secure=true，省略 Path 与指定 path 互斥。",
        "subtle",
      ),
      element(
        "p",
        "地域选择只使用静态实例或可信发现元数据。单层 failover 按本区及备用列表顺序选择；weighted 让已列可用区同层按份额分流，zone_weights 只用于此模式。声明 local_region 后须使用非空 targets，不混用单层备用、权重和劣化列表；分层先按 priority，failover 再按距离，weighted 在同 priority 内分流。劣化只降低同层份额，不提升优先级或代替健康摘除。未列实例仅在显式允许且已列层全不可用时兜底。移除整段 locality 才关闭地域约束。",
        "subtle",
      ),
      element(
        "p",
        "负载反馈供 least_conn 和 weighted_least_request（p2c）在当前候选层内比较；缺失、过期、非法或样本不足时回退基础算法，不改变实例健康。新鲜反馈覆盖不足时整体回退，覆盖下限为 0 仍须至少一份有效反馈。反馈只取真实上游响应或固定实例订阅，不信任客户端报告。带外订阅须 utilization、h2/h2c 和 upstream-orca 能力；默认要求 TLS 身份验证，明文须显式允许，不能使用 insecure_skip_verify。设置任一 out_of_band 子字段即声明订阅，关闭须移除整段；将反馈模式改为 none 时也须移除订阅。",
        "subtle",
      ),
    );
  }
  if (["service", "stream_route", "stream_route_new"].includes(kind)) {
    node.append(
      element(
        "p",
        "上游 CA 文件与内联 CA 互斥；客户端证书和私钥须成对，且不能与 SPIRE 混用。非空 SAN 列表使用 dns: 或 uri:，此时 server_name 只选择 SNI，证书链仍须验证。仅加密模式不能同时声明信任约束或客户端身份。服务实例须使用 HTTPS；lb:// 流上游在服务配置 TLS。SPIRE 需要目标具备 spire-workload 能力和可用的本地 Workload API。内联客户端材料请在完整声明中维护，常用字段不回填私钥。",
        "subtle",
      ),
    );
  }
  if (["proxy", "stream"].includes(kind)) {
    node.append(
      element(
        "p",
        "切换 TLS 来源时请明确移除不再适用的声明；原目标预检会检查互斥条件。manifest 可保留文件种子，SNI 身份单独配置。",
        "subtle",
      ),
    );
  } else if (kind === "tls_identity") {
    node.append(
      element(
        "p",
        "SNI 身份使用自己的材料或外部签名引用，不继承默认 manifest、SPIRE 或 OCSP 响应。",
        "subtle",
      ),
    );
  }
  if (kind === "proxy") {
    node.append(
      element(
        "p",
        "连接总寿命会终止长流；H2 窗口授予接收额度，不预分配等量缓冲。旧代连接池缓存淘汰不终止已在途请求。PROXY protocol 只接受 accept_from 中的直连对端，必须发送合法前导，且不能与 HTTP/3 同时启用。",
        "subtle",
      ),
    );
    node.append(
      element(
        "p",
        "ACME 只为 HTTP 默认 TLS 身份签发。新增身份或更换账户路径、DNS provider 声明须在目标节点本地配置；共享预检会拒绝改变这些引用。DNS 凭据使用 SecretSource 引用，固定命令参数不要包含秘密；切换 provider 时请显式处理旧字段。Redis 续期锁必须配合 shared-file 和实际共享卷。编辑候选不会创建订单或检查 DNS 控制权。",
        "subtle",
      ),
    );
    node.append(
      element(
        "p",
        "HTTP/3 复用当前 TLS 入口。单向流预算包含 control/QPACK；DATAGRAM 队列满时按不可靠语义丢弃。0-RTT 还需 early_data 扩展和明确的路由授权，多节点部署必须具备共享重放保护。仅填写这些声明不会授予能力。",
        "subtle",
      ),
    );
  }
  if (kind === "stream") {
    node.append(
      element(
        "p",
        "TLS 与 MQTT 预读不能同时启用。TLS 预读与终止组合需要显式 terminate_tls 路由。UDP 不使用 TCP 前导或协议预读，队列满时丢弃当前报文；预算不提供报文重组。前置代理信任与向上游发送前导分别声明。",
        "subtle",
      ),
    );
    node.append(
      element(
        "p",
        "MQTT 治理需要目标具备 mqtt-governance 能力、TCP 和 CONNECT 预读，不能与 Kafka 治理同时启用。空发布或订阅名单拒绝对应操作；订阅过滤器必须整体落在授权边界内。双向包缓冲按连接数与包上限预留，不代表实际内存用量。",
        "subtle",
      ),
    );
    node.append(
      element(
        "p",
        "Kafka 治理需要目标具备 kafka-governance 能力、TCP 且关闭 MQTT 与 TLS 预读。topic 和 group 按精确名称授权；空名单拒绝对应操作。broker 响应缺少任一地址映射会拒绝转发。帧期限不计纯空闲，总缓冲按连接数与帧上限预留；启用不代表支持全部 Kafka API。",
        "subtle",
      ),
    );
  }
  for (const [prefix, title, definitions] of [
    ...(groups[kind] ?? []),
    ...routeDeadlineFieldGroups(kind),
    ...routeWafFieldGroups(kind),
    ...routeWafPackFieldGroups(kind),
    ...routeBotFieldGroups(kind),
    ...routeBotRateFieldGroups(kind),
    ...routeBotTrustedFieldGroups(kind),
    ...routeDlpFieldGroups(kind),
    ...routeCsrfFieldGroups(kind),
    ...routeGeoipFieldGroups(kind),
    ...routeRequestValidationFieldGroups(kind),
    ...routeResponseContractFieldGroups(kind),
    ...routeBodyTransformFieldGroups(kind),
    ...routeGraphqlGuardFieldGroups(kind),
    ...routeDegraphqlFieldGroups(kind),
    ...routeCasbinFieldGroups(kind),
    ...routeOpaFieldGroups(kind),
    ...routeExtProcFieldGroups(kind),
    ...routeGrpcTranscodingFieldGroups(kind),
    ...routeGrpcEdgeFieldGroups(kind),
    ...wasmSourceFieldGroups(kind),
    ...scriptCircuitFieldGroups(kind),
    ...routeBffFieldGroups(kind),
    ...routeMockFieldGroups(kind),
    ...routeFaultFieldGroups(kind),
    ...routeDubboFieldGroups(kind),
    ...routeRedirectFieldGroups(kind),
    ...routeWsFrameFieldGroups(kind),
    ...routeForwardProxyFieldGroups(kind),
    ...routeWebTransportFieldGroups(kind),
    ...routeEarlyDataFieldGroups(kind),
    ...routeLlmFieldGroups(kind),
    ...routeAiSecurityFieldGroups(kind),
    ...routeRagFieldGroups(kind),
    ...routeOutputModerationFieldGroups(kind),
    ...listenerFieldGroups(kind),
    ...streamTransportFieldGroups(kind),
    ...mqttFieldGroups(kind),
    ...kafkaFieldGroups(kind),
    ...http3FieldGroups(kind),
    ...tlsFieldGroups(kind),
    ...upstreamTlsFieldGroups(kind),
    ...upstreamRetryFieldGroups(kind),
    ...upstreamCapacityFieldGroups(kind),
    ...upstreamAffinityFieldGroups(kind),
    ...upstreamLocalityFieldGroups(kind),
    ...upstreamFeedbackFieldGroups(kind),
  ]) {
    const group = element("details");
    group.append(element("summary", title));
    let current = values;
    let valid = true;
    for (const key of prefix) {
      if (current === undefined) {
        continue;
      }
      if (!current || Array.isArray(current) || typeof current !== "object") {
        valid = false;
        break;
      }
      current = Object.hasOwn(current, key) ? current[key] : undefined;
    }
    valid &&=
      current === undefined ||
      (!!current && !Array.isArray(current) && typeof current === "object");
    if (!valid) {
      group.append(
        element(
          "p",
          "当前父字段不是映射，不能隐式覆盖；请使用其它声明中的整值编辑。",
          "subtle",
        ),
      );
    } else {
      for (const [key, label, type] of definitions) {
        const path = [...prefix, key];
        const row = fieldRow(
          path.join(" → "),
          label,
          type,
          current && Object.hasOwn(current, key) ? current[key] : undefined,
          capacity,
        );
        rows.push({
          path,

          row,
        });
        group.append(row.node);
      }
    }
    node.append(group);
  }

  /**
   * 业务作用：只提交显式子字段动作，未知子字段继续由服务端原始树持有。
   * 参数说明: 无。
   * 返回：有限设置和移除序列，不包含完整原始父对象；同次动作的祖先与子项重叠时拒绝。
   */
  function read() {
    const edits = [];
    for (const { path, row } of rows) {
      const action = row.read();
      if (action?.remove) {
        edits.push({
          op: "remove",

          path,
        });
      } else if (action) {
        edits.push({
          op: "set",

          path,

          value: action.value,
        });
      }
    }
    // 整段声明和子项不能争用同一原始子树，避免候选含有依赖动作顺序的半完成策略。
    for (let index = 0; index < edits.length; index++) {
      for (const other of edits.slice(index + 1)) {
        const left = edits[index].path;
        const right = other.path;
        const shared = Math.min(left.length, right.length);
        if (
          left.slice(0, shared).every((key, offset) => key === right[offset])
        ) {
          throw new Error(
            "同一字段不能同时整值修改和编辑子项，请只选择一种方式。",
          );
        }
      }
    }
    return edits;
  }
  return {
    node,

    read,
  };
}

/**
 * 业务作用：把明确的根字段与子项组合为一个原子草稿动作，新对象只从空映射构造。
 * 参数说明：
 * - `object`：冻结的对象身份。
 * - `patch`：表单读出的独立动作。
 * - `creating`：是否创建新对象。
 * 返回：旧字段 patch、有限嵌套 patch 或完整新对象；冲突祖先与新增移除均拒绝。
 */
export function fieldAction(object, patch, creating) {
  const edits = patch.edits ?? [];
  if (creating) {
    if (patch.remove.length || edits.some((edit) => edit.op === "remove")) {
      throw new Error("新增对象不能移除字段，请将不需要的字段保持未声明。");
    }
    const fields = patch.fields;
    for (const edit of edits) {
      let parent = fields;
      for (const key of edit.path.slice(0, -1)) {
        if (!Object.hasOwn(parent, key)) {
          parent[key] = Object.create(null);
        }
        parent = parent[key];
        if (!parent || Array.isArray(parent) || typeof parent !== "object") {
          throw new Error("新增对象的父字段与子项冲突。");
        }
      }
      parent[edit.path.at(-1)] = edit.value;
    }
    return {
      type: "create",

      object,

      fields,
    };
  }
  if (!edits.length) {
    return {
      type: "patch",

      object,

      fields: patch.fields,

      remove: patch.remove,
    };
  }
  for (const [key, value] of Object.entries(patch.fields)) {
    edits.push({
      op: "set",

      path: [key],

      value,
    });
  }
  for (const key of patch.remove) {
    edits.push({
      op: "remove",

      path: [key],
    });
  }
  if (edits.length > 128) {
    throw new Error("单次字段动作超过容量，请分次编辑候选。");
  }
  return {
    type: "patch_nested",

    object,

    edits,
  };
}
