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
  if (kind === "route") {
    node.append(
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
   * 返回：有限设置和移除序列，不包含读取到的完整原始父对象。
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
