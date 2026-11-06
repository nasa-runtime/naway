import { acmeFieldGroups } from "./acme.js";

const tlsFileFields = [
  ["cert_file", "证书链路径", "string"],
  ["key_file", "私钥路径", "string"],
  ["keypair_manifest_file", "证书对清单路径", "string"],
];

const tlsSignerFields = [
  ["provider", "外部签名服务名称", "string"],
  ["key_id", "外部密钥身份", "string"],
  ["algorithms", "允许的签名算法（每行一项）", "lines"],
];

const tlsStapleFields = [
  ["response_file", "OCSP 响应文件路径", "string"],
  ["issuer_file", "签发者证书路径", "string"],
  ["mode", "响应策略：optional / required", "string"],
  [
    "max_age_without_next_update_seconds",
    "无 nextUpdate 时最大年龄（秒）",
    "number",
  ],
  ["clock_skew_seconds", "允许时钟偏差（秒）", "number"],
  ["fetch_from_aia", "从证书 AIA 获取响应", "boolean"],
  ["refresh_interval_seconds", "响应刷新间隔（秒）", "number"],
  ["request_timeout_ms", "响应请求期限（毫秒）", "number"],
  ["allowed_responder_cidrs", "允许的私网响应者 CIDR（每行一项）", "lines"],
];

const tlsClientFields = [
  ["mode", "客户端认证：require / optional / insecure_fallback", "string"],
  ["ca_file", "客户端 CA 路径", "string"],
  ["crl_files", "CRL 路径（每行一项）", "lines"],
  ["revocation_mode", "CRL 策略：off / hard_fail / soft_fail", "string"],
  ["enforce_crl_expiration", "拒绝已过期的 CRL", "boolean"],
  ["allowed_spiffe_ids", "允许的精确 SPIFFE ID（每行一项）", "lines"],
  ["allowed_spiffe_trust_domains", "允许的 SPIFFE 信任域（每行一项）", "lines"],
];

const tlsClientOcspFields = [
  ["mode", "在线吊销策略：hard_fail / soft_fail", "string"],
  ["timeout_ms", "响应请求期限（毫秒）", "number"],
  ["max_stale_seconds", "已验证陈旧缓存保留期（秒）", "number"],
  [
    "max_age_without_next_update_seconds",
    "无 nextUpdate 时最大年龄（秒）",
    "number",
  ],
  ["clock_skew_seconds", "允许时钟偏差（秒）", "number"],
  ["max_cache_entries", "缓存身份上限", "number"],
  ["max_concurrency", "并发响应请求上限", "number"],
  ["allowed_responder_cidrs", "允许的私网响应者 CIDR（每行一项）", "lines"],
];

const tlsSpireFields = [
  ["socket_path", "Workload API Unix socket 绝对路径", "string"],
  ["spiffe_id", "精确 SPIFFE ID", "string"],
  ["hint", "身份选择 hint", "string"],
  ["federation_trust_domains", "允许的联邦信任域（每行一项）", "lines"],
  ["timeout_ms", "建连及首响应期限（毫秒）", "number"],
  ["reconnect_min_ms", "最短重连退避（毫秒）", "number"],
  ["reconnect_max_ms", "最长重连退避（毫秒）", "number"],
  ["max_response_bytes", "完整响应字节上限", "number"],
  ["min_validity_seconds", "发布时最短剩余有效期（秒）", "number"],
  ["clock_skew_seconds", "允许时钟偏差（秒）", "number"],
];

const tlsTicketFields = [
  ["keys", "会话密钥 SecretSource（每行一项，首项签发）", "lines"],
  ["lifetime_seconds", "会话票据最长轮换窗口（秒）", "number"],
];

export const tlsIdentityFields = [
  ["server_names", "SNI 名称（每行一项，保留顺序）", "lines"],
  ["cert_file", "证书链路径", "string"],
  ["key_file", "私钥路径", "string"],
];

/**
 * 业务作用：按真实 TLS 身份类型提供精确子字段，默认身份与 SNI 的来源能力分别声明。
 * 参数说明：
 * - `kind`：HTTP 入口、流监听器或列表内的 SNI 身份类型。
 * 返回：只含字段定义的分组；不会解析材料、补默认值或替调用者移除互斥声明。
 */
export function tlsFieldGroups(kind) {
  if (!["proxy", "stream", "tls_identity"].includes(kind)) {
    return [];
  }
  const identity = kind === "tls_identity";
  const prefix = identity ? [] : ["tls"];
  const groups = [
    [[...prefix, "private_key_provider"], "外部私钥签名", tlsSignerFields],
    [
      [...prefix, "ocsp_stapling"],
      "当前身份的服务端 OCSP 响应",
      tlsStapleFields,
    ],
  ];
  if (identity) {
    return groups;
  }
  groups.unshift([
    prefix,
    "TLS 监听与材料路径",
    kind === "proxy"
      ? [["listen", "TLS 监听地址", "string"], ...tlsFileFields]
      : [
          ...tlsFileFields,
          ["handshake_timeout_ms", "TLS 握手期限（毫秒）", "number"],
        ],
  ]);
  groups.push(
    [["tls", "client_auth"], "客户端证书验证", tlsClientFields],
    [
      ["tls", "client_auth", "ocsp"],
      "客户端证书在线 OCSP",
      tlsClientOcspFields,
    ],
    [["tls", "session_tickets"], "会话票据密钥与轮换", tlsTicketFields],
    [["tls", "spire"], "SPIRE 身份订阅", tlsSpireFields],
    ...acmeFieldGroups(kind),
  );
  return groups;
}

/**
 * 业务作用：开放 TLS 身份与授权列表的原位置编辑，避免整值替换无关身份或策略。
 * 参数说明：
 * - `kind`：所属配置对象类型。
 * 返回：HTTP 与流监听器的有界列表位置；其它对象不获得 TLS 列表入口。
 */
export function tlsDraftLists(kind) {
  if (!["proxy", "stream"].includes(kind)) {
    return [];
  }
  const lists = [
    {
      path: ["tls", "certs"],
      title: "SNI 证书身份",
      type: "tls_identity",
    },
  ];
  for (const [prefix, , fields] of tlsFieldGroups(kind)) {
    for (const [key, title, type] of fields) {
      if (type === "lines") {
        lists.push({
          path: [...prefix, key],
          title,
          type: "string",
        });
      }
    }
  }
  return lists;
}
