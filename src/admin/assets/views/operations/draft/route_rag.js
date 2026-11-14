export const ragSourceFields = [
  ["id", "检索来源稳定 id（1–64字节，仅字母、数字、.、_、-）", "string"],
  ["target", "完整固定检索服务（替换 uri、path 与独立凭据引用）", "json"],
  ["invocation", "完整调用 ACL（替换全部约束，不继承其它来源授权）", "json"],
  ["timeout_ms", "单来源检索及完整正文期限（1–60000毫秒）", "number"],
  ["max_documents", "单次返回文档数量上限（1–32）", "number"],
  ["max_response_bytes", "完整检索响应字节上限（1024–4194304）", "number"],
  [
    "allowed_sources",
    "完整文档来源白名单（每行一项，1–64个安全 ASCII 标识）",
    "lines",
  ],
  [
    "allowed_citation_origins",
    "完整引用域白名单（每行一个规范 HTTPS origin，1–32项）",
    "lines",
  ],
  [
    "fail_mode",
    "依赖故障策略（closed、open；明确拒绝与坏来源证明始终拒绝）",
    "string",
  ],
];

/**
 * 业务作用：独立维护检索来源、上下文及引用约束，不从请求或其它来源推导目标和授权。
 * 参数说明：
 * - `kind`：路由或检索来源的草稿对象类别。
 * 返回：当前类别的原生字段，缺省值不写入候选，来源凭据只编辑引用。
 */
export function routeRagFieldGroups(kind) {
  if (["rag_source", "rag_source_new"].includes(kind)) {
    return [
      [
        ["target"],
        "RAG 固定检索服务",
        [
          [
            "uri",
            "固定 HTTP(S) origin 或 lb://service（不含业务路径）",
            "string",
          ],
          [
            "path",
            "固定检索 path（无模板、百分号、query 或 fragment）",
            "string",
          ],
          [
            "api_key",
            "独立 Bearer 凭据 SecretSource（空表示不注入）",
            "string",
          ],
        ],
      ],
      [
        ["invocation"],
        "RAG 独立调用 ACL",
        [
          [
            "allow_authenticated",
            "显式允许已认证身份（其它约束仍须同时满足）",
            "boolean",
          ],
          [
            "consumers",
            "完整已认证 consumer 名单（每行一项，最多64项）",
            "lines",
          ],
          [
            "groups",
            "完整已验证组名单（每行一项，最多64项，至少一组匹配）",
            "lines",
          ],
          [
            "scopes",
            "完整已验签 scope 名单（每行一项，最多64项，全部满足）",
            "lines",
          ],
        ],
      ],
    ];
  }
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["llm", "governance"],
      "RAG 完整声明（需 ai-governance）",
      [
        [
          "rag",
          "完整检索与引用治理（移除保留安全身份、固定模板与输出裁决）",
          "json",
        ],
      ],
    ],
    [
      ["llm", "governance", "rag"],
      "RAG 来源与引用",
      [
        ["sources", "完整检索来源目录（1–8项，也可按原位置逐项编辑）", "json"],
        [
          "citations",
          "回答引用策略（required、optional；仅支持缓冲回答）",
          "string",
        ],
        [
          "max_context_bytes",
          "检索上下文 JSON 字节上限（1024–1048576）",
          "number",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：按原位置编辑检索来源，已有稳定身份和未编辑来源声明不随展示重建。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供来源目录，新增与替换须明确全部原生必需字段。
 */
export function routeRagDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["llm", "governance", "rag", "sources"],
      title: "RAG 固定检索来源",
      type: "rag_source",
    },
  ];
}
