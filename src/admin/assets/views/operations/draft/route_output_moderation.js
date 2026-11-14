import { llmModerationFields } from "./route_llm.js";

/**
 * 业务作用：独立维护输出裁决服务、尚未交付的文本窗口与调用预算，不默认放宽依赖失败策略。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供原生输出裁决字段，未编辑的身份、模板、检索和其它内容规则保持原声明。
 */
export function routeOutputModerationFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["llm", "governance"],
      "AI 输出裁决完整声明（需 ai-governance）",
      [
        [
          "output_moderation",
          "完整输出裁决（移除保留身份、模板、RAG 与其它内容规则）",
          "json",
        ],
      ],
    ],
    [
      ["llm", "governance", "output_moderation"],
      "AI 输出裁决窗口与预算",
      [
        ["service", "完整输出判定服务（替换整个服务声明及独立凭据）", "json"],
        [
          "stream_window_bytes",
          "交付前保留的文本窗口（64–16384字节；服务请求预算至少为窗口×4+1024）",
          "number",
        ],
        ["max_calls", "本次输出最多调用次数（1–4096；耗尽始终拒绝）", "number"],
      ],
    ],
    [
      ["llm", "governance", "output_moderation", "service"],
      "AI 独立输出判定服务",
      llmModerationFields,
    ],
  ];
}
