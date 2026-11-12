/**
 * 业务作用：显式维护 LLM 入口协议与请求资源预算，避免编辑预算时重建模型凭据或其它治理声明。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供八项原生声明，不自动选择模型、注入凭据或修改其它终端后端。
 */
export function routeLlmFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["llm"],
      "LLM 入口协议与请求预算",
      [
        [
          "api_type",
          "API 类型（如 chat_completions、responses、embeddings；须与模型兼容）",
          "string",
        ],
        ["max_body_bytes", "请求实体字节上限（1–16777216）", "number"],
        ["max_prompt_tokens", "提示词估算 token 上限（1–16777216）", "number"],
        [
          "max_completion_tokens",
          "补全 token 上限（1–16777216；请求未声明时也生效）",
          "number",
        ],
        [
          "max_response_bytes",
          "响应字节上限（1–16777216；原生长连接按协议计量）",
          "number",
        ],
        [
          "max_stream_frame_bytes",
          "流事件、行或原生帧上限（正数；不超过响应上限和4194304）",
          "number",
        ],
        [
          "max_duration_ms",
          "单次模型请求或长连接期限（毫秒；1–86400000）",
          "number",
        ],
        [
          "max_cost_microusd",
          "估算费用上限（正数，微美元；保留原声明的仅观测模式）",
          "number",
        ],
      ],
    ],
  ];
}
