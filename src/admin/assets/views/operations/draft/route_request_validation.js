/**
 * 业务作用：显式编辑请求合同的来源、操作身份与正文资源边界，避免来源切换时隐式移除原有校验。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十项请求校验原生字段；Schema 保持 JSON 值，文件仅编辑本地路径声明。
 */
export function routeRequestValidationFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["request_validation"],
      "请求 JSON Schema 与 OpenAPI 校验",
      [
        ["head_schema", "内联请求 head Schema（JSON 值）", "json"],
        [
          "head_schema_file",
          "请求 head Schema 本地 JSON / YAML 路径",
          "string",
        ],
        ["body_schema", "内联 JSON 正文 Schema（JSON 值）", "json"],
        [
          "body_schema_file",
          "JSON 正文 Schema 本地 JSON / YAML 路径",
          "string",
        ],
        ["openapi_file", "OpenAPI 本地 JSON / YAML 路径", "string"],
        ["operation_id", "OpenAPI operationId（与路径和方法二选一）", "string"],
        ["operation_path", "OpenAPI 路径模板（须同时填写方法）", "string"],
        [
          "operation_method",
          "OpenAPI HTTP 方法（须同时填写路径模板）",
          "string",
        ],
        [
          "max_body_bytes",
          "正文校验字节上限（1–16777216；head-only 为 0）",
          "number",
        ],
        ["body_required", "拒绝空正文（未声明时遵从合同来源）", "boolean"],
      ],
    ],
  ];
}
