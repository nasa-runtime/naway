/**
 * 业务作用：显式编辑固定响应的状态、单值头映射和原始正文，不自动选择终端后端。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供三项原生 mock 字段；未编辑声明与正文换行保持原值。
 */
export function routeMockFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["mock_response"],
      "固定 mock 响应",
      [
        ["status", "固定最终状态码（200–999；204/304 必须为空正文）", "number"],
        [
          "headers",
          "完整单值响应头映射（最多64项；大小写别名同值合并、冲突拒绝）",
          "json",
        ],
        ["body", "固定 UTF-8 正文（最多1MiB，保留换行与空串）", "multiline"],
      ],
    ],
  ];
}
