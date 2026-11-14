export const mediaFields = [
  ["format", "明确容器（mp4 时间起播；flv 原文件字节起播）", "string"],
  ["max_file_bytes", "单文件字节上限（1–1099511627776）", "number"],
  ["max_metadata_bytes", "元数据字节上限（1024–16777216）", "number"],
  [
    "max_parse_bytes",
    "累计解析读取上限（至少元数据容量，至多33554432字节）",
    "number",
  ],
  ["max_box_bytes", "单 box/tag 字节上限（1024–16777216）", "number"],
  ["max_boxes", "结构数量上限（16–100000）", "number"],
  ["max_depth", "结构深度上限（4–32）", "number"],
  ["max_samples", "全部轨道样本或 FLV tag 上限（1–500000）", "number"],
  ["max_inflight", "真实静态根的在途媒体操作上限（1–8）", "number"],
  ["timeout_ms", "单次解析期限（毫秒；10–10000）", "number"],
];

/**
 * 业务作用：显式维护静态媒体容器与解析预算，不因选中容器自动开放路由或改写静态根。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十个原生字段，终端组合、工作集和目标 feature 仍须原目标完整预检。
 */
export function routeMediaFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [[["media"], "有界静态媒体容器与解析预算", mediaFields]];
}
