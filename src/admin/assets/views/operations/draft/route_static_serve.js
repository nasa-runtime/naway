export const staticServeFields = [
  ["root", "固定静态根目录（相对主配置目录；必须已存在）", "string"],
  ["try_files", "依次选择文件模板（每行一项；末项可明确 SPA 回落）", "lines"],
  ["index", "目录索引文件名（每行一项，按顺序选择）", "lines"],
  ["cache_control", "明确的 Cache-Control 响应头", "string"],
  ["expires", "Expires 时长（秒整数或 s/m/h/d；off 关闭，0 合法）", "string"],
  ["default_type", "未知扩展名的默认 Content-Type", "string"],
  ["types", "完整扩展名到 Content-Type 映射", "json"],
  ["allow_dotfiles", "明确允许根内点文件及点目录", "boolean"],
  ["etag", "生成弱 ETag（不改变 Last-Modified 条件请求）", "boolean"],
  ["range", "接受单段 HTTP Range", "boolean"],
];

/**
 * 业务作用：显式编辑静态根、文件选择和响应语义，不因切换本地后端自动移除其它终端或开放文件权限。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供完整 static 声明和十个子项，未编辑的原文及其它 serve 声明保持原值。
 */
export function routeStaticServeFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["serve"],
      "本地服务后端",
      [["static", "完整静态文件与 SPA 声明", "json"]],
    ],
    [["serve", "static"], "静态文件与 SPA", staticServeFields],
  ];
}

/**
 * 业务作用：按原始位置维护文件模板和目录索引顺序，单项动作不改写文件根或响应权限。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供两个字符串列表；新增、移动和删除均保持另一列表及其它声明不变。
 */
export function routeStaticServeDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["serve", "static", "try_files"],
      title: "静态文件选择顺序",
      type: "string",
    },
    {
      path: ["serve", "static", "index"],
      title: "静态目录索引顺序",
      type: "string",
    },
  ];
}
