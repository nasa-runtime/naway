export const webdavFields = [
  ["mode", "明确存储模式（local 或 proxy）", "string"],
  ["mount_prefix", "公开挂载的规范绝对前缀（无尾斜杠，根除外）", "string"],
  ["upstream_prefix", "proxy 的固定上游前缀（local 须移除）", "string"],
  ["methods", "明确允许的方法（每行一项，1–12项且唯一）", "lines"],
  ["lock_scope", "local 须明确 process；proxy 须移除", "string"],
  ["exclusive_process", "明确单进程独占本地目录（local 须 true）", "boolean"],
  ["max_file_bytes", "单文件字节上限（1–1073741824）", "number"],
  [
    "max_total_bytes",
    "目录总字节上限（至少单文件上限，至多1099511627776）",
    "number",
  ],
  ["max_entries", "目录项上限（1–4096）", "number"],
  ["max_path_depth", "相对路径深度上限（1–32）", "number"],
  ["max_inflight", "在途操作上限（1–128）", "number"],
  ["max_xml_bytes", "XML 字节上限（1024–1048576）", "number"],
  ["max_xml_nodes", "XML 节点上限（1–16384）", "number"],
  ["max_xml_depth", "XML 深度上限（1–32）", "number"],
  [
    "max_multistatus_bytes",
    "多状态响应容量（至少 XML 容量，至多8388608字节）",
    "number",
  ],
  ["max_locks", "进程内锁上限（1–1024）", "number"],
  ["max_lock_seconds", "锁最长寿命（秒；1–86400）", "number"],
  ["timeout_ms", "单操作期限（毫秒；100–60000）", "number"],
];

/**
 * 业务作用：分别维护 DAV 模式、目录权限和资源预算，不因选择 local 自动授予写方法或独占权。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十八个原生字段，目录归属、写审计和模式组合仍由原目标完整预检。
 */
export function routeWebdavFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [[["webdav"], "WebDAV 方法、存储归属与预算", webdavFields]];
}

/**
 * 业务作用：按原位置编辑 DAV 允许方法，不把列表删除或模式切换解释为开放所有写操作。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供明确方法的字符串列表，空集、重复和不支持的方法仍由原目标拒绝。
 */
export function routeWebdavDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    { path: ["webdav", "methods"], title: "WebDAV 允许方法", type: "string" },
  ];
}
