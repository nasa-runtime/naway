import { tlsSpireFields } from "./tls.js";

const upstreamTlsFields = [
  ["server_name", "上游 SNI 与默认认证名称", "string"],
  ["insecure_skip_verify", "仅加密传输，关闭服务端证书认证", "boolean"],
  ["ca_file", "上游信任 CA 文件路径", "string"],
  ["ca_pem", "上游信任 CA PEM（与文件互斥）", "multiline"],
  ["subject_alt_names", "允许的证书 SAN（每行一项，最多五项）", "lines"],
  ["client_cert_file", "上游客户端证书链路径", "string"],
  ["client_key_file", "上游客户端私钥路径", "string"],
];

/**
 * 业务作用：为服务及流路由提供相同的上游信任和身份子字段，避免整值替换无关声明。
 * 参数说明：
 * - `kind`：具名服务或列表内的流路由类型。
 * 返回：精确的 TLS 与 SPIRE 字段分组；不会加载材料、填充私钥或自动开启仅加密模式。
 */
export function upstreamTlsFieldGroups(kind) {
  if (!["service", "stream_route", "stream_route_new"].includes(kind)) {
    return [];
  }
  return [
    [["tls"], "上游身份与信任", upstreamTlsFields],
    [["tls", "spire"], "上游 SPIRE 客户端身份", tlsSpireFields],
  ];
}

/**
 * 业务作用：按原位置编辑服务上游 SAN 与 SPIRE 联邦信任域，不重写其它身份策略。
 * 参数说明：
 * - `kind`：所属候选对象类型。
 * 返回：服务声明内的两个有界列表位置；其它类型保留各自的列表编辑边界。
 */
export function upstreamTlsDraftLists(kind) {
  if (kind !== "service") {
    return [];
  }
  const lists = [];
  for (const [prefix, , fields] of upstreamTlsFieldGroups(kind)) {
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
