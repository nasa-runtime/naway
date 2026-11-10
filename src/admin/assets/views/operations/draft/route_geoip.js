/**
 * 业务作用：显式声明本地地域数据与失败处置，避免清空规则时隐式撤销原有地域保护。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供十二项 GeoIP 原生字段；不上传、下载或解析数据库文件。
 */
export function routeGeoipFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["geoip"],
      "地域、ASN 与匿名网络",
      [
        [
          "country_database_file",
          "Country / City / Enterprise 本地 MMDB 路径",
          "string",
        ],
        ["asn_database_file", "ASN 本地 MMDB 路径", "string"],
        ["anonymous_database_file", "Anonymous-IP 本地 MMDB 路径", "string"],
        ["allowed_countries", "允许国家（两位 ASCII 字母，每行一项）", "lines"],
        ["denied_countries", "拒绝国家（两位 ASCII 字母，每行一项）", "lines"],
        [
          "allowed_asns",
          "允许 ASN（JSON 数字数组，每项 1–4294967295）",
          "json",
        ],
        ["denied_asns", "拒绝 ASN（JSON 数字数组，每项 1–4294967295）", "json"],
        ["denied_anonymous_traits", "拒绝匿名网络 trait（每行一项）", "lines"],
        ["on_not_found", "记录或所需字段缺失：allow / deny", "string"],
        ["on_lookup_error", "查询或解码错误：allow / deny", "string"],
        ["on_stale", "构建时库过期：reject / allow / deny", "string"],
        [
          "max_database_age_secs",
          "构建时最大数据库年龄（1–31622400 秒）",
          "number",
        ],
      ],
    ],
  ];
}

/**
 * 业务作用：按原位置维护国家、数值 ASN 和匿名网络规则，保持原声明及各名单之间的独立边界。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：路由的五个列表；ASN 使用数值元素，其它名单使用字符串元素。
 */
export function routeGeoipDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["geoip", "allowed_countries"],
      title: "GeoIP 允许国家",
      type: "string",
    },
    {
      path: ["geoip", "denied_countries"],
      title: "GeoIP 拒绝国家",
      type: "string",
    },
    {
      path: ["geoip", "allowed_asns"],
      title: "GeoIP 允许 ASN",
      type: "number",
    },
    {
      path: ["geoip", "denied_asns"],
      title: "GeoIP 拒绝 ASN",
      type: "number",
    },
    {
      path: ["geoip", "denied_anonymous_traits"],
      title: "GeoIP 拒绝匿名网络",
      type: "string",
    },
  ];
}
