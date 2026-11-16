# 全局 IP 与客户端来源策略

根配置的 `acl` 在接口守卫之后、HTTP 路由之前执行，同时约束 TCP 与 UDP 业务入口。
它与路由 `allow` / `deny`、动态封禁分别生效；通过全局 ACL 不会跳过其它门禁。
HTTP 拒绝返回 403，TCP 关闭连接，UDP 丢弃数据报。Admin 使用独立监听、认证和权限。
ACME HTTP-01 的有效挑战响应沿用独立验证通道，不执行全局 ACL 和动态封禁。

```yaml
schema_version: 2
acl:
  mode: whitelist
  entries:
    - 192.0.2.0/24
    - 2001:db8::/32
client_ip_policy:
  mode: forwarded
  header: forwarded
  max_forwarded_hops: 2
proxies:
  - id: main
    listen: 127.0.0.1:8080
    trusted_proxies:
      - 127.0.0.1/32
    routes:
      - id: orders
        uri: http://127.0.0.1:9000
        predicates: [Path=/orders/**]
```

`acl.mode` 支持 `off`、`whitelist`、`blacklist`，缺省为 `off`。
白名单只允许匹配地址，空白名单拒绝全部；黑名单拒绝匹配地址，空黑名单放行。
`entries` 最多 4096 项，每项最多 128 字节，支持精确 IPv4、IPv6 和 CIDR。
配置构建时完整解析、排序并去重，非法条目拒绝整个候选，保留活动快照。
IPv4 与对应的 IPv4-mapped IPv6 视为同一来源；普通 IPv6 网段不隐式授予 IPv4 权限。

显式 `client_ip_policy` 的缺省模式是 `socket_addr`，忽略两种来源头。
`forwarded` 模式只在直连前置位于当前 HTTP 入口的 `trusted_proxies` 时解析；
不可信直连提供的头不参与来源判断。经可信 PROXY protocol 得到的来源直接作为权威，
不再由 HTTP 来源头覆盖。TCP 使用该协议确定的真实来源，UDP 使用数据报对端地址。

`header` 只能选择 `x_forwarded_for`（缺省）或 `forwarded`；不会从另一种头回退取值。
从右向左跳过可信前置，取首个非可信地址。`max_forwarded_hops` 为完整来源链元素上限，
范围 1–64，缺省 64。可信前置缺少选定头、链中没有非可信客户端、头格式错误、元素不具备
字面 IP 或超过上限时，HTTP 返回 400，不以代理地址代替客户端继续执行。
`Forwarded` 支持多行、引号、带端口的 IPv4 与 IPv6；重复参数及歧义值被拒绝。

ACL、按 IP 限流、动态封禁、审计与上游来源头共用一次确定的客户端地址。
显式策略保留原始头供业务鉴权验签；正常上游转发前移除原始 `Forwarded` 与
`X-Forwarded-For`，按已确定来源生成 `X-Forwarded-For` 和 `X-Real-IP`。
路由配置中显式设置头的操作仍按其声明执行，不能把它解释为新的客户端来源权威。

任何非 null 的 `acl` 或 `client_ip_policy` 声明，包括空对象和 `mode: off`，
均要求 `schema_version: 2`。省略或设为 null 表示未声明该项。
只支持配置 schema 1 的制品将拒绝整个候选，避免忽略安全声明后继续服务；混合制品集群
须先核对全部原目标的预检结果。没有这两个声明的既有配置保留原来的可信 XFF 解析行为；
移除 `client_ip_policy` 会恢复该兼容行为，明确关闭来源头解析须配置 `mode: socket_addr`。
当前 xDS server 的 `http_routing` 投影不支持这两种根声明，组合配置会拒绝，避免下游丢失保护。

动态 IP / CIDR 封禁在 HTTP、TCP 与 UDP 共用同一缓存，命中时独立复验到期时间。
管理写入使用规范地址键；单地址撤销同时清理既有 IPv4 映射地址键，不删除重叠的独立 CIDR。
相关键的删除不构成跨键事务，失败时前面的删除可能已经提交，须核对当前事实后再处理。
UDP 在复用会话前也检查当前门禁。手工封禁会向本机匹配连接发出关闭信号；从共享事实源
完成同步的新封禁也会关闭本机既有受控连接，包括 TCP、UDP、WebSocket 与 gRPC 长流。
共享存储的写入确认不表示所有读者已经观察到新值；尤其 Nacos 的订阅更新可能晚于写入响应。
需要确认生效时，应核对目标节点的当前事实或业务入口行为。
信号覆盖 stream 握手、拨号和转发等待；关闭结果表示信号数量，不是对端确认。
长连接先登记再复验当前封禁，握手或响应头迟到的请求也不能错过已经结束的封禁扫描。
静态 ACL 热更约束新 TCP 连接和后续 UDP 报文；已有 TCP 会话需要显式关闭或按配置换版 drain。

管理台的全局 IP 策略对象提供兼容门、ACL 和来源策略的字段编辑；可信前置在各 HTTP
入口对象中编辑。生成候选不等于发布，全部修改仍须共享提案审批和各原目标完整预检。
