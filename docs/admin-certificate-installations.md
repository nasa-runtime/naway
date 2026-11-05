# 集群证书实际安装观察

`POST /api/certificate-installations` 查询原目标监听器实际加载的完整证书材料代。任一有管理发行
能力的 Admin 可查询多个 Data 或 all-in-one 节点，返回全部原目标及失败结果。查询只保留当前
事实，没有历史，不写证书，不登记任务，不生成持久执行收据。

证书文件已经写入，并不意味着 HTTPS、HTTP/3 和 stream TLS 都已经换入相同材料。公开叶证书
相同也不能证明完整证书链、私钥或材料代相同。安装观察把本轮文件条件和实际监听器加载事实
分别返回；相同字节重新安装仍产生新的材料代，只有各协议实际加载新代之后才记为当前安装。

## 部署与开关

目标节点启用 `node-actions`，配置受信管理发行者、mTLS、认证 RBAC、本地文件配置和匹配节点
身份的持久 journal，并明确打开：

```yaml
admin:
  management:
    enabled: true
    reporter:
      material_installations: true
```

`material_installations` 默认关闭，独立于 `material_previews`、配置 `previews`、执行 `actions`、
材料提案和影响审批。开启安装查询不启用这些能力；纯 Data 不需要 PostgreSQL 或材料加密钥环。
管理发行者、节点 journal 和凭据的部署要求见[集群证书目录](admin-certificates.md)。未声明
安装观察能力的节点返回 `unsupported`，关闭开关返回 `disabled`，均保留在原目标分母中。

## 请求与授权

请求正文与[原目标批量材料条件查询](admin-certificates.md#集群原目标材料条件)使用同一格式：
`targets` 中逐项提供 `node_id`、`boot_id`、`base_version`、`base_fingerprint`、
`node_baseline` 及 `target`。`target` 使用 `kind`、`listener`、`entry` 精确标识默认或 SNI
声明。最多 128 个原目标，正文最多 128 KiB；不接受文件路径、客户端安装证明或替补节点。

平台请求使用 `/api/certificate-installations`；工作区请求使用
`/api/certificate-installations?workspace=<workspace>`。平台读取需要材料域读取权；工作区
还须满足当前成员和对象归属。任何共享来源的受影响对象越界，整个节点拒绝，不能省略其它
工作区的影响后返回安装成功。查询期间权限、配置、启动身份、节点存储或受理代变化会撤下
原成功结果。请求只能通过 Admin 或 all-in-one 入口发行。

## 响应含义

响应使用 `Cache-Control: no-store`，保留 `target_count`、`complete_count`、原节点 `indices`
及 `targets`。`execution_supported` 固定为 `false`。

- `complete_count`：已取得完整观察的原目标数。观察完整可以包含未受管、旧材料或尚未安装状态。
- `installed_count`：所属完整共享来源的每个受影响目标、每个必需协议均为 `current` 的原目标数。
- `nodes[].conditions`：同次观察的完整文件条件和共享影响，与原条件查询使用同一原生合同。
- `nodes[].installations.groups[i].targets[j].protocols`：严格对应
  `conditions.groups[i].affected[j]` 的实际协议事实，不再复制目标关系。

代理入口必须有 `https`，启用 HTTP/3 时还必须有 `http3`；stream 入口使用 `stream_tls`。
每项返回 `protocol`、`state`、`bindings` 和可选 `material_generation`。状态含义如下：

| 状态 | 含义 |
|---|---|
| `current` | 实际选中绑定的完整来源与材料代均等于本次文件条件 |
| `different_material` | 监听器实际加载了受管材料，但与本次文件条件中的材料代不同 |
| `unmanaged` | 实际加载的合法文件材料没有受管记录 |
| `unproven` | 已加载材料的归属缺失有效证明、与完整 pair 不符或来源不一致 |
| `external` | 外部 signer、SDS 或 SPIRE 提供的身份没有本机受管材料代 |
| `pending` | 对应协议缺席，或实际监听计划尚未追上当前完整配置 |
| `not_selected` | 当前 SNI 选择表不会命中该声明，不能以其它声明的证书代替 |
| `capacity` | 实际安装目录无法表达完整事实 |
| `unavailable` | 实际材料事实不可用，或必需的 OCSP 响应已经过期 |

只有 `current` 和 `different_material` 携带实际加载的材料代。若文件条件本身不能完整读取，
整节点返回 `unavailable` 状态和明确 `reason`，不会返回部分安装树。外部身份通常不能满足
本地文件条件查询的入口要求；`external` 只说明实际安装来源，不授予本地文件写入权。

SNI 使用实际选证顺序：同名精确绑定以后声明为准，通配绑定取首个匹配后缀。较早的宽后缀
完全覆盖后面的窄后缀时，被遮住的声明也返回 `not_selected`，不计安装完成。

## 一致性与容量

受管材料在唯一材料锁内读取完整 pair 和同源归属，随后释放锁再解析密码学身份；私钥缓冲
释放时清除。归属随实际 resolver 安装一起发布，SNI 别名共享同一原生证据。握手和普通请求
不读取文件、不计算管理摘要、不访问数据库。失去监听器所有权的 watcher 不能发布新事实。

合法外部换证仍可正常服务，但不会继承旧受管材料的所有权。元数据损坏可以使查询不可用，
不能凭磁盘元数据恢复就声称现有 resolver 已经加载新代。坏 pair 或不满足 TLS 策略的候选
继续保持原来的可用材料。

每节点附加观察最多保留 32 KiB 原生对象、256 个影响位置；协议编码预算为 7 KiB，与原文件
条件共同遵守已有 32 KiB 管理消息上限。任一预算不足整节点拒绝，不截断分母。网络边界移动
原生字段到 protobuf，HTTP 边界借用结果编码，不建立中间 JSON 树。

这是有限查询窗口内取得的安装快照。返回后文件、监听器或节点仍可能变化；当前事实不能作为
以后执行、补偿或审批的凭据，也不保证已有长连接已经切换证书。原公开证书目录不增加材料代
字段，目录摘要与原文件条件查询的签名和响应保持各自合同。
