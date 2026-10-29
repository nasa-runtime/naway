# 结构化候选编辑

`POST /api/operations/proposals/draft?domain=gateway` 对调用者提交的候选原文进行对象编辑。
它要求启用持久管理提案、当前范围的读取和写入权限，以及 `Content-Type: application/json`。
`domain` 可选 `gateway`、`sentinel`、`interface-guard`；工作区请求另带 `workspace`。
独立 Data 不提供该入口。

编辑只改变响应中的候选，不读取节点配置、保存提案、批准变更或发布路由。结果应继续通过
[持久管理提案](admin-operations.md)保存，并由冻结的各原目标执行预检和应用。
接入 Admin 的编辑成功不代表其它节点已经接受配置。

服务端使用 NAML 读取原始 YAML，不执行环境插值、profile、imports 或 SecretSource。
编辑范围是文档中的显式声明；profile 或导入内容对运行配置的影响，仍由目标完整构建器验证。
候选、字段和结果只驻留本次请求，响应使用 `no-store`。输入不应包含无需编辑的秘密明文。

每个请求包含 `candidate` 原文字符串和 `action`：

```json
{
  "candidate": "schema_version: 1\nroutes: [{id: orders, uri: 'lb://orders', order: 0}]\n",
  "action": {
    "type": "patch",
    "object": { "kind": "route", "proxy": "default", "id": "orders" },
    "fields": { "order": 10, "request_timeout_ms": 3000 },
    "remove": ["backend_request_timeout_ms"]
  }
}
```

支持的动作如下：

| `type` | 其它字段 | 结果 |
|---|---|---|
| `inspect` | 可选 `object` | 有限对象目录；选择对象时返回其原始字段 |
| `patch` | `object`、`fields`、可选 `remove` | 设置完整字段值，明确移除指定字段 |
| `create` | `object`、`fields` | 在所属集合中新建一个对象，重复身份返回冲突 |
| `delete` | `object` | 只删除指定声明，引用关系留待目标预检验证 |

`null` 是实际字段值，移除覆盖应使用 `remove`。同一字段不能同时设置和移除，`id` 不能通过
字段编辑改名。新对象的稳定身份由 `object` 提供，`fields` 不含 `id`。其它未修改字段保持原值。
有变化时会重新编码 YAML，原注释、锚点和排版不保留；没有实际变化时返回完全相同的原文字节。

对象使用独立字段定位，名称中的斜线或点号不会被解释为路径：

| 领域 | `object` |
|---|---|
| Gateway 路由 | `{"kind":"route","proxy":"入口 id","id":"路由 id"}` |
| Gateway HTTP 入口 | `{"kind":"proxy","id":"入口 id"}` |
| Gateway 具名服务 | `{"kind":"service","name":"服务名"}` |
| Gateway stream 入口 | `{"kind":"stream","id":"入口 id"}` |
| Sentinel 流控 | `{"kind":"flow","id":"规则 id"}` |
| Sentinel 熔断 | `{"kind":"degrade","id":"规则 id"}` |
| 接口守卫 | `{"kind":"interface_rule","id":"规则 id"}` |

根级单入口 `routes` 的入口身份是 `default`。显式多入口下新增路由必须引用已有入口；不能通过
路由操作创建另一个监听器。重复身份、同时声明非空根路由和显式入口路由、集合类型错误均拒绝。

成功结果包含共享 `cluster_id`、授权 `scope`、所选 `domain`、`schema_version: 1`、
`validation: declaration_only`、`published: false` 与原文 `base_sha256`。
`scope` 为 `platform` 或 `workspace.<工作区名>`，不表示目标节点已验证。读取返回
`objects`、`selected`、`fields`；编辑返回 `changed`、
`candidate` 与 `candidate_sha256`。这些摘要用于核对原文，不授予节点动作权限。
调用方必须在页面范围、输入或权限变化后丢弃旧结果。

单候选沿用提案容量，最多 1024 个显式对象，身份最多 256 字节，一次设置和移除合计最多
128 个字段，JSON 响应上限 4 MiB。处理与完整候选共用每 Admin 两个任务名额，取消等待不会
提前释放真实工作单元。非法输入返回 `400`，无权限为 `403`，对象不存在为 `404`，身份重复或
请求期间权限快照变化为 `409`，输出容量不足为 `429`，候选任务忙碌为 `503`。所有失败均不发布
配置，错误不会回显原文或底层解析错误链。

## 管理页面

共享提案页在“候选 YAML”下提供“按对象编辑候选”。先读取原文中的对象目录，再选择对象读取字段。
对象选择包含类型、父入口与名称，名称中的斜线或点不作为路径。路由、HTTP 入口、上游服务、
流协议监听、Sentinel 流控和降级提供常用字段控件；其它已声明字段可展开单独编辑，新增字段
以 JSON 值明确输入。接口守卫规则可编辑启用状态及原始匹配、响应声明。

字段缺省保持原声明；只有选择“设置值”或“移除声明”的键才参与生成候选。布尔 false、空串、
JSON null 与移除互不等价。每行一项的列表保留行顺序及重复项，不自动裁剪。浏览器不能精确
表示的整数拒绝通过字段控件写入，应使用原始 YAML 输入。复杂字段作为完整值替换，编辑时
需要保留该字段内部仍需要的属性。

“新增对象”要求显式身份；新增路由还须填写所属 HTTP 入口，根单入口使用 default。删除对象
需要勾选确认，删除父对象同时删除其子声明。所有动作仅生成候选，不自动保存或执行。提案
目标和有效期不会随草稿编辑改变。保存后的原文仍须由另一主体审阅；执行按全部原目标的
完整基线、当前权限与独立开关校验。

页面不将草稿存入浏览器持久存储。原文变化、范围切换、页面隐藏或退出会撤下字段；权限
拒绝还会清空输入并关闭写入控件。响应须匹配原集群、领域、范围和完整源摘要，修改结果
还须匹配完整候选摘要，任何迟到或不一致的结果均不回填。
