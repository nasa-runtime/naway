# 封禁操作通知

通知将网关已经确认的单个封禁或解封操作交给业务系统。动态存储仍是当前封禁状态的权威，
通知没有跨节点全局顺序，也不证明收到消息时地址仍被封禁。TTL到期由数据面逐次命中检查，
不会依赖业务消费成功或收到一条额外解封消息。

省略 `runtime_state.blacklist.notifications` 时使用原 `DynamicStore.watch()`。
显式通知声明要求主配置 `schema_version: 4` 且启用黑名单；不能识别该合同的旧制品拒绝配置。
自动封禁的来源与范围见[客户端来源与封禁策略](ip-access-policy.md)。

## 原操作与默认总线

执行动作的节点先分配事件身份，将封禁事件作为事实值的 `notification` 字段一起写入。
事实写入确认后才记录审计和受理外发。其它节点观察共享变更、重建缓存和关闭仍被封禁的连接，
不会再次外发同一操作。手工动作使用已认证管理主体，自动动作使用固定 `gateway` 主体及实际原生拒绝来源。

写入提示的 `DynamicStoreChange.notification` 是可选JSON对象；缺失时须重读事实。
文件系统提示可能重复或不携带对象，Nacos提示来自完整快照差异；它们都没有持久消费游标。
Redis的固定通道为 `{store.redis.prefix}:{blacklist.collection}:events`，消息仍为NASA Stream的
`topic/data`信封，领域对象位于 `data.notification`。业务选择独立消费组，不能与网关缓存观察者竞争游标。
Redis XADD消息ID与领域 `event_id` 各自保留，不能互相替代。

`Event::from_change` 检查接收业务固定的集合、Put类型、事实键与规范IP，再读取原封禁事件。
Delete和普通失效提示返回 `None`，不把已删值中的旧封禁事件变成新操作。
业务直接修改存储时由该业务承担写入权限和审计；网关不会把外部写入冒充本机管理主体。

事件JSON使用当前 `schema_version: 1`，包含：

| 字段 | 含义 |
| --- | --- |
| `event_id` | 随机128位发送实例域与该实例的Snowflake序号，以冒号连接；消费去重使用整串 |
| `timestamp_unix_ms` | 原操作创建时间的规范十进制文本 |
| `action` | `ban` 或 `unban` |
| `ip` | 规范IPv4或IPv6文本，IPv4映射IPv6归一为IPv4 |
| `actor` | 实际管理主体或固定网关动作主体 |
| `source` | `admin`、`auto_limit_req`、`auto_waf`、`auto_authentication`、`auto_abnormal` |
| `expire_at_unix_ms` | 临时封禁原事实的绝对期限文本；永久封禁和解封省略 |

事件最多2048字节。单机Snowflake不承担实例间协调或重启时间上界；随机实例域防止不同发送实例复用消费身份。
重试不改变原事件身份、时间、期限或正文。事件不是请求日志，不包含原请求正文、Cookie或认证材料。

## 固定外发出口

外发计划属于平台快照，不接收业务请求提供的URL、主题或broker地址。一个进程最多一个投递worker，
队列固定128项，同时执行一个事件。配置提交先撤销旧计划；旧队列和重试不能转交新出口。
已经被远端收到的字节无法追撤，接收业务必须按原事件身份去重。

```yaml
schema_version: 4
runtime_state:
  blacklist:
    enabled: true
    notifications:
      attempts: 3
      timeout_ms: 2000
      retry_delay_ms: 250
      max_age_ms: 60000
      transport:
        kind: webhook
        url: https://business.example/acl-events
        signing_key: file://acl-notify.key
        tls:
          ca_pem: file://business-ca.pem
```

`attempts` 为1至8；`timeout_ms`为50至10000；`retry_delay_ms`为1至5000；`max_age_ms`为1000至300000，
且至少覆盖一次尝试。队列等待、网络等待和退避都消耗原事件的总年龄。重试退避逐次加倍，最多5秒。
满队列、过期、配置撤销和投递失败不撤销已经提交的封禁，也不重新执行整个管理动作。

HTTPS使用系统信任根；声明 `tls.ca_pem` 时只信任该材料。可同时提供
`tls.client_cert_pem`、`tls.client_key_pem`配置客户端身份，两者必须成对出现。
这些字段与签名秘密均使用SecretSource，文件轮换进入正常候选指纹与观察链。
明文HTTP必须明确 `allow_plaintext: true`，且不得同时声明不会生效的TLS材料。
客户端不跟随重定向或环境代理，不读取响应正文；只有HTTP 2xx确认本次投递。

## Webhook验签与消费

POST正文为完整事件JSON，三个请求头是 `x-naway-acl-event-id`、`x-naway-acl-timestamp`、
`x-naway-acl-signature`。投递时间使用规范Unix毫秒文本；签名为至少32字节共享秘密生成的小写十六进制HMAC-SHA256。
签名输入依次为 `naway.acl.v1`、投递时间、完整事件ID、原始UTF-8正文，段之间只有一个LF，末尾不额外加LF。
同一事件重试可更新投递时间，原正文保持不变。

接收方先按原字节调用 `verify_webhook`，验证协议、身份一致性、签名及投递时间的5秒偏差，
再调用所得 `VerifiedEvent::admit`。不得重新序列化正文后验签，也不能先让未验签的ID占用消费键。
来自受认证broker或受管存储的消息可使用 `VerifiedEvent::from_trusted_transport`，来源认证仍由业务承担。

消费域 `scope` 必须是接收业务固定配置的独立名称。原事件有效窗为1至300个整秒，重试不能续期。
`admit`使用严格ReplayGuard登记；只有 `Admission::First` 交付事件。
`NotAdmitted`也可能表示容量、依赖或严格合同不可用，不能断言消息已经处理。
本地ReplayGuard只保证本进程去重，共享Redis后端提供跨接收实例的原子登记。

去重登记与业务数据库副作用不是一个事务：登记后崩溃可能留下未完成业务，登记过期或本地账本重建也有自己的边界。
需要可恢复消费时，业务须以完整事件ID建立事务收件箱，将业务副作用和处理记录一起提交。
通知出口不提供端到端exactly-once。

## Kafka与RocketMQ

Kafka出口要求 `acl-kafka` 制品特性，`transport.kind: kafka`，并显式给出 `bootstrap_servers`、`topic`。
端点最多8个，主题为1至128字节ASCII字母、数字、点、下划线或连字符，不能为 `.` 或 `..`。
默认SSL；本地明文部署需明确 `allow_plaintext: true`，不能同时声明TLS材料。
可选 `sasl` 包含 `mechanism`、`username`、`password`，机制支持 `PLAIN`、`SCRAM-SHA-256`、`SCRAM-SHA-512`；
用户名与口令使用SecretSource。TLS材料字段与webhook相同。

Kafka载荷是原事件JSON，分区键为完整事件ID，事件头为 `gateway.acl`。
生产者使用NASA的幂等与顺序合同，内部消息和观察槽最多128，消息预算512KiB；内部重试仍受单次投递期限限制。
旧生产者须在有界shutdown确认后才能换用新客户端，停止失败将关闭本进程通知worker，需重启恢复外发。

RocketMQ出口要求 `acl-rocketmq` 制品特性，`transport.kind: rocketmq`，并提供固定Proxy的
`endpoint`与 `topic`，可选 `namespace`。Endpoint只允许HTTPS authority，不携带业务路径、query、userinfo或fragment；
本地明文部署同样需要显式允许。TLS材料字段与webhook相同。
可选 `access_key`、`secret_key`使用SecretSource且必须成对出现，按MQv2-HMAC-SHA1合同生成每次RPC认证。

RocketMQ桥接使用 [apache.rocketmq.v2普通消息协议](https://github.com/apache/rocketmq-apis/tree/v2.1.2)：
先QueryRoute确认原主题的普通消息可写leader队列，再向同一个固定Proxy执行SendMessage。
不会跟随响应中的其它broker地址。总状态和唯一消息回执均须为OK，部分失败、缺失回执或非法路由不确认成功。
MQ消息ID为完整事件身份的128位摘要域编码，完整 `event_id`仍保存在正文、消息属性和业务key中，消费去重使用完整ID。
此出口不建立消费、事务、延迟、FIFO或长期遥测会话。

## 确认边界与观测

事实写入与Redis Stream提示、进程内外发队列不是同一事务。进程在事实确认后、入队前退出，
队列满、配置撤销或网络结果未知都可能留下通知缺口；外发没有独立持久Outbox，也不会无限重试。
业务以事实源对账当前状态，不能把通知顺序或审计环形缓冲当作完整操作历史。

`GET /admin/blacklist/audit`同时返回有限本机审计和 `notifications`观测：当前传输、队列容量与占用，
以及 `submitted`、`delivered`、`failed`、`revoked`、`expired`、`full`累计文本计数和worker/队列状态。
计数只属于当前进程；`delivered`表示出口确认，不能代替业务处理或事务提交收据。
