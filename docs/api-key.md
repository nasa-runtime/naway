# API-Key 验证与撤销

路由的 `api_key` 策略从固定请求头或 query 参数验证凭据。可以通过 `value` 引用 SecretSource，
或通过 `sha256` 提供64个 ASCII 十六进制字符的摘要。验证成功后才形成声明的 `consumer` 和
API-Key 计额身份，客户端自行提交的消费者头不能代替认证。

```yaml
routes:
  - id: orders
    uri: lb://orders
    predicates: ["Path=/orders/**"]
    filters:
      - "api_key header=X-Api-Key value=env://ORDERS_OLD_KEY consumer=orders-client enabled=false"
      - "api_key header=X-Api-Key value=env://ORDERS_NEW_KEY consumer=orders-client"
```

`enabled` 默认 `true`。设置为 `false` 后，该凭据不再匹配任何请求，也不产生消费者或计额身份，
但仍保留路由上的 API-Key 认证要求。全部 API-Key 都被禁用时，API-Key 认证仍失败，不能变成
匿名入口。其它认证方式继续遵循当前 `satisfy` 配置；例如 `satisfy any` 仍可接受合法 Basic 凭据。

轮换时先部署新旧两条启用策略，确认客户端使用新密钥后，再禁用旧策略。多条 API-Key 之间为
“任一匹配即可”，不会要求一个请求同时携带新旧密钥。禁用最后一把密钥应保留该禁用声明；
删除全部 API-Key 声明表示移除这一认证方式，与撤销凭据含义不同。

禁用条目仍经过完整配置校验，包括来源、消费者和校验材料；SecretSource 继续按正常构建流程
解析。使用 `sha256` 的管理生成凭据不需要保存原始密钥或解析外部秘密。来源只能声明一次，
`header` 与 `query` 互斥；`value`、`key`、`secret` 是同一参数的别名，不能重复或与 `sha256`
混用。`consumer`、`sha256`、`enabled` 也不允许重复；非法候选不会替换当前有效配置。

具备消费者读取权限的本机管理接口 `GET /api/consumers/{consumer}/keys` 返回每条绑定的
`enabled` 状态、路由与来源，不返回原始密钥或其校验摘要。该接口只代表接入节点，不能用于
证明其它集群节点已经完成撤销。

撤销在各节点成功发布新配置后生效，集群发布应核对全部原目标的执行收据。尚未生效、不可达或
状态未知的节点不能视作已撤销。该状态不主动关闭已经建立的长连接，也不替代连接排空操作。

共享提案页的路由密钥面板支持浏览器生成原值、仅提交摘要、显式禁用与重新启用，并拒绝删除最后一条认证声明。详见[路由密钥草稿](admin-draft-editing.md#路由密钥)。发布仍通过原目标完整预览、独立审批和持久执行。
