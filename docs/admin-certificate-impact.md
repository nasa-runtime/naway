# 完整证书影响审批

多个完整管理节点可以共享一份证书提案的完整来源影响，由独立主体确认全部原目标和共享监听。
影响记录来自服务端对原加密材料执行的真实目标预检；客户端不能上传替代证明、删除失败目标或
改变原候选。旧材料的 pair-only 批准与完整影响批准分别保存，两种批准都不会触发节点换证。

本功能只提供完整影响登记、查询、独立审阅与有限保留。`execution_supported` 始终为 false。
批准是对冻结对象的确认，不表示审批时节点状态仍保持不变；持久材料交付、监听收据、条件补偿
和材料管理表单尚未提供。当前证书页面仍展示集群活动证书。

## 开关与共享存储

发行节点使用 `admin` 或 `all-in-one` 模式，制品需要 `admin-operations-pgsql` 与 `node-actions`，
并已配置加密材料存储、可信管理发行身份及节点 journal。实际目标只需要 `node-actions`，
显式打开 `admin.management.reporter.material_previews`，不需要 PostgreSQL 或发行方材料钥环。

```yaml
admin:
  operations:
    certificates:
      impact_approvals:
        enabled: true
        accept_proposals: true
        max_records: 4096
        max_records_per_scope: 256
        max_total_bytes: 67108864
```

`enabled` 默认 false。首次启用须使用相同配置显式执行迁移，然后重启管理节点：

```bash
naway --config /path/naway.yml --admin-operations-migrate admin
```

普通启动不会创建或接管未知数据库结构。
影响记录与原材料共用明确绑定的 operations namespace，并拥有独立的随机存储身份和容量。
已有结构即使功能关闭也要复验实际 catalog，结构漂移拒绝启动。

`enabled` 与三项预算属于启动资源；预算首次登记后持久固定，重启也不能改变同一存储的预算。
记录数范围为1至4096，单范围预算为1至全局记录数；总字节预算最小4198400、最大67108864。
每份公开证明最多4 MiB，每条记录额外计入4096字节元数据，全部保留状态均占用共享预算。
多个 Admin 在同一数据库锁中裁决容量。原材料密文预算保持独立。

`accept_proposals` 可热更，只停止新的完整影响登记；原请求回放、读取和已有记录的明确审阅仍可使用。
原材料的 `accept_proposals` 和 YAML 提案受理开关不会关闭已有材料的影响登记。
关闭影响功能不注册新 owner、不开放影响接口，也不删除已有批准；材料功能与保留任务仍启用时，
既有父子共同保留责任继续执行。注册中心、配置中心不参与该合同。

## 服务端登记

先读取 `GET /api/certificate-proposals/impact-context`，保存返回的字符串 `admission_epoch`。
它同时提供当前独立受理开关、动作权限和容量。工作区入口只附加 `?workspace={id}`，不支持
其它查询参数。

向 `POST /api/certificate-proposals/{proposal_id}/impact` 发送：

```http
Content-Type: application/json
Idempotency-Key: original-impact-request
Naway-Admission-Epoch: 1

{}
```

原材料必须处于未过期的 `awaiting_approval` 或 `approved`，请求者和原材料创建者必须仍有
完整范围的 Write。服务端认证解密原候选一次，预检全部原节点的 boot、配置、持久文档基线、
完整 pair、受管材料代和全部共享来源 TLS 策略。任一目标缺席、超量、拒绝或无法证明都不登记。
材料与节点工作复用有界预检许可，不安装材料、不推进节点材料代。

每个材料提案只允许一份不可变影响。来源、目标或条件变化后，应明确创建新的材料提案并重新审批，
不能覆盖已展示或已批准的影响。相同主体、范围、原受理代和幂等键重试返回原记录，不重新解密
或驱动节点；同键不能改指另一提案。

登记最终持有当前配置发布权，重新认证并检查完整对象归属，然后依次锁定集群、影响 owner、
父材料。原记录状态、审阅人、更新时间、完整元数据与密文摘要仍须匹配最初标记。
原预检短窗口的单调时间预算一直保留到登记，不因数据库等待重新计时。影响与 NASA 幂等收据
在同一事务保存，超时或未知 COMMIT 不能被解释为未提交。

## 查询与独立审阅

`GET /api/certificate-proposals/{proposal_id}/impact` 返回唯一 `impact`，其中：

- `id` 与 `impact_sha256` 是审阅时必须明确确认的完整对象身份。
- `proof.targets` 保留全部原目标；`proof.nodes[].target_indices` 只引用该规范数组。
- 每个节点提供来源去重的 `conditions` 与节点影响摘要，`proof.certificate` 仅含公开新证书摘要。
- `status` 是影响自身状态，`material_status` 是当前父材料状态；`parent_active` 只说明父材料仍在
  可审阅生命周期内，不表示当前节点条件未变化或具有执行资格。
- `issued_at_ms`、`observed_until_ms` 描述原短期观察，持久保存不延长原下载令牌或节点权限。

普通读取不解密材料，当前权限必须覆盖全部原节点和完整共享影响。响应不包含路径、私钥、
材料帧摘要、内部授权摘要或下载接口，使用 `Cache-Control: no-store`。

`POST /api/certificate-proposals/{proposal_id}/impact/review` 接收：

```json
{
  "impact_id": "原记录中的32位身份",
  "impact_sha256": "原记录中的64位完整影响摘要",
  "decision": "approve"
}
```

`approve` 和 `reject` 需要当前 Review，且审阅者同时不同于原材料创建者和影响登记者；两名
创建者都必须仍有相同完整范围的 Write。`cancel` 只能由影响登记者持当前 Write 发起。
事务重新核对父材料、完整影响、冻结权限与期限，只允许影响的 `awaiting_approval` 迁移一次。
影响批准不覆盖父材料状态，也不继承旧 pair-only 审阅人的批准。

审阅确认服务端保存的完整观察，不重新采集并替换旧证明，也不重新解密材料。原父取消、拒绝、
过期或具有执行责任时不能继续审阅；当前权限与共享对象归属发生变化时拒绝状态转换。
实际材料执行仍须另行验证当前权威、原材料与全部来源条件，本功能尚未开放该执行链。

## 未知提交与联合保留

响应为 `outcome_unknown` 时，保留原身份调用
`GET /api/certificate-proposals/{proposal_id}/impact/resolve`，发送原 `Idempotency-Key` 与
`Naway-Admission-Epoch`。其它 Admin 可查询同一共享事实。暂时404不证明仍在途的原事务已经回滚，
不要改用新键创建替代操作。

影响有效期跟随父材料，不能独立延长。共同保留任务仅在父材料及影响原受理代都已关闭、原材料
到达共同保留期限且没有执行责任后，在同一事务精确删除影响及其收据、父材料及其收据。
任何收据缺失、仍在途或引用责任不成立都保留整批。批准不触发清理，关闭受理或审批开关也不
自动腾挪空间。

来源关系采用共享原生结构校验，完整摘要直接逐字段增量计算；只在实际存储和 HTTP 边界各编码
一次，不构造中间 JSON 树。公开证明的4 MiB上限与固定元数据组成有限 HTTP 输出预算。
