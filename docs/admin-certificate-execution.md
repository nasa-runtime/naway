# 集群证书材料执行

材料执行将已批准的证书与私钥交付到全部原节点，先完成整批准备，再逐节点应用。节点先持久
文件方向，只有全部原来源、逻辑目标和实际监听协议到达预分配材料代后，才生成稳定安装收据。
多个 Admin 共用同一 PostgreSQL 任务与 NASA 工作流，断线或切换入口后按原身份恢复。

执行使用独立的材料签名域、永久调度存储身份和水位。配置动作与材料动作仍互斥占用同一节点，
不能同时改写配置和证书。原目标包含离线或失败节点，不会按当前在线子集缩小。
本功能不签发证书、不判断客户端是否信任新证书，也不接管 ACME、SDS、SPIRE 或外部 signer。
文件材料必须已受管，完整来源关系和全部共享 TLS 策略必须能够证明。

## 启用与初始化

发行方使用 `admin` 或 `all-in-one`，制品同时启用 `node-actions` 和
`admin-operations-workflow-pgsql`。先配置[材料存储](admin-certificate-proposals.md)与
[完整影响审批](admin-certificate-impact.md)，完成其显式迁移及集群绑定。
当前认证、RBAC、可信管理发行身份以及启用 `fsync` 的管理审计都必须有效。

在相同 operations namespace 中启用工作流；初始化期间先保持材料执行关闭：

```yaml
admin:
  operations:
    workflow:
      enabled: true
    execution:
      enabled: false
    certificates:
      execution:
        enabled: false
```

显式安装工作流结构，不启动业务监听：

```sh
naway --config /data/naway/naway.yml --admin-operations-workflow-migrate admin
```

随后将 `admin.operations.certificates.execution.enabled` 设为 `true`，再安装材料执行结构：

```sh
naway --config /data/naway/naway.yml --admin-operations-migrate admin
```

普通启动只检查已有迁移和实际 catalog；不会自动创建、接管或重新初始化结构。材料执行结构
绑定原材料、影响审批、配置投递和工作流合同。即使关闭执行，已有结构仍须通过完整检查。

每个实际目标使用 `node-actions` 制品、已初始化的私有节点 journal、本地文件配置和可信管理
mTLS；需要 HTTP/3 的节点还须启用 `http3`。目标单独启用：

```yaml
admin:
  management:
    reporter:
      material_previews: true
      material_actions: true
```

`material_previews` 供完整影响登记预检，`material_actions` 供持久命令接收，均默认关闭。
目标无需 PostgreSQL 或材料加密钥环。all-in-one 使用相同节点合同，以原生对象执行本机任务。
`reporter.actions` 和 `admin.operations.execution.enabled` 只控制配置动作，可以保持关闭。
注册中心、配置中心不授予材料执行权。

在已安装材料执行结构的入口，执行开关可热关闭或恢复。关闭后停止新的发行与推进，不删除原
任务、已提交文件方向、未知受理或清理责任，也不自动回滚。保持材料读取功能与当前权限时，
关闭执行的 Admin 仍可查询完整原任务。

## 明确提交原批准

先读取 `GET /api/certificate-proposals/execution-context`。工作区请求只附加
`?workspace={id}`。返回的 `execution_supported`、`execution_enabled`、`execution_ready`
分别说明制品支持、独立开关和当前发行资格；`can_request_execution` 还要求当前请求者有 Write。
`full_impact_approval_required` 为 true，旧 pair-only 批准不能单独执行。

原材料与唯一完整影响都必须已经批准，首次执行时仍在原期限内。材料创建者、材料审阅者、
影响登记者和影响审阅者都须保有当前相应权限，完整对象归属和全部原节点基线必须一致。
平台仍需材料提案、证书和集群权限，工作区只使用本域成员与完整共享对象归属。

向 `POST /api/certificate-proposals/{proposal_id}/execution` 发送 JSON：

```json
{
  "impact_id": "原完整影响的32位身份",
  "impact_sha256": "原完整影响的64位摘要"
}
```

正文不接受替代材料、目标、路径、批次或新的幂等键；重复与未知字段均拒绝。服务器先记录
持久尝试审计，再复验原认证密文与完整批准。解密在共享事务之外执行且使用有界许可。
创建事务一起保存原任务、全部原节点、两份父批准的保留责任、互斥节点槽及 NASA 首步。
数据库等待后再次检查期限和当前权威，任何一项失败都不能留下半份任务。

成功响应提供 `cluster_id`、`scope`、`proposal_id`、`operation_id`、`impact_id` 和 `created`。
同一原批准重复提交返回原任务，`created` 为 false；不新增工作流、不更新原目标，也不重新
延长批准期限。已经创建的任务保留原责任，父批准过期本身不会删除或替换它。

遇到 `outcome_unknown`、连接中断或完成审计失败，应读取同一提案的 `/execution`，并仅以同一
`impact_id` 和摘要重试。暂时查不到任务不能证明在途事务已经回滚，不能创建替代提案绕过未知结果。
其它 Admin 可读取同一共享事实；已创建任务的原身份重放不要求重新解密候选。

## 准备、应用与补偿

每个任务至多128个逻辑目标，物理节点单独编号。每节点先冻结原配置、完整来源计划、全部目标
协议和新的材料代，同一来源只保留一份备份；元数据及后继收据空间在首次受理前一起预留。
秘密使用私有固定槽，候选最多1 MiB加帧头、单来源备份最多8 MiB加帧头、全部保留最多32 MiB。
同一共享存储至多16个活动材料任务，单个 Admin 的候选缓存也受16份容量限制。

全部节点准备完成后，NASA 才开始应用。文件前复验当前四主体、原配置、来源、有限窗口及
持久水位，先提交整批方向，再执行原来源变更。实际 HTTPS、HTTP/3、L4 TLS 的完整安装观察
必须与预分配代一致；文件已写入、进程已重启或收到网络响应都不能代替该证据。

失败后的条件补偿使用原备份与全批新分配的补偿代，不能复用旧材料代。补偿成功仍保留原正向
未知受理，不会改写为正向成功或“从未执行”。节点配置、来源或控制权无法证明时保留保护责任，
拒绝进一步写入；没有无条件覆盖或强制成功接口。

启动先解释唯一 head：未决定文件方向的准备失去继续正向应用资格；已提交的应用或补偿只沿
原方向恢复，随后正常构建监听。保护态、损坏记录及不含执行计划的旧保留格式拒绝开放业务监听。
原会话与签名过期不会变成新写权；后续命令仍需新的合法发行授权。

完整节点报告与 NASA 结果在同一共享事务保存，明确提交后才确认接收。缺完整监听证据时保存
原未决事实，不提前确认业务成功。网络确认丢失可重投同一事实；旧序号、替换收据或删减原受理
均拒绝。当前共享投递使用同一有界扫描器，暂不可投递的前序事件可能延迟其它任务。

## 查询、终态与保留

`GET /api/certificate-proposals/{proposal_id}/execution` 返回同一只读数据库快照中的任务、
全部原节点和工作流步骤；未开始时 `execution_started` 为 false、`execution` 为 null。
读取只需要当前完整范围的读权，不要求旧审阅者继续有写权，也不读取原私钥或依赖旧加密钥。

任务状态分别显示：

- `target_count` 是原逻辑目标数，`node_count` 是原物理节点数；`reported_count` 与
  `released_count` 分别统计完整报告与已确认释放，不能混为进度百分比。
- 每个节点保留原 boot、原选取目标与完整来源；`reported: false` 明确表示没有持久报告。
- `stage`、`direction`、`protection` 是原节点持久事实；`required_protocols` 与 `generations`
  保留完整协议分母及预分配材料代。
- `effects` 分别显示准备/应用的正向与补偿四个效果。`unconfirmed`、`admitted`、`succeeded`、
  `rejected`、`halted` 和 `not_admitted` 具有不同含义，实际安装证据只附着于原稳定收据。
- `business_status`、`control_state`、`current_step` 与 `steps` 来自同一 NASA 原定义；
  `lifecycle` 区分运行、释放、停止和完整关闭，业务完成不等于秘密已释放。

NASA 终态与所有原节点证据一致后，独立释放命令先持久清理责任，再精确删除原秘密槽并关闭
节点代际；永久材料 store 与最高水位保留。节点已经关闭而共享确认丢失时，原释放游标继续恢复。
两份父批准继续保留，只有全部节点释放、原受理代关闭并到达共同保留期限后，任务、节点、两份
批准及各自收据才在同一事务删除。任一删除失败保留整批，不以关闭功能开关代替回收。

响应使用 `Cache-Control: no-store`，仅交付公开来源与实际观察，不包含秘密帧摘要、文件位置、
备份内容或可重放命令。完整状态输出最多约20 MiB，超过容量整体拒绝，不截断原节点分母。
