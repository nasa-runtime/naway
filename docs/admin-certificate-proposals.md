# 加密证书材料提案

完整管理模式的多个 Admin 可以共用 PostgreSQL 保存和审阅证书材料。数据库保存 NASA NC2
认证密文，普通接口只返回公开证书摘要、有效期、固定目标和审阅状态；没有私钥下载接口。
入口独立于三个 YAML 文档的变更提案，不把证书正文放进配置候选或既有配置工作流。

材料受理、原请求查询、双人审阅和有限保留的成功响应均声明
`execution_supported: false`、`targets_validated: false`。材料通过证书链解析和叶证书与私钥匹配
检查，受理和批准本身不验证目标节点、完整 TLS 策略或实际监听安装；批准不会触发节点换证。
配置可信管理发行身份并启用目标的独立材料预检开关后，可发起[原提案目标预检](admin-certificates.md#原加密提案的目标预检)，
验证全部原目标的完整材料条件、共享对象权限和 TLS 策略。预检结果单独返回，仍不授予持久交付资格。
启用独立[完整影响审批](admin-certificate-impact.md)后，服务端可把全部目标成功的预检结果保存为
唯一不可变影响，并由同时不同于材料创建者和影响登记者的主体审阅。完整影响状态与原材料状态
分别保存，不会将旧批准自动升级为完整影响批准。
两份批准均成立后，可通过独立[材料执行入口](admin-certificate-execution.md)明确提交原完整影响；
执行能力、当前开关和发行就绪由 `execution-context` 单独查询，不能从 pair-only 响应推定。
管理端口的 `/certificate-proposals` 提供独立“证书材料”页面；`/certificates` 继续展示
[集群活动证书](admin-certificates.md)。两个页面的材料提交与实时安装观察分别授权。

## 使用材料管理页

登录完整管理入口后，选择平台或一个已授权工作区，读取材料节点，再逐项选择节点实际提供的
`default` 或 `sni-N` 声明。页面保留全部授权成员及不可用原因；目录过期后需要显式重新读取，
已选原目标不会自动换成当前在线节点。选择最多128个逻辑目标后，单独查询并冻结全部原材料
条件，核对原节点基线、公开 PEM ETag、受管材料代和每份来源的全部共享影响。

输入候选证书链、私钥和60至86400秒有效期，确认后保存材料提案。材料大小受当前服务器上限
约束，最大1 MiB。保存只完成加密受理；创建者不能批准自己的材料。材料审阅与完整影响审批
分别确认，完整影响审阅者还须不同于影响登记者。页面展示完整来源、全部受影响对象及摘要，
两份批准成立并且当前执行能力就绪后，才提供明确执行入口。

PEM 只在当前页面短期内存输入，提交时立即清空输入；隐藏、切换范围、退出或关闭页面也会
撤去输入和旧页面事实。页面不把 PEM 或请求正文写入浏览器持久存储，不提供秘密下载。
若请求超时、取消或响应丢失，仅保留原主体、集群、范围、受理代与幂等键等低敏身份供只读恢复，
不会自动重传正文或生成新键。刷新或关闭页面前应自行保存这些标识，在同一集群入口使用
“恢复原请求”；本次未找到不代表另一在途事务已经回滚。

原任务详情保留全部逻辑目标与物理节点、四项独立执行效果、原启动和实际观察启动、每个共享
对象的全部协议及实际材料代。补偿成功不会抹去正向受理未知的记录，任务完成还要求全部原节点
释放。页面只对正在运行或释放的原任务进行有界只读刷新；隐藏、退出或读取失败时停止刷新。
关闭新执行仍可读取已有原任务，完整影响功能缺席或当前权限不足时对应动作保持关闭。

## 选择原节点与材料目标

`GET /api/certificate-proposals/targets` 返回当前授权范围内的全部节点及明确可用性，
`GET /api/certificate-proposals/targets/{node_id}` 返回一个节点的原 boot、配置、journal 基线
和去重逻辑目标。工作区入口只附加 `?workspace={id}`，使用本域成员权限与精确对象归属；
无需借用平台监控权限。两个入口均要求材料存储已启用及当前材料读权，纯 Data 不开放。

目标以 `kind`、`listener`、`entry` 定位；`entry` 为 `default` 或原配置中的 `sni-N` 声明位置。
同一声明的多个 SNI 名称及 HTTPS/HTTP3 协议合并显示，名称、通配匹配次序和叶证书摘要都
不能用于推断声明编号。外部 signer、ACME、SDS、SPIRE 不提供可选材料写入目标。

节点清单最多128项，单节点最多2048条目录绑定，响应最多4 MiB。失联、目录超限、旧协议、
原基线缺失及工作区归属不一致分别保留不可用状态；失联节点仍在原成员分母内。未知节点
不会返回旧基线或可选目标。旧节点的活动证书目录仍可观察，但缺少目标引用证明时不能选择。

响应带 `Cache-Control: no-store` 和 `x-naway-sample-age-ms`。只有原观察年龄加请求耗时小于
6000毫秒时才可用于选择；采样中返回202，配置换代或过期返回409。客户端选择后仍必须调用
[完整材料条件查询](admin-certificates.md#集群原目标材料条件)，取得全部原目标的公开 PEM ETag、
受管材料代及共享来源关系，再冻结提案。目录本身不读取材料、采用未受管文件或授予执行权。

## 配置与初始化

制品需要 `admin-operations-pgsql`，使用 `admin` 或 `all-in-one` 模式，并启用管理认证、RBAC 和
`admin.operations`。纯 `data` 模式不启动材料存储。注册中心和配置中心不参与材料持久受理。

在现有 `admin.operations` 配置中增加：

```yaml
admin:
  operations:
    enabled: true
    cluster_id: production-gateway
    database_url: env://NAWAY_OPERATION_DB
    schema: naway_operations
    retention:
      enabled: true
      epoch_window_seconds: 900
      retain_seconds: 86400
      interval_seconds: 60
      batch_size: 32
    certificates:
      enabled: true
      accept_proposals: true
      write_key_id: material-main
      keys:
        material-main: env://NAWAY_MATERIAL_MAIN
      max_material_bytes: 1048576
      max_total_bytes: 67108864
      max_records: 4096
      max_records_per_scope: 256
```

首次初始化时，先完成[持久操作数据库配置](admin-operations.md)，暂设 `certificates.enabled: false`，
显式初始化基础结构并绑定唯一发行集群：

```sh
naway --config /data/naway/naway.yml --admin-operations-migrate admin
naway --config /data/naway/naway.yml --admin-operations-execution-bind admin
```

随后设 `certificates.enabled: true` 并配置合法钥环，再执行同一 `--admin-operations-migrate` 命令。
已有绑定的数据库可以直接启用材料功能后执行迁移。显式迁移安装完整前置结构和独立材料表；不会启动配置工作流或
节点执行器。普通启动只复验迁移和实际 catalog，结构缺失或漂移会拒绝就绪。
共享 schema 必须已绑定当前 `cluster_id`，不能由材料接口自动接管其它集群的存储。

`certificates.enabled` 默认关闭，关闭时不读取材料钥环、不登记材料 owner、不执行材料清理。
该开关是启动资源，修改需要重启；已有材料不会因关闭而删除。四项容量在材料存储首次登记时
持久固定，重启也不能改变既有存储的容量；当前不提供原地调整材料容量的操作。
`accept_proposals` 可热关闭新提案上传，读取及审阅仍可进行，原未知提交可以继续用 `resolve` 查询。
该开关独立于 YAML 提案的 `admin.operations.accept_proposals`。

## 密钥与容量

钥环最多八个 id，每个 id 最长64个 ASCII 字母、数字、点、横线或下划线。`write_key_id` 必须存在。
只接受 `env://`、`file://`、`k8s-file://`、`vault-agent://` SecretSource；不接受明文或 `literal://`。
解析后的秘密必须为32至1024字节，应使用独立随机高熵材料。配置文件只保存来源引用。

合法钥环和写钥选择可以热更。轮换时先让所有 Admin 同时持有旧钥和新钥，再切换写钥；原记录仍按
自己的 `key_id` 校验。删除旧钥前，应检查对应保留记录及处理责任；配置删除不会迁移或重新加密
原记录。缺钥时批准失败，公开查询、拒绝和创建者取消仍可使用。文件型来源变更通过配置依赖观察
重新构建快照，非法候选保留原生效配置。

材料 owner 保留数据库身份和容量，不永久持有启动钥环。请求使用当前获权快照；最后一个快照或
算法任务释放后清零其材料及解析密钥容器。算法、TLS 解析和协议库有各自分配，不能据此声称进程
中从未出现秘密副本。

单份证书与私钥合计最多一 MiB，最多128个目标、64 KiB目标元数据。全局记录最多4096条，每 scope
记录上限不得超过全局；全部保留容量最多64 MiB。数据库按最坏密文扩张、元数据及固定开销预留，
所有保留状态均占用容量。跨 Admin 在同一集群行锁内先检查预算，再运行加密，不能通过并发突破。
不同容量的进程不能共用同一材料 owner；现有 YAML 容量维护命令不会改变材料预算。

每个 Admin 最多两个实际阻塞加密任务，KDF 使用 NASA NC2 的固定有界参数。HTTP 取消后任务继续
持有许可直到算法结束；它不能自行提交数据库。算法失败、容量耗尽和数据库不可用均不改变运行中 TLS。

## 权限与范围

新增平台资源 `certificate-proposals`。内置 `admin` 拥有该资源，其它平台角色须显式声明 grant。
平台读取同时要求 `certificate-proposals/read`、`certs/read`、`cluster/read`；提交与审阅同时要求
相应三项 `write`，并保留读取资格。原创建者不能批准或拒绝自己的提案，只能取消。
材料提案使用独立授权摘要范围；新增材料权限不会改变既有配置提案、预览和执行的授权摘要。

工作区请求携带 `?workspace=<id>`，只通过当前成员动作权限授权，不持有平台 grant。完整目标必须
具有精确证书对象归属，且每个节点都在当前工作区的 `cluster_nodes` 内。归属必须匹配工作区、
租户和环境；HTTP 与 TCP 采用各自证书对象命名空间。
批准时重新检查原创建者与审阅者当前权限及冻结授权摘要。权限或归属变更后不能借旧提案跨越撤权。

## 提交、读取和审阅

先读取 `GET /api/certificate-proposals/context`，保存原 `admission_epoch`。向
`POST /api/certificate-proposals` 发送 `Content-Type: application/json` 和唯一
`Idempotency-Key`。正文含以下字段：

| 字段 | 含义 |
| --- | --- |
| `admission_epoch` | 最初取得的正受理代际，重试不得替换 |
| `ttl_seconds` | 60至86400秒的可审阅期限 |
| `certificate_pem` | 公开证书链 PEM |
| `private_key_pem` | 与叶证书匹配的本地私钥 PEM |
| `targets` | 完整原目标数组，不按在线情况缩小 |

每个目标包含 `node_id`、`boot_id`、`base_version`、16位小写 `base_fingerprint`、完整
`node_baseline`、`certificate_etag`、64位小写 `material_generation`，以及逻辑 `target`：

```json
{
  "kind": "proxy",
  "listener": "public-api",
  "entry": "default"
}
```

`kind` 为 `proxy` 或 `stream`；`entry` 为 `default` 或规范 `sni-0` 至 `sni-511`。SNI 序号只在
原配置代内有效。相同节点的多个目标必须具有同一 boot、配置和节点存储基线。不能声明任意文件路径。
`certificate_etag` 是完整 PEM 的强 ETag，不能拿活动目录的叶 DER 摘要代替；没有受管材料代的原始
文件不能用缺省值充当交付归属。本接口只保存这些声明，不证明它们来自目标节点。

相同主体、scope、受理代和原幂等键提交相同完整意图，会返回同一提案 id；材料、目标、期限或授权
不同会冲突。密文 AAD 同时绑定发行集群、随机持久存储身份、原代际、提案、key id、创建者、scope、
完整意图和创建/过期事实。不能把另一个提案或数据库中的密文搬入当前提案。

`GET /api/certificate-proposals` 支持 `after` 和1至100的 `limit`；单项为
`GET /api/certificate-proposals/{id}`。列表和单项只返回公开摘要与状态，均为 `Cache-Control: no-store`。

`POST /api/certificate-proposals/{id}/review` 接收：

```json
{
  "decision": "approve",
  "certificate_sha256": "<原记录的 certificate.certificate_sha256>"
}
```

`decision` 为 `approve`、`reject` 或 `cancel`。批准前按原钥解密认证并核对完整意图和公开摘要，
明文不会返回审批者。过期或已经审阅的状态不能覆盖。批准仍仅代表保存审阅事实。

## 失败与保留

提交出现 `outcome_unknown`、其它无法确认结果的错误或连接中断时，向任一同存储 Admin 的
`GET /api/certificate-proposals/resolve` 发送原 `Idempotency-Key`、`Naway-Admission-Epoch`，
并保持原主体和 scope。不要换键重新上传。一次查询未找到不证明另一个尚未结束的事务已经回滚。

未认证返回401，非法输入返回400，越权403，缺记录404，意图或状态冲突409，旧受理代410，容量耗尽429；存储、
密文认证或提交未知返回503和不同固定错误码。响应不包含 SQL、私钥、底层解析输入或秘密文件路径。

清理先持久关闭原受理代，再等待共同保留期。未开始交付且已拒绝、取消或过期的精确记录，其密文和
原幂等收据在同一事务删除；原收据不一致时保留整批事实。有交付或补偿责任的材料不得用普通过期清理
删除。功能关闭不删除密文，数据库故障不影响已经安装的业务监听器。
原材料已经登记完整影响时，影响记录及其独立幂等收据必须先在同一事务精确删除；父子原受理代
都关闭且共同保留门成立才释放空间。仅关闭影响审批不会解除这项已有保留责任。
