# 本地开发与外部服务测试

本文只描述公开、可复用的本地环境接入方式，不保存任何真实密码、令牌、内网地址或生产数据。
本地凭据应通过环境变量或未提交的 `.env.local` 注入。提交代码前必须确认日志、配置和测试夹具
中不存在敏感信息。

## 基础环境

- Rust 使用当前稳定工具链。
- Java SDK 需要 JDK 11 或更高版本以及 Maven。
- Redis、Nacos、Kafka 等外部服务只在相应实时测试中需要。
- 本地服务默认仅监听 `127.0.0.1`，不要为测试直接暴露到公网。

## Redis

通用 Redis 运行时测试读取 `GW_REDIS_URL`，gRPC 边缘集群测试读取
`GW_EDGE_TEST_REDIS`。URI 示例中的 `<password>` 必须替换为本地凭据：

```bash
export GW_REDIS_URL='redis://:<password>@127.0.0.1:6379'
export GW_EDGE_TEST_REDIS="$GW_REDIS_URL"
```

无密码的隔离测试实例可使用 `redis://127.0.0.1:6379`。Redis Stream 的历史消息
裁剪由业务生产侧负责，Naway 只按游标读取、检测裁剪缺口并执行散出。

边缘集群实时测试示例：

```bash
cargo test --features grpc-edge,redis-runtime --test edge_redis_cluster -- --ignored --test-threads=1
```

## Nacos

Nacos 地址通过环境变量注入，不要把控制台密码写入仓库：

```bash
export GW_NACOS_ADDR='127.0.0.1:8848'
export GW_NACOS_NAMESPACE='public'
```

具体变量以对应测试文件和配置结构为准；管理控制台端口与客户端服务端口应分别配置。

## Kafka

Kafka 实时测试使用独立的本地主题和消费者组，避免连接共享或生产集群：

```bash
export GW_KAFKA_BROKERS='127.0.0.1:9092'
```

## 验证原则

默认测试不依赖外部服务；需要真实基础设施的用例使用 `#[ignore]`。执行实时测试前显式设置
所需变量，测试结束后清理临时键、Stream、消费者组和主题。公开问题或日志中只能使用脱敏配置。
