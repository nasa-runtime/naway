# Naway gRPC 边缘模式 SDK

wire 契约见 [`../proto/naway/edge/v1/edge.proto`](../proto/naway/edge/v1/edge.proto)。
字段号由网关实现与 SDK 共同遵守，修改契约时必须同步更新两侧。

## 先读这三条产品语义

边缘面**不是消息队列**。集成前必须接受以下产品语义：

1. **at-most-once** —— 队满、peer 断线、节点重启、下游读得慢都允许丢消息,SDK 不重传。
2. **无离线堆积** —— 用户不在线时**没有任何队列**为其保存消息,重新上线也不补发。
3. **无最终客户端 ACK** —— 回执里所有计数止于「已进入散出队列」,**没有任何字段表示
   终端已收到**。这也是它不叫 `delivered` 的原因。

适用:行情推送、房间广播、状态同步这类"最新值优先、可容忍丢失、由客户端补齐"的流量。
不适用:订单状态机、支付通知——那些应当走后端消息系统,网关只承担扇出加速。

需要不丢的业务:在自己的 payload 里带单调 `seq`/`event_id`,订阅端发现空洞后向后端补拉。

## 两个 SDK 的共同取舍

- **payload 是 `bytes`/`byte[]`,SDK 不做 protobuf 编解码。** 网关本就不解析业务 payload，
  SDK 也不该强迫使用方绑定某一种 protobuf 实现。
- **身份不由客户端决定。** tenant/user 一律由网关从**已验证 principal**(JWT claim 或
  已认证 consumer)推导;客户端在 metadata 或消息体里放的任何身份字段都不作数。
  能碰哪个 group 由 route 的 `grpc_edge.authz` 决定,越权返回 `PERMISSION_DENIED(7)`。
- **SDK 真正兜住的是三件容易写错的事**:metadata 契约(action / group / target 头名与
  **精确**方法路径)、回执解析(proto3 省零 ⇒ **字段缺失即 0,不是"未知"**)、
  订阅断线后的退避重连(且授权类错误**不重试**)。

> 一个真实踩过的坑:定向 push 的默认头名是 `x-naway-target-user`,**不是**
> `x-naway-target`。两个 SDK 的默认值都已对齐网关,手写客户端请注意。

## Rust

```rust
use naway_edge_client::{Auth, EdgeClient, EdgeConfig};

let client = EdgeClient::new(
    EdgeConfig::new("http://127.0.0.1:8080", "edge.example.com")
        .with_auth(Auth::ApiKey { header: "x-api-key".into(), value: "sub-key".into() }),
);

// 订阅(自动重连;授权被拒会直接返回而不是无声打转)
let mut stream = client.subscribe("room.1");
while let Ok(message) = stream.next().await {
    handle(message); // message 是业务 payload,自行反序列化
}

// 群播。accepted 是**入队份数**,不代表任何终端已收到。
let summary = client.publish("room.1", payload).await?;
```

构建与测试:`cd sdk/rust/naway-edge-client && cargo test`
(端到端用例需要先在仓库根 `cargo build --features grpc-edge --bin naway`,
否则会**跳过并打印原因**,不会静默通过)。

## Java

```java
ManagedChannel channel = ManagedChannelBuilder
        .forAddress("127.0.0.1", 8080).usePlaintext().build();

EdgeClient client = new EdgeClient(channel, EdgeConfig.builder()
        .header("x-api-key", "sub-key")
        .build());

// 订阅(带自动重连;授权类错误走 onError,不重试)
client.subscribeWithReconnect("room.1", new StreamObserver<byte[]>() {
    public void onNext(byte[] message) { handle(message); }
    public void onError(Throwable t) { /* PERMISSION_DENIED 等不可重试错误 */ }
    public void onCompleted() {}
});

EdgeSummaries.PublishSummary summary = client.publish("room.1", payload);
```

channel 交给使用方自建,是为了让 TLS、名字解析、拦截器、连接池策略沿用其既有约定。

构建与测试:`cd sdk/java && mvn test`。
**不使用 protobuf 代码生成**——回执是平坦 varint 结构,手写 marshaller 避免了 protoc
这个平台相关的构建期依赖,也与 Rust SDK 解析同一份契约。

## 许可证

Rust 与 Java SDK 均采用 `Apache-2.0 OR MIT` 双许可证，使用者可自行选择其一：

- [Apache License 2.0](../LICENSE-APACHE)
- [MIT License](../LICENSE-MIT)
