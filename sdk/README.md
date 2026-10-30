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

> 定向 push 的默认头名是 `x-naway-target-user`，不是 `x-naway-target`。
> 手写客户端也必须使用与网关相同的头名，否则请求会因缺少目标身份而拒绝。

## Rust

```rust
use naway_edge_client::{Auth, EdgeClient, EdgeConfig};

let client = EdgeClient::new(
    EdgeConfig::new("http://127.0.0.1:8080", "edge.example.com")
        .with_auth(Auth::ApiKey {
            header: "x-api-key".into(),
            value: "sub-key".into(),
        }),
);

// 订阅(自动重连;授权被拒会直接返回而不是无声打转)
let mut stream = client.subscribe("room.1");
while let Ok(message) = stream.next().await {
    handle(message); // message 是业务 payload,自行反序列化
}

// 群播。accepted 是**入队份数**,不代表任何终端已收到。
let summary = client.publish("room.1", payload).await?;
```

构建 SDK：在 `sdk/rust/naway-edge-client` 目录执行 `cargo build`。
网关需启用 `grpc-edge`，并为精确方法路径配置对应的认证、授权与消息上限。

## Java

```java
ManagedChannel channel = ManagedChannelBuilder
        .forAddress("127.0.0.1", 8080).usePlaintext().build();

EdgeClient client = new EdgeClient(channel, EdgeConfig.builder()
        .header("x-api-key", "sub-key")
        .build());

// 订阅(带自动重连;授权类错误走 onError,不重试)
client.subscribeWithReconnect("room.1", new StreamObserver<byte[]>() {
    /** 业务作用：将完整业务 payload 交给应用处理。 */
    public void onNext(byte[] message) {
        handle(message);
    }
    /** 业务作用：接收授权拒绝等不可重试结果，由应用决定后续动作。 */
    public void onError(Throwable t) {
        reportFailure(t);
    }
    /** 业务作用：通知应用订阅已正常结束。 */
    public void onCompleted() {}
});

EdgeSummaries.PublishSummary summary = client.publish("room.1", payload);
```

channel 交给使用方自建,是为了让 TLS、名字解析、拦截器、连接池策略沿用其既有约定。

构建 SDK：在 `sdk/java` 目录执行 `mvn package`。
**不使用 protobuf 代码生成**——回执是平坦 varint 结构,手写 marshaller 避免了 protoc
这个平台相关的构建期依赖,也与 Rust SDK 解析同一份契约。

## 许可证

Rust 与 Java SDK 均采用 `Apache-2.0 OR MIT` 双许可证，使用者可自行选择其一：

- [Apache License 2.0](../LICENSE-APACHE)
- [MIT License](../LICENSE-MIT)

## 订阅关闭与重连

两种 SDK 仅在实际交付完整消息后重置重连间隔；连接失败、空流和正常断流均先等待，连续无消息
断流指数增长至上限。配置须满足 `0 < base <= max <= 24h`，不会以成功响应头证明业务已恢复。
`INVALID_ARGUMENT`、`PERMISSION_DENIED`、`UNAUTHENTICATED` 终止订阅，不再自动连接；其它远端
状态与传输中断仍按退避重试。Rust 的帧和状态解析错误、Java SDK 自身的 FramePush 解码异常也会
终止；Java 底层 gRPC 库映射出的状态仍按上述状态规则裁决。重连不补发消息。

Rust 的 `Subscription::close()` 幂等关闭当前流，后续 `next()` 返回 CANCELLED；已有终止原因
保持不变，`is_closed()` 可观察。终止后的 `next()` 返回原原因，不新建 RPC。取消一次 `next()`
等待后可以继续原句柄，已登记的退避截止保留；Drop 释放响应体和重组缓冲，没有后台订阅任务。
重组只在跨帧或共享底层字节无法取得独占存储时复制，交付的 `Bytes` 继续共享业务 payload。
响应头和流尾的认证拒绝使用相同裁决；缺失状态视为传输失败，非法状态或成功结束时残留半条
消息视为协议错误，绝不把半条消息交给应用。无消息超时由调用方对 `next()` 设置期限。

Java 的 `subscribeWithReconnect()` 返回可关闭句柄。关闭取消当前 gRPC 调用并唤醒退避；
正常退出、不可重试状态及回调异常都释放当前轮次和订阅 Context，Channel 仍由调用方拥有。
`onNext` 抛出运行期异常后停止重连，只通知一次 `onError`；显式关闭正常通知 `onCompleted`。
终态回调由同一工作线程串行执行，回调本身再次抛出异常不会重新触发订阅。关闭不等待应用
自定义回调执行完毕，SDK 无法强行终止阻塞的业务代码。普通 `subscribe()` 返回的直接迭代器
没有自动重连句柄；调用方可以用自己的 gRPC Context 管理其取消。
