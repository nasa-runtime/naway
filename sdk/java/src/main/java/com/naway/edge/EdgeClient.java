package com.naway.edge;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientInterceptors;
import io.grpc.Context;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.ClientCallStreamObserver;
import io.grpc.stub.ClientResponseObserver;
import io.grpc.stub.MetadataUtils;
import io.grpc.stub.StreamObserver;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Naway gRPC 边缘模式(V8)Java 客户端。
 *
 * <h2>先理解产品语义(架构规范 §25.2.2b)</h2>
 * <ul>
 *   <li><b>at-most-once</b>:队满、peer 断线、节点重启、下游读得慢都允许丢消息,SDK 不重传;</li>
 *   <li><b>无离线堆积</b>:不在线时没有任何队列为你保存消息,重连也不补发;</li>
 *   <li><b>无最终客户端 ACK</b>:回执的所有计数止于「已进入散出队列」。</li>
 * </ul>
 * 需要不丢的业务应在 payload 里自带单调 seq/event_id,由订阅端发现空洞后向后端补拉。
 *
 * <h2>SDK 负责什么</h2>
 * 业务 payload 对网关不透明,因此这里收发 {@code byte[]},使用方用自己的 protobuf 库编解码。
 * SDK 只兜住三件手写客户端最容易写错的事:<b>metadata 契约</b>(action/group/target 头名与
 * 精确方法路径)、<b>回执解析</b>(proto3 省零 = 缺失即 0)、<b>订阅断线的退避重连</b>。
 *
 * <h2>身份</h2>
 * tenant/user 一律由网关从<b>已验证 principal</b> 推导,客户端自报的任何身份字段都不作数;
 * 能碰哪个 group 由 route 的 {@code grpc_edge.authz} 决定,越权返回 {@code PERMISSION_DENIED}。
 */
public final class EdgeClient {

    private static final int MAX_COALESCE_KEY_BYTES = 256;

    /** 一条可参与 {@code latest_by_key} 合并的发布消息；发送完成前调用方不得修改数组。 */
    public static final class PublishFrame {
        public final byte[] payload;
        public final byte[] coalesceKey;

        /**
         * 业务作用：构造一条带显式合并键的 Publish/PublishStream 消息。
         *
         * @param coalesceKey 1..=256 字节业务实体键
         * @param payload 业务 protobuf 字节
         */
        public PublishFrame(byte[] coalesceKey, byte[] payload) {
            this.coalesceKey = java.util.Objects.requireNonNull(coalesceKey, "coalesceKey");
            this.payload = java.util.Objects.requireNonNull(payload, "payload");
        }
    }

    private final Channel channel;
    private final EdgeConfig config;
    private final MethodDescriptor<byte[], byte[]> subscribe;
    private final MethodDescriptor<byte[], byte[]> publish;
    private final MethodDescriptor<byte[], byte[]> push;
    private final MethodDescriptor<byte[], byte[]> publishStream;

    /**
     * @param channel 使用方自建的 gRPC channel(明文 h2c 用 {@code usePlaintext()});
     *                交给使用方是为了让 TLS、名字解析、拦截器、连接池策略沿用其既有约定
     * @param config  端点契约:方法路径与三个 metadata 头名
     */
    public EdgeClient(Channel channel, EdgeConfig config) {
        this.channel = channel;
        this.config = config;
        this.subscribe = descriptor(
                MethodDescriptor.MethodType.SERVER_STREAMING, config.subscribePath);
        this.publish = descriptor(MethodDescriptor.MethodType.UNARY, config.publishPath);
        this.push = descriptor(MethodDescriptor.MethodType.UNARY, config.pushPath);
        this.publishStream = descriptor(
                MethodDescriptor.MethodType.CLIENT_STREAMING, config.publishStreamPath);
    }

    /**
     * 群播一条消息给 group 全体订阅者。
     *
     * @param group   目标 group;能否发布由 {@code authz.publish_groups} 决定
     * @param payload 业务字节(<b>不含</b> gRPC 5 字节前缀,gRPC 栈负责分帧)
     * @return 群播回执;{@code accepted} 只表示入队份数,<b>不代表任何终端已收到</b>
     * @throws StatusRuntimeException 越权时 status 为 {@code PERMISSION_DENIED}
     */
    public EdgeSummaries.PublishSummary publish(String group, byte[] payload) {
        byte[] reply = ClientCalls.blockingUnaryCall(
                withHeaders("publish", config.groupHeader, group),
                publish, callOptions(), encodeFramePush(payload));
        return new EdgeSummaries.PublishSummary(EdgeSummaries.decodeFlat(reply));
    }

    /**
     * 业务作用：群播一条带合并键的消息，使 {@code latest_by_key} 队列按业务实体只保留最新状态。
     *
     * @param group 目标授权 group
     * @param coalesceKey 1..=256 字节合并键
     * @param payload 业务 protobuf 字节
     * @return 诚实入队回执，不代表终端已收到
     */
    public EdgeSummaries.PublishSummary publishKeyed(
            String group, byte[] coalesceKey, byte[] payload) {
        byte[] reply = ClientCalls.blockingUnaryCall(
                withHeaders("publish", config.groupHeader, group),
                publish, callOptions(), encodeFramePush(payload, coalesceKey));
        return new EdgeSummaries.PublishSummary(EdgeSummaries.decodeFlat(reply));
    }

    /**
     * 定向单播给某 user 的全部在线 session。
     *
     * @param targetUser 目标 user;能否 push 由 {@code authz.push_targets} 决定
     * @param payload    业务字节
     * @return 单播回执。目标完全不在线时 {@code accepted == 0},<b>这是正常结果不是错误</b>
     */
    public EdgeSummaries.PushSummary push(String targetUser, byte[] payload) {
        byte[] reply = ClientCalls.blockingUnaryCall(
                withHeaders("push", config.targetHeader, targetUser),
                push, callOptions(), encodeFramePush(payload));
        return new EdgeSummaries.PushSummary(EdgeSummaries.decodeFlat(reply));
    }

    /**
     * 业务作用：定向推送一条带合并键的消息，使目标会话 keyed 队列只保留最新状态。
     *
     * @param targetUser 目标授权 user
     * @param coalesceKey 1..=256 字节合并键
     * @param payload 业务 protobuf 字节
     * @return 诚实入队回执；目标离线仍正常返回 {@code accepted=0}
     */
    public EdgeSummaries.PushSummary pushKeyed(
            String targetUser, byte[] coalesceKey, byte[] payload) {
        byte[] reply = ClientCalls.blockingUnaryCall(
                withHeaders("push", config.targetHeader, targetUser),
                push, callOptions(), encodeFramePush(payload, coalesceKey));
        return new EdgeSummaries.PushSummary(EdgeSummaries.decodeFlat(reply));
    }

    /**
     * 以 client-streaming 长流持续群播,返回<b>本段</b>的聚合回执。
     *
     * <p>与 unary Publish 的关键差别在 {@code messages}:<b>它不是恒 1</b>,而是网关本段
     * <b>实际处理的条数</b>。网关按 route 的四门(生命周期 / 累计消息数 / 每秒速率 /
     * 累计字节)做<b>优雅轮转</b>——到界即停读并返回已聚合结果,而不是报错;发布方必须凭
     * {@code messages} 判断进度,把<b>剩下没被处理的</b>放进下一段发出去,否则会静默漏发。
     *
     * <p>速率门是<b>背压节流</b>不是丢弃:令牌不足时网关暂停读体并经 H2 流控传导回来,
     * 因此本调用可能变慢,但不会丢消息。
     *
     * @param group    目标 group;能否发布由 {@code authz.publish_groups} 决定
     * @param payloads 本段要发的业务字节序列,按顺序写出后 half-close
     * @return 本段聚合回执
     * @throws StatusRuntimeException 越权时 {@code PERMISSION_DENIED}
     */
    public EdgeSummaries.PublishSummary publishStream(String group, java.util.List<byte[]> payloads)
            throws InterruptedException {
        return publishStreamInternal(
                group,
                payloads,
                payload -> validateFramePushSize(payload.length, null),
                this::encodeFramePush);
    }

    /**
     * 业务作用：按 H2 flow-control 增量发送带 {@code coalesce_key} 的 PublishStream。
     *
     * @param group 目标授权 group
     * @param frames 本段 keyed 消息序列；只预检长度，不预编码整批 wire
     * @return 本段聚合回执
     * @throws InterruptedException 调用线程被取消
     */
    public EdgeSummaries.PublishSummary publishStreamKeyed(
            String group, java.util.List<PublishFrame> frames) throws InterruptedException {
        return publishStreamInternal(
                group,
                frames,
                frame -> validateFramePushSize(frame.payload.length, frame.coalesceKey),
                frame -> encodeFramePush(frame.payload, frame.coalesceKey));
    }

    /**
     * 业务作用：共用 PublishStream 的预检、isReady 背压、取消和 summary 生命周期。
     *
     * @param group 目标授权 group
     * @param items 调用方原始序列，不复制 payload
     * @param validator 单项无分配预检
     * @param encoder onNext 前才执行的单项 FramePush 编码器
     * @return 本段聚合回执
     * @throws InterruptedException 调用线程被取消
     */
    private <T> EdgeSummaries.PublishSummary publishStreamInternal(
            String group,
            java.util.List<T> items,
            Consumer<T> validator,
            Function<T, byte[]> encoder) throws InterruptedException {
        // 固定 List API 先做无持久缓冲的长度预检，保留本地参数错误时“一条都不发”；
        // wire 编码在 onNext 前逐条完成，不再额外驻留整段 FramePush 副本。
        for (T item : items) {
            validator.accept(item);
        }
        java.util.concurrent.CompletableFuture<byte[]> reply = new java.util.concurrent.CompletableFuture<>();
        Object readiness = new Object();
        AtomicReference<ClientCallStreamObserver<byte[]>> requestRef = new AtomicReference<>();
        java.util.concurrent.CountDownLatch started = new java.util.concurrent.CountDownLatch(1);
        ClientResponseObserver<byte[], byte[]> responses = new ClientResponseObserver<byte[], byte[]>() {
            @Override
            public void beforeStart(ClientCallStreamObserver<byte[]> requestStream) {
                // onReady 是 grpc-java 将 HTTP/2 flow-control 传回生产循环的唯一权威；
                // 不看它就会把整段消息重新堆进客户端内部缓冲，表面 streaming、实质预加载。
                requestStream.setOnReadyHandler(() -> {
                    synchronized (readiness) {
                        readiness.notifyAll();
                    }
                });
                requestRef.set(requestStream);
                started.countDown();
            }

            @Override
            public void onNext(byte[] value) {
                reply.complete(value);
            }

            @Override
            public void onError(Throwable t) {
                reply.completeExceptionally(t);
            }

            @Override
            public void onCompleted() {
                // summary 已在 onNext 到达；若对端只给 trailer 未给 body，
                // 这里让 future 以协议错误结束，而不是永远挂着。
                reply.completeExceptionally(new IllegalStateException(
                        "PublishStream completed without a PublishSummary"));
            }
        };
        ClientCalls.asyncClientStreamingCall(
                withHeaders("publish", config.groupHeader, group)
                        .newCall(publishStream, callOptions()),
                responses);
        if (!started.await(config.reconnectMaxMillis, TimeUnit.MILLISECONDS)) {
            throw new IllegalStateException("publish stream did not start before deadline");
        }
        ClientCallStreamObserver<byte[]> requests = requestRef.get();
        long deadlineNanos = System.nanoTime()
                + TimeUnit.MILLISECONDS.toNanos(config.reconnectMaxMillis);
        try {
            for (T item : items) {
                awaitReady(requests, readiness, reply, deadlineNanos);
                requests.onNext(encoder.apply(item));
            }
            requests.onCompleted();
            long remaining = Math.max(1L, deadlineNanos - System.nanoTime());
            byte[] summary = reply.get(remaining, TimeUnit.NANOSECONDS);
            return new EdgeSummaries.PublishSummary(EdgeSummaries.decodeFlat(summary));
        } catch (java.util.concurrent.ExecutionException e) {
            requests.cancel("publish stream failed", e.getCause());
            if (e.getCause() instanceof StatusRuntimeException) {
                throw (StatusRuntimeException) e.getCause();
            }
            throw new IllegalStateException("publish stream failed", e.getCause());
        } catch (java.util.concurrent.TimeoutException e) {
            requests.cancel("publish stream timed out", e);
            throw new IllegalStateException("publish stream timed out waiting for summary", e);
        } catch (RuntimeException e) {
            requests.cancel("publish stream local validation failed", e);
            throw e;
        }
    }

    /**
     * 业务作用：等待 grpc-java 宣布下一条消息可写，把 HTTP/2 flow-control 变成调用线程背压。
     *
     * @param requests 当前 client-streaming 请求控制器
     * @param readiness onReady 唤醒监视器
     * @param reply 对端完成/失败信号，避免已失败后继续等待
     * @param deadlineNanos 本段发送与回执共用的单调时钟截止点
     * @throws InterruptedException 调用线程被取消
     * @throws java.util.concurrent.TimeoutException 截止点前始终不可写
     */
    private static void awaitReady(
            ClientCallStreamObserver<byte[]> requests,
            Object readiness,
            java.util.concurrent.CompletableFuture<byte[]> reply,
            long deadlineNanos)
            throws InterruptedException, java.util.concurrent.TimeoutException {
        synchronized (readiness) {
            while (!requests.isReady() && !reply.isDone()) {
                long remaining = deadlineNanos - System.nanoTime();
                if (remaining <= 0) {
                    throw new java.util.concurrent.TimeoutException(
                            "publish stream remained flow-control blocked");
                }
                TimeUnit.NANOSECONDS.timedWait(readiness, remaining);
            }
        }
    }

    /**
     * 订阅 group,返回可迭代的消息流(<b>不含</b>自动重连)。
     *
     * <p>迭代在流结束时正常终止,在网关关闭/节点 drain 时抛 {@link StatusRuntimeException}。
     * 需要长期在线请用 {@link #subscribeWithReconnect}。
     *
     * @param group 目标 group;能否订阅由 {@code authz.subscribe_groups} 决定
     * @return 业务消息迭代器,每项是一条完整 payload
     */
    public Iterator<byte[]> subscribe(String group) {
        // 订阅请求体是**恰好一条**消息随后 half-close;gRPC 的 unary-request +
        // server-streaming-response 正好是这个形状,不需要手工控制 half-close。
        Iterator<byte[]> wire = ClientCalls.blockingServerStreamingCall(
                withHeaders("subscribe", config.groupHeader, group),
                subscribe, callOptions(), new byte[0]);
        return new Iterator<byte[]>() {
            @Override
            public boolean hasNext() {
                return wire.hasNext();
            }

            @Override
            public byte[] next() {
                return decodeFramePush(wire.next());
            }
        };
    }

    /**
     * 订阅并在断线后按抖动退避自动重连。
     *
     * <p><b>重连不补发</b>:断流期间的消息就是丢了(at-most-once + 无离线堆积)。
     * 授权/身份类错误({@code PERMISSION_DENIED}/{@code UNAUTHENTICATED}/
     * {@code INVALID_ARGUMENT})<b>不重试</b>——重试多少次结果都一样,只会把真问题
     * 掩埋成"一直连不上"。
     *
     * @param group    目标 group
     * @param observer 回调;{@code onNext} 收消息,{@code onError} 只在不可重试错误时触发
     * @return 可关闭句柄;调用 {@link Subscription#close()} 终止重连循环
     */
    public Subscription subscribeWithReconnect(String group, StreamObserver<byte[]> observer) {
        AtomicBoolean closed = new AtomicBoolean(false);
        Context.CancellableContext context = Context.current().withCancellation();
        Thread worker = new Thread(() -> context.run(() -> {
            long backoffMs = config.reconnectBaseMillis;
            while (!closed.get()) {
                try {
                    Iterator<byte[]> stream = subscribe(group);
                    backoffMs = config.reconnectBaseMillis;
                    while (!closed.get() && stream.hasNext()) {
                        observer.onNext(stream.next());
                    }
                } catch (StatusRuntimeException e) {
                    if (isTerminal(e.getStatus())) {
                        observer.onError(e);
                        return;
                    }
                } catch (RuntimeException e) {
                    // 其它运行期异常同样按可重试处理:边缘面断流是常态。
                }
                if (closed.get()) {
                    break;
                }
                try {
                    Thread.sleep(backoffMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                backoffMs = Math.min(backoffMs * 2, config.reconnectMaxMillis);
            }
            observer.onCompleted();
        }), "naway-edge-subscribe-" + group);
        worker.setDaemon(true);
        worker.start();
        return () -> {
            if (closed.compareAndSet(false, true)) {
                // WHY:只改 closed 无法唤醒阻塞在 Iterator.hasNext() 的 gRPC call，线程会
                // 一直泄漏到对端主动断流。取消 Context 才会向当前 call 传播 CANCELLED。
                context.cancel(null);
                worker.interrupt();
            }
        };
    }

    /** 订阅句柄。 */
    public interface Subscription extends AutoCloseable {
        @Override
        void close();
    }

    /**
     * 授权/身份类状态重试无意义,必须立刻上报。
     *
     * @param status gRPC 状态
     * @return true 表示不可重试
     */
    static boolean isTerminal(Status status) {
        Status.Code code = status.getCode();
        return code == Status.Code.PERMISSION_DENIED
                || code == Status.Code.UNAUTHENTICATED
                || code == Status.Code.INVALID_ARGUMENT;
    }

    /**
     * 返回一个会自动带上本次 action metadata 的 channel 视图。
     *
     * <p>grpc-java 的 {@code ClientCalls} 不接受 per-call metadata,标准做法是用
     * {@link MetadataUtils} 拦截器附加。每次调用构造一个轻量 wrapper,不新建连接。
     */
    private Channel withHeaders(String action, String scopeHeader, String scope) {
        Metadata metadata = new Metadata();
        metadata.put(key(config.actionHeader), action);
        metadata.put(key(scopeHeader), scope);
        for (Map.Entry<Metadata.Key<String>, String> extra : config.extraHeaders.entrySet()) {
            metadata.put(extra.getKey(), extra.getValue());
        }
        return ClientInterceptors.intercept(
                channel, MetadataUtils.newAttachHeadersInterceptor(metadata));
    }

    private static Metadata.Key<String> key(String name) {
        return Metadata.Key.of(name, Metadata.ASCII_STRING_MARSHALLER);
    }

    private CallOptions callOptions() {
        return CallOptions.DEFAULT.withMaxInboundMessageSize(config.maxMessageBytes);
    }

    /** 按统一 proto 编码 `FramePush { bytes payload = 1; }`。 */
    byte[] encodeFramePush(byte[] payload) {
        return encodeFramePush(payload, null);
    }

    /**
     * 业务作用：按统一 proto 编码 payload 与可选 {@code coalesce_key}，不依赖生成代码。
     *
     * @param payload 业务 protobuf 字节
     * @param coalesceKey 空缺或 1..=256 字节合并键
     * @return FramePush protobuf message 字节
     */
    byte[] encodeFramePush(byte[] payload, byte[] coalesceKey) {
        int wireLength = validateFramePushSize(payload.length, coalesceKey);
        byte[] wire = new byte[(int) wireLength];
        wire[0] = 0x0a;
        int cursor = writeVarint(payload.length, wire, 1);
        System.arraycopy(payload, 0, wire, cursor, payload.length);
        cursor += payload.length;
        if (coalesceKey != null) {
            wire[cursor++] = 0x12;
            cursor = writeVarint(coalesceKey.length, wire, cursor);
            System.arraycopy(coalesceKey, 0, wire, cursor, coalesceKey.length);
        }
        return wire;
    }

    /**
     * 业务作用：无分配校验 FramePush 精确 wire 长度，供整段预检与逐条编码共用。
     *
     * @param payloadLength 业务 payload 字节数
     * @param coalesceKey 空缺或 1..=256 字节合并键
     * @return FramePush protobuf message 字节数
     * @throws IllegalArgumentException 超过配置或 Java 数组边界
     */
    private int validateFramePushSize(int payloadLength, byte[] coalesceKey) {
        int lenBytes = varintLength(payloadLength);
        long wireLength = 1L + lenBytes + payloadLength;
        if (coalesceKey != null) {
            if (coalesceKey.length == 0 || coalesceKey.length > MAX_COALESCE_KEY_BYTES) {
                throw new IllegalArgumentException(
                        "FramePush coalesce_key length " + coalesceKey.length
                                + " is outside 1..=" + MAX_COALESCE_KEY_BYTES);
            }
            wireLength += 1L + varintLength(coalesceKey.length) + coalesceKey.length;
        }
        if (wireLength > config.maxMessageBytes || wireLength > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(
                    "FramePush wire length " + wireLength + " exceeds " + config.maxMessageBytes);
        }
        return (int) wireLength;
    }

    /**
     * 从统一 FramePush protobuf message 取 field 1。
     *
     * <p>必须是<b>真正的字段遍历</b>而不是"断言第一个字节是 0x0a、且 payload 占满整条
     * message":那种写法会拒掉两类完全合法的输入——
     * <ol>
     *   <li><b>proto3 省零</b>:{@code bytes payload = 1} 取默认值(空)时 protoc
     *       <b>不上 wire</b>,空帧序列化成 0 字节 message,"字段缺失"必须解释为空 payload;</li>
     *   <li><b>业务扩展</b>:{@code .proto} 明确允许只增字段,未知字段必须跳过;
     *       protobuf 也不保证字段顺序,payload 可能出现在未知字段之后。</li>
     * </ol>
     * 拒掉它们等于把 FramePush 信封本来要解决的互通问题又造回来。
     */
    byte[] decodeFramePush(byte[] wire) {
        if (wire.length > config.maxMessageBytes) {
            throw new IllegalArgumentException("oversized FramePush wire message");
        }
        byte[] payload = null;
        int cursor = 0;
        while (cursor < wire.length) {
            long[] key = readVarint(wire, cursor);
            cursor = (int) key[1];
            long tag = key[0] >>> 3;
            int wireType = (int) (key[0] & 0x7);
            if (tag == 1) {
                if (wireType != 2 || payload != null) {
                    throw new IllegalArgumentException(
                            "FramePush.payload must be one length-delimited field");
                }
                long[] length = readVarint(wire, cursor);
                if (length[0] > Integer.MAX_VALUE) {
                    throw new IllegalArgumentException("FramePush payload length overflow");
                }
                int start = (int) length[1];
                int end = start + (int) length[0];
                if (end > wire.length || end < start) {
                    throw new IllegalArgumentException("FramePush payload overruns message");
                }
                payload = java.util.Arrays.copyOfRange(wire, start, end);
                cursor = end;
                continue;
            }
            cursor = skipProtobufField(wire, cursor, wireType);
        }
        // 缺失 = 空 payload(proto3 省零),不是错误。
        return payload == null ? new byte[0] : payload;
    }

    /** 跳过一个未知字段,返回新游标。 */
    private static int skipProtobufField(byte[] wire, int cursor, int wireType) {
        int end;
        switch (wireType) {
            case 0:
                return (int) readVarint(wire, cursor)[1];
            case 1:
                end = cursor + 8;
                break;
            case 2: {
                long[] length = readVarint(wire, cursor);
                if (length[0] > Integer.MAX_VALUE) {
                    throw new IllegalArgumentException("FramePush field length overflow");
                }
                end = (int) length[1] + (int) length[0];
                break;
            }
            case 5:
                end = cursor + 4;
                break;
            default:
                throw new IllegalArgumentException(
                        "unsupported protobuf wire type " + wireType + " in FramePush");
        }
        if (end > wire.length || end < cursor) {
            throw new IllegalArgumentException("FramePush field overruns message");
        }
        return end;
    }

    private static int varintLength(int value) {
        int len = 1;
        while ((value & ~0x7f) != 0) {
            value >>>= 7;
            len++;
        }
        return len;
    }

    private static int writeVarint(int value, byte[] out, int cursor) {
        while ((value & ~0x7f) != 0) {
            out[cursor++] = (byte) ((value & 0x7f) | 0x80);
            value >>>= 7;
        }
        out[cursor++] = (byte) value;
        return cursor;
    }

    private static long[] readVarint(byte[] body, int cursor) {
        long value = 0;
        int shift = 0;
        while (cursor < body.length && shift < 64) {
            int next = body[cursor++] & 0xff;
            value |= (long) (next & 0x7f) << shift;
            if ((next & 0x80) == 0) {
                return new long[]{value, cursor};
            }
            shift += 7;
        }
        throw new IllegalArgumentException("truncated FramePush length varint");
    }

    /**
     * 构造原始字节 method descriptor。
     *
     * <p>不使用 protobuf marshaller:网关不解析业务 payload,SDK 也不该强迫使用方
     * 走某一种 protobuf 实现。
     */
    private static MethodDescriptor<byte[], byte[]> descriptor(
            MethodDescriptor.MethodType type, String fullPath) {
        // gRPC 的 fullMethodName 不带前导斜杠,而 route 配置里写的是完整 :path。
        String name = fullPath.startsWith("/") ? fullPath.substring(1) : fullPath;
        return MethodDescriptor.<byte[], byte[]>newBuilder()
                .setType(type)
                .setFullMethodName(name)
                .setRequestMarshaller(BYTES_MARSHALLER)
                .setResponseMarshaller(BYTES_MARSHALLER)
                .build();
    }

    private static final MethodDescriptor.Marshaller<byte[]> BYTES_MARSHALLER =
            new MethodDescriptor.Marshaller<byte[]>() {
                @Override
                public InputStream stream(byte[] value) {
                    return new java.io.ByteArrayInputStream(value);
                }

                @Override
                public byte[] parse(InputStream stream) {
                    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                        byte[] buffer = new byte[4096];
                        int read;
                        while ((read = stream.read(buffer)) != -1) {
                            out.write(buffer, 0, read);
                        }
                        return out.toByteArray();
                    } catch (IOException e) {
                        throw new IllegalStateException("read grpc message", e);
                    }
                }
            };
}
