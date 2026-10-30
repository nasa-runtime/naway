package com.naway.edge.subscription;

import com.naway.edge.EdgeClient;
import io.grpc.Context;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;

import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import java.util.function.Supplier;

/** 持有一次订阅的工作线程、取消上下文和退避状态，调用者仍拥有底层 Channel。 */
public final class ReconnectingSubscription implements EdgeClient.Subscription {
    private final Supplier<Iterator<byte[]>> source;
    private final StreamObserver<byte[]> observer;
    private final Predicate<Status> terminal;
    private final long baseMillis;
    private final long maxMillis;
    private final Context.CancellableContext context;
    private final Thread worker;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private long backoffMillis;

    /**
     * 业务作用：建立尚未启动的订阅运行器，验证预算后才登记父上下文取消监听。
     * 参数说明：
     * @param source 每轮建立唯一 gRPC 消息迭代器的入口。
     * @param observer 串行业务消息和唯一终态的接收者。
     * @param baseMillis 首次断流后的等待时间。
     * @param maxMillis 最大退避，不超过24小时。
     * @param terminal 判断远端状态是否明确禁止自动重试。
     * 返回：完成资源所有者建立；非法参数在创建线程和 Context 前拒绝。
     */
    private ReconnectingSubscription(
            Supplier<Iterator<byte[]>> source,
            StreamObserver<byte[]> observer,
            long baseMillis,
            long maxMillis,
            Predicate<Status> terminal) {
        this.source = Objects.requireNonNull(source, "source");
        this.observer = Objects.requireNonNull(observer, "observer");
        this.terminal = Objects.requireNonNull(terminal, "terminal");
        if (baseMillis <= 0 || baseMillis > maxMillis || maxMillis > 86_400_000L) {
            throw new IllegalArgumentException("reconnect must satisfy 0 < base <= max <= 24h");
        }
        this.baseMillis = baseMillis;
        this.maxMillis = maxMillis;
        this.backoffMillis = baseMillis;
        this.context = Context.current().withCancellation();
        this.worker = new Thread(() -> context.run(this::run), "naway-edge-subscribe");
        this.worker.setDaemon(true);
        this.context.addListener(ignored -> {
            if (!closed.get()) {
                worker.interrupt();
            }
        }, Runnable::run);
    }

    /**
     * 业务作用：启动一个有明确关闭句柄的订阅，不为断流创建额外线程或离线消息队列。
     * 参数说明：
     * @param source 每轮实际订阅入口。
     * @param observer 原应用回调，payload 不额外复制。
     * @param baseMillis 首次退避毫秒数。
     * @param maxMillis 最大退避毫秒数。
     * @param terminal 当前协议的不可重试状态判定。
     * @return 已启动的句柄；线程无法启动时先取消上下文再传播异常。
     */
    public static EdgeClient.Subscription start(
            Supplier<Iterator<byte[]>> source,
            StreamObserver<byte[]> observer,
            long baseMillis,
            long maxMillis,
            Predicate<Status> terminal) {
        ReconnectingSubscription subscription = new ReconnectingSubscription(
                source, observer, baseMillis, maxMillis, terminal);
        try {
            subscription.worker.start();
        } catch (RuntimeException | Error error) {
            subscription.context.cancel(error);
            throw error;
        }
        return subscription;
    }

    /**
     * 业务作用：按唯一工作线程串行推进订阅，任何退出路径都先释放当前调用及父 Context。
     * 参数说明: 无。
     * 返回：显式关闭正常结束，其它终止原因通知一次 onError；应用回调异常不重连。
     */
    private void run() {
        Throwable failure = null;
        try {
            while (!closed.get() && !context.isCancelled()) {
                Context.CancellableContext attempt = context.withCancellation();
                try {
                    attempt.run(this::consume);
                } catch (CallbackFailure error) {
                    // 应用回调的异常不代表链路可恢复，重试会重复进入已经失败的业务处理。
                    failure = error.getCause();
                    break;
                } catch (StatusRuntimeException error) {
                    if (closed.get()) {
                        break;
                    }
                    // 明确失权或父上下文失效后，不能通过新 RPC 重新获取本次订阅的资格。
                    if (terminal.test(error.getStatus()) || context.isCancelled()) {
                        failure = error;
                        break;
                    }
                } catch (RuntimeException error) {
                    failure = error;
                    break;
                } finally {
                    // 半完成迭代、解码失败及回调退出都须取消同一轮调用，不能让旧流留在后台。
                    attempt.cancel(null);
                }
                if (closed.get() || context.isCancelled()) {
                    break;
                }
                try {
                    Thread.sleep(backoffMillis);
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    break;
                }
                backoffMillis = backoffMillis >= maxMillis - backoffMillis
                        ? maxMillis : backoffMillis * 2;
            }
        } finally {
            if (failure == null && context.isCancelled() && !closed.get()) {
                failure = Status.CANCELLED.withDescription("subscription context cancelled")
                        .asRuntimeException();
            }
            closed.set(true);
            context.cancel(null);
        }
        // 只有工作线程通知终态；close 只撤销权威并唤醒，避免取消与远端结束重复通知。
        if (failure == null) {
            observer.onCompleted();
        } else {
            observer.onError(failure);
        }
    }

    /**
     * 业务作用：在当前轮次上下文内交付完整消息，成功响应头或空流不能重置失败退避。
     * 参数说明: 无。
     * 返回：流结束或关闭时退出；解码和应用回调错误传播给唯一终态裁决。
     */
    private void consume() {
        Iterator<byte[]> stream = source.get();
        while (!closed.get() && !context.isCancelled() && stream.hasNext()) {
            if (closed.get() || context.isCancelled()) {
                return;
            }
            byte[] message = stream.next();
            try {
                observer.onNext(message);
            } catch (RuntimeException error) {
                throw new CallbackFailure(error);
            }
            backoffMillis = baseMillis;
        }
    }

    /**
     * 业务作用：撤销本句柄的调用与重连资格，并唤醒网络读取或退避等待。
     * 参数说明: 无。
     * 返回：幂等且不等待任意应用回调，不关闭调用者持有的 Channel。
     */
    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            context.cancel(null);
            worker.interrupt();
        }
    }

    /** 区分应用回调异常与远端 gRPC 状态，回调抛出的状态也不能触发自动重试。 */
    private static final class CallbackFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;

        /**
         * 业务作用：保留原应用异常身份，使运行器只通知一次且不把它当作网络暂态。
         * 参数说明：
         * @param cause 原 onNext 回调异常。
         * 返回：仅包装分类，不复制 payload 或改写异常原因。
         */
        private CallbackFailure(RuntimeException cause) {
            super(cause);
        }
    }
}
