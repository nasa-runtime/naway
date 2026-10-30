package com.naway.edge;

import io.grpc.Metadata;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 边缘客户端的端点契约。
 *
 * <p>默认值与公开 edge 协议一致；route 若改过方法路径或头名，<b>必须在此
 * 同步覆盖</b>——网关按<b>精确</b> {@code :path} 决定 action,前缀匹配会被拒绝。
 */
public final class EdgeConfig {

    /** Subscribe 精确方法路径。 */
    public final String subscribePath;
    /** unary Publish 精确方法路径。 */
    public final String publishPath;
    /** unary Push 精确方法路径。 */
    public final String pushPath;
    /**
     * client-streaming PublishStream 精确方法路径。
     *
     * <p>该方法在 route 上是<b>可选</b>的({@code grpc_edge.methods.publish_stream} 不配就没有)。
     */
    public final String publishStreamPath;
    /** action 确认头名。 */
    public final String actionHeader;
    /** group 头名。 */
    public final String groupHeader;
    /**
     * 定向 target 头名。默认 {@code x-naway-target-user}——注意<b>不是</b>
     * {@code x-naway-target},与网关的 {@code default_grpc_edge_target_header} 一致。
     */
    public final String targetHeader;
    /** 单条 FramePush protobuf message 的 wire 字节上限。 */
    public final int maxMessageBytes;
    /** 每次请求附带的额外 metadata(常用于 API-Key 认证头)。 */
    public final Map<Metadata.Key<String>, String> extraHeaders;
    /** 订阅断线后的首次重连退避(毫秒)。 */
    public final long reconnectBaseMillis;
    /** 重连退避上限(毫秒)。 */
    public final long reconnectMaxMillis;

    /**
     * 业务作用：冻结构造器的端点、metadata 与预算；复制额外头部，避免后续构造修改影响客户端。
     *
     *
     * 返回：得到独立且不可变的配置字段与头部映射。
     *
     * 参数说明：
     * @param builder 已完成预算校验的构造器。
     */
    private EdgeConfig(Builder builder) {
        this.subscribePath = builder.subscribePath;
        this.publishPath = builder.publishPath;
        this.pushPath = builder.pushPath;
        this.publishStreamPath = builder.publishStreamPath;
        this.actionHeader = builder.actionHeader;
        this.groupHeader = builder.groupHeader;
        this.targetHeader = builder.targetHeader;
        this.extraHeaders = Map.copyOf(builder.extraHeaders);
        this.maxMessageBytes = builder.maxMessageBytes;
        this.reconnectBaseMillis = builder.reconnectBaseMillis;
        this.reconnectMaxMillis = builder.reconnectMaxMillis;
    }

    /**
     * 业务作用：以公开默认方法路径、头名与资源预算创建客户端配置构造器。
     *
     *
     * 返回：尚未建立任何网络连接的配置构造器。
     *
     * 参数说明: 无。
     */
    public static Builder builder() {
        return new Builder();
    }

    /** {@link EdgeConfig} 构造器。 */
    public static final class Builder {
        private String subscribePath = "/naway.edge.v1.NawayEdge/Subscribe";
        private String publishPath = "/naway.edge.v1.NawayEdge/Publish";
        private String pushPath = "/naway.edge.v1.NawayEdge/Push";
        private String publishStreamPath = "/naway.edge.v1.NawayEdge/PublishStream";
        private String actionHeader = "x-naway-edge-action";
        private String groupHeader = "x-naway-group";
        private String targetHeader = "x-naway-target-user";
        private int maxMessageBytes = 64 * 1024;
        private final Map<Metadata.Key<String>, String> extraHeaders = new LinkedHashMap<>();
        private long reconnectBaseMillis = 200;
        private long reconnectMaxMillis = 10_000;

        /**
         * 业务作用：覆盖 PublishStream 方法路径。
         *
         * 返回：更新路径后返回同一构造器。
         *
         * 参数说明：
         * @param value 与网关一致的精确 PublishStream 方法路径。
         */
        public Builder publishStreamPath(String value) {
            this.publishStreamPath = value;
            return this;
        }

        /**
         * 业务作用：覆盖三个方法路径(route 改过 {@code grpc_edge.methods} 时必须同步)。
         *
         * 返回：更新三个端点后返回同一构造器。
         *
         * 参数说明：
         * @param subscribe 精确 Subscribe 路径。
         * @param publish 精确 Publish 路径。
         * @param push 精确 Push 路径。
         */
        public Builder methods(String subscribe, String publish, String push) {
            this.subscribePath = subscribe;
            this.publishPath = publish;
            this.pushPath = push;
            return this;
        }

        /**
         * 业务作用：覆盖三个 metadata 头名。
         *
         * 返回：更新三个作用域头名后返回同一构造器。
         *
         * 参数说明：
         * @param action action 确认头名。
         * @param group group 作用域头名。
         * @param target 目标 user 头名。
         */
        public Builder headers(String action, String group, String target) {
            this.actionHeader = action;
            this.groupHeader = group;
            this.targetHeader = target;
            return this;
        }

        /**
         * 业务作用：追加一个每请求都带上的 metadata,通常是 API-Key 认证头。
         *
         * <p>身份仍由网关从已验证 principal 推导;这里放的是<b>凭证</b>,不是身份声明。
         *
         * 返回：登记额外 metadata 后返回同一构造器；非法头名拒绝。
         *
         * 参数说明：
         * @param name 合法 ASCII metadata 头名。
         * @param value 每次调用携带的凭据或其他业务值，不作为自报身份。
         */
        public Builder header(String name, String value) {
            extraHeaders.put(Metadata.Key.of(name, Metadata.ASCII_STRING_MARSHALLER), value);
            return this;
        }

        /**
         * 业务作用：设置重连退避区间(毫秒)。
         *
         * 返回：记录退避区间并返回同一构造器，最终由 build 验证。
         *
         * 参数说明：
         * @param baseMillis 首次重连退避毫秒数，必须大于零。
         * @param maxMillis 重连退避上限毫秒数，不得小于首次退避或超过24小时。
         */
        public Builder reconnect(long baseMillis, long maxMillis) {
            this.reconnectBaseMillis = baseMillis;
            this.reconnectMaxMillis = maxMillis;
            return this;
        }

        /**
         * 业务作用：设置单条 FramePush wire message 上限，必须与 route 的 max_msg_bytes 一致。
         *
         * 返回：记录消息上限并返回同一构造器，最终由 build 验证。
         *
         * 参数说明：
         * @param value 单条 FramePush wire 字节硬上限，必须为正且与 route 一致。
         */
        public Builder maxMessageBytes(int value) {
            this.maxMessageBytes = value;
            return this;
        }

        /**
         * 业务作用：验证消息上限与重连区间后冻结客户端配置，非法资源策略不进入运行态。
         *
         * 完成构造。
         *
         * 返回：合法时返回冻结配置，非法消息上限或退避区间抛出异常。
         *
         * 参数说明: 无。
         */
        public EdgeConfig build() {
            if (maxMessageBytes <= 0) {
                throw new IllegalArgumentException("maxMessageBytes must be positive");
            }
            if (reconnectBaseMillis <= 0 || reconnectMaxMillis < reconnectBaseMillis
                    || reconnectMaxMillis > 86_400_000L) {
                throw new IllegalArgumentException("reconnect must satisfy 0 < base <= max <= 24h");
            }
            return new EdgeConfig(this);
        }
    }
}
