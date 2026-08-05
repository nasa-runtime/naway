package com.naway.edge;

import io.grpc.Metadata;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 边缘客户端的端点契约。
 *
 * <p>默认值取 架构规范 §25.2.3 的建议形态;route 若改过方法路径或头名,<b>必须在此
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

    /** 以 §25.2.3 默认方法路径与头名开始构造。 */
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

        /** 覆盖 PublishStream 方法路径。 */
        public Builder publishStreamPath(String value) {
            this.publishStreamPath = value;
            return this;
        }

        /** 覆盖三个方法路径(route 改过 {@code grpc_edge.methods} 时必须同步)。 */
        public Builder methods(String subscribe, String publish, String push) {
            this.subscribePath = subscribe;
            this.publishPath = publish;
            this.pushPath = push;
            return this;
        }

        /** 覆盖三个 metadata 头名。 */
        public Builder headers(String action, String group, String target) {
            this.actionHeader = action;
            this.groupHeader = group;
            this.targetHeader = target;
            return this;
        }

        /**
         * 追加一个每请求都带上的 metadata,通常是 API-Key 认证头。
         *
         * <p>身份仍由网关从已验证 principal 推导;这里放的是<b>凭证</b>,不是身份声明。
         */
        public Builder header(String name, String value) {
            extraHeaders.put(Metadata.Key.of(name, Metadata.ASCII_STRING_MARSHALLER), value);
            return this;
        }

        /** 设置重连退避区间(毫秒)。 */
        public Builder reconnect(long baseMillis, long maxMillis) {
            this.reconnectBaseMillis = baseMillis;
            this.reconnectMaxMillis = maxMillis;
            return this;
        }

        /** 设置单条 FramePush wire message 上限，必须与 route 的 max_msg_bytes 一致。 */
        public Builder maxMessageBytes(int value) {
            this.maxMessageBytes = value;
            return this;
        }

        /** 完成构造。 */
        public EdgeConfig build() {
            if (maxMessageBytes <= 0) {
                throw new IllegalArgumentException("maxMessageBytes must be positive");
            }
            if (reconnectBaseMillis <= 0 || reconnectMaxMillis < reconnectBaseMillis) {
                throw new IllegalArgumentException("reconnect must satisfy 0 < base <= max");
            }
            return new EdgeConfig(this);
        }
    }
}
