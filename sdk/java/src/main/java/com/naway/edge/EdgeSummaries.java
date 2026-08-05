package com.naway.edge;

import java.util.HashMap;
import java.util.Map;

/**
 * 两个回执消息的解析与语义。
 *
 * <p>wire 契约见 {@code proto/naway/edge/v1/edge.proto},字段号由网关侧的
 * {@code edge_proto_matches_wire_contract} 用例与实现锁死。这里手写解析而不是引 protobuf
 * 代码生成:回执是平坦的 varint-only 结构,手写既避免了 protoc 这个平台相关的构建期
 * 依赖,也让"proto3 省零 = 缺失即 0"这条最容易踩错的语义在代码里显式可见。
 */
public final class EdgeSummaries {

    private EdgeSummaries() {}

    /** 字段号,与 .proto 及网关的 {@code summary_field} 常量一一对应。 */
    static final int F_ACCEPTED = 1;
    static final int F_DROPPED = 2;
    static final int F_CLOSED_SLOW = 3;
    static final int F_MESSAGES = 4;
    static final int F_PEERS_ACCEPTED = 5;
    static final int F_PEERS_REJECTED = 6;
    static final int F_PEERS_UNKNOWN = 7;

    /**
     * 群播回执。
     *
     * <p><b>所有计数止于「已进入散出队列」,没有任何字段表示终端已收到</b>——这也是
     * 它不叫 {@code delivered} 的原因。需要不丢的业务必须在 payload 里自带 seq/event_id
     * 并由订阅端向后端补拉。
     */
    public static final class PublishSummary {
        /** 本地实际入队份数。 */
        public final long accepted;
        /** 未入队份数(队满丢弃 + 预算拒绝)。 */
        public final long dropped;
        /** 因慢消费被主动断流的成员数。 */
        public final long closedSlow;
        /** 已处理消息条数;unary Publish 恒为 1。 */
        public final long messages;
        /** peer 侧实际入队份数。 */
        public final long peersAccepted;
        /** 明确拒绝的 peer 数。 */
        public final long peersRejected;
        /** 断线或无回执的 peer 数;网关<b>不自动重试</b>。 */
        public final long peersUnknown;

        PublishSummary(Map<Integer, Long> fields) {
            this.accepted = get(fields, F_ACCEPTED);
            this.dropped = get(fields, F_DROPPED);
            this.closedSlow = get(fields, F_CLOSED_SLOW);
            this.messages = get(fields, F_MESSAGES);
            this.peersAccepted = get(fields, F_PEERS_ACCEPTED);
            this.peersRejected = get(fields, F_PEERS_REJECTED);
            this.peersUnknown = get(fields, F_PEERS_UNKNOWN);
        }

        @Override
        public String toString() {
            return "PublishSummary{accepted=" + accepted + ", dropped=" + dropped
                    + ", closedSlow=" + closedSlow + ", messages=" + messages
                    + ", peersAccepted=" + peersAccepted + ", peersRejected=" + peersRejected
                    + ", peersUnknown=" + peersUnknown + '}';
        }
    }

    /**
     * 定向单播回执。字段号与 {@link PublishSummary} 共用同一空间,2/3/4 在 push 语义下
     * 无意义且在 .proto 中 reserved。
     */
    public static final class PushSummary {
        /**
         * 目标 user 在线 session 中实际入队的份数。目标完全不在线时为 0,
         * <b>这是正常结果而不是错误</b>——边缘面无离线堆积。
         */
        public final long accepted;
        /** peer 侧实际入队份数。 */
        public final long peersAccepted;
        /** 明确拒绝的 peer 数。 */
        public final long peersRejected;
        /** 断线或无回执的 peer 数。 */
        public final long peersUnknown;

        PushSummary(Map<Integer, Long> fields) {
            this.accepted = get(fields, F_ACCEPTED);
            this.peersAccepted = get(fields, F_PEERS_ACCEPTED);
            this.peersRejected = get(fields, F_PEERS_REJECTED);
            this.peersUnknown = get(fields, F_PEERS_UNKNOWN);
        }

        @Override
        public String toString() {
            return "PushSummary{accepted=" + accepted + ", peersAccepted=" + peersAccepted
                    + ", peersRejected=" + peersRejected + ", peersUnknown=" + peersUnknown + '}';
        }
    }

    /**
     * proto3 省零:网关不发送值为 0 的字段,<b>缺失即 0,不是「未知」</b>。
     * 把缺失当成异常或 null 会让调用方在完全正常的响应上误判。
     */
    private static long get(Map<Integer, Long> fields, int tag) {
        Long value = fields.get(tag);
        return value == null ? 0L : value;
    }

    /**
     * 解析平坦 varint-only 消息。
     *
     * <p>遇到长度前缀字段整段跳过而不是报错:网关将来往回执里加非 varint 字段时,
     * 旧版 SDK 仍应能读懂已有字段(protobuf 前向兼容语义)。
     *
     * @param body 已去掉 gRPC 5 字节前缀的 message 体
     * @return 字段号到值的映射
     */
    static Map<Integer, Long> decodeFlat(byte[] body) {
        Map<Integer, Long> fields = new HashMap<>();
        int cursor = 0;
        while (cursor < body.length) {
            long[] key = readVarint(body, cursor);
            cursor = (int) key[1];
            int tag = (int) (key[0] >>> 3);
            int wireType = (int) (key[0] & 0x7);
            if (wireType == 0) {
                long[] value = readVarint(body, cursor);
                cursor = (int) value[1];
                fields.put(tag, value[0]);
            } else if (wireType == 2) {
                long[] len = readVarint(body, cursor);
                cursor = (int) (len[1] + len[0]);
                if (cursor > body.length) {
                    throw new IllegalArgumentException("length-delimited field overruns summary");
                }
            } else {
                throw new IllegalArgumentException("unsupported protobuf wire type " + wireType);
            }
        }
        return fields;
    }

    /** 返回 {@code [value, nextCursor]}。 */
    private static long[] readVarint(byte[] body, int cursor) {
        long value = 0;
        int shift = 0;
        while (true) {
            if (cursor >= body.length) {
                throw new IllegalArgumentException("varint truncated in summary");
            }
            int b = body[cursor++] & 0xff;
            value |= ((long) (b & 0x7f)) << shift;
            if ((b & 0x80) == 0) {
                return new long[] {value, cursor};
            }
            shift += 7;
            if (shift >= 64) {
                throw new IllegalArgumentException("varint too long in summary");
            }
        }
    }
}
