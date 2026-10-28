package com.naway.edge;

import java.util.HashMap;
import java.util.Map;

/**
 * 两个回执消息的解析与语义。
 *
 * <p>wire 契约见 {@code proto/naway/edge/v1/edge.proto}，字段号必须与网关保持一致。
 * 回执是平坦的 varint-only 结构，因此直接解析而不依赖 protoc 构建期代码生成。
 * proto3 省略零值字段，缺失计数必须解释为零，不能解释为未知或读取失败。
 */
public final class EdgeSummaries {

    /**
     * 业务作用：限制回执解析工具类实例化，业务只通过静态解析入口使用它。
     *
     *
     * 返回：不提供可供业务调用的实例。
     *
     * 参数说明: 无。
     */
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

        /**
         * 业务作用：按共享字段号构造群播回执，缺失的 proto3 计数字段按零处理。
         *
         *
         * 返回：冻结全部群播计数；没有对应字段的计数为零。
         *
         * 参数说明：
         * @param fields 已解析的 protobuf 字段号与计数映射。
         */
        PublishSummary(Map<Integer, Long> fields) {
            this.accepted = get(fields, F_ACCEPTED);
            this.dropped = get(fields, F_DROPPED);
            this.closedSlow = get(fields, F_CLOSED_SLOW);
            this.messages = get(fields, F_MESSAGES);
            this.peersAccepted = get(fields, F_PEERS_ACCEPTED);
            this.peersRejected = get(fields, F_PEERS_REJECTED);
            this.peersUnknown = get(fields, F_PEERS_UNKNOWN);
        }

        /**
         * 业务作用：输出群播回执计数摘要，不把入队数误标为最终交付数。
         *
         *
         * 返回：仅包含入队、丢弃、处理与 peer 计数的文本。
         *
         * 参数说明: 无。
         */
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

        /**
         * 业务作用：按共享字段号构造定向回执，离线目标的零入队数仍是正常结果。
         *
         *
         * 返回：冻结定向入队与 peer 计数，不创建离线投递状态。
         *
         * 参数说明：
         * @param fields 已解析的 protobuf 字段号与计数映射。
         */
        PushSummary(Map<Integer, Long> fields) {
            this.accepted = get(fields, F_ACCEPTED);
            this.peersAccepted = get(fields, F_PEERS_ACCEPTED);
            this.peersRejected = get(fields, F_PEERS_REJECTED);
            this.peersUnknown = get(fields, F_PEERS_UNKNOWN);
        }

        /**
         * 业务作用：输出定向回执计数摘要，保留 peer 拒绝与未知结果的区别。
         *
         *
         * 返回：仅包含本地与 peer 入队结果的文本。
         *
         * 参数说明: 无。
         */
        @Override
        public String toString() {
            return "PushSummary{accepted=" + accepted + ", peersAccepted=" + peersAccepted
                    + ", peersRejected=" + peersRejected + ", peersUnknown=" + peersUnknown + '}';
        }
    }

    /**
     * 业务作用：proto3 省零:网关不发送值为 0 的字段,<b>缺失即 0,不是「未知」</b>。
     * 把缺失当成异常或 null 会让调用方在完全正常的响应上误判。
     *
     * 返回：字段存在时返回原值，否则返回零。
     *
     * 参数说明：
     * @param fields 已解析的计数字段映射。
     * @param tag 公开回执协议中的字段号。
     */
    private static long get(Map<Integer, Long> fields, int tag) {
        Long value = fields.get(tag);
        return value == null ? 0L : value;
    }

    /**
     * 业务作用：解析平坦 varint-only 消息。
     *
     * <p>遇到长度前缀字段整段跳过而不是报错:网关将来往回执里加非 varint 字段时,
     * 旧版 SDK 仍应能读懂已有字段(protobuf 前向兼容语义)。
     *
     *
     * 参数说明：
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

    /**
     * 业务作用：返回 {@code [value, nextCursor]}。
     *
     * 返回：解码值与下一偏移；截断或超过 varint 位宽时抛出异常。
     *
     * 参数说明：
     * @param body 完整回执 message。
     * @param cursor 待解码 varint 的起始偏移。
     */
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
