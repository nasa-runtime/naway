-- 业务作用：为同一冻结目标取得数据库期限和新 fence，不把 Outbox 的内部租约当成节点写权。
-- 参数说明：
-- - p_cluster：已永久绑定的集群。
-- - p_operation：原工作流操作身份。
-- - p_node：原冻结节点。
-- - p_intent：节点稳定业务意图摘要。
-- - p_owner：本进程独立随机 owner。
-- 返回：当前事务内的新 fence、数据库取得时刻和期限；外层明确 COMMIT 前不得签发。
CREATE FUNCTION naway_delivery_acquire(
    p_cluster TEXT, p_operation TEXT, p_node TEXT, p_intent BYTEA, p_owner BYTEA
) RETURNS TABLE(fence BIGINT, now_ms BIGINT, expires_at_ms BIGINT)
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    previous BIGINT;
    granted BIGINT;
    observed BIGINT;
    slot naway_delivery_slots%ROWTYPE;
BEGIN
    IF octet_length(p_owner) <> 16 OR octet_length(p_intent) <> 32 OR p_owner IS NULL OR p_intent IS NULL THEN
        RAISE EXCEPTION 'delivery lease identity invalid' USING ERRCODE = 'PN006';
    END IF;
    -- 所有占位和租约先锁同一永久行，再锁目标；旧隔离快照不得略过新 owner 的提交。
    UPDATE naway_delivery_fence SET watermark = watermark
        WHERE singleton AND cluster_id = p_cluster RETURNING watermark INTO previous;
    IF NOT FOUND OR previous = 9223372036854775807 THEN
        RAISE EXCEPTION 'delivery fence unavailable or exhausted' USING ERRCODE = 'PN006';
    END IF;
    SELECT * INTO slot FROM naway_delivery_slots
        WHERE cluster_id = p_cluster AND node_id = p_node FOR UPDATE;
    IF NOT FOUND OR slot.operation_id <> p_operation OR NOT EXISTS (
        SELECT 1 FROM naway_delivery_targets t JOIN naway_delivery_executions e
            ON e.cluster_id = t.cluster_id AND e.operation_id = t.operation_id
        WHERE t.cluster_id = p_cluster AND t.operation_id = p_operation AND t.node_id = p_node
            AND t.intent_digest = p_intent AND NOT t.released AND e.state IN ('running', 'releasing')
    ) THEN
        RAISE EXCEPTION 'delivery target ownership differs' USING ERRCODE = 'PN006';
    END IF;
    observed := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF slot.owner IS NOT NULL AND slot.owner <> p_owner AND slot.expires_at_ms > observed THEN
        RAISE EXCEPTION 'delivery target leased by another owner' USING ERRCODE = 'PN008';
    END IF;
    granted := previous + 1;
    UPDATE naway_delivery_fence SET watermark = granted WHERE singleton AND cluster_id = p_cluster;
    UPDATE naway_delivery_slots SET owner = p_owner, fence = granted,
        leased_at_ms = observed, expires_at_ms = observed + 30000
        WHERE cluster_id = p_cluster AND node_id = p_node;
    RETURN QUERY SELECT granted, observed, observed + 30000;
END;
$$;
