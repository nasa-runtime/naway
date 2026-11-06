-- 业务作用：对原材料节点取得独立永久域的新水位与数据库期限，Outbox领取权不能代替此租约。
-- 参数说明：
-- - p_cluster：共享存储永久绑定的原集群。
-- - p_store：材料任务最初冻结的独立执行存储身份。
-- - p_operation：原工作流任务。
-- - p_node：原物理节点。
-- - p_intent：包含节点位置与完整原批准的意图摘要。
-- - p_owner：本次发行进程的独立随机owner。
-- 返回：当前事务内的新材料水位和有限期限；外层确认COMMIT后才可签发命令。
CREATE FUNCTION naway_material_execution_acquire(
    p_cluster TEXT, p_store TEXT, p_operation TEXT, p_node TEXT, p_intent BYTEA, p_owner BYTEA
) RETURNS TABLE(fence BIGINT, now_ms BIGINT, expires_at_ms BIGINT)
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    previous BIGINT;
    granted BIGINT;
    observed BIGINT;
    slot naway_material_execution_slots%ROWTYPE;
BEGIN
    IF octet_length(p_owner) <> 16 OR octet_length(p_intent) <> 32 OR p_owner IS NULL OR p_intent IS NULL THEN
        RAISE EXCEPTION 'material execution lease identity invalid' USING ERRCODE = 'PN010';
    END IF;
    -- 所有材料租约与任务预留保持共同并发门先于材料水位，避免跨域占位出现反向锁序。
    UPDATE naway_delivery_fence SET watermark = watermark WHERE singleton AND cluster_id = p_cluster;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'material execution cluster unavailable' USING ERRCODE = 'PN010';
    END IF;
    UPDATE naway_material_execution_fence SET watermark = watermark
        WHERE singleton AND cluster_id = p_cluster AND store_id = p_store RETURNING watermark INTO previous;
    IF NOT FOUND OR previous = 9223372036854775807 THEN
        RAISE EXCEPTION 'material execution fence unavailable or exhausted' USING ERRCODE = 'PN010';
    END IF;
    SELECT * INTO slot FROM naway_material_execution_slots
        WHERE cluster_id = p_cluster AND node_id = p_node FOR UPDATE;
    IF NOT FOUND OR slot.operation_id <> p_operation OR NOT EXISTS (
        SELECT 1 FROM naway_material_execution_nodes n JOIN naway_material_execution_tasks t
            ON t.cluster_id = n.cluster_id AND t.operation_id = n.operation_id
        WHERE n.cluster_id = p_cluster AND n.operation_id = p_operation AND n.node_id = p_node
            AND n.intent_digest = p_intent AND NOT n.released AND t.execution_store = p_store
            AND t.state IN ('running', 'releasing')
    ) THEN
        RAISE EXCEPTION 'material execution original node differs' USING ERRCODE = 'PN010';
    END IF;
    observed := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF slot.owner IS NOT NULL AND slot.owner <> p_owner AND slot.expires_at_ms > observed THEN
        RAISE EXCEPTION 'material execution leased by another owner' USING ERRCODE = 'PN012';
    END IF;
    granted := previous + 1;
    UPDATE naway_material_execution_fence SET watermark = granted
        WHERE singleton AND cluster_id = p_cluster AND store_id = p_store;
    UPDATE naway_material_execution_slots SET owner = p_owner, fence = granted,
        leased_at_ms = observed, expires_at_ms = observed + 30000
        WHERE cluster_id = p_cluster AND node_id = p_node;
    RETURN QUERY SELECT granted, observed, observed + 30000;
END;
$$;
