-- 业务作用：同节点完整事实只能沿原报告后继前进，首次受理前不能预填收据或关闭证明。
-- 参数说明: 无；OLD 和 NEW 为原物理节点的固定责任。
-- 返回：完整原身份不变且报告与关闭标记单调时继续；缺报告、回退或提前释放拒绝。
CREATE FUNCTION naway_material_execution_preserve_node() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    task naway_material_execution_tasks%ROWTYPE;
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'material execution nodes cannot be truncated' USING ERRCODE = 'PN010';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF NOT OLD.released OR NOT EXISTS (
            SELECT 1 FROM naway_material_execution_tasks WHERE cluster_id = OLD.cluster_id
                AND operation_id = OLD.operation_id AND state = 'complete'
        ) THEN
            RAISE EXCEPTION 'material execution node remains retained' USING ERRCODE = 'PN010';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO STRICT task FROM naway_material_execution_tasks
            WHERE cluster_id = NEW.cluster_id AND operation_id = NEW.operation_id FOR UPDATE;
        IF task.state <> 'running' OR NEW.node_index >= task.node_count
            OR NEW.released OR NEW.report IS NOT NULL OR NEW.report_revision IS NOT NULL THEN
            RAISE EXCEPTION 'material execution node admission differs' USING ERRCODE = 'PN010';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.cluster_id, NEW.operation_id, NEW.node_id, NEW.node_index, NEW.intent_digest, NEW.store_id, NEW.node_epoch)
        IS DISTINCT FROM ROW(OLD.cluster_id, OLD.operation_id, OLD.node_id, OLD.node_index, OLD.intent_digest, OLD.store_id, OLD.node_epoch)
        OR (OLD.released AND NOT NEW.released)
        OR (OLD.report_revision IS NOT NULL AND (NEW.report_revision IS NULL OR NEW.report_revision < OLD.report_revision))
        OR (OLD.report_revision = NEW.report_revision AND NEW.report IS DISTINCT FROM OLD.report)
        OR (OLD.released AND ROW(NEW.report_revision, NEW.report) IS DISTINCT FROM ROW(OLD.report_revision, OLD.report)) THEN
        RAISE EXCEPTION 'material execution node successor differs' USING ERRCODE = 'PN010';
    END IF;
    IF NEW.released AND NOT OLD.released AND NOT EXISTS (
        SELECT 1 FROM naway_material_execution_tasks WHERE cluster_id = OLD.cluster_id
            AND operation_id = OLD.operation_id AND state = 'releasing'
    ) THEN
        RAISE EXCEPTION 'material execution safe terminal absent' USING ERRCODE = 'PN010';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_material_execution_node_change BEFORE INSERT OR UPDATE OR DELETE ON naway_material_execution_nodes
    FOR EACH ROW EXECUTE FUNCTION naway_material_execution_preserve_node();
CREATE TRIGGER naway_material_execution_node_truncate BEFORE TRUNCATE ON naway_material_execution_nodes
    FOR EACH STATEMENT EXECUTE FUNCTION naway_material_execution_preserve_node();

-- 业务作用：材料节点租约只接管原意图，占位必须保留至同一节点关闭事实提交。
-- 参数说明: 无；OLD 和 NEW 是节点独占槽。
-- 返回：首次空租约、同意图更高材料水位或已关闭删除继续；换任务、越域水位和提前回收拒绝。
CREATE FUNCTION naway_material_execution_preserve_slot() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'material execution slots cannot be truncated' USING ERRCODE = 'PN010';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF NOT EXISTS (SELECT 1 FROM naway_material_execution_nodes WHERE cluster_id = OLD.cluster_id
            AND operation_id = OLD.operation_id AND node_id = OLD.node_id AND released) THEN
            RAISE EXCEPTION 'material execution slot remains retained' USING ERRCODE = 'PN010';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.owner IS NOT NULL OR NEW.fence <> 0 OR EXISTS (
            SELECT 1 FROM naway_material_execution_nodes WHERE cluster_id = NEW.cluster_id
                AND operation_id = NEW.operation_id AND node_id = NEW.node_id AND released
        ) THEN
            RAISE EXCEPTION 'material execution slot admission differs' USING ERRCODE = 'PN010';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.cluster_id, NEW.node_id, NEW.operation_id) IS DISTINCT FROM ROW(OLD.cluster_id, OLD.node_id, OLD.operation_id)
        OR NEW.owner IS NULL OR NEW.fence <= OLD.fence
        OR NOT EXISTS (SELECT 1 FROM naway_material_execution_fence WHERE singleton
            AND cluster_id = NEW.cluster_id AND watermark = NEW.fence)
        OR (OLD.owner IS NOT NULL AND NEW.owner IS DISTINCT FROM OLD.owner
            AND OLD.expires_at_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) THEN
        RAISE EXCEPTION 'material execution lease authority differs' USING ERRCODE = 'PN010';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_material_execution_slot_change BEFORE INSERT OR UPDATE OR DELETE ON naway_material_execution_slots
    FOR EACH ROW EXECUTE FUNCTION naway_material_execution_preserve_slot();
CREATE TRIGGER naway_material_execution_slot_truncate BEFORE TRUNCATE ON naway_material_execution_slots
    FOR EACH STATEMENT EXECUTE FUNCTION naway_material_execution_preserve_slot();

-- 业务作用：配置与材料任务争用同一物理节点时由持久行版本串行裁决，不能各自看到对方尚未提交。
-- 参数说明: 无；NEW 是任一独立执行域首次预留的节点槽。
-- 返回：另一域没有保留责任时继续；即使旧租约到期也不允许覆盖未知节点效果。
CREATE FUNCTION naway_material_execution_cross_slot() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    -- 只用共同原行建立并发屏障；材料投递签名仍必须取得自身独立store/fence的明确提交。
    UPDATE naway_delivery_fence SET watermark = watermark WHERE singleton AND cluster_id = NEW.cluster_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'material execution cluster authority absent' USING ERRCODE = 'PN010';
    END IF;
    IF (TG_TABLE_NAME = 'naway_delivery_slots' AND EXISTS (
        SELECT 1 FROM naway_material_execution_slots WHERE cluster_id = NEW.cluster_id AND node_id = NEW.node_id
    )) OR (TG_TABLE_NAME = 'naway_material_execution_slots' AND EXISTS (
        SELECT 1 FROM naway_delivery_slots WHERE cluster_id = NEW.cluster_id AND node_id = NEW.node_id
    )) THEN
        RAISE EXCEPTION 'node retained by another execution domain' USING ERRCODE = 'PN010';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_material_execution_cross_config BEFORE INSERT ON naway_delivery_slots
    FOR EACH ROW EXECUTE FUNCTION naway_material_execution_cross_slot();
CREATE TRIGGER naway_material_execution_cross_material BEFORE INSERT ON naway_material_execution_slots
    FOR EACH ROW EXECUTE FUNCTION naway_material_execution_cross_slot();
