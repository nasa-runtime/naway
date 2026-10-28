-- 业务作用：目标序号、意图和稳定效果不可替换，已关闭代际不能恢复成未释放状态。
-- 参数说明: 无；OLD 和 NEW 是冻结执行下的单个目标事实。
-- 返回：首次合法目标、单调结果和安全清理继续；其它写入封闭。
CREATE FUNCTION naway_delivery_preserve_target() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    execution naway_delivery_executions%ROWTYPE;
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'delivery targets cannot be truncated' USING ERRCODE = 'PN006';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF NOT OLD.released OR NOT EXISTS (SELECT 1 FROM naway_delivery_executions
            WHERE cluster_id = OLD.cluster_id AND operation_id = OLD.operation_id AND state = 'complete') THEN
            RAISE EXCEPTION 'delivery target is retained' USING ERRCODE = 'PN006';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO STRICT execution FROM naway_delivery_executions
            WHERE cluster_id = NEW.cluster_id AND operation_id = NEW.operation_id FOR UPDATE;
        IF execution.state <> 'running' OR NEW.target_index >= execution.target_count OR NEW.released
            OR NEW.prepare_outcome IS NOT NULL OR NEW.apply_outcome IS NOT NULL
            OR NEW.prepare_compensation IS NOT NULL OR NEW.apply_compensation IS NOT NULL THEN
            RAISE EXCEPTION 'delivery target admission differs' USING ERRCODE = 'PN006';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.cluster_id, NEW.operation_id, NEW.node_id, NEW.target_index, NEW.intent_digest, NEW.store_id, NEW.node_epoch)
        IS DISTINCT FROM ROW(OLD.cluster_id, OLD.operation_id, OLD.node_id, OLD.target_index, OLD.intent_digest, OLD.store_id, OLD.node_epoch)
        OR (OLD.released AND NOT NEW.released)
        OR (OLD.prepare_outcome IS NOT NULL AND OLD.prepare_outcome IS DISTINCT FROM NEW.prepare_outcome)
        OR (OLD.apply_outcome IS NOT NULL AND OLD.apply_outcome IS DISTINCT FROM NEW.apply_outcome)
        OR (OLD.prepare_compensation IS NOT NULL AND OLD.prepare_compensation IS DISTINCT FROM NEW.prepare_compensation)
        OR (OLD.apply_compensation IS NOT NULL AND OLD.apply_compensation IS DISTINCT FROM NEW.apply_compensation) THEN
        RAISE EXCEPTION 'delivery target successor differs' USING ERRCODE = 'PN006';
    END IF;
    IF NEW.released AND NOT OLD.released AND NOT EXISTS (
        SELECT 1 FROM naway_delivery_executions WHERE cluster_id = OLD.cluster_id
            AND operation_id = OLD.operation_id AND state = 'releasing'
    ) THEN
        RAISE EXCEPTION 'delivery target cannot release before safe terminal state' USING ERRCODE = 'PN006';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_delivery_target_change BEFORE INSERT OR UPDATE OR DELETE ON naway_delivery_targets
    FOR EACH ROW EXECUTE FUNCTION naway_delivery_preserve_target();
CREATE TRIGGER naway_delivery_target_truncate BEFORE TRUNCATE ON naway_delivery_targets
    FOR EACH STATEMENT EXECUTE FUNCTION naway_delivery_preserve_target();

-- 业务作用：目标占位只能属于原操作，过期租约不允许另一操作覆盖未知效果。
-- 参数说明: 无；OLD 和 NEW 为当前节点唯一占位。
-- 返回：同意图更高 fence 或已确认关闭后的删除继续，其它替换或清空拒绝。
CREATE FUNCTION naway_delivery_preserve_slot() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'delivery slots cannot be truncated' USING ERRCODE = 'PN006';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF NOT EXISTS (SELECT 1 FROM naway_delivery_targets WHERE cluster_id = OLD.cluster_id
            AND operation_id = OLD.operation_id AND node_id = OLD.node_id AND released) THEN
            RAISE EXCEPTION 'delivery slot is retained' USING ERRCODE = 'PN006';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.owner IS NOT NULL OR NEW.fence <> 0 OR EXISTS (
            SELECT 1 FROM naway_delivery_targets WHERE cluster_id = NEW.cluster_id
                AND operation_id = NEW.operation_id AND node_id = NEW.node_id AND released
        ) THEN
            RAISE EXCEPTION 'delivery slot reservation differs' USING ERRCODE = 'PN006';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.cluster_id, NEW.node_id, NEW.operation_id) IS DISTINCT FROM ROW(OLD.cluster_id, OLD.node_id, OLD.operation_id)
        OR NEW.owner IS NULL OR NEW.fence <= OLD.fence
        OR NOT EXISTS (SELECT 1 FROM naway_delivery_fence WHERE singleton
            AND cluster_id = NEW.cluster_id AND watermark = NEW.fence)
        OR (OLD.owner IS NOT NULL AND NEW.owner IS DISTINCT FROM OLD.owner
            AND OLD.expires_at_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) THEN
        RAISE EXCEPTION 'delivery slot ownership differs' USING ERRCODE = 'PN006';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_delivery_slot_change BEFORE INSERT OR UPDATE OR DELETE ON naway_delivery_slots
    FOR EACH ROW EXECUTE FUNCTION naway_delivery_preserve_slot();
CREATE TRIGGER naway_delivery_slot_truncate BEFORE TRUNCATE ON naway_delivery_slots
    FOR EACH STATEMENT EXECUTE FUNCTION naway_delivery_preserve_slot();
