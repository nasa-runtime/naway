ALTER TABLE naway_operation_clusters
    ADD COLUMN epoch_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN current_epoch BIGINT NOT NULL DEFAULT 0 CHECK (current_epoch >= 0),
    ADD COLUMN epoch_expires_at_ms BIGINT NOT NULL DEFAULT 0 CHECK (epoch_expires_at_ms >= 0),
    ADD COLUMN epoch_window_ms BIGINT NOT NULL DEFAULT 900000 CHECK (epoch_window_ms BETWEEN 60000 AND 86400000),
    ADD COLUMN retention_contract BYTEA CHECK (octet_length(retention_contract) = 32);

ALTER TABLE naway_operation_proposals
    ADD COLUMN admission_epoch BIGINT NOT NULL DEFAULT 0 CHECK (admission_epoch >= 0),
    ADD COLUMN execution_started BOOLEAN NOT NULL DEFAULT FALSE;

-- 业务作用：让所有数据库写入者经过同一受理代际门，旧进程不能在记录清理后重新创建旧请求。
-- 参数说明: 无。NEW 由 PostgreSQL 提供待写入记录。
-- 返回：持久权威仍接受此代际时返回 NEW；否则拒绝整条 INSERT。
CREATE FUNCTION naway_validate_proposal_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    authority naway_operation_clusters%ROWTYPE;
BEGIN
    -- 与代际轮换和清理争同一行锁，防止先证明旧代际、后在新代际下写入。
    SELECT * INTO STRICT authority FROM naway_operation_clusters
        WHERE cluster_id = NEW.cluster_id FOR UPDATE;
    IF NEW.admission_epoch = 0 THEN
        IF authority.epoch_required THEN
            RAISE EXCEPTION 'proposal admission epoch required' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.admission_epoch <> authority.current_epoch
        OR authority.epoch_expires_at_ms <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint THEN
        RAISE EXCEPTION 'proposal admission epoch expired' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_proposal_epoch_gate BEFORE INSERT ON naway_operation_proposals
    FOR EACH ROW EXECUTE FUNCTION naway_validate_proposal_epoch();

-- 业务作用：保持受理协议只向前推进，已关闭的兼容新建能力不能因旧配置或时间回拨恢复。
-- 参数说明: 无。OLD 和 NEW 由 PostgreSQL 提供同一集群的权威记录。
-- 返回：代际及保留合同未倒退时返回 NEW；否则拒绝整条 UPDATE。
CREATE FUNCTION naway_preserve_operation_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- 删除过旧幂等行之后，恢复兼容入口会让原请求再次执行，因此强制门不可解除。
    IF OLD.epoch_required AND NOT NEW.epoch_required
        OR NEW.current_epoch < OLD.current_epoch
        OR OLD.retention_contract IS NOT NULL AND (
            NEW.retention_contract IS DISTINCT FROM OLD.retention_contract
            OR NEW.epoch_window_ms <> OLD.epoch_window_ms
        ) THEN
        RAISE EXCEPTION 'operation admission authority cannot regress' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_operation_epoch_authority BEFORE UPDATE ON naway_operation_clusters
    FOR EACH ROW EXECUTE FUNCTION naway_preserve_operation_epoch();
