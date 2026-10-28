CREATE TABLE naway_delivery_schema (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    shape JSONB NOT NULL
);

CREATE TABLE naway_delivery_fence (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    cluster_id TEXT COLLATE "C" NOT NULL,
    watermark BIGINT NOT NULL CHECK (watermark >= 0)
);
INSERT INTO naway_delivery_fence(singleton, cluster_id, watermark)
    SELECT TRUE, cluster_id, 0 FROM naway_operation_namespace
    WHERE singleton AND cluster_id IS NOT NULL;

CREATE TABLE naway_delivery_executions (
    cluster_id TEXT COLLATE "C" NOT NULL,
    operation_id TEXT COLLATE "C" NOT NULL,
    admission_epoch BIGINT NOT NULL CHECK (admission_epoch > 0),
    scope TEXT COLLATE "C" NOT NULL,
    domain TEXT COLLATE "C" NOT NULL,
    creator TEXT COLLATE "C" NOT NULL,
    reviewer TEXT COLLATE "C" NOT NULL CHECK (reviewer <> creator),
    authority BYTEA NOT NULL CHECK (octet_length(authority) = 32),
    candidate_digest BYTEA NOT NULL CHECK (octet_length(candidate_digest) = 32),
    candidate_bytes INTEGER NOT NULL CHECK (candidate_bytes BETWEEN 1 AND 1048576),
    targets BYTEA NOT NULL CHECK (octet_length(targets) BETWEEN 2 AND 65536),
    target_count SMALLINT NOT NULL CHECK (target_count BETWEEN 1 AND 128),
    definition_digest TEXT COLLATE "C" NOT NULL CHECK (definition_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('running', 'releasing', 'halted', 'complete')),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms > 0),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms >= created_at_ms),
    PRIMARY KEY (cluster_id, operation_id),
    FOREIGN KEY (cluster_id, operation_id) REFERENCES naway_operation_proposals(cluster_id, id)
);

CREATE TABLE naway_delivery_targets (
    cluster_id TEXT COLLATE "C" NOT NULL,
    operation_id TEXT COLLATE "C" NOT NULL,
    node_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(node_id) BETWEEN 1 AND 128 AND node_id ~ '^[A-Za-z0-9._-]+$'),
    target_index SMALLINT NOT NULL CHECK (target_index BETWEEN 0 AND 127),
    intent_digest BYTEA NOT NULL CHECK (octet_length(intent_digest) = 32),
    store_id TEXT COLLATE "C" NOT NULL CHECK (store_id ~ '^[A-Za-z0-9_-]{43}$'),
    node_epoch NUMERIC(20, 0) NOT NULL CHECK (node_epoch BETWEEN 1 AND 18446744073709551615),
    prepare_outcome TEXT CHECK (prepare_outcome IN ('SUCCEEDED', 'REJECTED', 'HALTED')),
    apply_outcome TEXT CHECK (apply_outcome IN ('SUCCEEDED', 'REJECTED', 'HALTED')),
    prepare_compensation TEXT CHECK (prepare_compensation IN ('SUCCEEDED', 'HALTED')),
    apply_compensation TEXT CHECK (apply_compensation IN ('SUCCEEDED', 'HALTED')),
    released BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (cluster_id, operation_id, node_id),
    UNIQUE (cluster_id, operation_id, target_index),
    FOREIGN KEY (cluster_id, operation_id) REFERENCES naway_delivery_executions(cluster_id, operation_id)
);

CREATE TABLE naway_delivery_slots (
    cluster_id TEXT COLLATE "C" NOT NULL,
    node_id TEXT COLLATE "C" NOT NULL,
    operation_id TEXT COLLATE "C" NOT NULL,
    owner BYTEA CHECK (octet_length(owner) = 16),
    fence BIGINT NOT NULL DEFAULT 0 CHECK (fence >= 0),
    leased_at_ms BIGINT NOT NULL DEFAULT 0,
    expires_at_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (cluster_id, node_id),
    FOREIGN KEY (cluster_id, operation_id, node_id) REFERENCES naway_delivery_targets(cluster_id, operation_id, node_id),
    CHECK ((owner IS NULL AND fence = 0 AND leased_at_ms = 0 AND expires_at_ms = 0)
        OR (owner IS NOT NULL AND fence > 0 AND leased_at_ms > 0 AND expires_at_ms > leased_at_ms
            AND expires_at_ms - leased_at_ms = 30000))
);
CREATE INDEX naway_delivery_pending ON naway_delivery_executions(cluster_id, operation_id)
    WHERE state <> 'complete';

-- 业务作用：让永久 fence 只保持原值或递增一次，删除和耗尽不能重新发放旧写权。
-- 参数说明: 无；OLD 和 NEW 是数据库正在修改的永久保护行。
-- 返回：同集群合法后继继续，回退、换集群、跳号及移除权威拒绝。
CREATE FUNCTION naway_delivery_preserve_fence() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'delivery authority cannot be removed' USING ERRCODE = 'PN006';
    END IF;
    IF NEW.singleton IS DISTINCT FROM OLD.singleton OR NEW.cluster_id IS DISTINCT FROM OLD.cluster_id
        OR NEW.watermark < OLD.watermark OR NEW.watermark::numeric > OLD.watermark::numeric + 1 THEN
        RAISE EXCEPTION 'delivery fence successor differs' USING ERRCODE = 'PN006';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_delivery_fence_change BEFORE UPDATE OR DELETE ON naway_delivery_fence
    FOR EACH ROW EXECUTE FUNCTION naway_delivery_preserve_fence();
CREATE TRIGGER naway_delivery_fence_truncate BEFORE TRUNCATE ON naway_delivery_fence
    FOR EACH STATEMENT EXECUTE FUNCTION naway_delivery_preserve_fence();

-- 业务作用：冻结已经批准的原意图，并使所有 Admin 共用未释放执行的固定容量。
-- 参数说明: 无；NEW 来自创建工作流的同源事务。
-- 返回：批准、期限、完整元数据及容量同时成立才允许创建；没有节点副作用。
CREATE FUNCTION naway_delivery_admit_execution() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    proposal naway_operation_proposals%ROWTYPE;
BEGIN
    -- 创建行版本使并发旧隔离快照同样发生冲突，不能只在各自快照中计数。
    UPDATE naway_delivery_fence SET watermark = watermark
        WHERE singleton AND cluster_id = NEW.cluster_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'delivery namespace unavailable' USING ERRCODE = 'PN006';
    END IF;
    IF (SELECT count(*) FROM naway_delivery_executions WHERE state <> 'complete') >= 16 THEN
        RAISE EXCEPTION 'delivery execution capacity exceeded' USING ERRCODE = 'PN007';
    END IF;
    SELECT * INTO STRICT proposal FROM naway_operation_proposals
        WHERE cluster_id = NEW.cluster_id AND id = NEW.operation_id FOR UPDATE;
    IF proposal.state <> 'approved' OR proposal.execution_started OR NEW.state <> 'running'
        OR proposal.expires_at_ms <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
        OR ROW(NEW.admission_epoch, NEW.scope, NEW.domain, NEW.creator, NEW.reviewer,
            NEW.authority, NEW.candidate_digest, NEW.candidate_bytes, NEW.targets)
            IS DISTINCT FROM ROW(proposal.admission_epoch, proposal.scope, proposal.domain,
                proposal.creator, proposal.reviewer, proposal.authority, proposal.candidate_digest,
                octet_length(proposal.candidate), proposal.targets) THEN
        RAISE EXCEPTION 'delivery approved intent differs' USING ERRCODE = 'PN006';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_delivery_execution_admission BEFORE INSERT ON naway_delivery_executions
    FOR EACH ROW EXECUTE FUNCTION naway_delivery_admit_execution();

-- 业务作用：执行创建后只能更新生命周期，原批准身份和目标集合不能被重选。
-- 参数说明: 无；OLD 和 NEW 为同一持久执行的状态。
-- 返回：元数据不变且完成条件具备时继续；未释放引用不能被清理。
CREATE FUNCTION naway_delivery_preserve_execution() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'delivery executions cannot be truncated' USING ERRCODE = 'PN006';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF OLD.state <> 'complete' THEN
            RAISE EXCEPTION 'delivery execution is retained' USING ERRCODE = 'PN006';
        END IF;
        RETURN OLD;
    END IF;
    IF ROW(NEW.cluster_id, NEW.operation_id, NEW.admission_epoch, NEW.scope, NEW.domain,
        NEW.creator, NEW.reviewer, NEW.authority, NEW.candidate_digest, NEW.candidate_bytes,
        NEW.targets, NEW.target_count, NEW.definition_digest, NEW.created_at_ms)
        IS DISTINCT FROM ROW(OLD.cluster_id, OLD.operation_id, OLD.admission_epoch, OLD.scope, OLD.domain,
            OLD.creator, OLD.reviewer, OLD.authority, OLD.candidate_digest, OLD.candidate_bytes,
            OLD.targets, OLD.target_count, OLD.definition_digest, OLD.created_at_ms)
        OR NEW.updated_at_ms < OLD.updated_at_ms OR (OLD.state = 'complete' AND NEW.state <> 'complete') THEN
        RAISE EXCEPTION 'delivery execution identity differs' USING ERRCODE = 'PN006';
    END IF;
    IF NEW.state = 'complete' AND OLD.state <> 'complete' THEN
        -- 安全终态由 NASA 结果事务决定；全部冻结目标关闭代际之前不得释放执行容量。
        IF OLD.state <> 'releasing'
            OR (SELECT count(*) FROM naway_delivery_targets WHERE cluster_id = OLD.cluster_id
                AND operation_id = OLD.operation_id AND released) <> OLD.target_count
            OR EXISTS (SELECT 1 FROM naway_delivery_slots WHERE cluster_id = OLD.cluster_id
                AND operation_id = OLD.operation_id) THEN
            RAISE EXCEPTION 'delivery target release incomplete' USING ERRCODE = 'PN006';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_delivery_execution_change BEFORE UPDATE OR DELETE ON naway_delivery_executions
    FOR EACH ROW EXECUTE FUNCTION naway_delivery_preserve_execution();
CREATE TRIGGER naway_delivery_execution_truncate BEFORE TRUNCATE ON naway_delivery_executions
    FOR EACH STATEMENT EXECUTE FUNCTION naway_delivery_preserve_execution();
