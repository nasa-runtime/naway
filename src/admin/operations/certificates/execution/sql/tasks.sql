CREATE TABLE naway_material_execution_tasks (
    cluster_id TEXT COLLATE "C" NOT NULL,
    operation_id TEXT COLLATE "C" NOT NULL CHECK (operation_id ~ '^[0-9a-f]{32}$'),
    execution_store TEXT COLLATE "C" NOT NULL,
    proposal_id TEXT COLLATE "C" NOT NULL,
    impact_id TEXT COLLATE "C" NOT NULL,
    material_store TEXT COLLATE "C" NOT NULL CHECK (material_store ~ '^[0-9a-f]{64}$'),
    impact_store TEXT COLLATE "C" NOT NULL CHECK (impact_store ~ '^[0-9a-f]{64}$'),
    material_epoch BIGINT NOT NULL CHECK (material_epoch > 0),
    impact_epoch BIGINT NOT NULL CHECK (impact_epoch > 0),
    scope TEXT COLLATE "C" NOT NULL,
    material_creator TEXT COLLATE "C" NOT NULL,
    material_reviewer TEXT COLLATE "C" NOT NULL CHECK (material_reviewer <> material_creator),
    impact_creator TEXT COLLATE "C" NOT NULL,
    impact_reviewer TEXT COLLATE "C" NOT NULL CHECK (impact_reviewer <> impact_creator AND impact_reviewer <> material_creator),
    material_intent BYTEA NOT NULL CHECK (octet_length(material_intent) = 32),
    impact_digest BYTEA NOT NULL CHECK (octet_length(impact_digest) = 32),
    authority BYTEA NOT NULL CHECK (octet_length(authority) = 32),
    impact_authority BYTEA NOT NULL CHECK (octet_length(impact_authority) = 32),
    candidate_digest BYTEA NOT NULL CHECK (octet_length(candidate_digest) = 32),
    candidate_bytes INTEGER NOT NULL CHECK (candidate_bytes BETWEEN 18 AND 1048592),
    target_count SMALLINT NOT NULL CHECK (target_count BETWEEN 1 AND 128),
    node_count SMALLINT NOT NULL CHECK (node_count BETWEEN 1 AND target_count),
    definition_digest TEXT COLLATE "C" NOT NULL CHECK (definition_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('running', 'releasing', 'halted', 'complete')),
    terminal TEXT CHECK (terminal IN ('completed', 'compensated')),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms > 0),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms >= created_at_ms),
    PRIMARY KEY (cluster_id, operation_id),
    UNIQUE (cluster_id, proposal_id),
    UNIQUE (cluster_id, impact_id),
    FOREIGN KEY (cluster_id, execution_store) REFERENCES naway_material_execution_fence(cluster_id, store_id),
    FOREIGN KEY (cluster_id, proposal_id) REFERENCES naway_certificate_proposals(cluster_id, id),
    FOREIGN KEY (cluster_id, impact_id) REFERENCES naway_material_impact_proposals(cluster_id, id),
    CHECK ((state IN ('running', 'halted') AND terminal IS NULL)
        OR (state IN ('releasing', 'complete') AND terminal IS NOT NULL))
);
CREATE INDEX naway_material_execution_pending ON naway_material_execution_tasks(cluster_id, operation_id)
    WHERE state <> 'complete';

CREATE TABLE naway_material_execution_nodes (
    cluster_id TEXT COLLATE "C" NOT NULL,
    operation_id TEXT COLLATE "C" NOT NULL,
    node_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(node_id) BETWEEN 1 AND 128 AND node_id ~ '^[A-Za-z0-9._-]+$'),
    node_index SMALLINT NOT NULL CHECK (node_index BETWEEN 0 AND 127),
    intent_digest BYTEA NOT NULL CHECK (octet_length(intent_digest) = 32),
    store_id TEXT COLLATE "C" NOT NULL CHECK (store_id ~ '^[A-Za-z0-9_-]{43}$'),
    node_epoch NUMERIC(20, 0) NOT NULL CHECK (node_epoch BETWEEN 1 AND 18446744073709551615),
    report_revision NUMERIC(20, 0) CHECK (report_revision BETWEEN 1 AND 18446744073709551615),
    report BYTEA CHECK (octet_length(report) BETWEEN 2 AND 131072),
    released BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (cluster_id, operation_id, node_id),
    UNIQUE (cluster_id, operation_id, node_index),
    FOREIGN KEY (cluster_id, operation_id) REFERENCES naway_material_execution_tasks(cluster_id, operation_id),
    CHECK ((report_revision IS NULL) = (report IS NULL))
);

CREATE TABLE naway_material_execution_slots (
    cluster_id TEXT COLLATE "C" NOT NULL,
    node_id TEXT COLLATE "C" NOT NULL,
    operation_id TEXT COLLATE "C" NOT NULL,
    owner BYTEA CHECK (octet_length(owner) = 16),
    fence BIGINT NOT NULL DEFAULT 0 CHECK (fence >= 0),
    leased_at_ms BIGINT NOT NULL DEFAULT 0,
    expires_at_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (cluster_id, node_id),
    FOREIGN KEY (cluster_id, operation_id, node_id) REFERENCES naway_material_execution_nodes(cluster_id, operation_id, node_id),
    CHECK ((owner IS NULL AND fence = 0 AND leased_at_ms = 0 AND expires_at_ms = 0)
        OR (owner IS NOT NULL AND fence > 0 AND leased_at_ms > 0 AND expires_at_ms - leased_at_ms = 30000))
);

-- 业务作用：两份原批准、原全批目标与独立永久执行域共同允许首次任务，审批过期不被借作新执行。
-- 参数说明: 无；NEW 由共享工作流创建事务提供。
-- 返回：原批准和有界在途容量一致才受理，不触发节点副作用。
CREATE FUNCTION naway_material_execution_admit() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    material naway_certificate_proposals%ROWTYPE;
    impact naway_material_impact_proposals%ROWTYPE;
    now_ms BIGINT;
BEGIN
    -- 两类节点占位共用原行的并发屏障，但材料只使用自己的永久store与水位签发。
    UPDATE naway_delivery_fence SET watermark = watermark
        WHERE singleton AND cluster_id = NEW.cluster_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'material execution cluster unavailable' USING ERRCODE = 'PN010';
    END IF;
    -- 创建持久行版本后再计数，使并发旧隔离快照不能分别消耗最后一个名额。
    UPDATE naway_material_execution_fence SET watermark = watermark
        WHERE singleton AND cluster_id = NEW.cluster_id AND store_id = NEW.execution_store;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'material execution authority unavailable' USING ERRCODE = 'PN010';
    END IF;
    IF (SELECT count(*) FROM naway_material_execution_tasks WHERE state <> 'complete') >= 16 THEN
        RAISE EXCEPTION 'material execution capacity exhausted' USING ERRCODE = 'PN011';
    END IF;
    SELECT * INTO STRICT material FROM naway_certificate_proposals
        WHERE cluster_id = NEW.cluster_id AND id = NEW.proposal_id FOR UPDATE;
    SELECT * INTO STRICT impact FROM naway_material_impact_proposals
        WHERE cluster_id = NEW.cluster_id AND id = NEW.impact_id AND proposal_id = NEW.proposal_id FOR UPDATE;
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF material.state <> 'approved' OR impact.state <> 'approved'
        OR material.execution_started OR impact.execution_started
        OR now_ms >= material.expires_at_ms OR now_ms >= impact.expires_at_ms
        OR NEW.state <> 'running' OR NEW.terminal IS NOT NULL
        OR NEW.updated_at_ms <> NEW.created_at_ms OR NEW.created_at_ms > now_ms
        OR ROW(NEW.material_epoch, NEW.impact_epoch, NEW.scope, NEW.material_creator, NEW.material_reviewer,
            NEW.impact_creator, NEW.impact_reviewer, NEW.material_intent, NEW.impact_digest,
            NEW.authority, NEW.impact_authority, NEW.candidate_bytes)
        IS DISTINCT FROM ROW(material.admission_epoch, impact.admission_epoch, material.scope,
            material.creator, material.reviewer, impact.creator, impact.reviewer, material.intent_digest,
            impact.impact_digest, material.authority, impact.impact_authority, material.material_bytes)
        OR NEW.material_store IS DISTINCT FROM (SELECT store_id FROM naway_certificate_owners WHERE cluster_id = NEW.cluster_id)
        OR NEW.impact_store IS DISTINCT FROM (SELECT store_id FROM naway_material_impact_owners WHERE cluster_id = NEW.cluster_id)
        OR impact.scope <> material.scope OR impact.material_store_id <> NEW.material_store
        OR impact.material_admission_epoch <> NEW.material_epoch OR impact.material_intent <> NEW.material_intent
        OR impact.material_creator <> NEW.material_creator OR impact.authority <> NEW.authority
        OR NEW.target_count <> jsonb_array_length(convert_from(material.targets, 'UTF8')::jsonb)
        OR NEW.node_count <> jsonb_array_length(convert_from(impact.proof, 'UTF8')::jsonb -> 'nodes') THEN
        RAISE EXCEPTION 'material execution approved identity differs' USING ERRCODE = 'PN010';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_material_execution_admission BEFORE INSERT ON naway_material_execution_tasks
    FOR EACH ROW EXECUTE FUNCTION naway_material_execution_admit();

-- 业务作用：任务身份在首次批准后不可替换，安全终态和全部节点关闭之前持续保留父材料引用。
-- 参数说明: 无；OLD 和 NEW 是同一材料工作流的持久状态。
-- 返回：合法单调状态或完成后的精确回收继续；半完成、原终态改写或分母缺失拒绝。
CREATE FUNCTION naway_material_execution_preserve_task() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'material executions cannot be truncated' USING ERRCODE = 'PN010';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF OLD.state <> 'complete' THEN
            RAISE EXCEPTION 'material execution remains retained' USING ERRCODE = 'PN010';
        END IF;
        RETURN OLD;
    END IF;
    IF ROW(NEW.cluster_id, NEW.operation_id, NEW.execution_store, NEW.proposal_id, NEW.impact_id,
        NEW.material_store, NEW.impact_store, NEW.material_epoch, NEW.impact_epoch, NEW.scope,
        NEW.material_creator, NEW.material_reviewer, NEW.impact_creator, NEW.impact_reviewer,
        NEW.material_intent, NEW.impact_digest, NEW.authority, NEW.impact_authority,
        NEW.candidate_digest, NEW.candidate_bytes, NEW.target_count, NEW.node_count,
        NEW.definition_digest, NEW.created_at_ms)
        IS DISTINCT FROM ROW(OLD.cluster_id, OLD.operation_id, OLD.execution_store, OLD.proposal_id,
        OLD.impact_id, OLD.material_store, OLD.impact_store, OLD.material_epoch, OLD.impact_epoch,
        OLD.scope, OLD.material_creator, OLD.material_reviewer, OLD.impact_creator, OLD.impact_reviewer,
        OLD.material_intent, OLD.impact_digest, OLD.authority, OLD.impact_authority,
        OLD.candidate_digest, OLD.candidate_bytes, OLD.target_count, OLD.node_count,
        OLD.definition_digest, OLD.created_at_ms)
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR (OLD.state IN ('halted', 'complete') AND NEW.state <> OLD.state)
        OR (OLD.state = 'releasing' AND NEW.state NOT IN ('releasing', 'complete'))
        OR (OLD.terminal IS NOT NULL AND NEW.terminal IS DISTINCT FROM OLD.terminal) THEN
        RAISE EXCEPTION 'material execution successor differs' USING ERRCODE = 'PN010';
    END IF;
    IF NEW.state = 'complete' AND OLD.state <> 'complete' THEN
        -- 节点关闭和占位删除都须确认；NASA终态名称本身不释放任何永久节点责任。
        IF OLD.state <> 'releasing'
            OR (SELECT count(*) FROM naway_material_execution_nodes WHERE cluster_id = OLD.cluster_id
                AND operation_id = OLD.operation_id AND released) <> OLD.node_count
            OR EXISTS (SELECT 1 FROM naway_material_execution_slots WHERE cluster_id = OLD.cluster_id
                AND operation_id = OLD.operation_id) THEN
            RAISE EXCEPTION 'material execution release incomplete' USING ERRCODE = 'PN010';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_material_execution_task_change BEFORE UPDATE OR DELETE ON naway_material_execution_tasks
    FOR EACH ROW EXECUTE FUNCTION naway_material_execution_preserve_task();
CREATE TRIGGER naway_material_execution_task_truncate BEFORE TRUNCATE ON naway_material_execution_tasks
    FOR EACH STATEMENT EXECUTE FUNCTION naway_material_execution_preserve_task();
