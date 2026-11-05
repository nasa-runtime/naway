CREATE TABLE naway_material_impact_schema (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    shape JSONB NOT NULL
);

CREATE TABLE naway_material_impact_owners (
    cluster_id TEXT COLLATE "C" PRIMARY KEY REFERENCES naway_certificate_owners(cluster_id),
    store_id TEXT COLLATE "C" NOT NULL UNIQUE CHECK (store_id ~ '^[0-9a-f]{64}$'),
    max_records INTEGER NOT NULL CHECK (max_records BETWEEN 1 AND 4096),
    max_records_per_scope INTEGER NOT NULL CHECK (max_records_per_scope BETWEEN 1 AND max_records),
    max_total_bytes BIGINT NOT NULL CHECK (max_total_bytes BETWEEN 4198400 AND 67108864),
    retain_ms BIGINT NOT NULL CHECK (retain_ms BETWEEN 60000 AND 2678400000)
);

CREATE TABLE naway_material_impact_proposals (
    cluster_id TEXT COLLATE "C" NOT NULL REFERENCES naway_material_impact_owners(cluster_id),
    id TEXT COLLATE "C" NOT NULL CHECK (id ~ '^[0-9a-f]{32}$'),
    proposal_id TEXT COLLATE "C" NOT NULL CHECK (proposal_id ~ '^[0-9a-f]{32}$'),
    scope TEXT COLLATE "C" NOT NULL CHECK (octet_length(scope) BETWEEN 1 AND 128),
    creator TEXT COLLATE "C" NOT NULL CHECK (octet_length(creator) BETWEEN 1 AND 128),
    material_creator TEXT COLLATE "C" NOT NULL CHECK (octet_length(material_creator) BETWEEN 1 AND 128),
    reviewer TEXT COLLATE "C" CHECK (octet_length(reviewer) BETWEEN 1 AND 128),
    client_key TEXT COLLATE "C" NOT NULL CHECK (octet_length(client_key) BETWEEN 1 AND 128),
    admission_epoch BIGINT NOT NULL CHECK (admission_epoch > 0),
    material_admission_epoch BIGINT NOT NULL CHECK (material_admission_epoch > 0),
    material_store_id TEXT COLLATE "C" NOT NULL CHECK (material_store_id ~ '^[0-9a-f]{64}$'),
    authority BYTEA NOT NULL CHECK (octet_length(authority) = 32),
    impact_authority BYTEA NOT NULL CHECK (octet_length(impact_authority) = 32),
    material_intent BYTEA NOT NULL CHECK (octet_length(material_intent) = 32),
    impact_digest BYTEA NOT NULL CHECK (octet_length(impact_digest) = 32),
    proof BYTEA NOT NULL CHECK (octet_length(proof) BETWEEN 2 AND 4194304),
    reserved_bytes BIGINT NOT NULL CHECK (reserved_bytes = octet_length(proof)::bigint + 4096),
    issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms >= 0),
    observed_until_ms BIGINT NOT NULL CHECK (observed_until_ms > issued_at_ms AND observed_until_ms <= issued_at_ms + 20000),
    state TEXT NOT NULL CHECK (state IN ('awaiting_approval', 'approved', 'rejected', 'cancelled')),
    execution_started BOOLEAN NOT NULL DEFAULT FALSE CHECK (NOT execution_started),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms >= created_at_ms),
    PRIMARY KEY (cluster_id, id),
    UNIQUE (cluster_id, proposal_id),
    UNIQUE (cluster_id, scope, creator, admission_epoch, client_key),
    FOREIGN KEY (cluster_id, proposal_id) REFERENCES naway_certificate_proposals(cluster_id, id),
    CHECK ((state = 'awaiting_approval' AND reviewer IS NULL)
        OR (state IN ('approved', 'rejected') AND reviewer IS NOT NULL
            AND reviewer <> creator AND reviewer <> material_creator)
        OR (state = 'cancelled' AND reviewer = creator))
);
CREATE INDEX naway_material_impact_scope ON naway_material_impact_proposals(cluster_id, scope, id);

-- 业务作用：只在已绑定材料存储内首次登记影响owner，重启不能重置共享容量或替换身份。
-- 参数说明: 无；触发器的NEW来自明确启用的存储登记，UPDATE和DELETE不具有修改权威。
-- 返回：合法首次登记返回NEW；异集群、不同保留责任或任意改写拒绝整个语句。
CREATE FUNCTION naway_material_impact_preserve_owner() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    keep_ms BIGINT;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'material impact storage authority is immutable';
    END IF;
    -- 影响容量与材料容量共用集群裁决，但分别保持不可变的owner，不借新功能改变既有预算。
    PERFORM 1 FROM naway_operation_clusters WHERE cluster_id = NEW.cluster_id FOR UPDATE;
    SELECT retain_ms INTO STRICT keep_ms FROM naway_certificate_owners WHERE cluster_id = NEW.cluster_id;
    IF NEW.retain_ms <> keep_ms OR NOT EXISTS (
        SELECT 1 FROM naway_operation_namespace WHERE singleton AND cluster_id = NEW.cluster_id
    ) THEN
        RAISE EXCEPTION 'material impact requires original bound retention authority';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_material_impact_owner_guard BEFORE INSERT OR UPDATE OR DELETE ON naway_material_impact_owners
FOR EACH ROW EXECUTE FUNCTION naway_material_impact_preserve_owner();

-- 业务作用：在共享权威锁内核对全部影响记录的容量，多个Admin不能分别消耗同一份预算。
-- 参数说明：
-- - p_cluster：已绑定原材料存储的发行集群。
-- - p_scope：当前精确平台或工作区域。
-- - p_bytes：实际证明字节与固定元数据所占的完整容量。
-- 返回：所有预算成立时无返回值；缺owner或任一预算耗尽时拒绝，不删除旧记录腾挪空间。
CREATE FUNCTION naway_material_impact_capacity(p_cluster TEXT, p_scope TEXT, p_bytes BIGINT)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    owner naway_material_impact_owners%ROWTYPE;
    records BIGINT;
    scoped BIGINT;
    retained BIGINT;
BEGIN
    PERFORM 1 FROM naway_operation_clusters WHERE cluster_id = p_cluster FOR UPDATE;
    SELECT * INTO STRICT owner FROM naway_material_impact_owners WHERE cluster_id = p_cluster FOR UPDATE;
    SELECT count(*), count(*) FILTER (WHERE scope = p_scope), coalesce(sum(reserved_bytes), 0)
    INTO records, scoped, retained FROM naway_material_impact_proposals WHERE cluster_id = p_cluster;
    IF p_bytes < 4098 OR p_bytes > 4198400 OR records >= owner.max_records
        OR scoped >= owner.max_records_per_scope OR retained > owner.max_total_bytes - p_bytes THEN
        RAISE EXCEPTION 'material impact capacity exhausted' USING ERRCODE = 'PN001';
    END IF;
END;
$$;

-- 业务作用：保护影响登记、独立审阅和联合回收，旧材料批准不能被当作完整影响批准。
-- 参数说明: 无；触发器按当前行操作使用数据库提供的OLD和NEW。
-- 返回：原材料仍有效且符合明确状态迁移才继续；登记期限、不可变意图或保留责任不成立则回滚。
CREATE FUNCTION naway_material_impact_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    cluster naway_operation_clusters%ROWTYPE;
    material naway_certificate_proposals%ROWTYPE;
    owner naway_material_impact_owners%ROWTYPE;
    original_store TEXT;
    selected_cluster TEXT;
    selected_proposal TEXT;
    now_ms BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        selected_cluster := NEW.cluster_id;
        selected_proposal := NEW.proposal_id;
    ELSE
        selected_cluster := OLD.cluster_id;
        selected_proposal := OLD.proposal_id;
    END IF;
    -- 集群、影响owner、原材料的固定锁序与应用事务一致，不能在审阅和回收时倒置权威顺序。
    SELECT * INTO STRICT cluster FROM naway_operation_clusters WHERE cluster_id = selected_cluster FOR UPDATE;
    SELECT * INTO STRICT owner FROM naway_material_impact_owners WHERE cluster_id = selected_cluster FOR UPDATE;
    SELECT * INTO STRICT material FROM naway_certificate_proposals
    WHERE cluster_id = selected_cluster AND id = selected_proposal FOR UPDATE;
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF TG_OP = 'DELETE' THEN
        -- 父材料和影响记录都退出原受理代且无执行责任后才可联合释放，父取消不会留下可用孤立批准。
        IF NOT cluster.epoch_required OR OLD.admission_epoch >= cluster.current_epoch
            OR material.admission_epoch >= cluster.current_epoch
            OR OLD.execution_started OR material.execution_started
            OR (CASE WHEN material.state IN ('rejected', 'cancelled') THEN material.updated_at_ms
                ELSE material.expires_at_ms END) > now_ms - owner.retain_ms THEN
            RAISE EXCEPTION 'material impact retention responsibility remains';
        END IF;
        RETURN OLD;
    END IF;
    SELECT store_id INTO STRICT original_store FROM naway_certificate_owners WHERE cluster_id = selected_cluster;
    -- 父记录失效立即关闭新的登记和审批，不能从先前已通过的节点预检恢复它的写入资格。
    IF material.state NOT IN ('awaiting_approval', 'approved') OR material.execution_started
        OR now_ms >= material.expires_at_ms OR NEW.scope <> material.scope
        OR NEW.material_creator <> material.creator OR NEW.authority <> material.authority
        OR NEW.material_intent <> material.intent_digest OR NEW.material_store_id <> original_store
        OR NEW.material_admission_epoch <> material.admission_epoch
        OR NEW.expires_at_ms <> material.expires_at_ms THEN
        RAISE EXCEPTION 'original material authority changed' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NOT cluster.epoch_required OR cluster.current_epoch <> NEW.admission_epoch
            OR now_ms >= cluster.epoch_expires_at_ms OR NEW.created_at_ms > now_ms
            OR NEW.issued_at_ms > now_ms + 5000 OR NEW.observed_until_ms <= now_ms
            OR NEW.state <> 'awaiting_approval' OR NEW.updated_at_ms <> NEW.created_at_ms THEN
            RAISE EXCEPTION 'material impact admission closed' USING ERRCODE = '23514';
        END IF;
        PERFORM naway_material_impact_capacity(NEW.cluster_id, NEW.scope, NEW.reserved_bytes);
        RETURN NEW;
    END IF;
    IF ROW(
        NEW.cluster_id,
        NEW.id,
        NEW.proposal_id,
        NEW.scope,
        NEW.creator,
        NEW.material_creator,
        NEW.client_key,
        NEW.admission_epoch,
        NEW.material_admission_epoch,
        NEW.material_store_id,
        NEW.authority,
        NEW.impact_authority,
        NEW.material_intent,
        NEW.impact_digest,
        NEW.proof,
        NEW.reserved_bytes,
        NEW.issued_at_ms,
        NEW.observed_until_ms,
        NEW.execution_started,
        NEW.created_at_ms,
        NEW.expires_at_ms
    ) IS DISTINCT FROM ROW(
        OLD.cluster_id,
        OLD.id,
        OLD.proposal_id,
        OLD.scope,
        OLD.creator,
        OLD.material_creator,
        OLD.client_key,
        OLD.admission_epoch,
        OLD.material_admission_epoch,
        OLD.material_store_id,
        OLD.authority,
        OLD.impact_authority,
        OLD.material_intent,
        OLD.impact_digest,
        OLD.proof,
        OLD.reserved_bytes,
        OLD.issued_at_ms,
        OLD.observed_until_ms,
        OLD.execution_started,
        OLD.created_at_ms,
        OLD.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'material impact intent is immutable';
    END IF;
    IF OLD.state <> 'awaiting_approval' OR NEW.state = 'awaiting_approval'
        OR now_ms >= OLD.expires_at_ms OR NEW.updated_at_ms < OLD.updated_at_ms OR NEW.updated_at_ms > now_ms THEN
        RAISE EXCEPTION 'material impact review conflict' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_material_impact_proposal_guard BEFORE INSERT OR UPDATE OR DELETE ON naway_material_impact_proposals
FOR EACH ROW EXECUTE FUNCTION naway_material_impact_guard();
