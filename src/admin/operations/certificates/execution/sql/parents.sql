ALTER TABLE naway_certificate_proposals DROP CONSTRAINT naway_certificate_proposals_execution_started_check;

-- 业务作用：保留原材料批准的受理和审阅门，并仅由原共享任务改变执行保留标记。
-- 参数说明: 无；OLD 和 NEW 是原批准行，任务状态由同一事务验证。
-- 返回：原合法受理、审阅、执行标记或精确回收继续；未知责任保持拒绝。
CREATE OR REPLACE FUNCTION naway_certificate_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    cluster naway_operation_clusters%ROWTYPE;
    now_ms BIGINT;
    keep_ms BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.execution_started THEN
            RAISE EXCEPTION 'material proposal cannot begin with execution responsibility' USING ERRCODE = 'PN010';
        END IF;
        SELECT * INTO STRICT cluster FROM naway_operation_clusters WHERE cluster_id = NEW.cluster_id FOR UPDATE;
        now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
        IF NOT cluster.epoch_required OR cluster.current_epoch <> NEW.admission_epoch
            OR now_ms >= cluster.epoch_expires_at_ms OR NEW.created_at_ms > now_ms
            OR NEW.expires_at_ms <= now_ms OR NEW.state <> 'awaiting_approval'
            OR NEW.updated_at_ms <> NEW.created_at_ms THEN
            RAISE EXCEPTION 'certificate proposal admission closed' USING ERRCODE = '23514';
        END IF;
        PERFORM naway_certificate_capacity(NEW.cluster_id, NEW.scope, NEW.reserved_bytes, NEW.material_bytes);
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        -- 原受理代永久关闭且没有交付责任后才能释放材料，防止删除收据后旧请求重新建立效果。
        SELECT * INTO STRICT cluster FROM naway_operation_clusters WHERE cluster_id = OLD.cluster_id FOR UPDATE;
        SELECT retain_ms INTO STRICT keep_ms FROM naway_certificate_owners WHERE cluster_id = OLD.cluster_id;
        now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
        IF NOT cluster.epoch_required OR OLD.admission_epoch >= cluster.current_epoch OR OLD.execution_started
            OR (CASE WHEN OLD.state IN ('rejected', 'cancelled') THEN OLD.updated_at_ms ELSE OLD.expires_at_ms END) > now_ms - keep_ms THEN
            RAISE EXCEPTION 'certificate material retention responsibility remains';
        END IF;
        RETURN OLD;
    END IF;
    IF ROW(
        NEW.cluster_id,
        NEW.id,
        NEW.scope,
        NEW.creator,
        NEW.client_key,
        NEW.admission_epoch,
        NEW.authority,
        NEW.intent_digest,
        NEW.key_id,
        NEW.ciphertext,
        NEW.material_bytes,
        NEW.reserved_bytes,
        NEW.targets,
        NEW.summary,
        NEW.created_at_ms,
        NEW.expires_at_ms
    ) IS DISTINCT FROM ROW(
        OLD.cluster_id,
        OLD.id,
        OLD.scope,
        OLD.creator,
        OLD.client_key,
        OLD.admission_epoch,
        OLD.authority,
        OLD.intent_digest,
        OLD.key_id,
        OLD.ciphertext,
        OLD.material_bytes,
        OLD.reserved_bytes,
        OLD.targets,
        OLD.summary,
        OLD.created_at_ms,
        OLD.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'certificate proposal intent is immutable';
    END IF;
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    -- 任务引用已在同一事务建立；过期只能阻止新任务，不能阻断已确认终态的责任回收。
    IF NEW.execution_started IS DISTINCT FROM OLD.execution_started THEN
        IF OLD.state <> 'approved' OR ROW(NEW.state, NEW.reviewer) IS DISTINCT FROM ROW(OLD.state, OLD.reviewer)
            OR NEW.updated_at_ms < OLD.updated_at_ms OR NEW.updated_at_ms > now_ms
            OR NOT EXISTS (SELECT 1 FROM naway_material_execution_tasks t
                WHERE t.cluster_id = OLD.cluster_id AND t.proposal_id = OLD.id
                    AND ((NEW.execution_started AND t.state = 'running' AND now_ms < OLD.expires_at_ms)
                        OR (NOT NEW.execution_started AND t.state = 'complete'))) THEN
            RAISE EXCEPTION 'material execution parent responsibility differs' USING ERRCODE = 'PN010';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.execution_started THEN
        RAISE EXCEPTION 'material execution parent remains retained' USING ERRCODE = 'PN010';
    END IF;
    IF OLD.state <> 'awaiting_approval' OR NEW.state = 'awaiting_approval'
        OR now_ms >= OLD.expires_at_ms OR NEW.updated_at_ms < OLD.updated_at_ms OR NEW.updated_at_ms > now_ms THEN
        RAISE EXCEPTION 'certificate proposal review conflict' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE naway_material_impact_proposals DROP CONSTRAINT naway_material_impact_proposals_execution_started_check;

-- 业务作用：保留原材料批准的受理和审阅门，并仅由原共享任务改变执行保留标记。
-- 参数说明: 无；OLD 和 NEW 是原批准行，任务状态由同一事务验证。
-- 返回：原合法受理、审阅、执行标记或精确回收继续；未知责任保持拒绝。
CREATE OR REPLACE FUNCTION naway_material_impact_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
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
        IF NEW.execution_started THEN
            RAISE EXCEPTION 'material impact cannot begin with execution responsibility' USING ERRCODE = 'PN010';
        END IF;
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
    IF NEW.scope <> material.scope
        OR NEW.material_creator <> material.creator OR NEW.authority <> material.authority
        OR NEW.material_intent <> material.intent_digest OR NEW.material_store_id <> original_store
        OR NEW.material_admission_epoch <> material.admission_epoch
        OR NEW.expires_at_ms <> material.expires_at_ms THEN
        RAISE EXCEPTION 'original material authority changed' USING ERRCODE = '23514';
    END IF;
    -- 执行标记只允许原任务创建或全节点关闭后改变；普通登记和审阅仍受父材料原期限约束。
    IF (TG_OP = 'INSERT' OR NEW.execution_started = OLD.execution_started)
        AND (material.state NOT IN ('awaiting_approval', 'approved') OR material.execution_started
            OR now_ms >= material.expires_at_ms) THEN
        RAISE EXCEPTION 'original material admission closed' USING ERRCODE = '23514';
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
        OLD.created_at_ms,
        OLD.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'material impact intent is immutable';
    END IF;
    -- 任务引用已在同一事务建立；过期只能阻止新任务，不能阻断已确认终态的责任回收。
    IF NEW.execution_started IS DISTINCT FROM OLD.execution_started THEN
        IF OLD.state <> 'approved' OR ROW(NEW.state, NEW.reviewer) IS DISTINCT FROM ROW(OLD.state, OLD.reviewer)
            OR NEW.updated_at_ms < OLD.updated_at_ms OR NEW.updated_at_ms > now_ms
            OR NOT EXISTS (SELECT 1 FROM naway_material_execution_tasks t
                WHERE t.cluster_id = OLD.cluster_id AND t.impact_id = OLD.id
                    AND ((NEW.execution_started AND t.state = 'running' AND now_ms < OLD.expires_at_ms)
                        OR (NOT NEW.execution_started AND t.state = 'complete'))) THEN
            RAISE EXCEPTION 'material execution parent responsibility differs' USING ERRCODE = 'PN010';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.execution_started THEN
        RAISE EXCEPTION 'material execution parent remains retained' USING ERRCODE = 'PN010';
    END IF;
    IF OLD.state <> 'awaiting_approval' OR NEW.state = 'awaiting_approval'
        OR now_ms >= OLD.expires_at_ms OR NEW.updated_at_ms < OLD.updated_at_ms OR NEW.updated_at_ms > now_ms THEN
        RAISE EXCEPTION 'material impact review conflict' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
