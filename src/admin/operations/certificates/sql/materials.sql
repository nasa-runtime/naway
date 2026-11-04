CREATE TABLE naway_certificate_schema (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    shape JSONB NOT NULL
);

CREATE TABLE naway_certificate_owners (
    cluster_id TEXT COLLATE "C" PRIMARY KEY REFERENCES naway_operation_clusters(cluster_id),
    store_id TEXT COLLATE "C" NOT NULL UNIQUE CHECK (store_id ~ '^[0-9a-f]{64}$'),
    max_records INTEGER NOT NULL CHECK (max_records BETWEEN 1 AND 4096),
    max_records_per_scope INTEGER NOT NULL CHECK (max_records_per_scope BETWEEN 1 AND max_records),
    max_material_bytes INTEGER NOT NULL CHECK (max_material_bytes BETWEEN 1024 AND 1048576),
    max_total_bytes BIGINT NOT NULL CHECK (max_total_bytes BETWEEN max_material_bytes * 2 + 65536 AND 67108864),
    retain_ms BIGINT NOT NULL CHECK (retain_ms BETWEEN 60000 AND 2678400000)
);

CREATE TABLE naway_certificate_proposals (
    cluster_id TEXT COLLATE "C" NOT NULL REFERENCES naway_certificate_owners(cluster_id),
    id TEXT COLLATE "C" NOT NULL CHECK (id ~ '^[0-9a-f]{32}$'),
    scope TEXT COLLATE "C" NOT NULL CHECK (octet_length(scope) BETWEEN 1 AND 128),
    creator TEXT COLLATE "C" NOT NULL CHECK (octet_length(creator) BETWEEN 1 AND 128),
    reviewer TEXT COLLATE "C" CHECK (octet_length(reviewer) BETWEEN 1 AND 128),
    client_key TEXT COLLATE "C" NOT NULL CHECK (octet_length(client_key) BETWEEN 1 AND 128),
    admission_epoch BIGINT NOT NULL CHECK (admission_epoch > 0),
    authority BYTEA NOT NULL CHECK (octet_length(authority) = 32),
    intent_digest BYTEA NOT NULL CHECK (octet_length(intent_digest) = 32),
    key_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(key_id) BETWEEN 1 AND 64),
    ciphertext TEXT NOT NULL CHECK (left(ciphertext, 14) = 'NC2.65536.3.4.' AND octet_length(ciphertext) BETWEEN 64 AND 2097440),
    material_bytes INTEGER NOT NULL CHECK (material_bytes BETWEEN 18 AND 1048592),
    reserved_bytes BIGINT NOT NULL CHECK (reserved_bytes > 0),
    targets BYTEA NOT NULL CHECK (octet_length(targets) BETWEEN 2 AND 65536),
    summary BYTEA NOT NULL CHECK (octet_length(summary) BETWEEN 2 AND 1024),
    state TEXT NOT NULL CHECK (state IN ('awaiting_approval', 'approved', 'rejected', 'cancelled')),
    execution_started BOOLEAN NOT NULL DEFAULT FALSE CHECK (NOT execution_started),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms BETWEEN created_at_ms + 60000 AND created_at_ms + 86400000),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms >= created_at_ms),
    PRIMARY KEY (cluster_id, id),
    UNIQUE (cluster_id, scope, creator, admission_epoch, client_key),
    CHECK (reserved_bytes = material_bytes::bigint * 2 + octet_length(targets) + 4096),
    CHECK (octet_length(ciphertext) <= material_bytes::bigint * 2 + 256),
    CHECK ((state = 'awaiting_approval' AND reviewer IS NULL)
        OR (state IN ('approved', 'rejected') AND reviewer IS NOT NULL AND reviewer <> creator)
        OR (state = 'cancelled' AND reviewer = creator))
);
CREATE INDEX naway_certificate_proposals_scope ON naway_certificate_proposals(cluster_id, scope, id);

-- 业务作用：只允许在已绑定集群内首次登记材料存储，阻止重启或配置切换重置身份与容量。
-- 参数说明: 无；触发器的 NEW 来自材料 owner 登记，UPDATE 和 DELETE 不具有变更权威。
-- 返回：合法首次登记返回 NEW；错误集群、修改或删除拒绝整个语句。
CREATE FUNCTION naway_certificate_preserve_owner() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'certificate material storage authority is immutable';
    END IF;
    PERFORM 1 FROM naway_operation_clusters WHERE cluster_id = NEW.cluster_id FOR UPDATE;
    IF NOT EXISTS (SELECT 1 FROM naway_operation_namespace WHERE singleton AND cluster_id = NEW.cluster_id) THEN
        RAISE EXCEPTION 'certificate material requires bound cluster namespace';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_certificate_owner_guard BEFORE INSERT OR UPDATE OR DELETE ON naway_certificate_owners
FOR EACH ROW EXECUTE FUNCTION naway_certificate_preserve_owner();

-- 业务作用：在共享集群锁内核对全部保留材料预算，避免不同 Admin 同时预占同一份容量。
-- 参数说明：
-- - p_cluster：已绑定的发行集群。
-- - p_scope：当前精确平台或工作区域。
-- - p_bytes：最坏密文扩张和元数据的预留字节。
-- - p_material：含固定长度帧的明文字节数。
-- 返回：容量足够时无返回值；缺权威或任一预算耗尽则拒绝，不删除旧材料腾挪空间。
CREATE FUNCTION naway_certificate_capacity(p_cluster TEXT, p_scope TEXT, p_bytes BIGINT, p_material INTEGER)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    owner naway_certificate_owners%ROWTYPE;
    records BIGINT;
    scoped BIGINT;
    retained BIGINT;
BEGIN
    -- 在同一集群锁内先预留最坏材料容量；所有保留状态都占用预算，过期不等于已回收。
    PERFORM 1 FROM naway_operation_clusters WHERE cluster_id = p_cluster FOR UPDATE;
    SELECT * INTO STRICT owner FROM naway_certificate_owners WHERE cluster_id = p_cluster;
    SELECT count(*), count(*) FILTER (WHERE scope = p_scope), coalesce(sum(reserved_bytes), 0)
    INTO records, scoped, retained FROM naway_certificate_proposals WHERE cluster_id = p_cluster;
    IF p_bytes <= 0 OR p_material <= 16 OR p_material > owner.max_material_bytes + 16
        OR records >= owner.max_records OR scoped >= owner.max_records_per_scope
        OR retained > owner.max_total_bytes - p_bytes THEN
        RAISE EXCEPTION 'certificate proposal capacity exhausted' USING ERRCODE = 'PN001';
    END IF;
END;
$$;

-- 业务作用：在材料写入、审阅与回收边界保护原意图、单调代际和保留责任。
-- 参数说明: 无；触发器按当前行操作使用数据库提供的 OLD 和 NEW。
-- 返回：只有合法首次受理、单次审阅或已关闭原代的精确清理才能继续，失败回滚整个语句。
CREATE FUNCTION naway_certificate_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    cluster naway_operation_clusters%ROWTYPE;
    now_ms BIGINT;
    keep_ms BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
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
        NEW.execution_started,
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
        OLD.execution_started,
        OLD.created_at_ms,
        OLD.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'certificate proposal intent is immutable';
    END IF;
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF OLD.state <> 'awaiting_approval' OR NEW.state = 'awaiting_approval'
        OR now_ms >= OLD.expires_at_ms OR NEW.updated_at_ms < OLD.updated_at_ms OR NEW.updated_at_ms > now_ms THEN
        RAISE EXCEPTION 'certificate proposal review conflict' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_certificate_proposal_guard BEFORE INSERT OR UPDATE OR DELETE ON naway_certificate_proposals
FOR EACH ROW EXECUTE FUNCTION naway_certificate_guard();
