ALTER TABLE naway_operation_clusters
    ADD COLUMN capacity_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN capacity_previous_digest BYTEA,
    ADD COLUMN max_records INTEGER,
    ADD COLUMN max_records_per_scope INTEGER,
    ADD COLUMN max_candidate_bytes INTEGER,
    ADD COLUMN max_total_candidate_bytes BIGINT,
    ADD CONSTRAINT naway_operation_capacity_contract CHECK (
        CASE WHEN max_records IS NULL THEN
            capacity_revision = 0 AND capacity_previous_digest IS NULL AND max_records_per_scope IS NULL
                AND max_candidate_bytes IS NULL AND max_total_candidate_bytes IS NULL
        ELSE
            capacity_revision > 0
                AND (capacity_previous_digest IS NULL AND capacity_revision = 1
                    OR capacity_previous_digest IS NOT NULL AND octet_length(capacity_previous_digest) = 32)
                AND max_records_per_scope IS NOT NULL
                AND max_candidate_bytes IS NOT NULL AND max_total_candidate_bytes IS NOT NULL
                AND max_records BETWEEN 1 AND 4096
                AND max_records_per_scope BETWEEN 1 AND max_records
                AND max_candidate_bytes BETWEEN 1024 AND 1048576
                AND max_total_candidate_bytes BETWEEN max_candidate_bytes AND 67108864
                AND capacity_digest = pg_catalog.sha256(
                    pg_catalog.int4send(max_records) || pg_catalog.int4send(max_records_per_scope)
                    || pg_catalog.int4send(max_candidate_bytes) || pg_catalog.int8send(max_total_candidate_bytes))
        END
    );

-- 业务作用：已登记容量只能连同单调修订一起变化，禁止部分更新或重新开启无实值的兼容合同。
-- 参数说明: 无；OLD 和 NEW 是数据库持有行锁的同一集群记录。
-- 返回：合法完整合同继续写入；退回旧修订或未登记状态时整条更新失败。
CREATE FUNCTION naway_preserve_operation_capacity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    total_count BIGINT;
    scoped_count BIGINT;
    total_bytes BIGINT;
    largest_candidate BIGINT;
BEGIN
    IF ROW(NEW.capacity_digest, NEW.max_records, NEW.max_records_per_scope,
            NEW.max_candidate_bytes, NEW.max_total_candidate_bytes)
        IS DISTINCT FROM ROW(OLD.capacity_digest, OLD.max_records, OLD.max_records_per_scope,
            OLD.max_candidate_bytes, OLD.max_total_candidate_bytes) THEN
        -- 容量变更必须消费一个新修订；相同摘要重新出现不能恢复旧维护令牌的权威。
        IF OLD.capacity_revision = 9223372036854775807
            OR NEW.capacity_revision <> OLD.capacity_revision + 1
            OR NEW.capacity_previous_digest IS DISTINCT FROM OLD.capacity_digest
            OR NEW.max_records IS NULL THEN
            RAISE EXCEPTION 'operation capacity revision differs' USING ERRCODE = '23514';
        END IF;
        -- 缩容不能丢弃任何保留状态；持有同一集群锁期间，创建与清理都不能改变这组用量。
        SELECT coalesce(sum(records), 0), coalesce(max(records), 0), coalesce(sum(bytes), 0), coalesce(max(largest), 0)
            INTO total_count, scoped_count, total_bytes, largest_candidate
            FROM (SELECT count(*) AS records, sum(octet_length(candidate)) AS bytes, max(octet_length(candidate)) AS largest
                FROM naway_operation_proposals WHERE cluster_id = OLD.cluster_id GROUP BY scope) AS usage;
        IF total_count > NEW.max_records OR scoped_count > NEW.max_records_per_scope
            OR total_bytes > NEW.max_total_candidate_bytes OR largest_candidate > NEW.max_candidate_bytes THEN
            RAISE EXCEPTION 'operation retained usage exceeds requested capacity' USING ERRCODE = 'PN001';
        END IF;
    ELSIF NEW.capacity_revision <> OLD.capacity_revision
        OR NEW.capacity_previous_digest IS DISTINCT FROM OLD.capacity_previous_digest THEN
        RAISE EXCEPTION 'operation capacity revision has no contract change' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER naway_operation_capacity_monotonic BEFORE UPDATE ON naway_operation_clusters
    FOR EACH ROW EXECUTE FUNCTION naway_preserve_operation_capacity();

-- 业务作用：让新旧 Admin 都受同一持久容量约束，旧进程中的较大预算不能绕过已经提交的缩容。
-- 参数说明: 无；NEW 是尚未保存的提案。
-- 返回：仅预算足够时继续插入；拒绝会连同同事务的幂等占位一起回滚。
CREATE FUNCTION naway_validate_proposal_capacity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    capacity naway_operation_clusters%ROWTYPE;
    total_count BIGINT;
    scoped_count BIGINT;
    total_bytes BIGINT;
BEGIN
    -- 调整容量、清理与创建共用集群行锁；取得锁后再统计，不能用等待前的空余放行。
    SELECT * INTO STRICT capacity FROM naway_operation_clusters WHERE cluster_id = NEW.cluster_id FOR UPDATE;
    IF capacity.max_records IS NULL THEN
        RETURN NEW;
    END IF;
    IF octet_length(NEW.candidate) > capacity.max_candidate_bytes THEN
        RAISE EXCEPTION 'operation candidate capacity exhausted' USING ERRCODE = 'PN001';
    END IF;
    SELECT count(*), count(*) FILTER (WHERE scope = NEW.scope), coalesce(sum(octet_length(candidate)), 0)::bigint
        INTO total_count, scoped_count, total_bytes
        FROM naway_operation_proposals WHERE cluster_id = NEW.cluster_id;
    IF total_count >= capacity.max_records OR scoped_count >= capacity.max_records_per_scope
        OR total_bytes + octet_length(NEW.candidate) > capacity.max_total_candidate_bytes THEN
        RAISE EXCEPTION 'operation shared capacity exhausted' USING ERRCODE = 'PN001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER naway_proposal_capacity_gate BEFORE INSERT ON naway_operation_proposals
    FOR EACH ROW EXECUTE FUNCTION naway_validate_proposal_capacity();
