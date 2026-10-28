CREATE TABLE naway_operation_namespace (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    cluster_id TEXT COLLATE "C",
    bound_at_ms BIGINT,
    CHECK (
        (cluster_id IS NULL AND bound_at_ms IS NULL)
        OR (cluster_id IS NOT NULL AND bound_at_ms IS NOT NULL
            AND octet_length(cluster_id) BETWEEN 1 AND 128
            AND cluster_id ~ '^[A-Za-z0-9._-]+$' AND bound_at_ms >= 0)
    )
);
INSERT INTO naway_operation_namespace(singleton) VALUES (TRUE);

-- 业务作用：永久保存工作流所属集群；关闭进程或清空业务记录不重新开放此 schema。
-- 参数说明: 无；OLD 和 NEW 是数据库持锁的命名空间行。
-- 返回：同值写或首次合法绑定继续；改换身份、移除权威或已有其它集群时拒绝。
CREATE FUNCTION naway_preserve_execution_namespace() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'execution namespace cannot be removed' USING ERRCODE = 'PN002';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF OLD.cluster_id IS NOT NULL OR NEW.singleton IS DISTINCT FROM OLD.singleton
        OR NEW.cluster_id IS NULL OR NEW.bound_at_ms IS NULL THEN
        RAISE EXCEPTION 'execution namespace cannot be reassigned' USING ERRCODE = 'PN002';
    END IF;
    -- 注册也写同一行；等待后重新核对已有集群，旧隔离快照则由 MVCC 冲突拒绝。
    IF EXISTS (SELECT 1 FROM naway_operation_clusters WHERE cluster_id <> NEW.cluster_id) THEN
        RAISE EXCEPTION 'execution namespace contains another cluster' USING ERRCODE = 'PN002';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER naway_execution_namespace_update
BEFORE UPDATE OR DELETE ON naway_operation_namespace
FOR EACH ROW EXECUTE FUNCTION naway_preserve_execution_namespace();
CREATE TRIGGER naway_execution_namespace_truncate
BEFORE TRUNCATE ON naway_operation_namespace
FOR EACH STATEMENT EXECUTE FUNCTION naway_preserve_execution_namespace();

-- 业务作用：使所有新旧集群注册均受同一持久命名空间约束，避免工作流跨集群投递。
-- 参数说明: 无；NEW 是正在登记或变更身份的集群。
-- 返回：未绑定或所属集群一致时继续；保护行缺席、异集群或旧快照写冲突时拒绝。
CREATE FUNCTION naway_validate_execution_cluster() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    owner_cluster TEXT;
BEGIN
    -- 值不变的 UPDATE 仍创建行版本；只加共享锁会让较早的 REPEATABLE READ 快照漏掉注册。
    UPDATE naway_operation_namespace SET singleton = singleton
        WHERE singleton RETURNING cluster_id INTO owner_cluster;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'execution namespace authority missing' USING ERRCODE = 'PN002';
    END IF;
    IF owner_cluster IS NOT NULL AND owner_cluster IS DISTINCT FROM NEW.cluster_id THEN
        RAISE EXCEPTION 'cluster differs from execution namespace' USING ERRCODE = 'PN002';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER naway_cluster_execution_namespace
BEFORE INSERT OR UPDATE OF cluster_id ON naway_operation_clusters
FOR EACH ROW EXECUTE FUNCTION naway_validate_execution_cluster();
