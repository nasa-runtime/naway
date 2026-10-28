-- 先取得已永久绑定的命名空间，初始化不能隐式替某个进程决定集群归属。
DO $$
BEGIN
    PERFORM 1 FROM naway_operation_namespace WHERE singleton AND cluster_id IS NOT NULL FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow requires a bound execution namespace';
    END IF;
    -- 仅接受空工作流存储；IF NOT EXISTS 不能把未知对象或部分历史结构登记为可信基线。
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema()
            AND (left(c.relname, 5) IN ('saga_', 'inbox') OR left(c.relname, 6) = 'outbox'
                OR left(c.relname, 10) = 'nasa_saga_' OR c.relname = 'naway_operation_workflow_schema')
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = current_schema() AND left(p.proname, 7) = 'nasaga_'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = current_schema()
            AND (left(t.typname, 5) IN ('saga_', 'inbox') OR left(t.typname, 6) = 'outbox'
                OR left(t.typname, 10) = 'nasa_saga_' OR t.typname = 'naway_operation_workflow_schema')
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_statistic_ext s
        JOIN pg_catalog.pg_namespace n ON n.oid = s.stxnamespace
        WHERE n.nspname = current_schema() AND left(s.stxname, 5) = 'saga_'
    ) THEN
        RAISE EXCEPTION 'workflow namespace already contains unmanaged objects';
    END IF;
END;
$$;

-- 提案证据表限定原合同名称；工作流单独持证，不改变任何已安装提案结构。
CREATE TABLE naway_operation_workflow_schema (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    shape JSONB NOT NULL
);
