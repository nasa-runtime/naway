SELECT jsonb_build_object(
    'columns', (
        SELECT jsonb_agg(jsonb_build_array(a.attnum, a.attname,
            pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull,
            a.attidentity, a.attgenerated, coll.collname,
            pg_catalog.pg_get_expr(d.adbin, d.adrelid)) ORDER BY a.attnum)
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
        LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = a.attcollation
        WHERE n.nspname = current_schema() AND a.attnum > 0 AND NOT a.attisdropped
            AND c.relname = 'naway_operation_namespace'
    ),
    'constraints', (
        SELECT jsonb_agg(jsonb_build_array(k.conname, k.convalidated,
            pg_catalog.pg_get_constraintdef(k.oid)) ORDER BY k.conname)
        FROM pg_catalog.pg_constraint k
        JOIN pg_catalog.pg_class c ON c.oid = k.conrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relname = 'naway_operation_namespace'
    ),
    'indexes', (
        SELECT jsonb_agg(jsonb_build_array(idx.relname, i.indisvalid,
            i.indisready, pg_catalog.pg_get_indexdef(i.indexrelid)) ORDER BY idx.relname)
        FROM pg_catalog.pg_index i
        JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
        JOIN pg_catalog.pg_class idx ON idx.oid = i.indexrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relname = 'naway_operation_namespace'
    ),
    'tables', (
        SELECT jsonb_agg(jsonb_build_array(c.relkind, c.relrowsecurity,
            c.relforcerowsecurity, c.relhastriggers))
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relname = 'naway_operation_namespace'
    ),
    'functions', (
        SELECT jsonb_agg(jsonb_build_array(p.proname, pg_catalog.pg_get_functiondef(p.oid)) ORDER BY p.proname)
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = current_schema()
            AND p.proname IN ('naway_preserve_execution_namespace', 'naway_validate_execution_cluster')
    ),
    'triggers', (
        SELECT jsonb_agg(jsonb_build_array(t.tgname, t.tgenabled,
            pg_catalog.pg_get_triggerdef(t.oid)) ORDER BY t.tgname)
        FROM pg_catalog.pg_trigger t
        JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND NOT t.tgisinternal
            AND c.relname = 'naway_operation_namespace'
    )
) AS shape
