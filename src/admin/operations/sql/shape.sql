SELECT jsonb_build_object(
    'columns', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, a.attnum, a.attname,
            pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull,
            a.attidentity, a.attgenerated, coll.collname,
            pg_catalog.pg_get_expr(d.adbin, d.adrelid)) ORDER BY c.relname, a.attnum)
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
        LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = a.attcollation
        WHERE n.nspname = current_schema() AND a.attnum > 0 AND NOT a.attisdropped
        AND c.relname IN ('naway_operation_clusters', 'naway_operation_proposals', 'idempotency_record_v2')
    ),
    'constraints', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, k.conname, k.convalidated,
            pg_catalog.pg_get_constraintdef(k.oid)) ORDER BY c.relname, k.conname)
        FROM pg_catalog.pg_constraint k
        JOIN pg_catalog.pg_class c ON c.oid = k.conrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema()
        AND c.relname IN ('naway_operation_clusters', 'naway_operation_proposals', 'idempotency_record_v2')
    ),
    'indexes', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, idx.relname, i.indisvalid,
            i.indisready, pg_catalog.pg_get_indexdef(i.indexrelid)) ORDER BY c.relname, idx.relname)
        FROM pg_catalog.pg_index i
        JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
        JOIN pg_catalog.pg_class idx ON idx.oid = i.indexrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema()
        AND c.relname IN ('naway_operation_clusters', 'naway_operation_proposals', 'idempotency_record_v2')
    ),
    'tables', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, c.relkind, c.relrowsecurity,
            c.relforcerowsecurity, c.relhastriggers) ORDER BY c.relname)
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema()
        AND c.relname IN ('naway_operation_clusters', 'naway_operation_proposals', 'idempotency_record_v2')
    )
) AS shape
