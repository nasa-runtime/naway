WITH relations AS (
    SELECT c.* FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = current_schema()
        AND left(c.relname, 15) = 'naway_delivery_'
)
SELECT jsonb_build_object(
    'columns', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, a.attnum, a.attname,
            pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull,
            a.attidentity, a.attgenerated, coll.collname,
            pg_catalog.pg_get_expr(d.adbin, d.adrelid)) ORDER BY c.relname, a.attnum)
        FROM relations c
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
        LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = a.attcollation
        WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p')
    ),
    'constraints', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, k.conname, k.convalidated,
            pg_catalog.pg_get_constraintdef(k.oid)) ORDER BY c.relname, k.conname)
        FROM pg_catalog.pg_constraint k JOIN relations c ON c.oid = k.conrelid
    ),
    'indexes', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, idx.relname, i.indisvalid,
            i.indisready, pg_catalog.pg_get_indexdef(i.indexrelid)) ORDER BY c.relname, idx.relname)
        FROM pg_catalog.pg_index i JOIN relations c ON c.oid = i.indrelid
        JOIN pg_catalog.pg_class idx ON idx.oid = i.indexrelid
    ),
    'tables', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, c.relkind, c.relpersistence,
            c.relrowsecurity, c.relforcerowsecurity, c.relhastriggers, c.relispartition,
            am.amname) ORDER BY c.relname)
        FROM relations c LEFT JOIN pg_catalog.pg_am am ON am.oid = c.relam
        WHERE c.relkind NOT IN ('i', 'S')
    ),
    'sequences', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, s.seqstart, s.seqincrement,
            s.seqmax, s.seqmin, s.seqcache, s.seqcycle,
            pg_catalog.format_type(s.seqtypid, NULL), target.relname, d.refobjsubid, d.deptype)
            ORDER BY c.relname, target.relname, d.refobjsubid, d.deptype)
        FROM pg_catalog.pg_sequence s JOIN relations c ON c.oid = s.seqrelid
        LEFT JOIN pg_catalog.pg_depend d ON d.objid = c.oid
            AND d.classid = 'pg_catalog.pg_class'::regclass
            AND d.refclassid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i')
        LEFT JOIN pg_catalog.pg_class target ON target.oid = d.refobjid
    ),
    'functions', (
        SELECT jsonb_agg(jsonb_build_array(p.proname, pg_catalog.pg_get_functiondef(p.oid))
            ORDER BY p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid))
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = current_schema() AND left(p.proname, 15) = 'naway_delivery_'
    ),
    'triggers', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, t.tgname, t.tgenabled,
            pg_catalog.pg_get_triggerdef(t.oid)) ORDER BY c.relname, t.tgname)
        FROM pg_catalog.pg_trigger t JOIN relations c ON c.oid = t.tgrelid
        WHERE NOT t.tgisinternal
    ),
    'statistics', (
        SELECT jsonb_agg(jsonb_build_array(s.stxname, pg_catalog.pg_get_statisticsobjdef(s.oid)) ORDER BY s.stxname)
        FROM pg_catalog.pg_statistic_ext s JOIN relations c ON c.oid = s.stxrelid
    ),
    'policies', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, p.polname, p.polcmd, p.polpermissive,
            p.polroles, pg_catalog.pg_get_expr(p.polqual, p.polrelid),
            pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid)) ORDER BY c.relname, p.polname)
        FROM pg_catalog.pg_policy p JOIN relations c ON c.oid = p.polrelid
    )
) AS shape
