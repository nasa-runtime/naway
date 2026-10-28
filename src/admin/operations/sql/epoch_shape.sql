SELECT jsonb_build_object(
    'functions', (
        SELECT jsonb_agg(jsonb_build_array(p.proname, pg_catalog.pg_get_functiondef(p.oid)) ORDER BY p.proname)
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = current_schema()
            AND p.proname IN ('naway_validate_proposal_epoch', 'naway_preserve_operation_epoch')
    ),
    'triggers', (
        SELECT jsonb_agg(jsonb_build_array(c.relname, t.tgname, t.tgenabled,
            pg_catalog.pg_get_triggerdef(t.oid)) ORDER BY c.relname, t.tgname)
        FROM pg_catalog.pg_trigger t
        JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND NOT t.tgisinternal
            AND c.relname IN ('naway_operation_clusters', 'naway_operation_proposals')
    )
) AS shape
