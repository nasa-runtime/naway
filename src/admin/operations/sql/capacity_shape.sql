SELECT jsonb_agg(jsonb_build_array(p.proname, pg_catalog.pg_get_functiondef(p.oid)) ORDER BY p.proname) AS shape
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = current_schema()
    AND p.proname IN ('naway_preserve_operation_capacity', 'naway_validate_proposal_capacity')
