//! 加密材料采用独立结构证据，显式初始化前先验证已有持久合同。

pub(super) const MIGRATION: &str = concat!(
    "DO $$ BEGIN IF (SELECT shape FROM naway_operation_schema WHERE name = 'proposals') IS DISTINCT FROM (SELECT base.shape || jsonb_build_object('protocol', protocol.shape, 'capacity', capacity.shape, 'namespace', namespace.shape) FROM (",
    include_str!("../sql/shape.sql"),
    ") AS base CROSS JOIN (",
    include_str!("../sql/epoch_shape.sql"),
    ") AS protocol CROSS JOIN (",
    include_str!("../sql/capacity_shape.sql"),
    ") AS capacity CROSS JOIN (",
    include_str!("../sql/namespace_shape.sql"),
    ") AS namespace) OR (SELECT shape FROM naway_operation_workflow_schema WHERE singleton) IS DISTINCT FROM (SELECT shape FROM (",
    include_str!("../workflow/sql/shape.sql"),
    ") AS workflow) OR (SELECT shape FROM naway_delivery_schema WHERE singleton) IS DISTINCT FROM (SELECT shape FROM (",
    include_str!("../execution/sql/shape.sql"),
    ") AS delivery) THEN RAISE EXCEPTION 'operations schema structure differs before certificate initialization'; END IF; END $$;\n",
    "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND left(c.relname, 18) = 'naway_certificate_') OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = current_schema() AND left(p.proname, 18) = 'naway_certificate_') OR EXISTS (SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = current_schema() AND left(t.typname, 18) = 'naway_certificate_') THEN RAISE EXCEPTION 'certificate namespace contains unmanaged objects'; END IF; END $$;\n",
    include_str!("../certificates/sql/materials.sql"),
    "\nINSERT INTO naway_certificate_schema(singleton, shape) SELECT TRUE, shape FROM (\n",
    include_str!("../certificates/sql/shape.sql"),
    "\n) AS initial_shape;\n"
);

pub(super) const SHAPE: &str = concat!(
    "SELECT shape::text FROM (",
    include_str!("../certificates/sql/shape.sql"),
    ") AS certificate_shape"
);
