//! 目标占位与永久 fence 独立记录结构证据，已有工作流输入保持不可变。

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
    ") AS workflow) THEN RAISE EXCEPTION 'operations schema structure differs before delivery initialization'; END IF; END $$;\n",
    "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND left(c.relname, 15) = 'naway_delivery_') OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = current_schema() AND left(p.proname, 15) = 'naway_delivery_') OR EXISTS (SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = current_schema() AND left(t.typname, 15) = 'naway_delivery_') THEN RAISE EXCEPTION 'delivery namespace already contains unmanaged objects'; END IF; END $$;\n",
    include_str!("../execution/sql/delivery.sql"),
    include_str!("../execution/sql/targets.sql"),
    include_str!("../execution/sql/acquire.sql"),
    "\nINSERT INTO naway_delivery_schema(singleton, shape) SELECT TRUE, shape FROM (\n",
    include_str!("../execution/sql/shape.sql"),
    "\n) AS initial_shape;\n"
);

pub(super) const SHAPE: &str = concat!(
    "SELECT shape::text FROM (",
    include_str!("../execution/sql/shape.sql"),
    ") AS delivery_shape"
);
