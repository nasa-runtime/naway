//! 材料执行追加独立永久域，父批准及跨域占位合同在同一显式迁移事务内生效。

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
    ") AS delivery) OR (SELECT shape FROM naway_certificate_schema WHERE singleton) IS DISTINCT FROM (SELECT shape FROM (",
    include_str!("../certificates/sql/shape.sql"),
    ") AS certificates) OR (SELECT shape FROM naway_material_impact_schema WHERE singleton) IS DISTINCT FROM (SELECT shape FROM (",
    include_str!("../certificates/impact/sql/shape.sql"),
    ") AS impact) THEN RAISE EXCEPTION 'operations schema structure differs before material execution initialization'; END IF; END $$;\n",
    "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND left(c.relname, 25) = 'naway_material_execution_') OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = current_schema() AND left(p.proname, 25) = 'naway_material_execution_') OR EXISTS (SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = current_schema() AND left(t.typname, 25) = 'naway_material_execution_') THEN RAISE EXCEPTION 'material execution namespace contains unmanaged objects'; END IF; END $$;\n",
    include_str!("../certificates/execution/sql/namespace.sql"),
    "\n",
    include_str!("../certificates/execution/sql/tasks.sql"),
    "\n",
    include_str!("../certificates/execution/sql/nodes.sql"),
    "\n",
    include_str!("../certificates/execution/sql/parents.sql"),
    "\n",
    include_str!("../certificates/execution/sql/acquire.sql"),
    "\nUPDATE naway_delivery_schema SET shape = (SELECT shape FROM (",
    include_str!("../execution/sql/shape.sql"),
    ") AS current_shape) WHERE singleton;\nUPDATE naway_certificate_schema SET shape = (SELECT shape FROM (",
    include_str!("../certificates/sql/shape.sql"),
    ") AS current_shape) WHERE singleton;\nUPDATE naway_material_impact_schema SET shape = (SELECT shape FROM (",
    include_str!("../certificates/impact/sql/shape.sql"),
    ") AS current_shape) WHERE singleton;\nINSERT INTO naway_material_execution_schema(singleton, shape) SELECT TRUE, shape FROM (",
    include_str!("../certificates/execution/sql/shape.sql"),
    ") AS initial_shape;\n"
);

pub(super) const SHAPE: &str = concat!(
    "SELECT shape::text FROM (",
    include_str!("../certificates/execution/sql/shape.sql"),
    ") AS material_execution_shape"
);
