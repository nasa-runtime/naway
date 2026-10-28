//! 工作流结构在同一迁移事务中创建；普通启动只读取已提交的合同尾部。

pub(super) const MIGRATION: &str = concat!(
    "DO $$ BEGIN IF (SELECT shape FROM naway_operation_schema WHERE name = 'proposals') IS DISTINCT FROM (SELECT base.shape || jsonb_build_object('protocol', protocol.shape, 'capacity', capacity.shape, 'namespace', namespace.shape) FROM (",
    include_str!("../sql/shape.sql"),
    ") AS base CROSS JOIN (",
    include_str!("../sql/epoch_shape.sql"),
    ") AS protocol CROSS JOIN (",
    include_str!("../sql/capacity_shape.sql"),
    ") AS capacity CROSS JOIN (",
    include_str!("../sql/namespace_shape.sql"),
    ") AS namespace) THEN RAISE EXCEPTION 'operations schema structure differs from migration evidence'; END IF; END $$;\n",
    include_str!("../workflow/sql/initialize.sql"),
    include_str!("../workflow/sql/saga_state.sql"),
    include_str!("../workflow/sql/result_inbox.sql"),
    include_str!("../workflow/sql/command_outbox.sql"),
    include_str!("../workflow/sql/quotas.sql"),
    "\nINSERT INTO naway_operation_workflow_schema(singleton, shape) SELECT TRUE, shape FROM (\n",
    include_str!("../workflow/sql/shape.sql"),
    "\n) AS initial_shape;\n"
);

pub(super) const SHAPE: &str = concat!(
    "SELECT shape::text FROM (",
    include_str!("../workflow/sql/shape.sql"),
    ") AS workflow_shape"
);
