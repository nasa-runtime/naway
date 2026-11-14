//! 聚合根轮转通过显式追加索引安装，既有工作流证据在写入前重新核对。

pub(super) const MIGRATION: &str = concat!(
    "DO $$ BEGIN IF (SELECT shape FROM naway_operation_workflow_schema WHERE singleton) IS DISTINCT FROM (SELECT shape FROM (",
    include_str!("../workflow/sql/shape.sql"),
    ") AS workflow) OR (SELECT shape FROM naway_delivery_schema WHERE singleton) IS DISTINCT FROM (SELECT shape FROM (",
    include_str!("../execution/sql/shape.sql"),
    ") AS delivery) THEN RAISE EXCEPTION 'operations schema differs before aggregate dispatch initialization'; END IF; END $$;\n",
    include_str!("../workflow/sql/aggregate_dispatch.sql"),
    "\nUPDATE naway_operation_workflow_schema SET shape = (SELECT shape FROM (",
    include_str!("../workflow/sql/shape.sql"),
    ") AS current_shape) WHERE singleton;\n"
);
