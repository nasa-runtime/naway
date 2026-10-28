-- 空结构与配额零事实同事务提交，普通启动不能把缺失账本误认为尚无在途实例。
INSERT INTO saga_tenant_quota(tenant_id, in_flight, initialized)
SELECT cluster_id, 0, TRUE FROM naway_operation_namespace WHERE singleton AND cluster_id IS NOT NULL;
INSERT INTO outbox_tenant_quota(tenant_id, in_flight, initialized)
SELECT cluster_id, 0, TRUE FROM naway_operation_namespace WHERE singleton AND cluster_id IS NOT NULL;
