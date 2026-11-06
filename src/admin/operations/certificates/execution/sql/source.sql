SELECT original.*, p.key_id, p.created_at_ms AS material_created,
    p.reviewer AS material_reviewer, p.material_bytes,
    octet_length(p.ciphertext) AS ciphertext_bytes,
    sha256(convert_to(p.ciphertext, 'UTF8')) AS ciphertext_sha256,
    e.store_id AS execution_store,
    t.operation_id AS task_id, t.state AS task_state, t.candidate_digest,
    t.definition_digest, t.target_count, t.node_count,
    (t.operation_id IS NULL OR ROW(
        t.cluster_id, t.execution_store, t.proposal_id, t.impact_id,
        t.material_store, t.impact_store, t.material_epoch, t.impact_epoch,
        t.scope, t.material_creator, t.material_reviewer, t.impact_creator,
        t.impact_reviewer, t.material_intent, t.impact_digest, t.authority,
        t.impact_authority, t.candidate_bytes
    ) = ROW(
        original.cluster_id, e.store_id, original.proposal_id, original.id,
        original.material_store_id, original.impact_store_id,
        original.material_admission_epoch, original.admission_epoch,
        original.scope, original.material_creator, p.reviewer, original.creator,
        original.reviewer, original.material_intent, original.impact_digest,
        original.authority, original.impact_authority, p.material_bytes
    )) AS task_matches
FROM (
