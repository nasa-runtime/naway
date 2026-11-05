SELECT i.*, o.store_id AS impact_store_id,
    p.targets AS original_targets, p.summary AS original_summary,
    p.creator AS original_creator, p.scope AS original_scope,
    p.authority AS original_authority, p.intent_digest AS original_intent,
    p.admission_epoch AS original_epoch, p.expires_at_ms AS original_expires,
    p.state AS material_state, p.execution_started AS material_execution_started,
    m.store_id AS original_store,
    floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms
FROM naway_material_impact_proposals i
JOIN naway_material_impact_owners o ON o.cluster_id=i.cluster_id
JOIN naway_certificate_proposals p ON p.cluster_id=i.cluster_id AND p.id=i.proposal_id
JOIN naway_certificate_owners m ON m.cluster_id=i.cluster_id
