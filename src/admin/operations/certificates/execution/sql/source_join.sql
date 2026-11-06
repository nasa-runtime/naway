) original
JOIN naway_certificate_proposals p ON p.cluster_id=original.cluster_id AND p.id=original.proposal_id
JOIN naway_material_execution_fence e ON e.singleton AND e.cluster_id=original.cluster_id
LEFT JOIN naway_material_execution_tasks t ON t.cluster_id=original.cluster_id AND t.impact_id=original.id
