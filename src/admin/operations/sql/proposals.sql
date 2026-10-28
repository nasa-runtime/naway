CREATE TABLE naway_operation_clusters (
    cluster_id TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(cluster_id) BETWEEN 1 AND 128),
    capacity_digest BYTEA NOT NULL CHECK (octet_length(capacity_digest) = 32)
);

CREATE TABLE naway_operation_proposals (
    cluster_id TEXT COLLATE "C" NOT NULL REFERENCES naway_operation_clusters(cluster_id),
    id TEXT COLLATE "C" NOT NULL CHECK (octet_length(id) = 32),
    scope TEXT COLLATE "C" NOT NULL CHECK (octet_length(scope) BETWEEN 1 AND 128),
    domain TEXT COLLATE "C" NOT NULL CHECK (domain IN ('gateway', 'sentinel', 'interface-guard')),
    creator TEXT COLLATE "C" NOT NULL CHECK (octet_length(creator) BETWEEN 1 AND 128),
    reviewer TEXT COLLATE "C" CHECK (octet_length(reviewer) BETWEEN 1 AND 128),
    client_key TEXT COLLATE "C" NOT NULL CHECK (octet_length(client_key) BETWEEN 1 AND 128),
    authority BYTEA NOT NULL CHECK (octet_length(authority) = 32),
    candidate BYTEA NOT NULL CHECK (octet_length(candidate) BETWEEN 1 AND 1048576),
    candidate_digest BYTEA NOT NULL CHECK (octet_length(candidate_digest) = 32),
    targets BYTEA NOT NULL CHECK (octet_length(targets) BETWEEN 2 AND 65536),
    state TEXT NOT NULL CHECK (state IN ('awaiting_approval', 'approved', 'rejected', 'cancelled')),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms >= created_at_ms),
    PRIMARY KEY (cluster_id, id),
    UNIQUE (cluster_id, scope, creator, client_key),
    CHECK ((state = 'awaiting_approval' AND reviewer IS NULL)
        OR (state IN ('approved', 'rejected') AND reviewer IS NOT NULL AND reviewer <> creator)
        OR (state = 'cancelled' AND reviewer = creator))
);
CREATE INDEX naway_operation_proposals_scope ON naway_operation_proposals(cluster_id, scope, id);

CREATE TABLE idempotency_record_v2 (
    tenant TEXT COLLATE "C" NOT NULL CHECK (octet_length(tenant) BETWEEN 1 AND 128),
    subject TEXT COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 190),
    route_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(route_id) BETWEEN 1 AND 190),
    client_key TEXT COLLATE "C" NOT NULL CHECK (octet_length(client_key) BETWEEN 1 AND 190),
    fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint) = 32),
    lease BYTEA NOT NULL CHECK (octet_length(lease) = 16),
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    state SMALLINT NOT NULL CHECK (state IN (0, 1)),
    status INTEGER CHECK (status BETWEEN 100 AND 599),
    body BYTEA,
    headers BYTEA,
    lease_expires_at_ms BIGINT NOT NULL CHECK (lease_expires_at_ms >= 0),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms >= 0),
    CONSTRAINT idempotency_record_v2_pkey PRIMARY KEY (tenant, subject, route_id, client_key)
);

CREATE TABLE naway_operation_schema (
    name TEXT PRIMARY KEY CHECK (name = 'proposals'),
    shape JSONB NOT NULL
);
