-- Fleet DB: lets an operator flag a node as business-critical. The reason and
-- timestamp are stored alongside the flag so the decision stays auditable.

ALTER TABLE nodes
ADD COLUMN IF NOT EXISTS critical BOOLEAN DEFAULT FALSE NOT NULL,
ADD COLUMN IF NOT EXISTS critical_reason TEXT,
ADD COLUMN IF NOT EXISTS critical_marked_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_nodes_critical ON nodes(critical);
