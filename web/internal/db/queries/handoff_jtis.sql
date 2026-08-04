-- name: BurnHandoffJTI :one
-- Records a handoff token id as spent and reports whether this call was the first
-- to do so. ON CONFLICT DO NOTHING means a second presentation returns no rows,
-- i.e. pgx.ErrNoRows, so the winner is decided inside Postgres rather than by a
-- read followed by a write. Replaces a process-local map that only bounded replays
-- within a single replica.
INSERT INTO handoff_jtis (jti, expires_at)
VALUES ($1, $2)
ON CONFLICT (jti) DO NOTHING
RETURNING jti;

-- name: DeleteExpiredHandoffJTIs :execrows
-- A spent id is only worth remembering until the token it belongs to expires,
-- which is 30 seconds. Swept periodically; without it the table grows by one row
-- per cross-host login indefinitely.
DELETE FROM handoff_jtis WHERE expires_at < now();
