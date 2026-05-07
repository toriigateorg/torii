-- name: InsertAuditLog :one
INSERT INTO audit_logs (
    event_type,
    actor_user_id,
    actor_username,
    target_type,
    target_id,
    target_name,
    client_ip,
    user_agent,
    metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: ListAuditLogs :many
SELECT *
FROM audit_logs
WHERE (sqlc.narg('actor_user_id')::uuid IS NULL OR actor_user_id = sqlc.narg('actor_user_id')::uuid)
  AND (sqlc.narg('event_type')::text IS NULL OR event_type = sqlc.narg('event_type')::text)
  AND (sqlc.narg('target_type')::text IS NULL OR target_type = sqlc.narg('target_type')::text)
  AND (sqlc.narg('target_id')::uuid IS NULL OR target_id = sqlc.narg('target_id')::uuid)
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts')::timestamptz)
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at < sqlc.narg('to_ts')::timestamptz)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int;

-- name: CountAuditLogs :one
SELECT count(*)
FROM audit_logs
WHERE (sqlc.narg('actor_user_id')::uuid IS NULL OR actor_user_id = sqlc.narg('actor_user_id')::uuid)
  AND (sqlc.narg('event_type')::text IS NULL OR event_type = sqlc.narg('event_type')::text)
  AND (sqlc.narg('target_type')::text IS NULL OR target_type = sqlc.narg('target_type')::text)
  AND (sqlc.narg('target_id')::uuid IS NULL OR target_id = sqlc.narg('target_id')::uuid)
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts')::timestamptz)
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at < sqlc.narg('to_ts')::timestamptz);

-- name: DeleteAuditLogsBefore :execrows
DELETE FROM audit_logs WHERE created_at < $1;
