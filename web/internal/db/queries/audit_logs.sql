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

-- name: CountAuditLogsByDay :many
SELECT
    date_trunc('day', created_at AT TIME ZONE 'UTC')::timestamptz AS day,
    count(*)::bigint AS count
FROM audit_logs
WHERE created_at >= sqlc.arg('from_ts')::timestamptz
  AND created_at <  sqlc.arg('to_ts')::timestamptz
GROUP BY 1
ORDER BY 1 ASC;

-- name: TopServicesByAccess :many
SELECT
    s.id,
    s.title,
    s.domain,
    count(*)::bigint AS access_count
FROM audit_logs a
JOIN services s ON s.id = a.target_id
WHERE a.event_type = 'proxy.access'
  AND a.target_type = 'service'
  AND a.created_at >= sqlc.arg('from_ts')::timestamptz
  AND a.created_at <  sqlc.arg('to_ts')::timestamptz
GROUP BY s.id, s.title, s.domain
ORDER BY access_count DESC, s.title ASC
LIMIT sqlc.arg('lim')::int;
