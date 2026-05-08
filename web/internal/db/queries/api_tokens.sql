-- name: CreateAPIToken :one
INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetAPITokenByHash :one
SELECT * FROM api_tokens WHERE token_hash = $1;

-- name: GetAPITokenByID :one
SELECT * FROM api_tokens WHERE id = $1;

-- name: TouchAPITokenLastUsed :exec
UPDATE api_tokens SET last_used_at = now() WHERE id = $1;

-- name: DeleteAPIToken :exec
DELETE FROM api_tokens WHERE id = $1;

-- name: ListAPITokensWithUsers :many
SELECT
    t.id,
    t.user_id,
    t.name,
    t.token_prefix,
    t.expires_at,
    t.last_used_at,
    t.created_at,
    u.username,
    u.email
FROM api_tokens t
JOIN users u ON u.id = t.user_id
ORDER BY t.created_at DESC, t.id ASC
LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int;

-- name: CountAPITokens :one
SELECT count(*) FROM api_tokens;
