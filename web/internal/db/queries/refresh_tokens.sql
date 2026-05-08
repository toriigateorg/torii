-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = $1;

-- name: DeleteRefreshTokenByHash :exec
DELETE FROM refresh_tokens WHERE token_hash = $1;

-- name: DeleteRefreshTokensForUser :exec
DELETE FROM refresh_tokens WHERE user_id = $1;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < now();

-- name: ListRefreshTokensWithUsers :many
SELECT
    rt.id,
    rt.user_id,
    rt.token_hash,
    rt.expires_at,
    rt.created_at,
    rt.revoked_at,
    u.username,
    u.email
FROM refresh_tokens rt
JOIN users u ON u.id = rt.user_id
ORDER BY rt.created_at DESC, rt.id ASC
LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int;

-- name: CountRefreshTokens :one
SELECT count(*) FROM refresh_tokens;

-- name: CountActiveRefreshTokens :one
SELECT count(*) FROM refresh_tokens
WHERE revoked_at IS NULL AND expires_at > now();

-- name: GetRefreshTokenByID :one
SELECT * FROM refresh_tokens WHERE id = $1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1;

-- name: DeleteExpiredOrRevokedRefreshTokens :execrows
DELETE FROM refresh_tokens WHERE expires_at < now() OR revoked_at IS NOT NULL;
