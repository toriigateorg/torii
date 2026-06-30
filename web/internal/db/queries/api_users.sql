-- name: CreateAPIUser :one
INSERT INTO api_users (name, description, token_hash, token_prefix, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetAPIUserByID :one
SELECT * FROM api_users WHERE id = $1;

-- name: GetAPIUserByHash :one
SELECT * FROM api_users WHERE token_hash = $1;

-- name: ListAPIUsers :many
SELECT * FROM api_users
ORDER BY created_at DESC, id ASC
LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int;

-- name: CountAPIUsers :one
SELECT count(*) FROM api_users;

-- name: UpdateAPIUserToken :one
UPDATE api_users
SET token_hash = $2,
    token_prefix = $3,
    expires_at = $4,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteAPIUser :exec
DELETE FROM api_users WHERE id = $1;

-- name: TouchAPIUserLastUsed :exec
UPDATE api_users SET last_used_at = now() WHERE id = $1;

-- name: GetAPIUserRoleIDs :many
SELECT role_id FROM api_user_roles WHERE api_user_id = $1;

-- name: ListAPIUserRoles :many
SELECT r.* FROM roles r
JOIN api_user_roles aur ON aur.role_id = r.id
WHERE aur.api_user_id = $1
ORDER BY r.is_system DESC, r.name ASC;

-- name: AssignAPIUserRole :exec
INSERT INTO api_user_roles (api_user_id, role_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RevokeAPIUserRole :exec
DELETE FROM api_user_roles WHERE api_user_id = $1 AND role_id = $2;
