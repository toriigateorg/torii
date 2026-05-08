-- name: CreateSSOProvider :one
INSERT INTO sso_providers (slug, name, issuer_url, client_id, client_secret, scopes, enabled, allow_signup, link_by_email)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetSSOProviderByID :one
SELECT * FROM sso_providers WHERE id = $1;

-- name: GetSSOProviderBySlug :one
SELECT * FROM sso_providers WHERE slug = $1;

-- name: ListSSOProviders :many
SELECT * FROM sso_providers
ORDER BY created_at ASC, id ASC
LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int;

-- name: ListEnabledSSOProviders :many
SELECT id, slug, name FROM sso_providers
WHERE enabled = true
ORDER BY created_at ASC, id ASC;

-- name: CountSSOProviders :one
SELECT count(*) FROM sso_providers;

-- name: UpdateSSOProvider :one
UPDATE sso_providers
SET slug = $2,
    name = $3,
    issuer_url = $4,
    client_id = $5,
    client_secret = $6,
    scopes = $7,
    enabled = $8,
    allow_signup = $9,
    link_by_email = $10,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteSSOProvider :exec
DELETE FROM sso_providers WHERE id = $1;
