-- name: GetUserIdentity :one
SELECT * FROM user_identities WHERE provider_id = $1 AND subject = $2;

-- name: CreateUserIdentity :one
INSERT INTO user_identities (provider_id, subject, user_id, email)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: UpsertUserIdentity :one
INSERT INTO user_identities (provider_id, subject, user_id, email)
VALUES ($1, $2, $3, $4)
ON CONFLICT (provider_id, subject) DO UPDATE
SET email = EXCLUDED.email
RETURNING *;
