-- name: CreateUser :one
INSERT INTO users (username, email, first_name, last_name, password_hash)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByUsernameOrEmail :one
SELECT * FROM users
WHERE lower(username) = lower($1::text)
   OR lower(email) = lower($1::text)
LIMIT 1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY created_at ASC, id ASC
LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int;

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;
