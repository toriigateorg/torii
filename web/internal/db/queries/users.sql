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

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $2,
    updated_at = now()
WHERE id = $1;

-- name: IncrementFailedLogin :one
UPDATE users
SET failed_login_count = failed_login_count + 1,
    locked_until = CASE
        WHEN failed_login_count + 1 >= 10 THEN now() + interval '15 minutes'
        ELSE locked_until
    END,
    updated_at = now()
WHERE id = $1
RETURNING failed_login_count, locked_until;

-- name: ResetFailedLogin :exec
UPDATE users
SET failed_login_count = 0,
    locked_until = NULL,
    updated_at = now()
WHERE id = $1;
