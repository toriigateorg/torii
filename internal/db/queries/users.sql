-- name: CreateUser :one
INSERT INTO users (username, email, first_name, last_name, password_hash, user_type)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByUsernameOrEmail :one
SELECT * FROM users
WHERE lower(username) = lower($1::text)
   OR lower(email) = lower($1::text)
LIMIT 1;
