-- name: CreateService :one
INSERT INTO services (title, description, service_url, domain, headers, preserve_host, passthrough_errors)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetServiceByID :one
SELECT * FROM services WHERE id = $1;

-- name: GetServiceByDomain :one
SELECT * FROM services WHERE domain = $1;

-- name: ListServices :many
SELECT * FROM services
ORDER BY created_at ASC, id ASC
LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int;

-- name: CountServices :one
SELECT count(*) FROM services;

-- name: UpdateService :one
UPDATE services
SET title = $2,
    description = $3,
    service_url = $4,
    domain = $5,
    headers = $6,
    preserve_host = $7,
    passthrough_errors = $8,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteService :exec
DELETE FROM services WHERE id = $1;

-- name: RotateServiceSigningSecret :one
UPDATE services
SET signing_secret = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;
