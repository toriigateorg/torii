-- name: CreateRole :one
INSERT INTO roles (name, description, is_system)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetRoleByID :one
SELECT * FROM roles WHERE id = $1;

-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = $1;

-- name: ListRoles :many
SELECT * FROM roles
ORDER BY is_system DESC, name ASC, id ASC
LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int;

-- name: CountRoles :one
SELECT count(*) FROM roles;

-- name: UpdateRole :one
UPDATE roles
SET name = $2,
    description = $3,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteRole :exec
DELETE FROM roles WHERE id = $1 AND is_system = false;

-- name: ListRolePermissions :many
SELECT permission FROM role_permissions
WHERE role_id = $1
ORDER BY permission ASC;

-- name: GetUserPermissions :many
SELECT DISTINCT rp.permission
FROM role_permissions rp
JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = $1
ORDER BY rp.permission ASC;

-- name: DeleteRolePermissions :exec
DELETE FROM role_permissions WHERE role_id = $1;

-- name: InsertRolePermission :exec
INSERT INTO role_permissions (role_id, permission)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: ListUserRoles :many
SELECT r.* FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1
ORDER BY r.is_system DESC, r.name ASC;

-- name: GetUserRoleIDs :many
SELECT role_id FROM user_roles WHERE user_id = $1;

-- name: ListUsersInRole :many
SELECT u.*
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
WHERE ur.role_id = $1
ORDER BY u.created_at ASC, u.id ASC
LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int;

-- name: CountUsersInRole :one
SELECT count(*) FROM user_roles WHERE role_id = $1;

-- name: AssignUserRole :exec
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RevokeUserRole :exec
DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2;

-- name: CountAdmins :one
SELECT count(DISTINCT ur.user_id)
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
WHERE r.name = 'admin';

-- name: ListRoleServices :many
SELECT s.*
FROM services s
JOIN role_services rs ON rs.service_id = s.id
WHERE rs.role_id = $1
ORDER BY s.created_at ASC, s.id ASC;

-- name: ListServiceRoles :many
SELECT r.*
FROM roles r
JOIN role_services rs ON rs.role_id = r.id
WHERE rs.service_id = $1
ORDER BY r.name ASC;

-- name: ListServicesForUser :many
SELECT DISTINCT s.*
FROM services s
JOIN role_services rs ON rs.service_id = s.id
JOIN user_roles ur ON ur.role_id = rs.role_id
WHERE ur.user_id = $1
ORDER BY s.title ASC, s.id ASC;

-- name: AssignRoleService :exec
INSERT INTO role_services (role_id, service_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RevokeRoleService :exec
DELETE FROM role_services WHERE role_id = $1 AND service_id = $2;

-- name: ListAllServicesWithRolesForCache :many
SELECT
    s.id,
    s.title,
    s.description,
    s.service_url,
    s.domain,
    s.headers,
    s.signing_secret,
    s.preserve_host,
    s.passthrough_errors,
    s.max_body_size,
    s.read_timeout_secs,
    s.write_timeout_secs,
    s.dial_timeout_secs,
    s.created_at,
    s.updated_at,
    COALESCE(
        (SELECT array_agg(rs.role_id) FROM role_services rs WHERE rs.service_id = s.id),
        ARRAY[]::uuid[]
    )::uuid[] AS role_ids
FROM services s;
