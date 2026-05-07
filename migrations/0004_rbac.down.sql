ALTER TABLE users ADD COLUMN user_type VARCHAR(16) NOT NULL DEFAULT 'user'
    CHECK (user_type IN ('admin', 'user'));

UPDATE users SET user_type = 'admin'
WHERE id IN (
    SELECT ur.user_id FROM user_roles ur
    JOIN roles r ON r.id = ur.role_id
    WHERE r.name = 'admin'
);

DROP TABLE role_services;
DROP TABLE user_roles;
DROP TABLE role_permissions;
DROP TABLE roles;
