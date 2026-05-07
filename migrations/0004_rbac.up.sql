CREATE TABLE roles (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(64)  NOT NULL UNIQUE,
    description TEXT         NOT NULL DEFAULT '',
    is_system   BOOLEAN      NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE role_permissions (
    role_id    UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission VARCHAR(64) NOT NULL,
    PRIMARY KEY (role_id, permission)
);
CREATE INDEX role_permissions_perm_idx ON role_permissions(permission);

CREATE TABLE user_roles (
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_roles_role_idx ON user_roles(role_id);

CREATE TABLE role_services (
    role_id    UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    service_id UUID        NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, service_id)
);
CREATE INDEX role_services_service_idx ON role_services(service_id);

INSERT INTO roles (name, description, is_system) VALUES
    ('all',   'Default group present on all users.', true),
    ('admin', 'Full administrative access.',         true);

INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
CROSS JOIN (VALUES
    ('users.create'),         ('users.read'),         ('users.update'),         ('users.delete'),
    ('roles.create'),         ('roles.read'),         ('roles.update'),         ('roles.delete'),
    ('user_roles.create'),    ('user_roles.read'),    ('user_roles.delete'),
    ('role_services.create'), ('role_services.read'), ('role_services.delete'),
    ('services.create'),      ('services.read'),      ('services.update'),      ('services.delete'),
    ('tokens.read'),          ('tokens.delete'),
    ('permissions.read')
) AS p(permission)
WHERE r.name = 'admin';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r WHERE r.name = 'all';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE r.name = 'admin' AND u.user_type = 'admin';

ALTER TABLE users DROP COLUMN user_type;
