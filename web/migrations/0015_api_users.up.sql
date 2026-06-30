CREATE TABLE api_users (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(200) NOT NULL UNIQUE,
    description  TEXT         NOT NULL DEFAULT '',
    token_hash   BYTEA        NOT NULL UNIQUE,
    token_prefix VARCHAR(32)  NOT NULL,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    disabled     BOOLEAN      NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE api_user_roles (
    api_user_id UUID        NOT NULL REFERENCES api_users(id) ON DELETE CASCADE,
    role_id     UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (api_user_id, role_id)
);

CREATE INDEX api_user_roles_role_idx ON api_user_roles(role_id);

INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
CROSS JOIN (VALUES
    ('api_users.create'),
    ('api_users.read'),
    ('api_users.update'),
    ('api_users.delete')
) AS p(permission)
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;
