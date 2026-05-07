ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

CREATE TABLE sso_providers (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          VARCHAR(64)  NOT NULL UNIQUE,
    name          VARCHAR(128) NOT NULL,
    issuer_url    TEXT         NOT NULL,
    client_id     TEXT         NOT NULL,
    client_secret TEXT         NOT NULL,
    scopes        TEXT         NOT NULL DEFAULT 'openid email profile',
    enabled       BOOLEAN      NOT NULL DEFAULT true,
    allow_signup  BOOLEAN      NOT NULL DEFAULT false,
    link_by_email BOOLEAN      NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE user_identities (
    provider_id UUID        NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    subject     TEXT        NOT NULL,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email       TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, subject)
);
CREATE INDEX user_identities_user_idx ON user_identities(user_id);

INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
CROSS JOIN (VALUES
    ('sso.create'), ('sso.read'), ('sso.update'), ('sso.delete')
) AS p(permission)
WHERE r.name = 'admin';
