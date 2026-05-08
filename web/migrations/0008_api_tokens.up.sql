CREATE TABLE api_tokens (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         VARCHAR(200) NOT NULL,
    token_hash   BYTEA       NOT NULL UNIQUE,
    token_prefix VARCHAR(32) NOT NULL,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX api_tokens_user_id_idx ON api_tokens(user_id);

INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
CROSS JOIN (VALUES
    ('api_tokens.create'),
    ('api_tokens.read'),
    ('api_tokens.delete')
) AS p(permission)
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;
