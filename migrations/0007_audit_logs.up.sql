CREATE TABLE audit_logs (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    event_type     VARCHAR(64)  NOT NULL,
    actor_user_id  UUID         REFERENCES users(id) ON DELETE SET NULL,
    actor_username TEXT         NOT NULL DEFAULT '',
    target_type    VARCHAR(32)  NOT NULL DEFAULT '',
    target_id      UUID,
    target_name    TEXT         NOT NULL DEFAULT '',
    client_ip      TEXT         NOT NULL DEFAULT '',
    user_agent     TEXT         NOT NULL DEFAULT '',
    metadata       JSONB        NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_logs_created_at_idx ON audit_logs (created_at DESC);
CREATE INDEX audit_logs_actor_idx      ON audit_logs (actor_user_id, created_at DESC);
CREATE INDEX audit_logs_event_idx      ON audit_logs (event_type, created_at DESC);
CREATE INDEX audit_logs_target_idx     ON audit_logs (target_type, target_id);

INSERT INTO role_permissions (role_id, permission)
SELECT r.id, 'audit.read'
FROM roles r
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;
