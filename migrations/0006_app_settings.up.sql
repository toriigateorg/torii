CREATE TABLE app_settings (
    key        VARCHAR(64)  PRIMARY KEY,
    value      TEXT         NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

INSERT INTO app_settings (key, value) VALUES ('signup_enabled', 'true');

INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
CROSS JOIN (VALUES ('settings.read'), ('settings.update')) AS p(permission)
WHERE r.name = 'admin';
