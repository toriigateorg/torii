DELETE FROM role_permissions WHERE permission IN ('sso.create', 'sso.read', 'sso.update', 'sso.delete');

DROP INDEX IF EXISTS user_identities_user_idx;
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS sso_providers;

UPDATE users SET password_hash = '' WHERE password_hash IS NULL;
ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;
