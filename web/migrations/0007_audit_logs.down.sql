DELETE FROM role_permissions WHERE permission = 'audit.read';
DROP TABLE IF EXISTS audit_logs;
