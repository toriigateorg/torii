DELETE FROM role_permissions
WHERE permission IN ('api_tokens.create', 'api_tokens.read', 'api_tokens.delete');

DROP TABLE IF EXISTS api_tokens;
